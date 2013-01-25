from twisted.internet import reactor
from twisted.python import log
from autobahn.websocket import WebSocketClientProtocol, WebSocketClientFactory
from twisted.internet.protocol import ReconnectingClientFactory
import rpi_data.interface as interface
import rpi_data.utility
import json
from hashlib import sha1
import hmac
import binascii
import settings, common_protocol, buffer


class StreamState(common_protocol.State):
    def __init__(self, protocol, reads, writes):
        # reads/writes look like this
        # {u'cls:ADC, port:3': {'equations': [u'zzzz', u'asdfadfad'], 'obj': <rpi_data.interface.ADC object at 0x036D18D0>}}
        super(StreamState, self).__init__(protocol)
        self.config_reads = reads
        self.config_writes = writes
        self.polldata_read = buffer.UpdateDict()
        self.polldata_write = buffer.UpdateDict()
        self.ackcount = 0
        self.paused = True

    def onMessage(self, msg):
        msg = json.loads(msg)

        if msg['cmd'] == common_protocol.ServerCommands.DROP_TO_CONFIG:
            # wrong state, drop
            # flush IO
            io_clss = interface.get_interface_desc()
            for cls in io_clss['read']:
                cls.flush()
            for cls in io_clss['write']:
                cls.flush()
            self.protocol.pop_state()

            resp_msg = {'cmd':common_protocol.RPIClientCommands.DROP_TO_CONFIG_OK}
            self.protocol.sendMessage(json.dumps(resp_msg))
            return

        elif msg['cmd'] == common_protocol.ServerCommands.ACK_DATA:
            server_ackcount = msg['ack_count']
            self.ackcount += server_ackcount
            if self.ackcount > -10:
                self.poll_and_send()

        elif msg['cmd'] == common_protocol.ServerCommands.RESUME_STREAMING:
            self.resume_streaming()

        elif msg['cmd'] == common_protocol.ServerCommands.PAUSE_STREAMING:
            self.pause_streaming()

        elif msg['cmd'] == common_protocol.ServerCommands.WRITE_DATA:
            key = msg['iface_port']
            value = msg['value']
            self.write_to_iface(key, value)

    def write_to_iface(self, iface_port, value):
        if iface_port not in self.config_writes:
            return
        self.config_writes[iface_port]['obj'].write(value)

    def poll_and_send(self):
        if self.ackcount <= -10 or self.paused:
            return

        for key, value in self.config_reads.iteritems():
            self.polldata_read[key] = value['obj'].read()
        for key, value in self.config_writes.iteritems():
            self.polldata_write[key] = value['obj'].read()

        if len(self.polldata_read) > 0 or len(self.polldata_write) > 0:
            msg = {'cmd':common_protocol.RPIClientCommands.DATA}
            msg['read'] = self.polldata_read
            msg['write'] = self.polldata_write
            self.ackcount -= 1
            self.protocol.sendMessage(json.dumps(msg))

        reactor.callLater(0, self.poll_and_send)

    def pause_streaming(self):
        self.paused = True

    def resume_streaming(self):
        self.paused = False
        self.poll_and_send()


class ConfigState(common_protocol.State):
    """
    Responsible for setting up the IO
    """
    def onMessage(self, msg):
        msg = json.loads(msg)

        if msg['cmd'] == common_protocol.ServerCommands.CONFIG:
            reads = msg['payload']['read']
            writes = msg['payload']['write']

            if self.protocol.factory.debug:
                log.msg("ConfigState.onMessage - Received configs, %d reads, %d writes"
                        % (len(reads), len(writes)))

            # attempt to configure IO.......
            def instantiate_io(io_collection):
                # instantiate interface instances
                # {u'cls:ADC, port:3': {'cls_name':'ADC', 'ch_port':3, 'equations': [u'dddd', u'']}}
                # to:
                # {u'cls:ADC, port:3': {'cls_name':'ADC', 'ch_port':3, 'equations': [u'dddd', u''], 'obj':<instance>}}
                for key, value in io_collection.iteritems():
                    cls_str = value['cls_name']
                    ch_port = value['ch_port']
                    if self.protocol.factory.debug:
                        log.msg('ConfigState - Configuring module %s on ch/port %d' %
                            (cls_str, ch_port))

                    cls = getattr(interface, cls_str)
                    try:
                        instance = cls(ch_port)
                    except Exception, ex:
                        if self.protocol.factory.debug:
                            log.msg('ConfigState - Ex creating module %s', str(ex))
                        value['obj'] = None
                        continue

                    value['obj'] = instance

            instantiate_io(reads)
            instantiate_io(writes)

            if self.protocol.factory.debug:
                log.msg('ConfigState - Instantiated %d read interfaces' % len(reads))
                log.msg('ConfigState - Instantiated %d write interfaces' % len(writes))

            log.msg(str(reads))

            # there should be some feedback done here if something fails
            msg = {'cmd':common_protocol.RPIClientCommands.CONFIG_OK}

            self.protocol.push_state(StreamState(self.protocol, reads=reads, writes=writes))
            self.protocol.sendMessage(json.dumps(msg))



class RegisterState(common_protocol.State):
    def onMessage(self, msg):
        msg = json.loads(msg)

        if msg['cmd'] == common_protocol.ServerCommands.AUTH:
            self.token = msg['payload']['token']
            if self.protocol.factory.debug:
                log.msg("RegisterState.onMessage - Received token %s" % self.token)

            # compute HMAC reply
            hashed = hmac.new(settings.HMAC_TOKEN, self.protocol.mac + self.token, sha1)
            self.hamc_token = binascii.b2a_base64(hashed.digest())[:-1]
            reply = {'cmd':common_protocol.ServerCommands.AUTH, 'payload':{'token':self.hamc_token}}
            self.protocol.sendMessage(json.dumps(reply))
            self.hmac_reply_expected = True
            return

        if self.hmac_reply_expected and msg['cmd'] == common_protocol.ServerCommands.ACK:
            if self.protocol.factory.debug:
                log.msg("RegisterState.onMessage - Registration Ack")
            self.protocol.push_state(ConfigState(self.protocol))

    def __init__(self, protocol):
        super(RegisterState, self).__init__(protocol)
        self.hmac_reply_expected = False
        self._send_desc()

    def _send_desc(self):
        desc = {}
        desc['iface'] = {}
        desc['mac'] = self.protocol.mac

        def idesc(ifaces):
            # list of classes
            ret = []
            for cls in ifaces:
                name = cls.__name__
                desc = rpi_data.utility.trim(cls.__doc__)
                choices = []
                for choice_key, choice_value in cls.IO_CHOICES:
                    choice = {}
                    choice['s'] = choice_key
                    choice['d'] = choice_value
                    choices.append(choice)

                ret.append({'name':name, 'desc':desc, 'choices':choices, 'io_type':cls.IO_TYPE})
            return ret

        for key in self.protocol.interfaces.iterkeys():
            desc['iface'][key] = idesc(self.protocol.interfaces[key])

        self.protocol.sendMessage(json.dumps(desc))


class RPIClientProtocol(WebSocketClientProtocol, common_protocol.ProtocolState):
    def __init__(self):
        common_protocol.ProtocolState.__init__(self)
        self.mac = rpi_data.utility.get_mac()
        self.interfaces = interface.get_interface_desc()

    def onOpen(self):
        # push the initial state
        self.push_state(RegisterState(self))

    def onMessage(self, msg, binary):
        try:
            state = self.state_stack.pop_wr()
        except IndexError:
            if self.factory.debug:
                log.msg("RPIClientProtocol.onMessage - Received a message in an unknown state, ignored")
        state.onMessage(msg)


class ReconnectingWebSocketClientFactory(ReconnectingClientFactory, WebSocketClientFactory):
    maxDelay = 30