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
import settings, common_protocol


class StreamState(common_protocol.State):
    def __init__(self, protocol, reads, writes):
        # reads/writes look like this
        # {u'cls:ADC, port:3': {'equations': [u'zzzz', u'asdfadfad'], 'obj': <rpi_data.interface.ADC object at 0x036D18D0>}}
        super(StreamState, self).__init__(protocol)
        self.config_reads = reads
        self.config_writes = writes

    def onMessage(self, msg):
        msg = json.loads(msg)

        if msg['cmd'] == common_protocol.ServerCommands.CONFIG:
            # wrong state, drop
            # flush IO
            io_clss = interface.get_interface_desc()
            for cls in io_clss['read']:
                cls.flush()
            for cls in io_clss['write']:
                cls.flush()
            self.protocol.pop_state()

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
            def config_io(io_collection):
                # deal with duplicates...........
                # duplicate equations allowed, duplicate instances not allowed
                instanced_io_dict = {}
                for io in io_collection:
                    cls_str = io['cls_name']
                    ch_port = io['ch_port']
                    equation = io['equation']
                    if self.protocol.factory.debug:
                        log.msg('ConfigState - Configuring module %s on ch/port %s with eq \'%s\'' %
                            (cls_str, ch_port, equation))

                    key = 'cls:%s, port:%s' % (cls_str, ch_port)
                    if key not in instanced_io_dict:
                        cls = getattr(interface, cls_str)
                        try:
                            instance = cls(ch_port)
                        except Exception, ex:
                            if self.protocol.factory.debug:
                                log.msg('ConfigState - Ex creating module %s', str(ex))
                            continue

                        io_new_dict = {'obj':instance}
                        if equation != '':
                            io_new_dict['equations'] = [equation]
                        else:
                            io_new_dict['equations'] = []
                        instanced_io_dict[key] = io_new_dict
                    else:
                        # we can have more then one equation per instance
                        existing_instance = instanced_io_dict[key]
                        equations = existing_instance['equations']
                        if equation not in equations:
                            equations.append(equation)

                return instanced_io_dict

            # looks like this:
            # {u'cls:ADC, port:3': {'equations': [u'zzzz', u'asdfadfad'], 'obj': <rpi_data.interface.ADC object at 0x036D18D0>}}
            read_instances = config_io(reads)
            write_instances = config_io(writes)

            if self.protocol.factory.debug:
                log.msg('ConfigState - Instantiated %d read interfaces' % len(read_instances))
                log.msg('ConfigState - Instantiated %d write interfaces' % len(write_instances))

            # there should be some feedback done here if something fails
            if read_instances is not None and write_instances is not None:
                msg = {'cmd':common_protocol.RPIClientCommands.CONFIG_OK}
                self.protocol.sendMessage(json.dumps(msg))

                self.protocol.push_state(StreamState(self.protocol, reads=read_instances, writes=write_instances))



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