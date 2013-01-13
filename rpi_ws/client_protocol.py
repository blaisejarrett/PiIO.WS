from twisted.internet import reactor
from twisted.python import log
from autobahn.websocket import WebSocketClientProtocol
import rpi_data.interface as interface
import rpi_data.utility
import json
from hashlib import sha1
import hmac
import binascii
import settings, common_protocol



class ConfigState(common_protocol.State):
    """
    Responsible for setting up the IO
    """
    pass


class StreamState(common_protocol.State):
    pass


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

