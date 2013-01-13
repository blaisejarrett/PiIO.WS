from twisted.python import log
from twisted.internet import threads, reactor
from autobahn.websocket import WebSocketServerFactory, WebSocketServerProtocol
from twisted.web import resource
import json
import time
import os
import binascii
import hashlib
import settings, common_protocol
from hashlib import sha1
import hmac
import urllib2, urllib

class SiteComm(resource.Resource):
    """
    To handle requests from the website
    """
    isLeaf = True

    def __init__(self, ws_factory, *args, **kwargs):
        resource.Resource.__init__(self, *args, **kwargs)
        self.ws_factory = ws_factory

    def render_GET(self, request):
        request.setHeader("Content-Type", "application/json")
        return "%s" % (str(self.ws_factory.rpi_clients),)

    def render_POST(self, request):
        # should be called to update configs by admin change

        request.setHeader("Content-Type", "application/json")
        return str(request.args)


    def register_rpi(self, rpi):
        # we need mac, ip, interface desc
        payload = {}
        payload['mac'] = rpi.mac
        payload['ip'] = rpi.protocol.peer.host
        payload['iface'] = rpi.iface

        post_data = {'json':json.dumps(payload)}
        post_data = urllib.urlencode(post_data)
        try:
            url = urllib2.Request('http://%s/ws_comm/register/' % settings.SITE_SERVER_ADDRESS, post_data)
            url_response = urllib2.urlopen(url)
        except urllib2.HTTPError, e:
            print e.read()
        print url_response.read()

        # register should return configs


    def disconnect_rpi(self, rpi):
        payload = {}
        payload['mac'] = rpi.mac

        post_data = {'json':json.dumps(payload)}
        post_data = urllib.urlencode(post_data)
        try:
            url = urllib2.Request('http://%s/ws_comm/disconnect/' % settings.SITE_SERVER_ADDRESS, post_data)
            url_response = urllib2.urlopen(url)
        except urllib2.HTTPError, e:
            print e.read()
        print url_response.read()


class ServerState(common_protocol.State):
    def __init__(self, client):
        self.client = client

    def activated(self):
        if self.client.protocol.debug:
            log.msg("%s.activated()" % self.__class__.__name__)

    def deactivated(self):
        if self.client.protocol.debug:
            log.msg("%s.deactivated()" % self.__class__.__name__)

class Client(common_protocol.ProtocolState):
    def __init__(self, protocol):
        common_protocol.ProtocolState.__init__(self)
        self.protocol = protocol

    def onMessage(self, msg):
        try:
            state = self.state_stack.pop_wr()
        except IndexError:
            if self.protocol.factory.debug:
                log.msg("%s.onMessage - Received a message in an unknown state, ignored", self.__class__.__name__)
        state.onMessage(msg)

    def onClose(self, wasClean, code, reason):
        pass


class UserClient(Client):
    pass


"""
RPI client related protocol and states
"""

class RPIConfigState(ServerState):
    """
    In this state, the RPI is waiting to be configured.
    Server is not required to configure the RPI immediately.
    """
    def __init__(self, client):
        super(RPIConfigState, self).__init__(client)


class RPIRegisterState(ServerState):
    def __init__(self, client):
        super(RPIRegisterState, self).__init__(client)
        self.registered = False
        self.re_message_count = 0

    def onMessage(self, msg):
        if self.re_message_count == 0 and not self.registered:
            # msg contains a register request
            parsed = json.loads(msg)
            self.client.mac = parsed['mac']
            self.client.iface = parsed['iface']
            if self.client.protocol.debug:
                log.msg("RPIClient.onMessage - Register Request from %s" % self.client.mac)

            # confirm legitimacy of request
            self.hmac_authorize()
            self.re_message_count += 1
            return

        if self.re_message_count == 1 and not self.registered:
            # msg contains HMAC response
            parsed = json.loads(msg)
            if parsed['cmd'] != common_protocol.ServerCommands.AUTH:
                if self.client.protocol.debug:
                    log.msg("RPIClient.onMessage - Auth fail, dropping")
                self.client.protocol.failConnection()

            # verify expected response
            if self.hamc_token == parsed['payload']['token']:
                self.registered = True
                self.re_message_count = 0
                if self.client.protocol.debug:
                    log.msg("RPIClient.onMessage - Successful registration")
                self.client.protocol.sendMessage(json.dumps({'cmd':common_protocol.ServerCommands.ACK}))
                self.client.push_state(RPIConfigState(self.client))
                # add to dictionary of clients in the factory
                self.client.protocol.factory.register_rpi(self.client)
            else:
                if self.client.protocol.debug:
                    self.client.protocol.failConnection()
                    log.msg("RPIClient.onMessage - Registration failed")
            return

    def hmac_authorize(self):
        _time = time.time()
        _rand = binascii.hexlify(os.urandom(32))
        hashed = hashlib.sha1(str(_time) + _rand).digest()
        self.rand_token = binascii.b2a_base64(hashed)[:-1]

        # calculate expected response
        hashed = hmac.new(settings.HMAC_TOKEN, self.client.mac + self.rand_token, sha1)
        self.hamc_token = binascii.b2a_base64(hashed.digest())[:-1]

        # send token
        msg = {'cmd':common_protocol.ServerCommands.AUTH, 'payload':{'token':self.rand_token}}
        self.client.protocol.sendMessage(json.dumps(msg))



class RPIClient(Client):
    def __init__(self, protocol):
        Client.__init__(self, protocol)
        self.push_state(RPIRegisterState(self))

    def onClose(self, wasClean, code, reason):
        # if we're registered remove ourselves from active client list
        if hasattr(self, 'mac'):
            self.protocol.factory.disconnect_rpi(self)



class RPIServerProtocol(WebSocketServerProtocol):
    """
    Base server protocol, instantiates child protocols
    """

    def __init__(self):
        self.client = None

    def onMessage(self, msg, binary):
        """
        Message received from client
        """
        if self.client is None:
            if self.debug:
                log.msg("RPIServerProtocol.onMessage - No Client type")
            self.failConnection()

        self.client.onMessage(msg)

    def onOpen(self):
        # check user agent
        if 'user-agent' in self.http_headers:
            if self.http_headers['user-agent'] == settings.RPI_USER_AGENT:
                if self.debug:
                    log.msg("RPIServerProtocol.onOpen - RPI connected")
                self.client = RPIClient(self)
                return

        if self.debug:
            log.msg("RPIServerProtocol.onOpen - User connected")
        self.client = UserClient(self)


    def onClose(self, wasClean, code, reason):
        """
        Connect closed, cleanup
        """
        # base logs
        WebSocketServerProtocol.onClose(self, wasClean, code, reason)
        if self.client is None:
            if self.debug:
                log.msg("RPIServerProtocol.onClose - No Client type")

        self.client.onClose(wasClean, code, reason)


class RPISocketServerFactory(WebSocketServerFactory):
    def __init__(self, *args, **kwargs):
        WebSocketServerFactory.__init__(self, *args, **kwargs)

        # identify rpi's by their macs
        # only store registered clients
        self.rpi_clients = {}
        self.user_client = []

    def register_rpi(self, rpi):
        reactor.callInThread(self.sitecomm.register_rpi, rpi)
        self.rpi_clients[rpi.mac] = rpi
        if self.debug:
            log.msg("RPISocketServerFactory.register_rpi - %s registered, %d rpi" % (rpi.mac, len(self.rpi_clients)))
        # should raise an event to push config if exits ???? we don't cache do we?

    def disconnect_rpi(self, rpi):
        if hasattr(rpi, 'mac'):
            reactor.callInThread(self.sitecomm.disconnect_rpi, rpi)
            del self.rpi_clients[rpi.mac]


