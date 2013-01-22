from twisted.internet import reactor, ssl
import twisted.internet.protocol as twistedsockets
from twisted.python import log
import sys
from autobahn.websocket import listenWS
from rpi_ws.server_protocol import RPIServerProtocol, RPISocketServerFactory, SiteComm, FlashSocketPolicyServerProtocol
from twisted.web import server

# SSL applies to both HTTP and WS
WS_USE_SSL = False
HTTP_USE_SSL = False
WS_PORT = 9000
SERVER = "localhost"
DEBUG = True
HTTP_PORT = 8090
PROVIDEFLASHSOCKETPOLICYFILE = True

def main():
    if WS_USE_SSL or HTTP_USE_SSL:
        contextFactory = ssl.DefaultOpenSSLContextFactory('certs/server.key',
            'certs/server.crt')

    if WS_USE_SSL:
        uri_type = "wss"
    else:
        uri_type = "ws"

    server_url = "%s://%s:%d" % (uri_type, SERVER, WS_PORT)

    if DEBUG:
        log.startLogging(sys.stdout)

    factory = RPISocketServerFactory(server_url, debug=DEBUG, debugCodePaths=DEBUG)
    factory.protocol = RPIServerProtocol

    sitecomm = SiteComm(factory)
    factory.sitecomm = sitecomm
    site = server.Site(sitecomm)

    if WS_USE_SSL:
        listenWS(factory, contextFactory)
    else:
        listenWS(factory)

    if HTTP_USE_SSL:
        reactor.listenSSL(HTTP_PORT, site, contextFactory)
    else:
        reactor.listenTCP(HTTP_PORT, site)

    if PROVIDEFLASHSOCKETPOLICYFILE:
        socketfactory = twistedsockets.Factory()
        socketfactory.protocol = FlashSocketPolicyServerProtocol
        reactor.listenTCP(843, socketfactory)

    reactor.run()


if __name__ == '__main__':
    main()
