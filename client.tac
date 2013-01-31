from twisted.application import service, internet


from rpi_ws.client_protocol import RPIClientProtocol, ReconnectingWebSocketClientFactory
from rpi_ws import settings



def getService():
    server_url = "ws://192.168.1.207:9000/rpi/"
    factory = ReconnectingWebSocketClientFactory(server_url, useragent=settings.RPI_USER_AGENT, debug=False)
    factory.protocol = RPIClientProtocol
    return internet.TCPClient(factory.host, factory.port, factory)

# this is the core part of any tac file, the creation of the root-level
# application object
application = service.Application("PiIOClient")

# attach the service to its parent application
service = getService()
service.setServiceParent(application)
