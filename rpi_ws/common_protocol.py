from twisted.python import log

class State(object):
    def onMessage(self, msg):
        raise NotImplementedError("Should have implemented this")

    def activated(self):
        """
        When state has become the top of the stack
        """
        self.active = True
        if self.protocol.debug:
            log.msg("%s.activated()" % self.__class__.__name__)

    def deactivated(self):
        self.active = False
        if self.protocol.debug:
            log.msg("%s.deactivated()" % self.__class__.__name__)

    def __init__(self, protocol):
        self.protocol = protocol
        self.active = False


class ServerCommands(object):
    AUTH = 'auth'
    ACK = 'ack'


class StateStack(list):
    def push(self, item):
        self.append(item)

    def pop_wr(self):
        """
        Pop last item without removing it
        """
        return self[-1]


class ProtocolState(object):
    def __init__(self):
        self.state_stack = StateStack()

    def push_state(self, state):
        try:
            self.state_stack.pop_wr().deactivated()
        except IndexError:
            # its the first on the stack
            pass
        self.state_stack.push(state)
        state.activated()

    def pop_state(self):
        self.state_stack.pop().deactivated()
        self.state_stack.pop_wr().activated()

    def current_state(self):
        return self.state_stack.pop_wr()

