import time
import random


class IBase(object):
    IO_TYPE_BINARY = 'B'
    IO_TYPE_INTEGER = 'I'

    # default state, override this
    IO_TYPE = IO_TYPE_BINARY
    # override this, stored value, description
    # stored value must be an integer, desc must be str
    # ex: ((1, 'GPIO1'),)
    IO_CHOICES = ()

    def close(self):
        """
        Because we're probably dealing with IO
        """
        raise NotImplementedError("Should have implemented this")

    @classmethod
    def open(cls, *args, **kwargs):
        """
        Open constructor, idea is to provide a File like interface
        """
        return cls(*args, **kwargs)


class IRead(IBase):
    """
    Interface you should extend to define interfaces that are
    available to poll for data on the RPI.
    """

    def read(self):
        """
        Poll for new data
        Blocks until new data becomes available.
        Returns data
        """
        raise NotImplementedError("Should have implemented this")

    def __iter__(self):
        """
        Generator to repeatedly poll
        """
        while True:
            yield self.read()


class IWrite(IBase):
    """
    Interface you should extend to implement a rpi writable interface
    """
    def write(self):
        raise NotImplementedError("Should have implemented this")


class ADC(IRead):
    """
    Maps to ADC using library
    Read only implied
    """
    IO_TYPE = IBase.IO_TYPE_INTEGER
    # we're using an 8 channel ADC
    IO_CHOICES = (
        (1, 'CH1'),
        (2, 'CH2'),
        (3, 'CH3'),
        (4, 'CH4'),
        (5, 'CH5'),
        (6, 'CH6'),
        (7, 'CH7'),
        (8, 'CH8'),
    )

    class ChannelInUseError(Exception): pass

    channels_in_use = {}

    def __init__(self, channel):
        if channel in ADC.channels_in_use:
            raise ADC.ChannelInUseError("Channel %d is in use" % channel)

        ADC.channels_in_use[channel] = self
        self.channel = channel

    def close(self):
        del ADC.channels_in_use[self.channel]

    def read(self):
        # for now simulate IO time
        time.sleep(1)
        return random.randrange(0, 9999)


class GPIOInput(IRead):
    """
    Maps to GPIO read only
    """
    IO_TYPE = IBase.IO_TYPE_BINARY
    IO_CHOICES = (
        (2, 'GPIO2 P3'),
        (3, 'GPIO3 P5'),
        (4, 'GPIO4 P7'),
        (7, 'GPIO7 P26'),
        (8, 'GPIO8 P24'),
        (9, 'GPIO9 P21'),
        (10, 'GPIO10 P19'),
        (11, 'GPIO11 P23'),
        (14, 'GPIO14 P8'),
        (15, 'GPIO15 P10'),
        (17, 'GPIO17 P11'),
        (18, 'GPIO18 P12'),
        (22, 'GPIO22 P15'),
        (23, 'GPIO23 P16'),
        (24, 'GPIO24 P18'),
        (25, 'GPIO25 P22'),
        (27, 'GPIO27 P13'),
    )

    class PortInUseError(Exception): pass
    class PortDoesntExistError(Exception): pass

    ports_in_use = {}

    def __init__(self, port):
        if port in GPIOInput.ports_in_use:
            raise GPIOInput.PortInUseError("Port %d is in use" % port)

        # Implement further logic to map to existing ports otherwise throw

        GPIOInput.ports_in_use[port] = self
        self.port = port

    def read(self):
        """
        Note: GPIO reads should be faster then network IO, careful of poll rate
        """
        return True

    def close(self):
        del GPIOInput.ports_in_use[self.port]


class GPIOOutput(IWrite):
    """
    Maps to GPIO write
    """
    IO_TYPE = IBase.IO_TYPE_BINARY
    IO_CHOICES = (
        (2, 'GPIO2 P3'),
        (3, 'GPIO3 P5'),
        (4, 'GPIO4 P7'),
        (7, 'GPIO7 P26'),
        (8, 'GPIO8 P24'),
        (9, 'GPIO9 P21'),
        (10, 'GPIO10 P19'),
        (11, 'GPIO11 P23'),
        (14, 'GPIO14 P8'),
        (15, 'GPIO15 P10'),
        (17, 'GPIO17 P11'),
        (18, 'GPIO18 P12'),
        (22, 'GPIO22 P15'),
        (23, 'GPIO23 P16'),
        (24, 'GPIO24 P18'),
        (25, 'GPIO25 P22'),
        (27, 'GPIO27 P13'),
    )

    def write(self, value):
        print "wrote %s" % str(value)


# not actually used...
class GPIO(GPIOInput, GPIOOutput): pass


def get_interface_desc():
    read_cls = IRead.__subclasses__()
    write_cls = IWrite.__subclasses__()

    ret = {}
    ret['read'] = read_cls
    ret['write'] = write_cls
    return ret

