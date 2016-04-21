from scapy.fields import *
from scapy.packet import *


class PGPPacketList(PacketListField):
    def __init__(self, name, default):
        PacketListField.__init__(self, name, default, Packet)

    def is_new_format(self, bytes):
        if bytes[0] & 0b01000000:
            return True
        return False

    def parse_packet_list(self, s):
        from .newformat import PGPNewFormatPacket
        from .oldformat import PGPOldFormatPacket
        packets = []
        while len(s) > 0:
            if self.is_new_format(s):
                packet = PGPNewFormatPacket(s)
            else:
                packet = PGPOldFormatPacket(s)
            packets.append(packet)
            s = s[len(packet):]
        return packets

    def i2m(self, pkt, value):
        return b"".join([bytes(p) for p in value])

    def m2i(self, pkt, raw_value):
        return self.parse_packet_list(raw_value)

    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)

    def getfield(self, pkt, s):
        return b"", self.m2i(pkt, s)
