from scapy.fields import *
from scapy.packet import *
from ..tags import *

class PGPNewFormatLengthField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default)

    def i2m(self, pkt, value):
        #TODO: support partial body length

        if value is None:
            value = len(pkt.payload)

        if value < 192:
            return bytes([value])
        elif value > 191 and value < 224:
            # represented as 'bytes more than 192'
            value -= 192
            return bytes([ (value >> 8) + 192, value & 0xFF])
        else:
            return bytes([
                0xFF,
                (value >> 24) & 0xFF,
                (value >> 16) & 0xFF,
                (value >> 8) & 0xFF,
                value & 0xFF
            ])

    def m2i(self, pkt, raw_value):
        if len(raw_value) == 1:
            return raw_value[0]
        elif len(raw_value) == 2:
            return ((raw_value[0] - 192) << 8) + (raw_value[1]) + 192
        else:
            return ((raw_value[1] << 24) |
                    (raw_value[2] << 16) |
                    (raw_value[3] << 8)  |
                     raw_value[4])

    def addfield(self, pkt, s, val):
        if pkt.length is None:
            return s+self.i2m(pkt, val)
        else:
            return s+self.i2m(pkt, len(pkt.payload))

    def getfield(self, pkt, s):
        value = s[0]
        if value < 192:
            return s[1:], self.m2i(pkt, s[:1])
        elif value > 191 and value < 224:
            return s[2:], self.m2i(pkt, s[:2])
        elif value == 255:
            return s[5:], self.m2i(pkt, s[:5])
        assert(False)

class PGPNewFormatPacket(Packet):
    fields_desc = [
        BitEnumField("format_version", 0b11, 2,
                     { 0b10: "Old Format",
                       0b11: "New Format"}),
        BitEnumField("tag", None, 6, TAG_STRINGS),
        PGPNewFormatLengthField("length", None),
    ]

    def guess_payload_class(self, payload):
        return PACKET_TAGS[PacketType(self.tag)]

    def extract_padding(self, s):
        return s[:self.length], None
