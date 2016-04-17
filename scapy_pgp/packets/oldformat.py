from scapy.fields import *
from scapy.packet import *
from ..tags import *
from math import log2, ceil

class PGPOldFormatLengthFormatField(BitEnumField):
    def __init__(self, name, default, size, enum):
        BitEnumField.__init__(self, name, default, size, enum)

    @staticmethod
    def needed_format(num_bytes):
        bytes_needed = ceil(log2(num_bytes+1)/8)
        if bytes_needed in (0, 1):
            return 0b00
        elif bytes_needed == 2:
            return 0b01
        elif bytes_needed in (3, 4):
            return 0b10
        else:
            return 0b11

    def addfield(self, pkt, s, val):
        if pkt.length_format is not None:
            return BitEnumField.addfield(self, pkt, s, self.i2m(pkt, val))
        else:
            format = PGPOldFormatLengthFormatField.needed_format(len(pkt.payload))
            return BitEnumField.addfield(self, pkt, s, self.i2m(pkt, format))


class PGPOldFormatLengthField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default)

    def i2m(self, pkt, value):
        if pkt.length_format is None:
            format = PGPOldFormatLengthFormatField.needed_format(len(pkt.payload))
        else:
            format = pkt.length_format
        if format == 0:
            return bytes([value])
        elif format == 1:
            return bytes([ (value >> 8), value & 0xFF])
        elif format == 2:
            return bytes([
                (value >> 24) & 0xFF,
                (value >> 16) & 0xFF,
                (value >> 8) & 0xFF,
                value & 0xFF
            ])
        elif format == 3:
            return b""
        assert(False)

    def m2i(self, pkt, raw_value):
        if len(raw_value) == 1:
            return raw_value[0]
        elif len(raw_value) == 2:
            return (raw_value[0] << 8) | raw_value[1]
        elif len(raw_value) == 4:
            return ((raw_value[0] << 24) |
                    (raw_value[1] << 16) |
                    (raw_value[2] << 8)  |
                     raw_value[3])
        assert(False)

    def addfield(self, pkt, s, val):
        if pkt.length is not None:
            return s+self.i2m(pkt, val)
        else:
            return s+self.i2m(pkt, len(pkt.payload))

    def getfield(self, pkt, s):
        value = s[0]
        if pkt.length_format == 0:
            return s[1:], self.m2i(pkt, s[:1])
        elif pkt.length_format == 1:
            return s[2:], self.m2i(pkt, s[:2])
        elif pkt.length_format == 2:
            return s[4:], self.m2i(pkt, s[:4])
        elif pkt.length_format == 3:
            return s, bytes([len(s)])
        assert(False)

class PGPOldFormatPacket(Packet):
    fields_desc = [
        BitEnumField("format_version", 0b10, 2,
                     { 0b10: "Old Format",
                       0b11: "New Format"}),
        BitEnumField("tag", None, 4, TAG_STRINGS),
        PGPOldFormatLengthFormatField("length_format", None, 2,
                                      { 0b00: "1 byte",
                                        0b01: "2 bytes",
                                        0b10: "4 bytes",
                                        0b11: "0 bytes"}),
        PGPOldFormatLengthField("length", None),
    ]

    def guess_payload_class(self, payload):
        return PACKET_TAGS[PacketType(self.tag)]

    def extract_padding(self, s):
        return s[-self.length:], None
