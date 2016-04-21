from scapy.fields import *
from scapy.packet import *
from .packetlist import PGPPacketList
from ..enumerations import COMPRESSION_ALGORITHMS
import zlib
import bz2


class PGPCompressedPacketList(PGPPacketList):
    def __init__(self, name, default):
        PGPPacketList.__init__(self, name, default)

    def i2m(self, pkt, value):
        contents = b"".join([bytes(p) for p in value])
        if pkt.compression_algorithm == 0:
            return contents
        elif pkt.compression_algorithm == 1:
            obj = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
            obj.compress(contents)
            return obj.flush()
        elif pkt.compression_algorithm == 2:
            return zlib.compress(contents)
        elif pkt.compression_algorithm == 3:
            return bz2.compress(contents)

    def m2i(self, pkt, raw_value):
        if pkt.compression_algorithm == 0:
            return self.parse_packet_list(raw_value)
        elif pkt.compression_algorithm == 1:
            contents = zlib.decompress(raw_value, -15)
        elif pkt.compression_algorithm == 2:
            contents = zlib.decompress(raw_value)
        elif pkt.compression_algorithm == 3:
            contents = bz2.decompress(raw_value)
        return self.parse_packet_list(contents)

class PGPCompressedDataPacket(Packet):
    fields_desc = [
        ByteEnumField("compression_algorithm", "ZLIB", COMPRESSION_ALGORITHMS),
        PGPCompressedPacketList("packets", None)
    ]
