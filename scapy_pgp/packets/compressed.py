from scapy.fields import *
from scapy.packet import *
from ..enumerations import COMPRESSION_ALGORITHMS
import zlib
import bz2


class PGPCompressedDataPacket(Packet):
    fields_desc = [
        ByteEnumField("compression_algorithm", "ZLIB", COMPRESSION_ALGORITHMS),
    ]

    def extract_padding(self, s):
        return s, None

    def guess_payload_class(self, payload):
        from .newformat import PGPNewFormatPacket
        from .oldformat import PGPOldFormatPacket
        if payload[0] & 0b01000000:
            return PGPNewFormatPacket
        else:
            return PGPOldFormatPacket

    def do_dissect_payload(self, payl):
        if self.compression_algorithm == 0:
            Packet.do_dissect_payload(self, payl)
            return
        elif self.compression_algorithm == 1:
            payload = zlib.decompress(payl, -15)
        elif self.compression_algorithm == 2:
            payload = zlib.decompress(payl)
        elif self.compression_algorithm == 3:
            payload = bz2.decompress(payl)
        Packet.do_dissect_payload(self, payload)

    def do_build_payload(self):
        if self.compression_algorithm == 0:
            return self.payload.do_build()
        elif self.compression_algorithm == 1:
            obj = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
            obj.compress(bytes(self.payload.do_build()))
            return obj.flush()
        elif self.compression_algorithm == 2:
            return zlib.compress(bytes(self.payload.do_build()))
        elif self.compression_algorithm == 3:
            return bz2.compress(bytes(self.payload.do_build()))
