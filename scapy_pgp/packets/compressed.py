from scapy.fields import *
from scapy.packet import *
from ..enumerations import COMPRESSION_ALGORITHMS
from zlib import compress, decompress

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
        payload = decompress(payl)
        Packet.do_dissect_payload(self, payload)

    def do_build_payload(self):
        return compress(bytes(self.payload.do_build()))
