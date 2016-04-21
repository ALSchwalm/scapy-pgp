from scapy.packet import *
from .packets import PGPNewFormatPacket, PGPOldFormatPacket
from .packets.packetlist import PGPPacketList
from .tags import *
from .enumerations import *

for tag, packet in PACKET_TAGS.items():
    bind_layers(PGPNewFormatPacket, packet, {"tag": tag})
    bind_layers(PGPOldFormatPacket, packet, {"tag": tag})

bind_layers(PGPCompressedDataPacket, PGPNewFormatPacket)
bind_layers(PGPCompressedDataPacket, PGPOldFormatPacket)


class PGPFile(Packet):
    fields_desc = [
        PGPPacketList("packets", None)
    ]

    def save(self, filename):
        with open(filename, "wb+") as f:
            f.write(bytes(self))


def parsepgp(filename=None, bytes=None):
    if filename is not None and bytes is not None:
        raise ValueError("Only specify `filename` or `bytes`, not both")

    if filename is not None:
        with open(filename, "rb") as f:
            return PGPFile(f.read())
    else:
        return PGPFile(bytes)
