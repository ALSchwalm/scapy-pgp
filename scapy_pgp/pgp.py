from scapy.packet import *
from .packets import PGPNewFormatPacket, PGPOldFormatPacket
from .tags import *
from .enumerations import *

for tag, packet in PACKET_TAGS.items():
    bind_layers(PGPNewFormatPacket, packet, {"tag": tag})
    bind_layers(PGPOldFormatPacket, packet, {"tag": tag})

bind_layers(PGPCompressedDataPacket, PGPNewFormatPacket)
bind_layers(PGPCompressedDataPacket, PGPOldFormatPacket)
