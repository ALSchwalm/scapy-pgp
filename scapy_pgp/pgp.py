from scapy.packet import *
from .packets import *
from .enumerations import *


bind_layers(PGPNewFormatPacket, PGPLiteralDataPacket,
            {"tag": PacketType.PGPLiteralDataPacket})
bind_layers(PGPOldFormatPacket, PGPLiteralDataPacket,
            {"tag": PacketType.PGPLiteralDataPacket})
