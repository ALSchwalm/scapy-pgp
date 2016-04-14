from .packets import *
from enum import IntEnum

class PacketType(IntEnum):
    PGPCompressedDataPacket = 8
    PGPLiteralDataPacket = 11

PACKET_TAGS = {
    PacketType.PGPLiteralDataPacket : PGPLiteralDataPacket
}
