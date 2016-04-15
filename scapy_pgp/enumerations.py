from .packets import *
from enum import IntEnum, unique

@unique
class PacketType(IntEnum):
    PGPCompressedDataPacket = 8
    PGPLiteralDataPacket = 11

TAG_STRINGS = {
    m.name : m.value for m in PacketType
}

PACKET_TAGS = {
    PacketType.PGPLiteralDataPacket : PGPLiteralDataPacket
}
