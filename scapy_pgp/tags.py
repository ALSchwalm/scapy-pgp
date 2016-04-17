from .packets import *
from enum import IntEnum, unique

@unique
class PacketType(IntEnum):
    PGPPublicKeySessionKeyPacket = 1
    PGPSymmetricKeySessionKeyPacket = 3
    PGPCompressedDataPacket = 8
    PGPLiteralDataPacket = 11

TAG_STRINGS = {
    m.name : m.value for m in PacketType
}

PACKET_TAGS = {
    PacketType.PGPPublicKeySessionKeyPacket : PGPPublicKeySessionKeyPacket,
    PacketType.PGPSymmetricKeySessionKeyPacket : PGPSymmetricKeySessionKeyPacket,
    PacketType.PGPCompressedDataPacket : PGPCompressedDataPacket,
    PacketType.PGPLiteralDataPacket : PGPLiteralDataPacket
}
