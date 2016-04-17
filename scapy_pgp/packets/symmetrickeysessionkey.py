from scapy.fields import *
from scapy.packet import *
from .stringtokey import PGPStringToKeyField
from ..enumerations import SYMMETRIC_KEY_ALGORITHMS

class PGPSymmetricKeySessionKeyPacket(Packet):
    fields_desc = [
        ByteEnumField("version", 4, {"v1" : 1,
                                     "v2" : 2,
                                     "v3" : 3,
                                     "v4" : 4}),
        ByteEnumField("symmetric_algorithm", None, SYMMETRIC_KEY_ALGORITHMS),
        PacketField("session_key", None, PGPStringToKeyField)
    ]
