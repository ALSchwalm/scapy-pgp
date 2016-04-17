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
        PacketField("session_key_parameters", None, PGPStringToKeyField),

        # If there are any bytes left, they must be the encrypted session key
        ConditionalField(
            StrLenField("encrypted_session_key", "",
                        length_from=lambda pkt:pkt.underlayer.length-2-len(bytes(pkt.session_key_parameters))),
            lambda pkt:pkt.underlayer.length-2-len(bytes(pkt.session_key_parameters)) > 0
        )
    ]
