from scapy.fields import *
from scapy.packet import *
from .stringtokey import PGPStringToKeyField
from ..enumerations import SYMMETRIC_KEY_ALGORITHMS


def encrypted_session_key_length(pkt):
    if pkt.underlayer.length is not None:
        return pkt.underlayer.length-2-len(bytes(pkt.session_key_parameters))
    return 0

class PGPSymmetricKeySessionKeyPacket(Packet):
    fields_desc = [
        ByteEnumField("version", 4, {"v1" : 1,
                                     "v2" : 2,
                                     "v3" : 3,
                                     "v4" : 4}),
        ByteEnumField("symmetric_algorithm", None, SYMMETRIC_KEY_ALGORITHMS),
        PacketField("session_key_parameters", None, PGPStringToKeyField),

        # If there are any bytes left, they must be the encrypted session key
        StrLenField("encrypted_session_key", None,
                    length_from=encrypted_session_key_length)
    ]
