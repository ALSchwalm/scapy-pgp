from scapy.fields import *
from scapy.packet import *
from ..enumerations import PUBLIC_KEY_ALGORITHMS

def encrypted_session_key_length(pkt):
    if pkt.underlayer.length is not None:
        return pkt.underlayer.length-10
    return 0

class PGPPublicKeySessionKeyPacket(Packet):
    fields_desc = [
        ByteEnumField("version", 3, {"v1" : 1,
                                     "v2" : 2,
                                     "v3" : 3}),

        LongField("key_id", None),
        ByteEnumField("pubkey_algorithm", None, PUBLIC_KEY_ALGORITHMS),
        StrLenField("encrypted_key", "", length_from=encrypted_session_key_length),
    ]
