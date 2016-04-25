from scapy.fields import *
from scapy.packet import *

class PGPSymmetricallyEncryptedMDCPacket(Packet):
    fields_desc = [
        ByteField("version", 1),
        StrLenField("encrypted_data", "",
                    length_from=lambda pkt: pkt.underlayer.length - 1),
    ]
