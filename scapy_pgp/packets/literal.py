from scapy.fields import *
from scapy.packet import *

class PGPLiteralDataPacket(Packet):
    fields_desc = [
        ByteEnumField("format", None, {"text" : ord("t"),
                                       "binary" : ord("b"),
                                       "unicode" : ord("u")}),
        FieldLenField("filename_length", None, fmt="B", length_of="filename"),
        StrLenField("filename", "", length_from=lambda pkt:pkt.filename_length),
        IntField("date", None),
        StrLenField("data", "", length_from=lambda pkt:pkt.underlayer.length-pkt.filename_length-6)
    ]
