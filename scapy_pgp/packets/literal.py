from scapy.fields import *
from scapy.packet import *
from time import gmtime, strftime, strptime
from calendar import timegm

class DateField(IntField):
    def __init__(self, name, default):
        IntField.__init__(self, name, default)

    def h2i(self, pkt, value):
        return timegm(strptime(value, "%d %b %Y %H:%M:%S"))

    def i2h(self, pkt, value):
        return strftime("%d %b %Y %H:%M:%S", gmtime(value))


class PGPLiteralDataPacket(Packet):
    fields_desc = [
        ByteEnumField("format", "text", {"text" : ord("t"),
                                         "binary" : ord("b"),
                                         "unicode" : ord("u")}),
        FieldLenField("filename_length", None, fmt="B", length_of="filename"),
        StrLenField("filename", "", length_from=lambda pkt:pkt.filename_length),
        DateField("date", "01 Jan 1970 00:00:00"),
        StrLenField("data", "", length_from=lambda pkt:pkt.underlayer.length-pkt.filename_length-6)
    ]
