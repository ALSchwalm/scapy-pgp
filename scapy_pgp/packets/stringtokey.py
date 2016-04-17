from scapy.fields import *
from scapy.packet import *
from ..enumerations import HASH_ALGORITHMS

class PGPStringToKeyField(Packet):
    fields_desc = [
        ByteEnumField("kind", None, {
            "Simple S2K" : 0,
            "Salted S2K" : 1,
            "Iterated and Salted S2K" : 3
        })
    ]

    def guess_payload_class(self, payload):
        if self.kind == 0:
            return PGPSimpleStringToKey
        elif self.kind == 1:
            return PGPSaltedStringToKey
        elif self.kind == 3:
            return PGPIteratedSaltedStringToKey

    def extract_padding(self, s):
        if self.kind == 0:
            return s[:1], s[1:]
        elif self.kind == 1:
            return s[:9], s[9:]
        elif self.kind == 3:
            return s[:10], s[10:]

class PGPSimpleStringToKey(Packet):
    fields_desc = [
        ByteEnumField("algorithm", None, HASH_ALGORITHMS)
    ]

class PGPSaltedStringToKey(Packet):
    fields_desc = [
        ByteEnumField("algorithm", None, HASH_ALGORITHMS),
        XLongField("salt", None)
    ]

class PGPIteratedSaltedStringToKey(Packet):
    fields_desc = [
        ByteEnumField("algorithm", None, HASH_ALGORITHMS),
        XLongField("salt", None),
        ByteField("count", None)
    ]
