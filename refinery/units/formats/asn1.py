from __future__ import annotations

from refinery.lib.asn1 import ASN1Reader
from refinery.lib.asn1.defs import ROOT_SCHEMAS
from refinery.units.formats import JSONEncoderUnit


class asn1(JSONEncoderUnit):
    """
    Generic ASN.1 parser that converts BER/DER encoded structures to JSON. When the input matches
    a known schema (X.509, CRL, CSR, PKCS#1, PKCS#7, PKCS#8, TSP), the output uses named fields.
    Otherwise, raw TLV parsing is used: SEQUENCE and SET become lists, INTEGER becomes a number,
    OBJECT IDENTIFIER becomes a resolved name string, and non-universal tags are represented as
    objects with tag and value fields.
    """
    def process(self, data):
        mv = memoryview(data)
        for _, schema, min_size in ROOT_SCHEMAS:
            if len(mv) < min_size:
                continue
            try:
                reader = ASN1Reader(mv, bigendian=True)
                result = reader.decode_with_schema(schema)
                if reader.remaining_bytes == 0:
                    return self.to_json(result)
            except Exception:
                continue
        reader = ASN1Reader(mv, bigendian=True)
        return self.to_json(reader.read_tlv())
