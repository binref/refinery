from __future__ import annotations

from refinery.lib.asn1.reader import ASN1Reader
from refinery.units import Unit


class carve_der(Unit):
    """
    Extracts anything from the input data that looks like a DER sequence.

    The carving can be very slow: The unit will attempt to parse an ASN1 sequence at every
    offset where a byte with value 0x30 is found, since this can indicate the start of an
    ASN1 SEQUENCE. It will only consider the next 10KB of data at this offset, but it
    nevertheless remains a poor heuristic.
    """
    def process(self, data: bytearray):
        cursor = 0
        mv = memoryview(data)
        while True:
            try:
                pos = data.index(0x30, cursor)
            except Exception:
                break
            else:
                cursor = pos + 1
            if pos + 1 < len(data) and data[pos + 1] == 0:
                continue
            chunk = mv[pos:pos + 10_000]
            try:
                reader = ASN1Reader(chunk, bigendian=True)
                result = reader.read_tlv()
            except Exception:
                continue
            if not isinstance(result, list) or len(result) < 2:
                self.log_info(F'0x{pos:08X}: not a valid DER sequence')
                continue
            consumed = reader.tell()
            der = bytes(chunk[:consumed])
            cursor = pos + consumed
            yield self.labelled(der, offset=pos)
