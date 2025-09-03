from __future__ import annotations

from refinery.units import Unit


class carve_der(Unit):
    """
    Extracts anything from the input data that looks like a DER sequence. The carving can be very
    slow: The unit will attempt to parse an ASN1 sequence at every offset where a byte with value
    0x30 is found, since this can indicate the start of an ASN1 SEQUENCE. It will only consider the
    next 10KB of data at this offset, but it nevertheless remains a poor heuristic.
    """
    @Unit.Requires('pyasn1', ['default', 'extended'])
    def _pyasn1parsers():
        from pyasn1.codec.der.decoder import decode
        from pyasn1.codec.der.encoder import encode
        return encode, decode

    def process(self, data: bytearray):
        cursor = 0
        encode, decode = self._pyasn1parsers
        while True:
            try:
                pos = data.index(0x30, cursor)
            except Exception:
                break
            else:
                cursor += 1
            if pos + 1 < len(data) and data[pos + 1] == 0:
                continue
            try:
                sequence = decode(bytes(data[pos:pos + 10_000]))
            except Exception:
                continue
            if not (der := sequence[0]):
                self.log_info(F'0x{pos:08X}: parser returned nothing')
                continue
            if len(der) < 2:
                self.log_info(F'0x{pos:08X}: parser returned empty sequence')
                continue
            der = encode(der)
            cursor = pos + len(der)
            yield self.labelled(der, offset=pos)
