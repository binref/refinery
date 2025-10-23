from __future__ import annotations

from refinery.units import Unit


class hex(Unit):
    """
    Hex-decodes and encodes binary data. Non-hex characters are removed from
    the input. For decoding, any odd trailing hex digits are stripped as two
    hex digits are required to represent a byte.
    """

    def reverse(self, data):
        import base64
        return base64.b16encode(data)

    def process(self, data):
        import base64
        import re
        data = re.sub(B'[^A-Fa-f0-9]+', B'', data)
        if len(data) % 2:
            data = data[:-1]
        return base64.b16decode(data, casefold=True)

    @classmethod
    def handles(cls, data):
        from refinery.lib.patterns import formats
        if formats.b16s.value.bin.fullmatch(data):
            return True
