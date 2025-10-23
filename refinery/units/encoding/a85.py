from __future__ import annotations

import base64
import re

from refinery.units import Unit


class a85(Unit):
    """
    Ascii85 encoding and decoding, the predecessor variant of Base85 with a different alphabet.
    """
    def reverse(self, data):
        return base64.a85encode(data)

    def process(self, data):
        if re.search(BR'\s', data) is not None:
            data = re.sub(BR'\s+', B'', data)
        return base64.a85decode(data)

    @classmethod
    def handles(cls, data):
        from refinery.lib.patterns import formats
        return formats.a85s.value.bin.fullmatch(data) is not None
