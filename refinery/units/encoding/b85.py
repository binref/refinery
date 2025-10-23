from __future__ import annotations

import base64
import re

from refinery.units import Unit


class b85(Unit):
    """
    Base85 encoding and decoding.
    """
    def reverse(self, data):
        return base64.b85encode(data)

    def process(self, data):
        if re.search(BR'\s', data) is not None:
            data = re.sub(BR'\s+', B'', data)
        return base64.b85decode(data)

    @classmethod
    def handles(cls, data):
        from refinery.lib.patterns import formats
        return formats.b85s.value.bin.fullmatch(data) is not None
