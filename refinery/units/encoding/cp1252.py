from __future__ import annotations

from refinery.units import Unit


class cp1252(Unit):
    """
    Encodes and decodes Windows CP 1252 (aka Latin1) encoded string data.
    """

    def process(self, data):
        return data.decode(self.codec).encode('cp1252')

    def reverse(self, data):
        return data.decode('cp1252').encode(self.codec)
