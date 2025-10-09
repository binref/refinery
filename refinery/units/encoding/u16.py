from __future__ import annotations

from refinery.lib.id import guess_text_encoding
from refinery.units import Unit


class u16(Unit):
    """
    Encodes and decodes UTF-16 encoded string data.
    """

    def reverse(self, data: bytearray):
        return data.decode(self.codec).encode('utf-16LE')

    def process(self, data: bytearray):
        return data.decode('utf-16').encode(self.codec)

    @classmethod
    def handles(cls, data):
        if encoding := guess_text_encoding(data):
            return encoding.step == 2
