from __future__ import annotations

from refinery.units import Unit


class u16(Unit):
    """
    Encodes and decodes UTF-16 encoded string data.
    """

    def reverse(self, data):
        return data.decode(self.codec).encode('utf-16LE')

    def process(self, data):
        return data.decode('utf-16').encode(self.codec)

    @classmethod
    def handles(cls, data: bytearray):
        view = memoryview(data)
        if len(view) % 2 != 0:
            return False
        if not any(view[1:0x100:2]):
            return True
        if not any(view[0:0x100:2]):
            return any(view[:4])
