from __future__ import annotations

from refinery.units.encoding.base import base


class b58(base):
    """
    Base58 encoding and decoding. It is famously used as an encoding in Bitcoin addresses
    because the alphabet omits digits and letters that look similar.
    """
    def __init__(self):
        super().__init__(b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')

    @classmethod
    def handles(cls, data):
        from refinery.lib.patterns import formats
        return (
            formats.b58.value.bin.fullmatch(data)
            and not formats.hex.value.bin.fullmatch(data)
            and not formats.b32.value.bin.fullmatch(data)
        )
