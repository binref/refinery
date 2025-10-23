from __future__ import annotations

import base64

from refinery.units import Unit

_b85alphabet = (
    b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    b'abcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~')
_z85alphabet = (
    b'0123456789abcdefghijklmnopqrstuvwxyz'
    b'ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#')
_z85_decode_diff = b';_`|~'
_b85_decode_diff = bytes(5)
_z85_decode_translation = bytes.maketrans(
    _z85alphabet + _z85_decode_diff,
    _b85alphabet + _b85_decode_diff,
)
_z85_encode_translation = bytes.maketrans(
    _b85alphabet, _z85alphabet)


class z85(Unit):
    """
    Z85 encoding and decoding, an alternative variant of Base85 with a different alphabet.
    This variant derives its name from the developer, ZeroMQ.
    """
    def reverse(self, data):
        return base64.b85encode(data).translate(_z85_encode_translation)

    def process(self, data: bytearray):
        return base64.b85decode(data.translate(_z85_decode_translation))

    @classmethod
    def handles(cls, data):
        from refinery.lib.patterns import formats
        return formats.z85s.value.bin.fullmatch(data) is not None
