from __future__ import annotations

import base64

from refinery.lib.types import Param
from refinery.units import Arg, Unit


class b64(Unit):
    """
    Base64 encoding and decoding.
    """
    def __init__(self, urlsafe: Param[bool, Arg.Switch('-u', help='use URL-safe alphabet')] = False):
        super().__init__(urlsafe=urlsafe)

    def reverse(self, data):
        altchars = None
        if self.args.urlsafe:
            altchars = B'-_'
        return base64.b64encode(data, altchars=altchars)

    def process(self, data: bytearray):
        if not data:
            return data
        if len(data) == 1:
            raise ValueError('single byte can not be base64-decoded.')
        data.extend(B'===')
        altchars = None
        if (B'-' in data or B'_' in data) and (B'+' not in data and B'/' not in data) or self.args.urlsafe:
            altchars = B'-_'
        return base64.b64decode(data, altchars=altchars)

    @Unit.Requires('numpy', ['speed', 'default', 'extended'])
    def _numpy():
        import numpy
        return numpy

    @classmethod
    def handles(cls, data) -> bool:
        from refinery.lib.patterns import formats
        if not formats.b64s.value.bin.fullmatch(data):
            return False
        try:
            np = cls._numpy
        except ImportError:
            histogram = set()
            lcase_count = 0
            ucase_count = 0
            digit_count = 0
            other_count = 0
            total_count = len(data)
            for byte in data:
                histogram.add(byte)
                if len(histogram) > 60:
                    return True
                elif byte in range(0x61, 0x7B):
                    lcase_count += 1
                elif byte in range(0x41, 0x5B):
                    ucase_count += 1
                elif byte in range(0x30, 0x40):
                    digit_count += 1
                elif byte in B'\v\f\t\r\n\x20':
                    total_count -= 1
                else:
                    other_count += 1
        else:
            hist = np.histogram(
                np.frombuffer(memoryview(data), np.uint8), range(0x101))[0]
            lcase_count = sum(hist[k] for k in range(0x61, 0x7B))
            ucase_count = sum(hist[k] for k in range(0x41, 0x5B))
            digit_count = sum(hist[k] for k in range(0x30, 0x40))
            space_count = sum(hist[k] for k in B'\v\f\t\r\n\x20')
            total_count = len(data) - space_count
            other_count = total_count - (digit_count + ucase_count + lcase_count)

        if any(c < total_count // 64 for c in (lcase_count, ucase_count, digit_count)):
            return False
        if other_count * 2 > total_count:
            return False

        return True
