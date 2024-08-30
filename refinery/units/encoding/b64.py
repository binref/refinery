#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64

from refinery.units import Arg, Unit


class b64(Unit):
    """
    Base64 encoding and decoding.
    """
    def __init__(self, urlsafe: Arg.Switch('-u', help='use URL-safe alphabet') = False):
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

    @classmethod
    def handles(self, data: bytearray) -> bool:
        from refinery.lib.patterns import formats
        if not formats.spaced_b64.value.fullmatch(data):
            return False
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
        for c in (lcase_count, ucase_count, digit_count, other_count):
            # Call this a false positive if more than 2/3ds of the data
            # consist of a single category of letters.
            if c * 3 > total_count * 2:
                return False
        return True
