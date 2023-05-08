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
        if not formats.b64space.fullmatch(data):
            return False
        return len(set(data)) in range(60, 67)
