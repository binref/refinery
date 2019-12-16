#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit


class hex(Unit):
    """
    Hex-decodes and encodes binary data. Non hex characters are removed from
    the input. For decoding, any odd trailing hex digits are stripped as two
    hex digits are required to represent a byte.
    """

    def reverse(self, data):
        import base64
        return base64.b16encode(data)

    def process(self, data):
        import re
        import base64
        data = re.sub(B'[^A-Fa-f0-9]+', B'', data)
        if len(data) % 2:
            data = data[:-1]
        return base64.b16decode(data, casefold=True)
