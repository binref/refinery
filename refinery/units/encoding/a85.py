#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import re

from refinery.units import Unit


class a85(Unit):
    """
    Ascii85 encoding and decoding, the predecessor variant of Base85 with a different alphabet.
    """
    def reverse(self, data):
        return base64.a85encode(data)

    def process(self, data):
        if re.search(BR'\s', data) is not None:
            data = re.sub(BR'\s+', B'', data)
        return base64.a85decode(data)

    @classmethod
    def handles(self, data: bytearray):
        from refinery.lib.patterns import formats
        return formats.spaced_a85.value.fullmatch(data)
