#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import re

from refinery.units import Arg, Unit


class b85(Unit):
    """
    Base85 encoding and decoding.
    Also supports Ascii85, a slightly different variant of the same encoding.
    """
    def __init__(
            self,
            ascii: Arg.Switch('-a', help='Use Ascii85 instead of Base85.') = False,
    ):
        self.ascii = ascii
        super().__init__()

    def reverse(self, data):
        if self.ascii:
            return base64.a85encode(data)
        return base64.b85encode(data)

    def process(self, data):
        if re.search(BR'\s', data) is not None:
            data = re.sub(BR'\s+', B'', data)
        if self.ascii:
            return base64.a85decode(data)
        return base64.b85decode(data)

    @classmethod
    def handles(self, data: bytearray):
        from refinery.lib.patterns import formats
        return formats.spaced_b85.value.fullmatch(data)
