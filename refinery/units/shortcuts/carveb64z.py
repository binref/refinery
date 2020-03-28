#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ..pattern.carve import arg, carve
from ..compression.decompress import decompress


class carveb64z(carve):
    """
    Carves base64 encoded expressions, decodes them, and then applies the `refinery.decompress`
    unit to the result. By default, only the longest base64 string is processed.
    """
    def __init__(
        self, single: arg.switch('-m', '--multi', help='Process all base64 strings instead of just the longest.') = True,
        min=1, max=None, stripspace=False, unique=False, longest=False, take=None, utf16=True, ascii=True
    ):
        super().__init__('b64', decode=True,
            single=single, min=min, max=max, stripspace=stripspace, unique=unique, longest=longest, take=take, utf16=utf16, ascii=ascii)
        self.decompressor = decompress()

    def process(self, data):
        for chunk in super().process(data):
            yield self.decompressor(chunk)
