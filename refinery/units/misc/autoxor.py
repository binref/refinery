#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from refinery.units.blockwise.xor import xor
from refinery.units.misc.xkey import xkey


class autoxor(xkey, extend_docs=True):
    """
    Assumes a XOR-encoded input and automatically attempts to find the correct XOR key.
    """
    def process(self, data: bytearray):
        key = super().process(data)
        if not key:
            self.log_warn('No key was found; returning original data.')
            return data
        bin, = data | xor(key)
        txt, = bin | xor(0x20)
        if re.fullmatch(BR'[\s!-~]+', txt) and not txt.isspace():
            key = bytes(key | xor(0x20))
            bin = txt
        return self.labelled(bin, key=key)
