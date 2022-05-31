#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from refinery import Unit
from refinery.units.blockwise.xor import xor
from refinery.units.misc.xkey import xkey


class autoxor(Unit):
    """
    Assumes a XOR-encoded input and automatically attempts to find the correct XOR key. The method
    is based on the assumption that the plaintext input contains one letter that occurs with a much
    higher frequency than all other letters; this is the case for the null byte in PEs, and also
    for the space character in many text files.
    """
    def process(self, data: bytearray):
        key, = data | xkey
        out, = data | xor(key)
        txt, = out | xor(0x20)
        if re.fullmatch(BR'[\s!-~]+', txt):
            key = bytes(key | xor(0x20))
            out = txt
        return self.labelled(out, key=key)
