#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from refinery.units.blockwise.xor import xor
from refinery.units.misc.xkey import xkey


class autoxor(xkey):
    """
    Assumes a XOR-encoded input and automatically attempts to find the correct XOR key. The method
    is based on the assumption that the plaintext input contains one letter that occurs with a much
    higher frequency than all other letters; this is the case for the null byte in PEs, and also
    for the space character in many text files.
    """
    def process(self, data: bytearray):
        key = super().process(data)
        bin, = data | xor(key)
        txt, = bin | xor(0x20)
        if re.fullmatch(BR'[\s!-~]+', txt):
            key = bytes(key | xor(0x20))
            bin = txt
        return self.labelled(bin, key=key)
