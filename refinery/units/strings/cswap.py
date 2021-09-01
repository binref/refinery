#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit


class cswap(Unit):
    """
    Swap the case of the input string; all lowercase letters are turned into their uppercase
    variant and vice-versa.
    """
    def process(self, data: bytearray):
        lcase = bytes(range(B'a'[0], B'z'[0] + 1))
        ucase = bytes(range(B'A'[0], B'Z'[0] + 1))
        delta = lcase[0] - ucase[0]
        for k, letter in enumerate(data):
            if letter in ucase:
                data[k] += delta
            elif letter in lcase:
                data[k] -= delta
        return data
