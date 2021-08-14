#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ...units import Unit


class atbash(Unit):
    """
    https://en.wikipedia.org/wiki/Atbash
    Atbash encoding and decoding. Fairly useless in the 21st century, except
    for picking out crypto nerds.
    """

    def process(self, data: bytearray):
        uc = range(B'A'[0], B'Z'[0] + 1)
        lc = range(B'a'[0], B'z'[0] + 1)
        for k, letter in enumerate(data):
            if letter in uc:
                data[k] = uc[~uc.index(letter)]
                continue
            if letter in lc:
                data[k] = lc[~lc.index(letter)]
                continue
        return data

    reverse = process
