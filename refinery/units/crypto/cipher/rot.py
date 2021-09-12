#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import arg, Unit

_UCASE = range(ord('A'), ord('Z') + 1)
_LCASE = range(ord('a'), ord('z') + 1)


class rot(Unit):
    """
    Rotate the characters of the alphabet by the given amount. The default
    amount is 13, providing the common (and weak) string obfuscation method.
    """

    def __init__(self, amount: arg.number(help='Number of letters to rotate by; Default is 13.') = 13):
        super().__init__(amount=amount)

    def process(self, data: bytearray):
        rot = self.args.amount % 26
        for index, byte in enumerate(data):
            for alphabet in _LCASE, _UCASE:
                if byte in alphabet:
                    zero = alphabet[0]
                    data[index] = zero + (byte - zero + rot) % 26
                    break
        return data
