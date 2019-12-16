#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import Unit
from ....lib.argformats import number


class rot(Unit):
    """
    Rotate the characters of the alphabet by the given amount. The default
    amount is 13, providing the common (and weak) string obfuscation method.
    """

    def interface(self, argp):
        argp.add_argument('amount', nargs='?', default=13, type=number[1:25], help='rotation amount')
        return super().interface(argp)

    def process(self, data):
        def rotate(char):
            if 0x41 <= char <= 0x5A:  # A-Z
                return (char - 0x41 + self.args.amount) % 26 + 0x41
            if 0x61 <= char <= 0x7A:  # a-z
                return (char - 0x61 + self.args.amount) % 26 + 0x61
            return char
        return bytes(rotate(char) for char in data)
