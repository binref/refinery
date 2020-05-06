#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class netbios(Unit):
    """
    Encodes and decodes strings using the same algorithm that is used for NetBIOS
    labels. Each byte 0xUL is encoded as two bytes, which are the sum of 0xU and
    0xL with an offset character, respectively. The default offset is the capital
    letter A.
    """

    def __init__(self, key: arg(help="Provide a single letter to use as the offset.") = B'A'):
        if len(key) != 1:
            raise ValueError("The key must be a binary string of length exactly 1")
        super().__init__(key=key[0])

    def reverse(self, data):
        result = bytearray(2 * len(data))
        for k, byte in enumerate(data):
            hi, lo = byte >> 4, byte & 15
            result[2 * k + 0] = hi + self.args.key
            result[2 * k + 1] = lo + self.args.key
        return result

    def process(self, data):
        def merge(it):
            while True:
                try:
                    hi = next(it) - self.args.key
                    lo = next(it) - self.args.key
                    if hi not in range(16) or lo not in range(16):
                        raise ValueError(F'Invalid character encoding detected: hi={hi:X}, lo={lo:X}.')
                    yield (hi << 4) | lo
                except StopIteration:
                    break
        return bytearray(merge(iter(data)))
