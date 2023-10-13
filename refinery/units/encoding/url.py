#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from urllib.parse import unquote_to_bytes
from refinery.units import Arg, Unit


class url(Unit):
    """
    Decodes and encodes URL-Encoding, which preserves only alphanumeric characters and the symbols `_`, `.`, `-`, `~`, `\\`, and `/`.
    Every other character is escaped by hex-encoding it and prefixing it with a percent symbol.
    """

    def __init__(
        self,
        plus: Arg.Switch('-p', help='also replace plus signs by spaces') = False,
        hex : Arg.Switch('-x', help='hex encode every character in reverse mode') = False
    ):
        super().__init__(plus=plus, hex=hex)

    def process(self, data):
        if self.args.plus:
            data = data.replace(B'+', B' ')
        return unquote_to_bytes(bytes(data))

    def reverse(self, data):
        if self.args.hex:
            result = bytearray(len(data) * 3)
            offset = 0
            for byte in data:
                result[offset + 0] = 0x25
                offset += 1
                result[offset:offset + 2] = B'%02X' % byte
                offset += 2
            return result
        elif self.args.plus:
            def replace(m):
                c = m[0][0]
                return b'+' if c == 0x20 else B'%%%02X' % c
        else:
            def replace(m):
                return B'%%%02X' % m[0][0]
        return re.sub(B'[^a-zA-Z0-9_.-~\\/]', replace, data)
