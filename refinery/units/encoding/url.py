#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import arg, Unit


class url(Unit):
    """
    Decodes and encodes URL-Encoding, which preserves only alphanumeric
    characters and the symbols `_`, `.`, `-`, `~`, `\\`, and `/`.
    Every other character is escaped by hex-encoding it and prefixing it
    with a percent symbol.
    """

    def __init__(
        self,
        plus: arg.switch('-p', help='also replace plus signs by spaces') = False,
        hex : arg.switch('-x', help='hex encode every character in reverse mode') = False
    ):
        super().__init__(plus=plus, hex=hex)

    def process(self, data):
        data = re.sub(
            B'\\%([0-9a-fA-F]{2})',
            lambda m: bytes((int(m[1], 16),)),
            data
        )
        if self.args.plus:
            data = data.replace(B'+', B' ')
        return data

    def reverse(self, data):
        if self.args.plus:
            data = data.replace(B' ', B'+')
        if not self.args.hex:
            return re.sub(B'[^a-zA-Z0-9_.-~\\/]', lambda m: B'%%%02X' % ord(m[0]), data)
        result = bytearray(len(data) * 3)
        offset = 0
        for byte in data:
            result[offset] = B'%'[0]
            offset += 1
            result[offset:offset + 2] = B'%02X' % byte
            offset += 2
        return result
