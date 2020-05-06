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

    def __init__(self, plus: arg.switch('-p', help='also replace plus signs by spaces') = False):
        super().__init__(plus=plus)

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
        data = re.sub(
            B'[^a-zA-Z0-9_.-~\\/]',
            lambda m: B'%%%02X' % ord(m[0]),
            data
        )
        return data
