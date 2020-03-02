#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Unit


class url(Unit):
    """
    Decodes and encodes URL-Encoding, which preserves only alphanumeric
    characters and the symbols `_`, `.`, `-`, `~`, `\\`, and `/`.
    Every other character is escaped by hex-encoding it and prefixing it
    with a percent symbol.
    """

    @classmethod
    def interface(cls, argp):
        argp.add_argument('-p', '--plus', action='store_true', help='also replace plus signs by spaces')
        return super().interface(argp)

    def process(self, data):
        data = re.sub(
            B'\\%([0-9a-fA-F]{2})',
            lambda m: bytes((int(m.group(1), 16),)),
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
            lambda m: B'%%%02X' % ord(m.group(0)),
            data
        )
        return data
