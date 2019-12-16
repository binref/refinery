#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
from struct import pack
from string import printable

from .. import Unit


class esc(Unit):
    """
    Encodes and decodes common ASCII escape sequences.
    """
    _ESCAPE = {
        0x00: BR'\0',
        0x07: BR'\a',
        0x08: BR'\b',
        0x0C: BR'\f',
        0x0A: BR'\n',
        0x0D: BR'\r',
        0x09: BR'\t',
        0x0B: BR'\v',
        0x5C: BR'\\',
        0x27: BR'\'',
        0x22: BR'\"'
    }
    _UNESCAPE = {
        BR'0': B'\x00',
        BR'a': B'\x07',
        BR'b': B'\x08',
        BR'f': B'\x0C',
        BR'n': B'\x0A',
        BR'r': B'\x0D',
        BR't': B'\x09',
        BR'v': B'\x0B',
        B'\\': B'\x5C',
        BR"'": B'\x27',
        BR'"': B'\x22'
    }

    def interface(self, argp):
        mode = argp.add_mutually_exclusive_group()
        mode.add_argument('-x', '--hex', action='store_true',
            help='Hex encode everything, do not use C escape sequences.')
        mode.add_argument('-u', '--unicode', action='store_true',
            help='Expect input/output to be an UTF-8 encoded unicode string and '
                 'use unicode escape sequences.')
        return super().interface(argp)

    def process(self, data):
        if self.args.unicode:
            return data.decode('UNICODE_ESCAPE').encode(self.codec)

        def unescape(match):
            c = match.group(1)
            if c[0] == 0x75:  # unicode
                return pack('H', int(c[1:], 16))
            if c[0] == 0x78:  # hexadecimal
                return pack('B', int(c[1:], 16))
            return self._UNESCAPE.get(c, c)
        data = re.sub(
            RB'\\(u[a-fA-F0-9]{4}|x[a-fA-F0-9]{2}|.)', unescape, data)
        return data

    def reverse(self, data):
        if self.args.unicode:
            return data.decode(self.codec).encode('UNICODE_ESCAPE')

        def escape(c):
            if chr(c) not in printable or c in self._ESCAPE and self.args.hex:
                return RB'\x%02x' % c
            else:
                return self._ESCAPE.get(c, B'%c' % c)
        return B''.join(escape(c) for c in data)
