#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import arg, Unit


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

    def __init__(self,
        hex     : arg.switch('-x', help='Hex encode everything, do not use C escape sequences.') = False,
        unicode : arg.switch('-u', help='Use unicode escape sequences and UTF-8 encoding.') = False,
        greedy  : arg.switch('-g', help='Replace \\x by x and \\u by u when not followed by two or four hex digits, respectively.') = False,
        quoted  : arg.switch('-q', help='Remove enclosing quotes while decoding and add them for encoding.') = False,
        bare    : arg.switch('-b', help='Do not escape quote characters.') = False,
        expand  : arg.switch('-p', help='Decode sequences of the form \\uHHLL as two bytes when the upper byte is nonzero.') = False,
    ) -> Unit: pass  # noqa

    def process(self, data):
        if self.args.quoted:
            quote = data[0]
            if data[~0] != quote:
                raise ValueError('string is not correctly quoted')
            data = data[1:~0]

        if self.args.unicode:
            return data.decode('UNICODE_ESCAPE').encode(self.codec)

        def unescape(match):
            c = match[1]
            if len(c) > 1:
                if c[0] == 0x75:
                    # unicode
                    upper = int(c[1:3], 16)
                    lower = int(c[3:5], 16)
                    if self.args.expand:
                        return bytes((upper, lower))
                    return bytes((lower,))
                elif c[0] == 0x78:
                    # hexadecimal
                    return bytes((int(c[1:3], 16),))
                else:
                    # octal escape sequence
                    return bytes((int(c, 8) & 0xFF,))
            elif c in B'ux':
                return c if self.args.greedy else match[0]
            return self._UNESCAPE.get(c, c)
        data = re.sub(
            RB'\\(u[a-fA-F0-9]{4}|x[a-fA-F0-9]{2}|[0-7]{3}|.)', unescape, data)
        return data

    def reverse(self, data):
        if self.args.unicode:
            string = data.decode(self.codec).encode('UNICODE_ESCAPE')
        else:
            if not self.args.hex:
                def escape(match):
                    c = match[0][0]
                    return self._ESCAPE.get(c, RB'\x%02x' % c)
                pattern = RB'[\x00-\x1F\x22\x27\x5C\x7F-\xFF]'
                if self.args.bare:
                    pattern = RB'[\x00-\x1F\x5C\x7F-\xFF]'
                string = re.sub(pattern, escape, data)
            else:
                string = bytearray(4 * len(data))
                for k in range(len(data)):
                    a = k * 4
                    b = k * 4 + 4
                    string[a:b] = RB'\x%02x' % data[k]
        if self.args.quoted:
            string = B'"%s"' % string
        return string
