from __future__ import annotations

import re

from refinery.lib.types import Param
from refinery.units import Arg, Unit


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
        hex: Param[bool, Arg.Switch('-x',
            help='Hex encode everything, do not use C escape sequences.')] = False,
        unicode: Param[bool, Arg.Switch('-u',
            help='Use unicode escape sequences and UTF-8 encoding.')] = False,
        greedy: Param[bool, Arg.Switch('-g',
            help='Replace \\x by x and \\u by u when not followed by two or four hex digits, respectively.')] = False,
        unquoted: Param[bool, Arg.Switch('-p', group='Q',
            help='Never remove enclosing quotes.')] = False,
        quoted: Param[bool, Arg.Switch('-q', group='Q',
            help='Remove enclosing quotes while decoding and add them for encoding.')] = False,
        bare: Param[bool, Arg.Switch('-b',
            help='Do not escape quote characters.')] = False,
    ): pass # noqa

    def process(self, data):
        data = memoryview(data)

        if self.args.quoted:
            quote = data[0]
            if data[-1] != quote:
                self.log_info('string is not correctly quoted')
            else:
                data = data[1:-1]
        elif not self.args.unquoted:
            quote = data[:1]
            strip = data[1:-1]
            if data[-1:] == quote and not re.search(br'(?<!\\)' + re.escape(quote), strip):
                self.log_info('removing automatically detected quotes')
                data = strip

        def unescape(match: re.Match[bytes]):
            c = match[1]
            if len(c) > 1:
                if c[0] == 0x75:
                    # unicode
                    upper = int(c[1:3], 16)
                    lower = int(c[3:5], 16)
                    if self.args.unicode:
                        return bytes((lower, upper)).decode('utf-16le').encode(self.codec)
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
            RB'\\(u[a-fA-F0-9]{4}|x[a-fA-F0-9]{1,2}|[0-7]{3}|.)', unescape, data)
        return data

    def reverse(self, data):
        if self.args.unicode:
            string = data.decode(self.codec).encode('UNICODE_ESCAPE')
        else:
            if not self.args.hex:
                def escape(match: re.Match[bytes]):
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
