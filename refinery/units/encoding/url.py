from __future__ import annotations

import re

from urllib.parse import unquote_to_bytes

from refinery.lib.types import Param
from refinery.units import Arg, Unit


class url(Unit):
    """
    Decodes and encodes URL-encoding.

    The unit preserves only alphanumeric characters, backslash, slash, underscore, dots, dashes,
    and the tilde character when encoding. Every other character is escaped by hex-encoding it and
    prefixing it with a percent symbol. The unit also supports unicode escape seuqences that use
    the format `%uFFFF`.
    """

    def __init__(
        self,
        plus: Param[bool, Arg.Switch('-p', help='also replace plus signs by spaces')] = False,
        hex: Param[bool, Arg.Switch('-x', help='hex encode every character in reverse mode')] = False
    ):
        super().__init__(plus=plus, hex=hex)

    def process(self, data):
        if self.args.plus:
            data = data.replace(B'+', B' ')
        data = unquote_to_bytes(bytes(data))
        data = re.sub(
            B'%[uU]([0-9a-fA-F]{4})',
            lambda m: int(m[1], 16).to_bytes(2, 'little'),
            data)
        return data

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
