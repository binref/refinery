from __future__ import annotations

import re

from refinery.lib.patterns import formats
from refinery.units.obfuscation import Deobfuscator, StringLiterals


class deob_vba_char_function(Deobfuscator):
    def deobfuscate(self, data):
        strings = StringLiterals(formats.vbastr, data)

        @strings.outside
        def evaluate_char_function(match: re.Match[str]):
            try:
                c = chr(int(match[1]))
            except ValueError:
                return match[0]
            if c == '"':
                return '""""'
            if c == '\\':
                return '"\\"'
            c = repr(c)[1:-1]
            if len(c) > 1:
                return match[0]
            return f'"{c}"'

        return re.sub(R'(?i)\bchrw?\s*\(\s*(\d+)\s*\)', evaluate_char_function, data)
