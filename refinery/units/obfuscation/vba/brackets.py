from __future__ import annotations

import re

from refinery.units.obfuscation import Deobfuscator, StringLiterals
from refinery.lib.patterns import formats


class deob_vba_brackets(Deobfuscator):
    _SENTINEL = re.compile(
        RF'''(?<![\w"']{{2}})'''  # this may be a function call
        RF'''\(\s*({formats.vbaint}|{formats.vbastr}|{formats.float})\s*(\S)''',
        flags=re.IGNORECASE
    )

    def deobfuscate(self, data):
        strlit = StringLiterals(formats.vbastr, data)
        repeat = True

        @strlit.outside
        def replacement(match):
            nonlocal repeat
            if match[2] == ')':
                repeat = True
                return match[1]

        while repeat:
            repeat = False
            data = self._SENTINEL.sub(replacement, data)

        return data
