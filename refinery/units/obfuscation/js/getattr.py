from __future__ import annotations

import re

from refinery.lib.patterns import formats
from refinery.units.obfuscation import Deobfuscator, StringLiterals


class deob_js_getattr(Deobfuscator):
    """
    JavaScript deobfuscator to turn `WScript["CreateObject"]` into `WScript.CreateObject`.
    """

    def deobfuscate(self, data):
        strlit = StringLiterals(formats.string, data)

        @strlit.outside
        def dottify(match: re.Match[str]):
            name = match[2][1:-1]
            if name.isidentifier():
                return F'{match[1]}.{name}'
            return match[0]

        return re.sub(FR'(\w+)\[({formats.string})\]', dottify, data)
