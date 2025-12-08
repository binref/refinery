from __future__ import annotations

import re

from refinery.lib.patterns import formats
from refinery.units.obfuscation import Deobfuscator, StringLiterals


class deob_js_comments(Deobfuscator):
    """
    JavaScript deobfuscator that removes comments from the script.
    """
    def deobfuscate(self, data):
        strings = StringLiterals(str(formats.string), data)

        @strings.outside
        def remove(_):
            return ''

        data = re.sub(R'/\*.*?\*/', remove, data, flags=re.DOTALL)
        data = re.sub(R'(?m)//.*$', remove, data)
        return data
