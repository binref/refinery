from __future__ import annotations

import re

from refinery.lib.patterns import formats
from refinery.units.obfuscation import Deobfuscator
from refinery.units.obfuscation.ps1 import Ps1StringLiterals


class deob_ps1_brackets(Deobfuscator):
    """
    PowerShell deobfuscation that removes superfluous brackets around constant
    literals, i.e. `("{0}{2}{1}")` is transformed to `"{0}{2}{1}"`. Currently,
    only integer and string constants are supported.
    """
    _SENTINEL = re.compile(
        RF'''(?<![\w"']{{2}})'''  # this may be a function call
        RF'''(\-\w+)?'''  # not a function call but an argument
        RF'''\(\s*({formats.integer}|{formats.ps1str})\s*(\S)''',
        flags=re.IGNORECASE
    )

    def deobfuscate(self, data):
        strlit = Ps1StringLiterals(data)
        repeat = True

        @strlit.outside
        def replacement(match):
            nonlocal repeat
            if match[3] == ')':
                repeat = True
                return (match[1] or '') + match[2]

        while repeat:
            repeat = False
            data = self._SENTINEL.sub(replacement, data)

        return data
