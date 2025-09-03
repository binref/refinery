from __future__ import annotations

import re

from refinery.lib.patterns import formats
from refinery.units.obfuscation import Deobfuscator, StringLiterals


class deob_js_arrays(Deobfuscator):
    """
    JavaScript deobfuscator to turn `["Z", "t", "s", "e"][0]` into `"Z"`.
    """

    def deobfuscate(self, data):
        strlit = StringLiterals(formats.string, data)

        @strlit.outside
        def litpick(match: re.Match[str]):
            try:
                array = match[1]
                index = int(match[2])
                lpick = array.split(',')[index].strip()
                self.log_debug(lambda: F'{lpick} = {match[0]}')
            except (TypeError, IndexError):
                lpick = match[0]
            return lpick

        p = R'\s{{0,5}}'.join([
            '\\[', '((?:{i}|{s})', '(?:,', '(?:{i}|{s})', ')*)', '\\]', '\\[', '({i})', '\\]'
        ]).format(i=formats.integer, s=formats.string)
        return re.sub(p, litpick, data)
