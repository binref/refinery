from __future__ import annotations

import re

from refinery.lib.patterns import formats
from refinery.units.obfuscation import Deobfuscator


class deob_js_tuples(Deobfuscator):
    """
    JavaScript deobfuscator to turn `("Z", "t", "s", "e")` into `"e"`.
    """

    def deobfuscate(self, data):

        def litpick(match):
            try:
                array = match[1]
                lpick = array.split(',')[-1].strip()
                self.log_debug(lambda: F'{lpick} = {match[0]}')
            except (TypeError, IndexError):
                lpick = match[0]
            return lpick

        p = R'\s{{0,5}}'.join([
            '\\(', '((?:{i}|{s})', '(?:,', '(?:{i}|{s})', ')*)', '\\)'
        ]).format(i=formats.integer, s=formats.string)
        return re.sub(p, litpick, data)
