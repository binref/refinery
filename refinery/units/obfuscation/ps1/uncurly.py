#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator
from . import Ps1StringLiterals


class deob_ps1_uncurly(Deobfuscator):
    """
    PowerShell deobfuscation that removes superfluous curly braces around variable
    names that do not require it, i.e. `${variable}` is transformed to just `$variable`.
    """

    _SENTINEL = re.compile(R'\$\{(\w+)\}')

    def deobfuscate(self, data):
        strlit = Ps1StringLiterals(data)
        @strlit.outside
        def strip(m): return F'${m[1]}'
        return self._SENTINEL.sub(strip, data)
