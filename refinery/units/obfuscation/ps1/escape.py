#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator
from . import Ps1StringLiterals


class deob_ps1_escape(Deobfuscator):

    def deobfuscate(self, data):
        strlit = Ps1StringLiterals(data)
        @strlit.outside
        def repl(m): return m[1]
        return re.sub(R'''`([^0abfnrtv`#'"\$])''', repl, data)
