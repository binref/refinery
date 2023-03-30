#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import re

from refinery.lib.patterns import formats
from refinery.units.obfuscation import Deobfuscator, StringLiterals
from refinery.units.obfuscation.vba import string_quote, string_unquote


class deob_vba_stringreverse(Deobfuscator):

    _SENTINEL = re.compile((
        R'(?i)\bStrReverse\s*\('  # the reverse call
        R'\s*({s})\s*\)'          # string
    ).format(s=formats.vbastr), flags=re.IGNORECASE)

    def deobfuscate(self, data):
        strlit = StringLiterals(formats.vbastr, data)

        @strlit.outside
        def replacement(match: re.Match[str]):
            return string_quote(''.join(reversed(string_unquote(match[1]))))

        return self._SENTINEL.sub(replacement, data)
