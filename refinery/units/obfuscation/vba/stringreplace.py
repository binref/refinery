#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import re

from refinery.lib.patterns import formats
from refinery.units.obfuscation import Deobfuscator, StringLiterals
from refinery.units.obfuscation.vba import string_quote, string_unquote


class deob_vba_stringreplace(Deobfuscator):

    _SENTINEL = re.compile((
        R'(?i)\bReplace\s*\('  # the replace call
        R'\s*({s}),'           # haystack (with brackets)
        R'\s*({s}),'           # needle (with brackets)
        R'\s*({s})\s*\)'       # insert (with brackets)
    ).format(s=formats.vbastr), flags=re.IGNORECASE)

    def deobfuscate(self, data):
        strlit = StringLiterals(formats.vbastr, data)

        @strlit.outside
        def replacement(match: re.Match[str]):
            return string_quote(
                string_unquote(match[1]).replace(
                    string_unquote(match[2]),
                    string_unquote(match[3])
                )
            )

        return self._SENTINEL.sub(replacement, data)
