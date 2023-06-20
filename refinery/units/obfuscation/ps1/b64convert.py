#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import re
import base64

from refinery.units.obfuscation import Deobfuscator
from refinery.units.obfuscation.ps1 import string_unquote, Ps1StringLiterals
from refinery.lib.patterns import formats


class deob_ps1_b64convert(Deobfuscator):

    _SENTINEL = re.compile('\\s*'.join(
        (re.escape('[System.Convert]::FromBase64String'), '\\(', '({s})', '\\)')
    ).format(s=formats.ps1str), flags=re.IGNORECASE)

    def deobfuscate(self, data):
        strlit = Ps1StringLiterals(data)

        def replacer(match: re.Match[str]):
            if strlit.get_container(match.start()):
                return match[0]
            try:
                string, = string_unquote(match[1])
            except ValueError:
                return match[0]
            try:
                bytes = base64.b64decode(string)
            except Exception:
                return match[0]
            return '@({})'.format(','.join(F'0x{b:02X}' for b in bytes))

        return self._SENTINEL.sub(replacer, data)
