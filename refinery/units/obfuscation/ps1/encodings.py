#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import re
import codecs

from refinery.units.obfuscation import Deobfuscator
from refinery.units.obfuscation.ps1 import string_quote, Ps1StringLiterals
from refinery.lib.patterns import formats


class deob_ps1_encodings(Deobfuscator):

    _SENTINEL = re.compile('\\s*'.join(
        (re.escape('[System.Text.Encoding]::') + '(\\w+)\\.GetString', '\\(', '@\\(', '({a})', '\\)', '\\)')
    ).format(a=formats.intarray), flags=re.IGNORECASE)

    def deobfuscate(self, data):
        strlit = Ps1StringLiterals(data)

        def replacer(match: re.Match[str]):
            if strlit.get_container(match.start()):
                return match[0]
            try:
                bytes = bytearray(int(x.strip(), 0) for x in match[2].split(','))
            except Exception:
                return match[0]
            encoding = {
                'ASCII': 'ascii',
                'BigEndianUnicode': 'utf-16be',
                'Default': 'latin1',
                'Unicode': 'utf-16le',
            }.get(match[1], match[1])
            try:
                codecs.lookup(encoding)
            except LookupError:
                encoding = 'utf8'
            try:
                string = bytes.decode(encoding)
            except Exception:
                return match[0]
            return string_quote(string)

        return self._SENTINEL.sub(replacer, data)
