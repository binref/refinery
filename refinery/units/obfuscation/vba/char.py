#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import re

from refinery.units.obfuscation import Deobfuscator, StringLiterals
from refinery.lib.patterns import formats


class deob_vba_char_function(Deobfuscator):
    def deobfuscate(self, data):
        strings = StringLiterals(formats.vbastr, data)

        @strings.outside
        def evaluate_char_function(match: re.Match[str]):
            try:
                c = chr(int(match[1]))
            except ValueError:
                return match[0]
            c = repr(c)[1:-1]
            if len(c) > 1:
                return match[0]
            return '"{}"'.format(c)

        return re.sub(R'(?i)\bchr\((\d+)\)', evaluate_char_function, data)
