#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import IterativeDeobfuscator
from . import string_unquote, string_quote, Ps1StringLiterals


class deob_ps1_concat(IterativeDeobfuscator):
    _SENTINEL = re.compile(R'''['"]\s*[\+\&]\s*['"]''')

    def deobfuscate(self, data):
        repeat = True
        strlit = Ps1StringLiterals(data)

        while repeat:
            repeat = False
            for match in self._SENTINEL.finditer(data):
                a, b = match.span()
                a = strlit.get_container(a)
                if a is None:
                    continue
                b = strlit.get_container(b)
                if b is None or b != a + 1:
                    continue
                a = strlit.ranges[a]
                b = strlit.ranges[b]
                stra = data[slice(*a)]
                strb = data[slice(*b)]
                s = string_quote(string_unquote(stra) + string_unquote(strb))
                data = data[:a[0]] + s + data[b[1]:]
                strlit.update(data)
                repeat = True
                break

        return data
