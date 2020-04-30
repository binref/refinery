#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import IterativeDeobfuscator
from . import string_unquote, string_quote, Ps1StringLiterals


class deob_ps1_concat(IterativeDeobfuscator):
    _SENTINEL = re.compile(R'''['"]\s*[+&]\s*['"]''')

    def deobfuscate(self, data):

        def concat(data):
            strlit = Ps1StringLiterals(data)
            repeat = True
            while repeat:
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
                    parts = list(string_unquote(stra))
                    it = iter(string_unquote(strb))
                    parts[~0] += next(it)
                    parts.extend(it)
                    yield data[:a[0]] + string_quote(parts)
                    data = data[b[1]:]
                    strlit.update(data)
                    break
                else:
                    repeat = False
            yield data

        return ''.join(concat(data))
