#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from refinery.lib.patterns import formats
from refinery.units.obfuscation import IterativeDeobfuscator
from refinery.units.obfuscation import StringLiterals


class deob_vba_concat(IterativeDeobfuscator):
    _SENTINEL = re.compile(R'''"\s*(\++|&)\s*"''')

    def deobfuscate(self, data):

        def concat(data):
            strlit = StringLiterals(formats.vbastr, data)
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
                    _, a = strlit.ranges[a]
                    b, c = strlit.ranges[b]
                    yield data[:a - 1] + data[b + 1:c]
                    data = data[c:]
                    strlit.update(data)
                    break
                else:
                    repeat = False
            yield data

        return ''.join(concat(data))
