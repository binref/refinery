#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from ....lib.patterns import formats
from ....lib.tools import lookahead
from .. import Deobfuscator
from . import string_unquote, string_apply, Ps1StringLiterals


class deob_ps1_stringreplace(Deobfuscator):

    _SENTINEL = re.compile((
        R'(?i)[\'"]\s*'               # end of haystack string
        R'(-c|-i|-|\.)replace'        # the replace call
        R'([\(\s]*)({s})([\)\s]*),'   # needle (with brackets)
        R'([\(\s]*)({s})([\)\s]*)'    # insert (with brackets)
    ).format(s=formats.ps1str), flags=re.IGNORECASE)

    def deobfuscate(self, data):
        repeat = True
        strlit = Ps1StringLiterals(data)

        while repeat:
            repeat = False
            needle = None

            for match in self._SENTINEL.finditer(data):
                for check in re.finditer(R'(?i)(-c|-i|-|\.)replace', data):
                    if check.start() in strlit:
                        break
                if check.start() < match.start():
                    break
                k = strlit.get_container(match.start())
                if k is None:
                    break
                offset, end = strlit.ranges[k]
                if match.start() != end - 1:
                    break
                string = data[offset:end]
                pf, bl1, needle, bl2, br1, insert, br2 = match.groups()
                end = match.end()
                case = '' if pf[0] in '.c' else '(?i)'
                bl = bl1.count('(') - bl2.count(')')
                br = br2.count(')') - br1.count('(')
                if pf[0] == '.':
                    bl -= 1
                    br -= 1
                if bl != 0 or br < 0:
                    break
                needle = list(string_unquote(needle))
                if len(needle) > 1:
                    break

                needle = needle[0]
                head, *body = string_unquote(insert)

                self.log_info('replacing', needle, 'by', insert)

                if not body:
                    def perform_replacement(string):
                        return re.sub(F'{case}{re.escape(needle)}', lambda _: head, string)
                else:
                    *body, tail = body
                    def perform_replacement(string): # noqa
                        parts = re.split(F'{case}{re.escape(needle)}', string)
                        if len(parts) == 1:
                            yield string
                            return
                        it = iter(parts)
                        yield next(it) + head
                        yield from body
                        for last, part in lookahead(it):
                            if last:
                                yield tail + part
                            else:
                                yield tail + part + head
                                yield from body

                replaced = string_apply(string, perform_replacement) + (br * ')')
                strlit.ranges[k] = offset, offset + len(replaced) - br
                strlit.ranges[k + 1: k + 3] = []
                strlit.shift(len(replaced) + offset - end, k + 1)
                data = data[:offset] + replaced + data[end:]
                repeat = True
                break

        return data
