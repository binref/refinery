#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from ....lib.patterns import formats
from .. import Deobfuscator
from . import string_unquote, string_quote, string_escape, Ps1StringLiterals


class deob_ps1_stringreplace(Deobfuscator):
    def deobfuscate(self, data):
        strlit = Ps1StringLiterals(data)
        repeat = True
        needle = None

        @strlit.outside
        def replacer(match):
            nonlocal repeat, needle
            if needle not in range(*match.span()):
                return None
            string, case, bl1, needle, bl2, br1, insert, br2 = match.groups()
            case = '' if case[0] in '.c' else '(?i)'
            bl = bl1.count('(') - bl2.count(')')
            br = br1.count(')') - br2.count('(')
            if bl < 0 or br < 0:
                return match[0]
            string = string_unquote(string)
            needle = string_unquote(needle)
            insert = string_escape(string_unquote(insert))
            needle = case + re.escape(needle)
            repeat = True
            return (bl * '(') + string_quote(re.sub(needle, lambda _: insert, string)) + (br * ')')

        while repeat:
            repeat = False
            needle = None
            strlit.update(data)

            for nm in re.finditer(R'''(?i)(-c|-i|-|\.)replace\s*[\(\s]*['"]''', data):
                if nm.start() in strlit:
                    continue
                k = strlit.get_container(nm.end() + 1)
                if k is None:
                    continue
                needle = strlit.ranges[k - 1][0]
                break

            if needle is None:
                break

            self.log_debug(needle)

            pattern = (
                R'(?i)'
                F'^.{{{{{needle}}}}}'        # anything before the actual string
                R'({s})'                     # string on which the replace is performed
                R'\s*(-c|-i|-|\.)replace'    # the replace call
                R'([\(\s]*)({s})([\)\s]*),'  # needle for the replacement (with brackets)
                R'([\(\s]*)({s})([\)\s]*)'   # replacement (with brackets)
            ).format(s=formats.ps1str)

            m = re.search(pattern, data)
            if m:
                self.log_debug(m[4])

            data = re.sub(pattern, replacer, data, count=1)

        return data
