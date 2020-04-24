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

        def trimbrackets(string: str):
            while True:
                string = string.strip()
                if not string.startswith('(') or not string.endswith(')'):
                    break
                string = string[1:-1]
            if string.startswith('('):
                raise ValueError
            pos = len(string)
            while string[pos - 1] not in ''''"''':
                pos -= 1
            return string[:pos], string[pos:]

        @strlit.outside
        def replacer(match):
            nonlocal repeat, needle
            if needle not in range(*match.span()):
                return None
            string, case, needle, insert = match.groups()
            case = '(?i)' if 'c' not in case else ''
            try:
                string, tmp = trimbrackets(string)
                assert not tmp
                needle, tmp = trimbrackets(needle)
                assert not tmp
                insert, end = trimbrackets(insert)
            except Exception:
                return match[0]
            string = string_unquote(string)
            needle = string_unquote(needle)
            # transforming "Tvar".replace('T', '$')
            # into "$var" would trigger a variable substitution,
            # hence we need to escape the insert variable:
            insert = string_escape(string_unquote(insert))
            needle = re.escape(needle)
            repeat = True
            return string_quote(re.sub(case + needle, insert, string)) + end

        while repeat:
            repeat = False
            needle = None
            strlit.update(data)

            for nm in re.finditer(R'''replace\s*[\(\s]*['"]''', data, flags=re.IGNORECASE):
                if nm.start() not in strlit:
                    needle = nm.start()
                    break

            if needle is None:
                break

            data = re.sub(
                R'\s*'.join([
                    R'({s})', R'-([ci]?)replace', R'([\(\s]*{s}[\)\s]*)', R',', R'([\(\s]*{s}[\)\s]*)'
                ]).format(s=formats.ps1str),
                replacer,
                data,
                count=1,
                flags=re.IGNORECASE
            )

            if repeat:
                continue

            data = re.sub(
                R'\s*'.join([
                    R'({s})', R'\.repla(c)e', R'\(', R'([\(\s]*{s}[\)\s]*)', R',', R'([\(\s]*{s}[\)\s]*)', R'\)'
                ]).format(s=formats.ps1str),
                replacer,
                data,
                count=1,
                flags=re.IGNORECASE
            )

        return data
