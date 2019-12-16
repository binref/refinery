#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from ....lib.patterns import formats
from .. import Deobfuscator
from . import string_unquote, string_quote, string_escape


class deob_ps1_stringreplace(Deobfuscator):
    def deobfuscate(self, data):
        def dash_replace(match):
            string, case, needle, insert = match.groups()
            case = '(?i)' if 'c' not in case else ''
            string = string_unquote(string)
            needle = string_unquote(needle)
            # transforming "Tvar".replace('T', '$')
            # into "$var" would trigger a variable substitution,
            # hence we need to escape the insert variable:
            insert = string_escape(string_unquote(insert))
            needle = re.escape(needle)
            return string_quote(re.sub(needle, lambda _: insert, string))

        def dot_replace(match):
            string, needle, insert = match.groups()
            string = string_unquote(string)
            needle = string_unquote(needle)
            insert = string_escape(string_unquote(insert))
            return string_quote(string.replace(needle, insert))

        data = re.sub(
            R'({s})\s*-([ci]?)replace\s*({s})\s*,\s*({s})'.format(s=formats.ps1str),
            dash_replace,
            data,
            flags=re.IGNORECASE
        )

        data = re.sub(
            R'({s}).Replace\(\s*({s})\s*,\s*({s})\s*\)'.format(s=formats.ps1str),
            dot_replace,
            data,
            flags=re.IGNORECASE
        )

        return data
