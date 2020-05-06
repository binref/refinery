#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import string

from ....lib.patterns import formats
from .. import Deobfuscator
from . import string_quote, Ps1StringLiterals


class deob_ps1_typecast(Deobfuscator):
    """
    Replaces sequences like [Char]120 to their string representation, in this
    case the string "x".
    """

    def deobfuscate(self, data):
        strlit = Ps1StringLiterals(data)

        @strlit.outside
        def strip_typecast(m): return m[1]

        data = re.sub(
            FR'\[(?:string|char\[\])\]\s*({formats.ps1str!s})',
            strip_typecast,
            data,
            flags=re.IGNORECASE
        )

        @strlit.outside
        def char_literal(match):
            c = chr(int(match[1]))
            if c == "'":
                return '''"'"'''
            return F"'{c}'"

        data = re.sub(
            R'\[char\]\s*0*(0x[0-9a-f]+|\d+)',
            char_literal,
            data,
            flags=re.IGNORECASE
        )

        def char_array(match):
            result = bytes(int(x, 0) for x in match[1].split(','))
            try:
                result = result.decode('ascii')
                if not all(x in string.printable or x.isspace() for x in result):
                    raise ValueError
            except ValueError:
                return match[0]
            else:
                return string_quote(result)

        data = re.sub(
            R'\s*'.join([
                R'\[char\[\]\]',
                R'\((',
                R'(?:\s*(?:0x[0-9a-f]+|\d+)\s*,)+',
                R'(?:0x[0-9a-f]+|\d+)',
                R')\)'
            ]),
            char_array,
            data,
            flags=re.IGNORECASE
        )

        return data
