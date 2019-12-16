#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import string

from ....lib.patterns import formats
from .. import Deobfuscator
from . import string_escape, string_quote


class deob_ps1_typecast(Deobfuscator):
    """
    Replaces sequences like [Char]120 to their string representation, in this
    case the string "x".
    """

    def deobfuscate(self, data):

        data = re.sub(
            R'\[(?:string|char\[\])\]\s*(%s)' % formats.ps1str,
            R'\1',
            data,
            flags=re.IGNORECASE
        )

        def char_literal(match):
            return string_quote(string_escape(chr(int(match.group(1), 0))))

        data = re.sub(
            R'\[char\]\s*0*(0x[0-9a-f]+|\d+)',
            char_literal,
            data,
            flags=re.IGNORECASE
        )

        def char_array(match):
            result = bytes(int(x, 0) for x in match.group(1).split(','))
            try:
                result = result.decode('ascii')
                if not all(x in string.printable for x in result):
                    raise ValueError
            except ValueError:
                return match.group(0)
            else:
                return string_quote(string_escape(result))

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
