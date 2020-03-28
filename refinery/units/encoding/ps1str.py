#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from ...lib.decorators import unicoded
from .. import Unit


class ps1str(Unit):
    """
    Escapes and unescapes PowerShell strings.
    """
    _UNESCAPE = {
        '`0': '\0',
        '`a': '\a',
        '`b': '\b',
        '`f': '\f',
        '`n': '\n',
        '`r': '\r',
        '`t': '\t',
        '`v': '\v',
        '``': '`',
        "`'": '\'',
        '`"': '\"',
    }
    _ESCAPE = {
        '`': '``',
        '\0': '`0',
        '\a': '`a',
        '\b': '`b',
        '\f': '`f',
        '\n': '`n',
        '\r': '`r',
        '\t': '`t',
        '\v': '`v',
        '\'': "`'",
        '\"': '`"',
    }

    def __init__(self) -> Unit: pass # noqa

    @unicoded
    def process(self, data):
        if data[0] not in ''''"''' or data[-1] != data[0]:
            raise ValueError(
                'No quotes found at beginning of input. To escape a PowerShell string, the '
                'quotes must be included because quote escaping depends on whether a single '
                'or double quote was used.')

        quote, data = data[0], data[1:-1]

        def unescape(match):
            string = match.group(0)
            return self._UNESCAPE.get(string, string[1:])

        return re.sub('`.', unescape, data).replace(2 * quote, quote)

    @unicoded
    def reverse(self, data):
        def escape(match):
            string = match.group(0)
            return self._ESCAPE[string]
        return "'{}'".format(re.sub(R'[`\0\a\b\f\n\r\t\v\'\"]', escape, data))
