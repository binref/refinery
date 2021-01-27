#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from ...lib.decorators import unicoded
from .. import Unit


class ps1str(Unit):
    """
    Escapes and unescapes PowerShell strings.
    """
    UNESCAPE = {
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
    ESCAPE = {
        '`' : '``',
        '$' : '`$',
        '\0': '`0',
        '\a': '`a',
        '\b': '`b',
        '\f': '`f',
        '\n': '`n',
        '\r': '`r',
        '\t': '`t',
        '\v': '`v',
        '\'': "`'",
        '\"': '""',
    }

    def __init__(self): pass

    @unicoded
    def process(self, data):
        match = re.fullmatch(R'''@(['"])\s*\n(.*?)\n\s*\1@''', data)
        if match:
            return match.group(2)
        if data[0] not in ''''"''' or data[-1] != data[0]:
            raise ValueError(
                'No quotes found at beginning of input. To escape a PowerShell string, the '
                'quotes must be included because quote escaping depends on whether a single '
                'or double quote was used.')

        quote, data = data[0], data[1:-1]

        def unescape(match):
            string = match[0]
            return self.UNESCAPE.get(string, string[1:])

        if quote == '"':
            if re.search(R'(?<!`)\$(?=[\w\(\{\$\?\^:])', data):
                self.log_warn('Loss of information: double quoted string contains variable substitutions.')
            data = re.sub('`.', unescape, data)

        return data.replace(quote + quote, quote)

    @unicoded
    def reverse(self, data):
        def escaper(match):
            char = match[0]
            return ps1str.ESCAPE.get(char, char)
        return '"{}"'.format(re.sub(R'''[\x00\x07-\x0D`$'"]''', escaper, data))
