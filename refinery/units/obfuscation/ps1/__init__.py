#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from functools import wraps
from typing import Callable

from ....lib.patterns import formats


def string_unquote(string):
    quote = string[:1]
    if quote != string[-1:] or ord(quote) not in (0x22, 0x27):
        raise ValueError(F'not a valid quoted string: {string}')
    string = string[1:-1].replace(quote + quote, quote)
    if quote == '"':
        string = string.replace('`"', '"')
    return string


def string_quote(string):
    return '"{}"'.format(string.replace('"', '""'))


def string_escape(string):
    def escaper(match):
        char = match.group(1)
        return '`' + {
            '\0': '0',
            '\a': 'a',
            '\b': 'b',
            '\f': 'f',
            '\n': 'n',
            '\r': 'r',
            '\t': 't',
            '\v': 'v',
        }.get(char, char)
    escaped = re.sub(R'(?<!`)([\x00\x07-\x0D`])', escaper, string)
    return re.sub(R'(?<!`)\$(?![\w\(\{\$\?\^:])', '`$', escaped)


class Ps1StringLiterals:

    def __init__(self, data: str):
        self.update(data)

    def update(self, data):
        self.data = data
        self.ranges = [
            match.span() for match in re.finditer(str(formats.ps1str), data)
        ]

    def outside(self, function: Callable[[re.Match], str]) -> Callable[[re.Match], str]:
        @wraps(function)
        def wrapper(match: re.Match) -> str:
            if match.string != self.data:
                self.update(match.string)
            a, b = match.span()
            for x, y in self.ranges:
                if x > b: break
                if (a in range(x, y) or x in range(a, b)) and (x < a or y > b):
                    return match.group(0)
            result = function(match)
            if result is not None:
                return result
            return match.group(0)
        return wrapper

    def __contains__(self, index):
        return any(index in range(*L) for L in self.ranges)

    def get_container(self, offset):
        for k, L in enumerate(self.ranges):
            if offset in range(*L):
                return k
        return None
