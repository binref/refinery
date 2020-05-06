#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from functools import wraps
from typing import Callable

from ....lib.patterns import formats
from ...encoding.ps1str import ps1str


def dq_unescape(string):
    def unescape(match):
        char = match[0]
        return ps1str.UNESCAPE.get(char, char[1:])

    def splitvars(string):
        backtick = False
        variable = ''
        lbc, rbc = None, None
        brackets = 0
        position = 0
        for k, character in enumerate(string):
            if backtick:
                backtick = False
                continue
            if not variable:
                if character == '`':
                    backtick = True
                elif character == '$':
                    variable = True
                    yield string[position:k]
                    position = k
                continue
            if position == k - 1:
                if character in '?$':
                    variable = False
                    next_pos = k + 1
                if character not in '({':
                    lbc, rbc = None, None
                elif character == '(':
                    lbc, rbc = '(', ')'
                elif character == '{':
                    lbc, rbc = '{', '}'
            if lbc:
                if character == lbc:
                    brackets += 1
                if character == rbc:
                    brackets -= 1
                if not brackets:
                    variable = False
                    next_pos = k + 1
            elif variable:
                variable = character.isalnum() or character in '_:'
                next_pos = k
            if not variable:
                yield string[position:next_pos]
                position = next_pos
        yield string[position:]
        if variable:
            yield ''

    for k, item in enumerate(splitvars(string)):
        yield item if k % 2 else re.sub('`.', unescape, item).replace('""', '"')


def string_unquote(string: str):
    """
    Returns the string contents without quotes as they would appear in double
    quotes. If the input string uses single quotes, it is escaped.
    """
    quote = string[0]
    if quote != string[-1] or quote not in ''''"''':
        raise ValueError(F'not a valid quoted string: {string}')
    string = string[1:-1]
    if quote == '"':
        yield from dq_unescape(string)
    else:
        yield string.replace("''", "'")


def string_quote(parts, quote=True):
    def escaper(match):
        char = match[0]
        return ps1str.ESCAPE.get(char, char)

    if isinstance(parts, str):
        parts = [parts]

    chunks = [
        part if k % 2 else re.sub(R'''[\x00\x07-\x0D`$'"]''', escaper, part)
        for k, part in enumerate(parts)
    ]

    for k in range(1, len(chunks) - 1, 2):
        suffix = chunks[k + 1]
        if suffix and chunks[k][~0] not in '})' and (suffix[0].isalnum() or suffix[0] in ':_'):
            chunks[k] = F'${{{chunks[k][1:]}}}'

    result = ''.join(chunks)
    if quote: result = '"{}"'.format(result)
    return result


def string_apply(string, callback):
    def application(parts):
        for k, part in enumerate(parts):
            if k % 2:
                yield part
                continue
            result = callback(part)
            if isinstance(result, str):
                yield result
            else:
                yield from result

    return string_quote(application(string_unquote(string)))


class Ps1StringLiterals:

    def __init__(self, data: str):
        self.update(data)

    def update(self, data):
        self.data = data
        self.ranges = [
            match.span() for match in re.finditer(str(formats.ps1str), data)
        ]

    def shift(self, by, start=0):
        for k in range(start, len(self.ranges)):
            a, b = self.ranges[k]
            self.ranges[k] = a + by, b + by

    def outside(self, function: Callable[[re.Match], str]) -> Callable[[re.Match], str]:
        @wraps(function)
        def wrapper(match: re.Match) -> str:
            if match.string != self.data:
                self.update(match.string)
            a, b = match.span()
            for x, y in self.ranges:
                if x > b: break
                if (a in range(x, y) or x in range(a, b)) and (x < a or y > b):
                    return match[0]
            result = function(match)
            if result is not None:
                return result
            return match[0]
        return wrapper

    def __contains__(self, index):
        return any(index in range(*L) for L in self.ranges)

    def get_container(self, offset):
        for k, L in enumerate(self.ranges):
            if offset in range(*L):
                return k
        return None
