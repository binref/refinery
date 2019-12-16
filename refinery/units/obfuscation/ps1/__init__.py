#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re


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
