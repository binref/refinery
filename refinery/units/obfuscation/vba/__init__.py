#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package containing deobfuscators for Visual Basic for Applications (VBA).
"""


def string_unquote(string: str) -> str:
    if string[0] != '"' or string[~0] != '"':
        raise ValueError(string)
    return string[1:~1].replace('""', '"')


def string_quote(string: str) -> str:
    return '"{}"'.format(string.replace('"', '""'))
