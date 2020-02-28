#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import IterativeDeobfuscator
from . import string_unquote, string_quote
from ....lib.patterns import formats


class deob_ps1_concat(IterativeDeobfuscator):
    def deobfuscate(self, data):
        def concatenate(match):
            a, b = match.groups()
            return string_quote(string_unquote(a) + string_unquote(b))
        return re.sub(
            R'({s})\s*[\+\&]{{1}}\s*({s})'.format(s=formats.ps1str),
            concatenate,
            data
        )
