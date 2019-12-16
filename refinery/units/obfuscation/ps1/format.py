#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from ....lib.patterns import formats
from . import string_unquote, string_quote
from .. import Deobfuscator


class deob_ps1_format(Deobfuscator):
    """
    PowerShell deobfuscation for the following "format string"-based technique:

    - `"{0}{2}{1}"-f 'signa','ures','t'`
    - `"{0}na{2}{1}"-f 'sig','ures','t'`
    """
    def deobfuscate(self, data):
        pattern = R'\s*'.join([
            R'''(?P<pattern>{s})''',
            R'''-[fF]''',
            R'''(?P<args>({s},\s*)*{s})'''
        ]).format(s=formats.ps1str)
        pattern = re.compile(pattern)

        def deobfuscate(match):
            md = match.groupdict()
            pattern = string_unquote(md['pattern'])
            args = re.split(F'({formats.ps1str})', md['args'])
            args = [
                string_unquote(a.strip())
                for a in args[1::2]
            ]
            try:
                return string_quote(re.sub(
                    R'\{(\d+)\}',
                    lambda m: args[int(m.group(1))],
                    pattern
                ))
            except IndexError:
                return match.group(0)

        return pattern.sub(deobfuscate, data)
