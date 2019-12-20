#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator


class deob_ps1_invoke(Deobfuscator):
    def deobfuscate(self, data):
        data = re.sub(
            R'''(\.|::)'''                    # preceeded by dot or namespace delimiter
            R'''(['"])(\w{1,200})\2'''        # quoted string (actually a method name)
            R'''(?=[\s\(\.\,\;\+\-])''',      # only if followed by certain characters
            R'\1\3', data                     # remove quotes around symbol
        )
        data = re.sub(
            '\\s{0,5}'.join([
                '[.&]', '(\\(',               # sourcing operator
                '(?:gcm|get-command)', ')?',  # potentially a get-command
                '([\'"])([-a-z]{1,100})\\2'   # string enclosing a command
                '(?(1)\\s{0,5}\\)|)',         # closing bracket for get-command
            ]), '\\3', data, flags=re.IGNORECASE
        )
        data = re.sub(
            R'''(\w{1,200})\.Invoke\s*\(''',
            R'\1(',
            data,
            flags=re.IGNORECASE
        )
        return data
