#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator
from . import Ps1StringLiterals


class deob_ps1_invoke(Deobfuscator):
    def deobfuscate(self, data):
        strlit = Ps1StringLiterals(data)

        @strlit.outside
        def invrepl1(m): return m[1] + m[3]

        data = re.sub(
            R'''(\.|::)'''                    # preceeded by dot or namespace delimiter
            R'''(['"])(\w{1,200})\2'''        # quoted string (actually a method name)
            R'''(?=[\s\(\.\,\;\+\-])''',      # only if followed by certain characters
            invrepl1, data                    # remove quotes around symbol
        )

        @strlit.outside
        def invrepl2(m): return m[1] + '('

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
            invrepl2, data,
            flags=re.IGNORECASE
        )

        return data
