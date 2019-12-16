#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator


class deob_ps1_invoke(Deobfuscator):
    def deobfuscate(self, data):
        data = re.sub(
            R'''(\.|::)'''                # preceeded by dot or namespace delimiter
            R'''(['"])(\w{1,200})\2'''    # quoted string (actually a method name)
            R'''(?=[\s\(\.\,\;\+\-])''',  # only if followed by certain characters
            R'\1\3',                      # remove quotes around symbol
            data
        )
        data = re.sub(R'''(\w{1,200})\.Invoke\s*\(''', R'\1(', data, flags=re.IGNORECASE)
        return data
