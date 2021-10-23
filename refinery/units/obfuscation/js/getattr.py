#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from refinery.lib.patterns import formats
from refinery.units.obfuscation import Deobfuscator


class deob_js_getattr(Deobfuscator):
    """
    JavaScript deobfuscator to turn `WScript["CreateObject"]` into `WScript.CreateObject`.
    """

    def deobfuscate(self, data):
        def dottify(match):
            name = match[2][1:-1]
            if name.isidentifier():
                return F'{match[1]}.{name}'
            return match[0]
        return re.sub(FR'(\w+)\[({formats.string})\]', dottify, data)
