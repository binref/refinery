#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from refinery.units.obfuscation import Deobfuscator


class deob_vba_comments(Deobfuscator):
    def deobfuscate(self, data):
        return re.sub(R"(?im)^\s{0,20}(?:'|rem\b|dim\b).*(?:\Z|$\n\r?)", '', data)
