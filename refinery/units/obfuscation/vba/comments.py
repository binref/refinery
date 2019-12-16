#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator


class deob_vba_comments(Deobfuscator):
    def deobfuscate(self, data):
        return re.sub(
            R"^\s{0,20}(?:'|rem\b|dim\b).*$\n\r?",
            '',
            data,
            flags=re.MULTILINE | re.IGNORECASE
        )
