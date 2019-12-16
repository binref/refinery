#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator


class deob_ps1_escape(Deobfuscator):
    def deobfuscate(self, data):
        return re.sub(R'''`([^0abfnrtv`#'"\$])''', R'\1', data)
