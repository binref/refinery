#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from ... import Unit


class deob_vba_chr_literals(Unit):
    def process(self, data):
        def _chr(m):
            code = int(m[1], 0)
            if code == 34:
                return B'""""'
            return B'"%s"' % chr(code).encode('unicode_escape')
        data = re.sub(BR'Chr\((\d+x?\d+)\)', _chr, data, flags=re.IGNORECASE)
        data = re.sub(BR'"\s*\&\s*"', B'', data)
        return data
