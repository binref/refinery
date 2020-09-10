#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from ....lib.patterns import formats
from .. import Deobfuscator


class deob_js_arrays(Deobfuscator):
    """
    JavaScript deobfuscator to turn `["Z", "t", "s", "e"][0]` into `"Z"`.
    """

    def deobfuscate(self, data):

        def litpick(match):
            try:
                array = match[1]
                index = int(match[2])
                lpick = array.split(',')[index].strip()
                self.log_debug(lambda: F'{lpick} = {match[0]}')
            except (TypeError, IndexError):
                lpick = match[0]
            return lpick

        p = R'\s{{0,5}}'.join([
            '\\[', '((?:{i}|{s})', '(?:,', '(?:{i}|{s})', ')*)', '\\]', '\\[', '({i})', '\\]'
        ]).format(i=formats.integer, s=formats.string)
        return re.sub(p, litpick, data)
