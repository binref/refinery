#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from refinery.units.obfuscation import IterativeDeobfuscator

from .arithmetic import deob_vba_arithmetic
from .brackets import deob_vba_brackets
from .char import deob_vba_char_function
from .comments import deob_vba_comments
from .concat import deob_vba_concat
from .constants import deob_vba_constants
from .dummies import deob_vba_dummy_variables
from .stringreplace import deob_vba_stringreplace
from .stringreverse import deob_vba_stringreverse


class deob_vba(IterativeDeobfuscator):

    _SUBUNITS = [sub() for sub in [
        deob_vba_comments,
        deob_vba_brackets,
        deob_vba_char_function,
        deob_vba_concat,
        deob_vba_arithmetic,
        deob_vba_constants,
        deob_vba_dummy_variables,
        deob_vba_stringreplace,
        deob_vba_stringreverse,
    ]]

    def deobfuscate(self, data):
        for u in self._SUBUNITS:
            u.log_level = self.log_level
        for unit in self._SUBUNITS:
            self.log_debug(lambda: F'invoking {unit.name}')
            checkpoint = hash(data)
            data = unit.deobfuscate(data)
            if checkpoint != hash(data) and not self.log_debug('data has changed.'):
                self.log_info(F'used {unit.name}')
        return re.sub(R'[\r\n]+', '\n', data)
