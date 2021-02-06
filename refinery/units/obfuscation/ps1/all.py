#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import IterativeDeobfuscator

from .brackets import deob_ps1_brackets
from .concat import deob_ps1_concat
from .escape import deob_ps1_escape
from .cases import deob_ps1_cases
from .format import deob_ps1_format
from .typecast import deob_ps1_typecast
from .stringreplace import deob_ps1_stringreplace
from .uncurly import deob_ps1_uncurly
from .invoke import deob_ps1_invoke


class deob_ps1(IterativeDeobfuscator):

    _SUBUNITS = [sub() for sub in [
        deob_ps1_escape,
        deob_ps1_cases,
        deob_ps1_brackets,
        deob_ps1_format,
        deob_ps1_typecast,
        deob_ps1_stringreplace,
        deob_ps1_concat,
        deob_ps1_invoke,
        deob_ps1_uncurly
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
