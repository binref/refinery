#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import IterativeDeobfuscator

from .brackets import deob_ps1_brackets
from .concat import deob_ps1_concat
from .escape import deob_ps1_escape
from .cases import deob_ps1_cases
from .format import deob_ps1_format
from .typecast import deob_ps1_typecast
from .stringreplace import deob_ps1_stringreplace
from .literals import deob_ps1_literals
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
        deob_ps1_literals
    ]]

    def deobfuscate(self, data):
        for unit in self._SUBUNITS:
            if self.log_debug():
                self.log_debug(F'invoking {unit.__class__.__name__}')
                checkpoint = hash(data)
            data = unit.deobfuscate(data)
            if self.log_debug() and checkpoint != hash(data):
                self.log_debug('data has changed.')
        return data
