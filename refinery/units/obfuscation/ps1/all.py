from __future__ import annotations

import re

from typing import TYPE_CHECKING

from refinery.units.obfuscation import IterativeDeobfuscator

if TYPE_CHECKING:
    from .. import Deobfuscator

from .b64convert import deob_ps1_b64convert
from .brackets import deob_ps1_brackets
from .cases import deob_ps1_cases
from .concat import deob_ps1_concat
from .encodings import deob_ps1_encodings
from .escape import deob_ps1_escape
from .format import deob_ps1_format
from .invoke import deob_ps1_invoke
from .stringreplace import deob_ps1_stringreplace
from .typecast import deob_ps1_typecast
from .uncurly import deob_ps1_uncurly


class deob_ps1(IterativeDeobfuscator):

    _SUBUNITS: list[type[Deobfuscator]] = [
        deob_ps1_escape,
        deob_ps1_cases,
        deob_ps1_brackets,
        deob_ps1_format,
        deob_ps1_typecast,
        deob_ps1_stringreplace,
        deob_ps1_b64convert,
        deob_ps1_encodings,
        deob_ps1_concat,
        deob_ps1_invoke,
        deob_ps1_uncurly
    ]

    def deobfuscate(self, data):
        units = [u() for u in self._SUBUNITS]
        for u in units:
            u.log_level = self.log_level
        for unit in units:
            self.log_debug(lambda: F'invoking {unit.name}')
            checkpoint = hash(data)
            data = unit.deobfuscate(data)
            if checkpoint != hash(data) and not self.log_debug('data has changed.'):
                self.log_info(F'used {unit.name}')
        return re.sub(R'[\r\n]+', '\n', data)
