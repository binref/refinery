from __future__ import annotations

import re

from refinery.units.obfuscation import Deobfuscator


class deob_vba_comments(Deobfuscator):
    def deobfuscate(self, data):
        return re.sub(R"(?im)^\s{0,20}(?:'|rem\b|dim\b).*(?:\Z|$\n\r?)", '', data)
