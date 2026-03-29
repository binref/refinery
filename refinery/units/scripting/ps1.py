from __future__ import annotations

import re

from refinery.lib.scripts.ps1.deobfuscation import Ps1Deobfuscator
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer
from refinery.units.obfuscation import IterativeDeobfuscator


class ppps(IterativeDeobfuscator):
    """
    AST-based PowerShell deobfuscator.

    Parses the script into an abstract syntax tree, applies simplifying transformations (constant
    folding, format string evaluation, bracket removal, type cast simplification, string
    operations, case normalization, invoke simplification, uncurly variables), and synthesizes
    clean output. Iterates until stable.
    """

    def deobfuscate(self, data: str) -> str:
        try:
            ast = Ps1Parser(data).parse()
        except Exception:
            return data
        try:
            Ps1Deobfuscator().visit(ast)
        except Exception:
            return data
        try:
            result = Ps1Synthesizer().convert(ast)
        except Exception:
            return data
        return re.sub(r'[\r\n]+', '\n', result)
