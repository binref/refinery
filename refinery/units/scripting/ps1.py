from __future__ import annotations

from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer
from refinery.units.scripting import IterativeDeobfuscator


class ps1(IterativeDeobfuscator):
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
            deobfuscate(ast)
        except Exception:
            return data
        try:
            result = Ps1Synthesizer().convert(ast)
        except Exception:
            return data
        return result
