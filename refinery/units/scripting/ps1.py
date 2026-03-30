from __future__ import annotations

from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.model import Ps1Script
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

    def parse(self, data: str) -> Ps1Script:
        return Ps1Parser(data).parse()

    transform = staticmethod(deobfuscate)

    def synthesize(self, ast: Ps1Script) -> str:
        return Ps1Synthesizer().convert(ast)
