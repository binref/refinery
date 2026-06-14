from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


class TestPs1(TestBase):

    def _deobfuscate(self, source: str, remove_junk: bool = True) -> str:
        ast = Ps1Parser(source).parse()
        deobfuscate(ast, remove_junk=remove_junk)
        return Ps1Synthesizer().convert(ast)

    def _deobfuscate_iterative(self, source: str, iterations: int = 100, remove_junk: bool = True) -> str:
        ast = Ps1Parser(source).parse()
        for _ in range(iterations):
            if not deobfuscate(ast, remove_junk=remove_junk):
                break
        return Ps1Synthesizer().convert(ast)

    def _apply(self, source: str, *transforms) -> str:
        """
        Run the given transformer passes once each, in order, and return the synthesized result.
        Lets a test target a single deobfuscation pass in isolation.
        """
        ast = Ps1Parser(source).parse()
        for transform in transforms:
            transform().visit(ast)
        return Ps1Synthesizer().convert(ast)
