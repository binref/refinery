from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.vba.deobfuscation import deobfuscate
from refinery.lib.scripts.vba.deobfuscation.simplify import VbaSimplifications
from refinery.lib.scripts.vba.parser import VbaParser
from refinery.lib.scripts.vba.synth import VbaSynthesizer


class TestVba(TestBase):

    def _fold(self, source: str) -> str:
        ast = VbaParser(source).parse()
        VbaSimplifications().visit(ast)
        return VbaSynthesizer().convert(ast)

    def _deobfuscate(self, source: str) -> str:
        ast = VbaParser(source).parse()
        deobfuscate(ast)
        return VbaSynthesizer().convert(ast)

    def _full_deobfuscate(self, source: str, max_rounds: int = 20) -> str:
        ast = VbaParser(source).parse()
        for _ in range(max_rounds):
            if not deobfuscate(ast):
                break
        return VbaSynthesizer().convert(ast)
