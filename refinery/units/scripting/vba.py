from __future__ import annotations

from refinery.lib.scripts.vba.deobfuscation import deobfuscate
from refinery.lib.scripts.vba.model import VbaModule
from refinery.lib.scripts.vba.parser import VbaParser
from refinery.lib.scripts.vba.synth import VbaSynthesizer
from refinery.units.scripting import IterativeDeobfuscator


class vba(IterativeDeobfuscator):
    """
    AST-based VBA deobfuscator and pretty-printer.

    This unit targets the deobfuscation of malicious VBA macros in Office documents. It parses the
    VBA code into an abstract syntax tree, applies simplifying transformations, and synthesizes
    clean output. Deobfuscating transformations are iterated until the output does not change any
    more: Running the unit twice does not change the output.
    """

    def parse(self, data: str) -> VbaModule:
        return VbaParser(data).parse()

    transform = staticmethod(deobfuscate)

    def synthesize(self, ast: VbaModule) -> str:
        return VbaSynthesizer().convert(ast)
