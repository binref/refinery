from __future__ import annotations

from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.units.scripting import IterativeDeobfuscator


class js(IterativeDeobfuscator):
    """
    AST-based JavaScript deobfuscator and pretty-printer.

    Parses the script into an abstract syntax tree, applies simplifying transformations, and
    synthesizes clean output.
    """

    def deobfuscate(self, data: str) -> str:
        ast = JsParser(data).parse()
        deobfuscate(ast)
        return JsSynthesizer().convert(ast)
