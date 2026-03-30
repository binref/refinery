from __future__ import annotations

from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.model import JsScript
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.units.scripting import IterativeDeobfuscator


class js(IterativeDeobfuscator):
    """
    AST-based JavaScript deobfuscator and pretty-printer.

    Parses the script into an abstract syntax tree, applies simplifying transformations, and
    synthesizes clean output.
    """

    def parse(self, data: str) -> JsScript:
        return JsParser(data).parse()

    transform = staticmethod(deobfuscate)

    def synthesize(self, ast: JsScript) -> str:
        return JsSynthesizer().convert(ast)
