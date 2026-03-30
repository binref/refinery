from __future__ import annotations

import re

from refinery.lib.scripts.js.deobfuscation import JsDeobfuscator
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
        try:
            ast = JsParser(data).parse()
        except Exception:
            return data
        try:
            JsDeobfuscator().visit(ast)
        except Exception:
            return data
        try:
            result = JsSynthesizer().convert(ast)
        except Exception:
            return data
        return re.sub(r'[\r\n]+', '\n', result)
