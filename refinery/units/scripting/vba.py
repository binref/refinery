from __future__ import annotations

import re

from refinery.lib.scripts.vba.deobfuscation import VbaDeobfuscator
from refinery.lib.scripts.vba.parser import VbaParser
from refinery.lib.scripts.vba.synth import VbaSynthesizer
from refinery.units.obfuscation import IterativeDeobfuscator


class vba(IterativeDeobfuscator):
    """
    AST-based VBA deobfuscator and pretty-printer.

    Parses the VBA code into an abstract syntax tree, applies simplifying transformations, and
    synthesizes clean output. Deobfuscating transformations are iterated until the output does not
    change any more: This unit targets the deobfuscation of malicious VBA macros in Office
    documents.
    """

    def deobfuscate(self, data: str) -> str:
        try:
            ast = VbaParser(data).parse()
        except Exception:
            return data
        try:
            VbaDeobfuscator().deobfuscate(ast)
        except Exception:
            return data
        try:
            result = VbaSynthesizer().convert(ast)
        except Exception:
            return data
        return re.sub(r'[\r\n]+', '\n', result)
