from __future__ import annotations

from refinery.lib.scripts.au3.deobfuscation import deobfuscate
from refinery.lib.scripts.au3.model import Au3Script
from refinery.lib.scripts.au3.parser import Au3Parser
from refinery.lib.scripts.au3.synth import Au3Synthesizer
from refinery.units.scripting import IterativeDeobfuscator


class dau3(IterativeDeobfuscator):
    """
    AST-based AutoIt3 deobfuscator and pretty-printer.

    Parses the script into an abstract syntax tree, applies simplifying transformations — `Execute`
    flattening, alias and indirection rewriting, flattening of `Call`, `Assign`, and `Eval` over a
    literal name, constant folding and propagation — and synthesizes clean output. This
    deobfuscator iterates until stable; running it twice does not change the output.
    """

    def parse(self, data: str) -> Au3Script:
        return Au3Parser(data).parse()

    def transform(self, ast: Au3Script) -> int:
        return deobfuscate(ast, max_steps=self.args.timeout)

    def synthesize(self, ast: Au3Script) -> str:
        return Au3Synthesizer().convert(ast)
