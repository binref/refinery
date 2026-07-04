from __future__ import annotations

from refinery.lib.scripts.php.deobfuscation import deobfuscate
from refinery.lib.scripts.php.model import PhpScript
from refinery.lib.scripts.php.parser import PhpParser
from refinery.lib.scripts.php.synth import PhpSynthesizer
from refinery.units.scripting import IterativeDeobfuscator


class php(IterativeDeobfuscator):
    """
    AST-based PHP deobfuscator and pretty-printer.

    Parses the script into an abstract syntax tree, applies simplifying transformations, and
    synthesizes clean output. No deobfuscation passes are registered yet, so this currently only
    pretty-prints the input. This deobfuscator iterates until stable; running it twice does not
    change the output.
    """

    def parse(self, data: str) -> PhpScript:
        return PhpParser(data).parse()

    def transform(self, ast: PhpScript) -> int:
        return deobfuscate(ast, max_steps=self.args.timeout)

    def synthesize(self, ast: PhpScript) -> str:
        return PhpSynthesizer().convert(ast)
