from __future__ import annotations

from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.model import JsScript
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.lib.types import Param
from refinery.units import Arg
from refinery.units.scripting import IterativeDeobfuscator


class js(IterativeDeobfuscator):
    """
    AST-based JavaScript deobfuscator and pretty-printer.

    Parses the script into an abstract syntax tree, applies simplifying transformations, and
    synthesizes clean output. This deobfuscator iterates until stable; running it twice does
    not change the output. By default the input is assumed to run as a classic global script; pass
    the module switch when it runs as an ES or CommonJS module instead.
    """

    def __init__(
        self,
        timeout=500,
        module: Param[bool, Arg.Switch('-m', help=(
            'Assume the input runs as an ES or CommonJS module (for example, node file.js), where a '
            'top-level declaration is scoped to the module and does not attach to the global object, '
            'rather than as a classic global script (a browser script tag, Windows Script Host).'))] = False,
    ):
        super().__init__(timeout=timeout, module=module)

    def parse(self, data: str) -> JsScript:
        return JsParser(data).parse()

    def transform(self, ast: JsScript) -> int:
        return deobfuscate(ast, module=self.args.module)

    def synthesize(self, ast: JsScript) -> str:
        return JsSynthesizer().convert(ast)
