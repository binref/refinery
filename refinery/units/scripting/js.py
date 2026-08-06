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
    the module switch when it runs as an ES or CommonJS module instead. Name any entrypoint a host
    calls into, or dead-code removal will discard it as unreachable.
    """

    def __init__(
        self,
        *entrypoints: Param[str, Arg.String(metavar='pattern', nargs='*', help=(
            'A wildcard pattern naming top-level functions that a host invokes by name, such as the '
            'run handler of a JXA script or a Windows Script Host event handler. Such a function has '
            'no caller inside the file, so it is otherwise removed as unreachable along with '
            'everything only it reached. Give a single asterisk to keep every top-level function.'))],
        timeout=500,
        module: Param[bool, Arg.Switch('-m', help=(
            'Assume the input runs as an ES or CommonJS module (for example, node file.js), where a '
            'top-level declaration is scoped to the module and does not attach to the global object, '
            'rather than as a classic global script (a browser script tag, Windows Script Host).'))] = False,
    ):
        super().__init__(timeout=timeout, module=module, entrypoints=entrypoints)

    def parse(self, data: str) -> JsScript:
        return JsParser(data).parse()

    def transform(self, ast: JsScript) -> int:
        return deobfuscate(
            ast,
            module=self.args.module,
            entrypoints=tuple(self.args.entrypoints),
        )

    def synthesize(self, ast: JsScript) -> str:
        return JsSynthesizer().convert(ast)
