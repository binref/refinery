from __future__ import annotations

from typing import TYPE_CHECKING, Callable, NamedTuple

if TYPE_CHECKING:
    from refinery.lib.scripts import Node
    from refinery.lib.scripts.js.model import JsErrorNode
    from refinery.lib.scripts.js.parser import JsParser
    from refinery.lib.scripts.js.synth import JsSynthesizer
    from refinery.lib.scripts.ps1.model import Ps1ErrorNode
    from refinery.lib.scripts.ps1.parser import Ps1Parser
    from refinery.lib.scripts.ps1.synth import Ps1Synthesizer
    from refinery.lib.scripts.vba.model import VbaErrorNode
    from refinery.lib.scripts.vba.parser import VbaParser
    from refinery.lib.scripts.vba.synth import VbaSynthesizer

from refinery.lib.types import INF
from refinery.units.scripting import IterativeDeobfuscator


class _Backend(NamedTuple):
    name: str
    parser: type[JsParser] | type[Ps1Parser] | type[VbaParser]
    deobfuscate: Callable[..., bool]
    synthesizer: type[JsSynthesizer] | type[Ps1Synthesizer] | type[VbaSynthesizer]
    error: type[JsErrorNode] | type[Ps1ErrorNode] | type[VbaErrorNode]


class defu(IterativeDeobfuscator):
    """
    Universal script deobfuscator supporting JavaScript, PowerShell, and VBA.

    Attempts to parse the input as JavaScript, PowerShell, and VBA, then selects the language
    whose parser produces the fewest error nodes and applies the corresponding deobfuscation
    pipeline. The deobfuscation is executed iteratively until the output does not change any
    more; running the unit twice does not change the output.
    """

    _backend: _Backend

    @classmethod
    def _backends(cls):
        from refinery.lib.scripts.ps1.deobfuscation import deobfuscate as ps1_deobfuscate
        from refinery.lib.scripts.ps1.model import Ps1ErrorNode
        from refinery.lib.scripts.ps1.parser import Ps1Parser
        from refinery.lib.scripts.ps1.synth import Ps1Synthesizer
        yield _Backend('ps1', Ps1Parser, ps1_deobfuscate, Ps1Synthesizer, Ps1ErrorNode)

        from refinery.lib.scripts.vba.deobfuscation import deobfuscate as vba_deobfuscate
        from refinery.lib.scripts.vba.model import VbaErrorNode
        from refinery.lib.scripts.vba.parser import VbaParser
        from refinery.lib.scripts.vba.synth import VbaSynthesizer
        yield _Backend('vba', VbaParser, vba_deobfuscate, VbaSynthesizer, VbaErrorNode)

        from refinery.lib.scripts.js.deobfuscation import deobfuscate as js_deobfuscate
        from refinery.lib.scripts.js.model import JsErrorNode
        from refinery.lib.scripts.js.parser import JsParser
        from refinery.lib.scripts.js.synth import JsSynthesizer
        yield _Backend('js', JsParser, js_deobfuscate, JsSynthesizer, JsErrorNode)

    def parse(self, data: str) -> Node:
        best_ast: Node | None = None
        best_errors = INF()
        best_backend = None
        for backend in self._backends():
            try:
                ast = backend.parser(data).parse()
                errors = sum(
                    len(n.text) for n in ast.walk() if isinstance(n, backend.error))
            except Exception:
                continue
            if errors < best_errors:
                best_errors = errors
                best_ast = ast
                best_backend = backend
                if errors == 0:
                    break
        if best_backend is None or best_ast is None or best_errors * 2 > len(data):
            raise ValueError('none of the available parsers was able to parse the input')
        self._backend = best_backend
        self.log_info(F'using {best_backend.name} with {best_errors / len(data) * 100:.2f}% errors')
        return best_ast

    def transform(self, ast: Node) -> bool:
        return self._backend.deobfuscate(ast)

    def synthesize(self, ast: Node) -> str:
        return self._backend.synthesizer().convert(ast)
