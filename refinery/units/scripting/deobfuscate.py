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

from refinery.lib.scripts.guess import ScriptBackend, select_backend
from refinery.lib.types import Param
from refinery.units import Arg
from refinery.units.scripting import IterativeDeobfuscator


class _Backend(NamedTuple):
    name: str
    parser: type[JsParser] | type[Ps1Parser] | type[VbaParser]
    deobfuscate: Callable[..., int]
    synthesizer: type[JsSynthesizer] | type[Ps1Synthesizer] | type[VbaSynthesizer]
    error: type[JsErrorNode] | type[Ps1ErrorNode] | type[VbaErrorNode]
    #: The keyword this backend takes for the unit's output-preserving switch, or `None` where the
    #: language has no statement whose only effect is to write a value out. Named per backend rather
    #: than passed to all of them, because the same switch is spelled differently by each pipeline
    #: and a backend that has never heard of it must not be handed one.
    keep_output: str | None = None


class defu(IterativeDeobfuscator):
    """
    Universal script deobfuscator supporting JavaScript, PowerShell, and VBA.

    Attempts to parse the input as JavaScript, PowerShell, and VBA, then selects the language
    whose parser produces the fewest error nodes and applies the corresponding deobfuscation
    pipeline. The deobfuscation is executed iteratively until the output does not change any
    more; running the unit twice does not change the output.

    Where the selected language has a notion of a statement whose only effect is to write a value to
    the console, such a statement is deleted by default and the switch below keeps it; see
    `refinery.ps1` for what that costs and the assumption it rests on. A language without that
    notion ignores the switch.
    """

    _backend: _Backend

    def __init__(
        self,
        timeout=500,
        keep_output: Param[bool, Arg.Switch('-k', help=(
            'Keep every statement whose only effect is to write a value to the output stream, '
            'including values an obfuscator injected as noise. Use this when the input is a module '
            'or a fragment of a larger script.'))] = False,
    ):
        super().__init__(timeout=timeout, keep_output=keep_output)

    @classmethod
    def _backends(cls):
        from refinery.lib.scripts.ps1.deobfuscation import deobfuscate as ps1_deobfuscate
        from refinery.lib.scripts.ps1.model import Ps1ErrorNode
        from refinery.lib.scripts.ps1.parser import Ps1Parser
        from refinery.lib.scripts.ps1.synth import Ps1Synthesizer
        yield _Backend(
            'ps1',
            Ps1Parser,
            ps1_deobfuscate,
            Ps1Synthesizer,
            Ps1ErrorNode,
            keep_output='preserve_bare_output',
        )

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
        backends = {backend.name: backend for backend in self._backends()}
        guess = select_backend(data, [
            ScriptBackend(backend.name, backend.parser, backend.error)
            for backend in backends.values()
        ])
        if guess is None:
            raise ValueError('none of the available parsers was able to parse the input')
        self._backend = backends[guess.name]
        self.log_info(F'using {guess.name} with {guess.errors / len(data) * 100:.2f}% errors')
        return guess.tree

    def transform(self, ast: Node) -> int:
        keyword = self._backend.keep_output
        options = {} if keyword is None else {keyword: self.args.keep_output}
        return self._backend.deobfuscate(ast, **options)

    def synthesize(self, ast: Node) -> str:
        return self._backend.synthesizer().convert(ast)
