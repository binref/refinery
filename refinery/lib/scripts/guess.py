from __future__ import annotations

from typing import TYPE_CHECKING, Iterable, NamedTuple

if TYPE_CHECKING:
    from refinery.lib.scripts import Node
    from refinery.lib.scripts.js.model import JsErrorNode
    from refinery.lib.scripts.js.parser import JsParser
    from refinery.lib.scripts.ps1.model import Ps1ErrorNode
    from refinery.lib.scripts.ps1.parser import Ps1Parser
    from refinery.lib.scripts.vba.model import VbaErrorNode
    from refinery.lib.scripts.vba.parser import VbaParser

    ScriptParser = type[JsParser] | type[Ps1Parser] | type[VbaParser]
    ScriptError = type[JsErrorNode] | type[Ps1ErrorNode] | type[VbaErrorNode]


class ScriptBackend(NamedTuple):
    """
    One parser to try on input whose language is unknown: the name of the language it reads, the
    parser class, and the node type that parser builds for a span of source no rule of its grammar
    could read.
    """
    name: str
    parser: ScriptParser
    error: ScriptError


class ScriptGuess(NamedTuple):
    """
    The backend that read the input best: the name of its language, the tree it built, and the
    number of characters its grammar could not read.
    """
    name: str
    tree: Node
    errors: int


def select_backend(data: str, backends: Iterable[ScriptBackend]) -> ScriptGuess | None:
    """
    Parse `data` with each of the `backends` in turn and return the one that left the fewest
    characters of the input unread, or `None` when even that one could not read more than half of
    it. A backend that reads every character wins immediately and the ones behind it are not tried,
    so the order they are given in decides an input that more than one of them reads without error.

    Only unread source is counted, and only up to the end of the file. A file that was cut off
    ends in the middle of some construct for every grammar alike, so neither a construct the cut
    left open nor the text a grammar could not read because the file stopped inside it says
    anything about which language the file is written in, and neither is scored.
    """
    best: ScriptGuess | None = None

    for name, parser_type, error_type in backends:
        try:
            tree = parser_type(data).parse()
            errors = sum(
                len(node.text)
                for node in tree.walk()
                if isinstance(node, error_type)
                and node.offset + len(node.text) < len(data)
            )
        except Exception:
            continue
        if best is None or errors < best.errors:
            best = ScriptGuess(name, tree, errors)
            if errors == 0:
                break

    if best is None or best.errors * 2 > len(data):
        return None

    return best


def guess_language(data: str | bytearray | bytes | memoryview) -> str | None:
    """
    Try to parse the input as JavaScript, PowerShell, and VBA, then return the name of the language
    whose parser leaves the fewest characters of it unread. Returns `None` when no parser can read
    more than half of the input.

    The count only separates the languages once the input is long enough for them to disagree about
    it. All three grammars read a script of a few lines without a single error — a `Sub`/`End Sub`
    block, a `var` declaration and a `Write-Host` call are each accepted by all three — so for a
    short input nothing but the order of the backends decides, and PowerShell, the language this
    tool exists for, is asked first.
    """
    from refinery.lib.scripts.js.model import JsErrorNode
    from refinery.lib.scripts.js.parser import JsParser
    from refinery.lib.scripts.ps1.model import Ps1ErrorNode
    from refinery.lib.scripts.ps1.parser import Ps1Parser
    from refinery.lib.scripts.vba.model import VbaErrorNode
    from refinery.lib.scripts.vba.parser import VbaParser

    backends = (
        ScriptBackend('ps1', Ps1Parser, Ps1ErrorNode),
        ScriptBackend('vba', VbaParser, VbaErrorNode),
        ScriptBackend('js', JsParser, JsErrorNode),
    )

    if not isinstance(data, str):
        import codecs
        data = codecs.decode(data, 'utf8', 'surrogateescape')

    guess = select_backend(data, backends)
    return None if guess is None else guess.name
