from __future__ import annotations

from refinery.lib.types import INF


def guess_language(data: str | bytearray | bytes | memoryview) -> str | None:
    """
    Try to parse the input as JavaScript, PowerShell, and VBA, then return the name of the language
    whose parser produces the fewest error nodes. Returns None when no parser can handle more than
    half of the input.
    """
    best_name: str | None = None
    best_errors = INF()

    from refinery.lib.scripts.js.model import JsErrorNode
    from refinery.lib.scripts.js.parser import JsParser
    from refinery.lib.scripts.ps1.model import Ps1ErrorNode
    from refinery.lib.scripts.ps1.parser import Ps1Parser
    from refinery.lib.scripts.vba.model import VbaErrorNode
    from refinery.lib.scripts.vba.parser import VbaParser

    backends = (
        ('ps1', Ps1Parser, Ps1ErrorNode),
        ('vba', VbaParser, VbaErrorNode),
        ('js', JsParser, JsErrorNode),
    )

    if not isinstance(data, str):
        import codecs
        data = codecs.decode(data, 'utf8', 'surrogateescape')

    for name, parser_type, error_type in backends:
        try:
            ast = parser_type(data).parse()
            errors = sum(
                len(n.text) for n in ast.walk() if isinstance(n, error_type))
        except Exception:
            continue
        if errors < best_errors:
            best_errors = errors
            best_name = name
            if errors == 0:
                break

    if best_name is None or best_errors * 2 > len(data):
        return None

    return best_name
