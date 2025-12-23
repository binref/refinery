from __future__ import annotations

import re
import textwrap
import unicodedata

from refinery.lib import json
from refinery.lib.tools import get_terminal_size
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


def is_printable(s: str):
    return all(unicodedata.category(c)[0] != 'C' for c in s)


class ppjson(Unit):
    """
    Expects JSON input data and outputs it in a neatly formatted manner.
    If the indentation is set to zero, the output is minified.
    """
    _TRAILING_COMMA = re.compile(BR',\s*(}|])')

    def __init__(
        self,
        tabular: Param[bool, Arg.Switch('-t', group='OUT',
            help='Convert JSON input into a flattened table.')] = False,
        minimal: Param[bool, Arg.Switch('-m', group='OUT',
            help='Minify the JSON output instead of pretty-printing.')] = False,
    ):
        return super().__init__(tabular=tabular, minimal=minimal)

    def _pretty_output(self, parsed, pretty=True):
        encoded = json.dumps(parsed, pretty=pretty)
        if self.args.tabular:
            table = list(json.flattened(json.loads(encoded)))
            width = max(len(key) for key, _ in table)
            tsize = get_terminal_size(80) - width - 4
            for key, value in table:
                if isinstance(value, str):
                    value = value.strip()
                    if not is_printable(value) and all(ord(c) < 0x100 for c in value):
                        value = value.encode('latin1').hex(':')
                value = str(value).rstrip()
                value = textwrap.wrap(value, tsize)
                it = iter(value)
                try:
                    item = next(it)
                except StopIteration:
                    continue
                yield F'{key:<{width}} : {item}'.encode(self.codec)
                for wrap in it:
                    yield F'{"":<{width + 3}}{wrap}'.encode(self.codec)
        else:
            yield encoded

    def process(self, data: buf):
        if self._TRAILING_COMMA.search(data):
            def smartfix(match: re.Match[bytes]):
                k = match.start()
                return match.group(0 if any(k in s for s in strings) else 1)
            from refinery.lib.patterns import formats
            strings = {range(*m.span()) for m in formats.str.value.finditer(data)}
            data = self._TRAILING_COMMA.sub(smartfix, data)
        yield from self._pretty_output(
            json.loads(data), pretty=not self.args.minimal)
