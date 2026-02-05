from __future__ import annotations

import re

from refinery.lib import json
from refinery.units.formats import JSONTableUnit


class ppjson(JSONTableUnit):
    """
    Expects JSON input data and outputs it in a neatly formatted manner.
    If the indentation is set to zero, the output is minified.
    """
    _TRAILING_COMMA = re.compile(BR',\s*(}|])')

    def json(self, data):
        if self._TRAILING_COMMA.search(data):
            def smartfix(match: re.Match[bytes]):
                k = match.start()
                return match.group(0 if any(k in s for s in strings) else 1)
            from refinery.lib.patterns import formats
            strings = {range(*m.span()) for m in formats.str.value.finditer(data)}
            data = self._TRAILING_COMMA.sub(smartfix, data)
        return json.loads(data)
