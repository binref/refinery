#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import re

from .. import arg, Unit
from ...lib.json import flattened


class ppjson(Unit):
    """
    Expects JSON input data and outputs it in a neatly formatted manner.
    If the indentation is set to zero, the output is minified.
    """
    _TRAILING_COMMA = re.compile(BR',\s*(}|])')

    def __init__(
        self,
        tabular: arg.switch('-t', group='OUT', help='Convert JSON input into a flattened table.') = False,
        indent : arg.number('-i', group='OUT', help='Number of spaces used for indentation. Default is {default}.') = 4
    ):
        return super().__init__(indent=indent, tabular=tabular)

    def _pretty_output(self, parsed, **kwargs):
        if self.args.tabular:
            table = list(flattened(parsed))
            width = max(len(key) for key, _ in table)
            for key, value in table:
                value = str(value).rstrip()
                yield F'{key:<{width}} : {value}'.encode(self.codec)
        else:
            yield json.dumps(parsed, **kwargs).encode(self.codec)

    def process(self, data):
        if self._TRAILING_COMMA.search(data):
            def smartfix(match):
                k = match.start()
                return match.group(0 if any(k in s for s in strings) else 1)
            from ...lib.patterns import formats
            strings = {range(*m.span()) for m in formats.string.finditer(data)}
            data = self._TRAILING_COMMA.sub(smartfix, data)
        kwargs = {'indent': self.args.indent} if self.args.indent else {'separators': (',', ':')}
        yield from self._pretty_output(json.loads(data), **kwargs)
