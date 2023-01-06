#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import re
import textwrap

from refinery.units import Arg, Unit
from refinery.lib.json import flattened
from refinery.lib.tools import get_terminal_size


class ppjson(Unit):
    """
    Expects JSON input data and outputs it in a neatly formatted manner.
    If the indentation is set to zero, the output is minified.
    """
    _TRAILING_COMMA = re.compile(BR',\s*(}|])')

    def __init__(
        self,
        tabular: Arg.Switch('-t', group='OUT', help='Convert JSON input into a flattened table.') = False,
        indent : Arg.Number('-i', group='OUT', help='Number of spaces used for indentation. Default is {default}.') = 4
    ):
        return super().__init__(indent=indent, tabular=tabular)

    def _pretty_output(self, parsed, **kwargs):
        if self.args.tabular:
            table = list(flattened(parsed))
            width = max(len(key) for key, _ in table)
            tsize = get_terminal_size(80) - width - 4
            for key, value in table:
                value = str(value).rstrip()
                value = textwrap.wrap(value, tsize)
                it = iter(value)
                try:
                    item = next(it)
                except StopIteration:
                    continue
                yield F'{key:<{width}} : {item}'.encode(self.codec)
                for wrap in it:
                    yield F'{"":<{width+3}}{wrap}'.encode(self.codec)
        else:
            yield json.dumps(parsed, **kwargs).encode(self.codec)

    def process(self, data):
        if self._TRAILING_COMMA.search(data):
            def smartfix(match):
                k = match.start()
                return match.group(0 if any(k in s for s in strings) else 1)
            from refinery.lib.patterns import formats
            strings = {range(*m.span()) for m in formats.string.finditer(data)}
            data = self._TRAILING_COMMA.sub(smartfix, data)
        kwargs = {'indent': self.args.indent} if self.args.indent else {'separators': (',', ':')}
        yield from self._pretty_output(json.loads(data), **kwargs)
