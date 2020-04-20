#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import re

from .. import arg, Unit
from ...lib.decorators import unicoded


class ppjson(Unit):
    """
    Expects JSON input data and outputs it in a neatly formatted manner.
    If the indentation is set to zero, the output is minified.
    """
    _TRAILING_COMMA = re.compile(R',\s*(}|])')

    def __init__(self, indent: arg.number('-i', help=(
        'Controls the amount of space characters used for indentation in the output. Default is 4.')) = 4
    ):
        return super().__init__(indent=indent)

    @unicoded
    def process(self, data: str) -> str:
        if self._TRAILING_COMMA.search(data):
            from ...lib.patterns import formats

            strings = {
                range(*m.span())
                for m in re.finditer(formats.string.pattern, data)
            }

            def smartfix(match):
                k = match.start()
                return match.group(0 if any(k in s for s in strings) else 1)

            data = self._TRAILING_COMMA.sub(smartfix, data)

        kwargs = dict(indent=self.args.indent)
        if not self.args.indent:
            kwargs.update(separators=(',', ':'))
        data = json.dumps(json.loads(data), **kwargs)
        return data if self.args.indent else data.replace('\n', '')
