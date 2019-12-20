#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import re

from .. import Unit
from ...lib.decorators import unicoded
from ...lib.argformats import number


class ppjson(Unit):
    """
    Expects JSON input data and outputs it in a neatly formatted manner.
    """
    _TRAILING_COMMA = R',\s*(}|])'

    def interface(self, argp):
        argp.add_argument('-i', '--indent', type=number, default=4,
            help='Controls the amount of space characters used for indentation in the output. Default is 4.')
        return super().interface(argp)

    @unicoded
    def process(self, data: str) -> str:
        if re.search(self._TRAILING_COMMA, data):
            from ...lib.patterns import formats

            strings = {
                range(*m.span())
                for m in re.finditer(formats.string.pattern, data)
            }

            def smartfix(match):
                k = match.start()
                return match.group(0 if any(k in s for s in strings) else 1)

            data = re.sub(self._TRAILING_COMMA, smartfix, data)

        return json.dumps(json.loads(data), indent=self.args.indent)
