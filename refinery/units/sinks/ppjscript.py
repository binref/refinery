#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import jsbeautifier

from .. import arg, Unit
from ...lib.decorators import unicoded


class ppjscript(Unit):
    """
    Pretty-prints JavaScript without any reflection or evaluation.
    """
    def __init__(self, indent: arg.number('-i', help=(
        'Controls the amount of space characters used for indentation in the output. Default is 4.')) = 4
    ):
        return super().__init__(indent=indent)

    @unicoded
    def process(self, data: str) -> str:
        return jsbeautifier.beautify(data, dict(
            eval_code=False,
            indent_size=self.args.indent
        ))
