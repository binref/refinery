#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import shlex

from ...lib.argformats import PythonExpression
from . import arg, ConditionalUnit


class ifexpr(ConditionalUnit):
    """
    Filter incoming chunks depending on whether a given Python expression evaluates
    to true.
    """
    def __init__(self, *expression: arg(help='A', type=str), negate=False):
        expression = ' '.join(shlex.quote(token) for token in expression)
        super().__init__(expression=expression, negate=negate)

    def match(self, chunk):
        return bool(PythonExpression.evaluate(self.args.expression, **getattr(chunk, 'meta', {})))
