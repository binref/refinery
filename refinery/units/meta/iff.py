#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ...lib.meta import metavars
from ...lib.argformats import PythonExpression
from . import arg, ConditionalUnit


class iff(ConditionalUnit):
    """
    Filter incoming chunks depending on whether a given Python expression evaluates
    to true.
    """
    def __init__(
        self,
        *expression: arg(metavar='token', type=str, help=(
            'All "token" arguments to this unit are joined with spaces to produce the expression to be '
            'evaluated. This is done so that unnecessary shell quoting is avoided.')),
        negate=False, temporary=False
    ):
        super().__init__(negate=negate, temporary=temporary, expression=' '.join(expression))

    def match(self, chunk):
        return bool(PythonExpression.evaluate(self.args.expression, metavars(chunk)))