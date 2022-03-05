#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import operator
from typing import Any, Callable, Optional

from refinery.lib.meta import metavars
from refinery.lib.argformats import PythonExpression, ParserVariableMissing
from refinery.units.meta import arg, ConditionalUnit


class iff(ConditionalUnit):
    """
    Filter incoming chunks depending on whether a given Python expression evaluates to true. If no
    expression is given, the unit filters out empty chunks. If the expression cannot be parsed, the
    unit assumes that it is the name of a meta variable and filters out chunks where that variable
    is defined and evaluates to true.
    """
    def __init__(
        self,
        *expression: arg(metavar='token', type=str, help=(
            'All "token" arguments to this unit are joined with spaces to produce the expression '
            'to be evaluated. This is done so that unnecessary shell quoting is avoided.')),
        ge: arg('-ge', type=str, metavar='<right-hand-side>', group='OP',
            help='check that the expression is greater or equal to {varname}') = None,
        gt: arg('-gt', type=str, metavar='<right-hand-side>', group='OP',
            help='check that the expression is greater than {varname}') = None,
        le: arg('-le', type=str, metavar='<right-hand-side>', group='OP',
            help='check that the expression is less or equal to {varname}') = None,
        lt: arg('-lt', type=str, metavar='<right-hand-side>', group='OP',
            help='check that the expression is less than {varname}') = None,
        ct: arg('-in', type=str, metavar='<right-hand-side>', group='OP',
            help='check that the expression is contained in {varname}') = None,
        negate=False, temporary=False
    ):
        operators = [
            (ge, operator.__ge__),
            (gt, operator.__gt__),
            (le, operator.__le__),
            (lt, operator.__lt__),
            (ct, lambda a, b: operator.__contains__(b, a)),
        ]
        operators = [
            (rhs, cmp) for (rhs, cmp) in operators
            if rhs is not None
        ]
        rhs, cmp, lhs = None, None, '\x20'.join(expression)
        if len(operators) > 0:
            if not lhs:
                raise ValueError('Comparison operator with empty left hand side.')
            if len(operators) > 1:
                raise ValueError('Only one comparison operation can be specified.')
            rhs, cmp = operators[0]
        super().__init__(
            negate=negate,
            temporary=temporary,
            lhs=lhs,
            rhs=rhs,
            cmp=cmp,
        )

    def match(self, chunk):
        meta = metavars(chunk)
        lhs: Optional[str] = self.args.lhs
        rhs: Optional[str] = self.args.rhs
        cmp: Optional[Callable[[Any, Any], bool]] = self.args.cmp
        try:
            lhs = lhs and PythonExpression.evaluate(lhs, meta)
        except ParserVariableMissing:
            return lhs in meta
        rhs = rhs and PythonExpression.evaluate(rhs, meta)
        if lhs is None:
            return bool(chunk)
        if rhs is None:
            return bool(lhs)
        return cmp(lhs, rhs)
