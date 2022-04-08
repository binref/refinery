#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import operator
from typing import Any, Callable, Optional

from refinery.lib.meta import metavars
from refinery.lib.argformats import DelayedNumSeqArgument, PythonExpression, ParserVariableMissing
from refinery.units.meta import Arg, ConditionalUnit


class iff(ConditionalUnit):
    """
    Filter incoming chunks depending on whether a given Python expression evaluates to true. If no
    expression is given, the unit filters out empty chunks. If the expression cannot be parsed, the
    unit assumes that it is the name of a meta variable and filters out chunks where that variable
    is defined and evaluates to true.
    """
    def __init__(
        self,
        *expression: Arg(metavar='token', type=str, help=(
            'All "token" arguments to this unit are joined with spaces to produce the expression '
            'to be evaluated. This is done so that unnecessary shell quoting is avoided.')),
        ge: Arg('-ge', type=str, metavar='<right-hand-side>', group='OP',
            help='check that the expression is greater or equal to {varname}') = None,
        gt: Arg('-gt', type=str, metavar='<right-hand-side>', group='OP',
            help='check that the expression is greater than {varname}') = None,
        le: Arg('-le', type=str, metavar='<right-hand-side>', group='OP',
            help='check that the expression is less or equal to {varname}') = None,
        lt: Arg('-lt', type=str, metavar='<right-hand-side>', group='OP',
            help='check that the expression is less than {varname}') = None,
        iN: Arg('-in', type=str, metavar='<right-hand-side>', group='OP',
            help='check that the expression is contained in {varname}') = None,
        ct: Arg('-ct', type=str, metavar='<right-hand-side>', group='OP',
            help='check that the expression contains {varname}') = None,
        eq: Arg('-eq', type=str, metavar='<right-hand-side>', group='OP',
            help='check that the expression is equal to {varname}') = None,
        negate=False, temporary=False
    ):
        operators = [
            (ge, operator.__ge__),
            (gt, operator.__gt__),
            (le, operator.__le__),
            (lt, operator.__lt__),
            (eq, None),
            (ct, operator.__contains__),
            (iN, lambda a, b: operator.__contains__(b, a)),
        ]
        operators = [
            (rhs, cmp) for (rhs, cmp) in operators
            if rhs is not None
        ]
        rhs, cmp, lhs = None, None, '\x20'.join(expression) or None
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
        rhs: Optional[Any] = self.args.rhs
        cmp: Optional[Callable[[Any, Any], bool]] = self.args.cmp
        try:
            lhs = lhs and PythonExpression.evaluate(lhs, meta)
        except ParserVariableMissing:
            return lhs in meta
        if cmp is None and rhs is not None:
            rhs = DelayedNumSeqArgument(rhs)(chunk)
            return lhs == rhs
        try:
            rhs = rhs and PythonExpression.evaluate(rhs, meta)
        except ParserVariableMissing:
            raise
        except Exception:
            rhs = rhs.encode(self.codec)
        if lhs is None:
            return bool(chunk)
        if rhs is None:
            return bool(lhs)
        return cmp(lhs, rhs)
