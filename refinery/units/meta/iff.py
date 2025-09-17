from __future__ import annotations

import operator

from typing import Any, Callable

from refinery.lib.argformats import DelayedNumSeqArgument, PythonExpression
from refinery.lib.meta import metavars
from refinery.lib.types import Param
from refinery.units.meta import Arg, ConditionalUnit


class iff(ConditionalUnit, docs='{0}{p}{1}'):
    """
    Filter incoming chunks depending on whether a given Python expression evaluates to true. If no
    expression is given, the unit filters out empty chunks.
    """
    def __init__(
        self,
        *expression: Param[str, Arg.String(metavar='token', help=(
            'All "token" arguments to this unit are joined with spaces to produce the expression '
            'to be evaluated. This is done so that unnecessary shell quoting is avoided.'))],
        ge: Param[str, Arg.String('-ge', metavar='RHS', group='OP',
            help='check that the expression is greater or equal to {varname}')] = None,
        gt: Param[str, Arg.String('-gt', metavar='RHS', group='OP',
            help='check that the expression is greater than {varname}')] = None,
        le: Param[str, Arg.String('-le', metavar='RHS', group='OP',
            help='check that the expression is less or equal to {varname}')] = None,
        lt: Param[str, Arg.String('-lt', metavar='RHS', group='OP',
            help='check that the expression is less than {varname}')] = None,
        ct: Param[str, Arg.String('-ct', metavar='RHS', group='OP',
            help='check that the expression contains {varname}')] = None,
        ne: Param[str, Arg.String('-ne', metavar='RHS', group='OP',
            help='check that the expression is equal to {varname}')] = None,
        iN: Param[str, Arg.String('-in', metavar='RHS', group='OP',
            help='check that the expression is contained in {varname}')] = None,
        eq: Param[str, Arg.String('-eq', metavar='RHS', group='OP',
            help='check that the expression is equal to {varname}')] = None,
        retain=False,
    ):
        def encodings(v: str):
            if not isinstance(v, str):
                return
            for codec in [self.codec, 'latin1', 'utf-16le']:
                yield v.encode(codec)

        def __br_contains__(container, value):
            if value in container:
                return True
            if isinstance(value, str):
                return any(b in container for b in encodings(value))
            else:
                return any(value == b for v in container for b in encodings(v))

        operators = [
            (ge, operator.__ge__),
            (gt, operator.__gt__),
            (le, operator.__le__),
            (lt, operator.__lt__),
            (eq, operator.__eq__),
            (ne, operator.__ne__),
            (ct, __br_contains__),
            (iN, lambda a, b: __br_contains__(b, a)),
        ]

        operators = [
            (rhs, cmp)
            for (rhs, cmp) in operators
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
            lhs=lhs,
            rhs=rhs,
            cmp=cmp,
            retain=retain,
        )

    def match(self, chunk):
        meta = metavars(chunk)
        lhs: str | None = self.args.lhs
        rhs: Any | None = self.args.rhs
        cmp: Callable[[Any, Any], bool] | None = self.args.cmp

        if cmp is None and rhs is not None:
            raise ValueError('right hand side defined but no operator')

        if lhs is not None:
            if rhs is not None:
                lhs = DelayedNumSeqArgument(lhs, additional_types=(float, str))(chunk)
            else:
                lhs = PythonExpression.Evaluate(lhs, meta)

        rhs = rhs and DelayedNumSeqArgument(rhs, additional_types=(float, str))(chunk)

        self.log_info(F'lhs: type={lhs.__class__.__name__}; value={lhs!r}')
        self.log_info(F'rhs: type={rhs.__class__.__name__}; value={rhs!r}')

        if lhs is None:
            return bool(chunk)
        if rhs is None:
            return bool(lhs)

        return cmp(lhs, rhs)
