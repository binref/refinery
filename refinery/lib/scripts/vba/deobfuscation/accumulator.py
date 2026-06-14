"""
VBA string accumulator folding: collapses chains of consecutive assignments that build a string
via concatenation and builtin transforms into a single assignment.
"""
from __future__ import annotations

from refinery.lib.scripts import Expression, Transformer
from refinery.lib.scripts.vba.deobfuscation.helpers import (
    apply_removals,
    body_lists,
    constant_args,
    make_string_literal,
    module_compare_mode,
    string_value,
)
from refinery.lib.scripts.vba.deobfuscation.names import CompareMode, Value, dispatch_builtin
from refinery.lib.scripts.vba.model import (
    VbaBinaryExpression,
    VbaCallExpression,
    VbaIdentifier,
    VbaLetStatement,
    VbaModule,
    VbaStringLiteral,
)


def _combine_surrogates_at_boundary(left: str, right: str) -> str:
    if not left or not right:
        return left + right
    hi = ord(left[-1])
    lo = ord(right[0])
    if 0xD800 <= hi <= 0xDBFF and 0xDC00 <= lo <= 0xDFFF:
        combined = chr(0x10000 + (hi - 0xD800) * 0x400 + (lo - 0xDC00))
        return left[:-1] + combined + right[1:]
    return left + right


def _try_concat_step(expr: Expression | None, var_key: str, accumulator: str) -> tuple[str, int] | None:
    if not isinstance(expr, VbaBinaryExpression):
        return None
    if expr.operator not in ('&', '+'):
        return None
    parts: list[str] = []
    node = expr
    while isinstance(node, VbaBinaryExpression) and node.operator in ('&', '+'):
        rhs = string_value(node.right)
        if rhs is None:
            break
        parts.append(rhs)
        node = node.left
    if isinstance(node, VbaIdentifier) and node.name.lower() == var_key and parts:
        parts.reverse()
        literal = ''.join(parts)
        return _combine_surrogates_at_boundary(accumulator, literal), len(literal)
    if isinstance(expr.right, VbaIdentifier) and expr.right.name.lower() == var_key:
        lhs = string_value(expr.left)
        if lhs is not None:
            return _combine_surrogates_at_boundary(lhs, accumulator), len(lhs)
    return None


def _try_builtin_step(
    expr: Expression | None, var_key: str, accumulator: str, compare_mode: CompareMode,
) -> str | None:
    if not isinstance(expr, VbaCallExpression):
        return None
    if not isinstance(expr.callee, VbaIdentifier):
        return None
    args = expr.arguments
    if not args:
        return None
    first_arg = args[0]
    if not isinstance(first_arg, VbaIdentifier):
        return None
    if first_arg.name.lower() != var_key:
        return None
    rest = constant_args(args[1:])
    if rest is None:
        return None
    literal_args: list[Value] = [accumulator, *rest]
    name = expr.callee.name.lower()
    try:
        matched, result = dispatch_builtin(name, literal_args, compare_mode)
    except (ValueError, OverflowError, TypeError, IndexError):
        return None
    if not matched:
        return None
    if not isinstance(result, str):
        return None
    return result


def _try_apply_step(
    stmt: VbaLetStatement, var_key: str, accumulator: str, compare_mode: CompareMode,
) -> tuple[str, int] | None:
    """
    Attempt to fold one chain step. Returns (new_accumulator, input_bytes_consumed) on success.
    """
    expr = stmt.value
    result = _try_concat_step(expr, var_key, accumulator)
    if result is not None:
        return result
    builtin_result = _try_builtin_step(expr, var_key, accumulator, compare_mode)
    if builtin_result is not None:
        assert isinstance(expr, VbaCallExpression)
        input_bytes = sum(
            len(n.value) for n in expr.walk() if isinstance(n, VbaStringLiteral)
        )
        return builtin_result, input_bytes
    return None


class VbaStringAccumulatorFolding(Transformer):
    """
    Collapse chains of consecutive assignments that build a string via concatenation and builtin
    transforms into a single assignment.
    """

    def __init__(self, max_growth: float = 0.2):
        super().__init__()
        self.max_growth = max_growth

    def visit(self, node):
        if isinstance(node, VbaModule):
            if self._fold_accumulators(node):
                self.mark_changed()
        return None

    def _fold_accumulators(self, module: VbaModule) -> bool:
        compare_mode = module_compare_mode(module)
        total_string_size = sum(
            len(n.value) for n in module.walk() if isinstance(n, VbaStringLiteral)
        )
        budget = int(total_string_size * self.max_growth)
        net_growth = 0
        removals: list[tuple[int, list]] = []
        changed = False
        for body in body_lists(module):
            i = 0
            while i < len(body):
                stmt = body[i]
                if not isinstance(stmt, VbaLetStatement):
                    i += 1
                    continue
                if not isinstance(stmt.target, VbaIdentifier):
                    i += 1
                    continue
                initial = string_value(stmt.value)
                if initial is None:
                    i += 1
                    continue
                var_key = stmt.target.name.lower()
                accumulator = initial
                input_size = len(initial)
                chain_start = i
                chain_end = i
                j = i + 1
                while j < len(body):
                    next_stmt = body[j]
                    if not isinstance(next_stmt, VbaLetStatement):
                        break
                    if not isinstance(next_stmt.target, VbaIdentifier):
                        break
                    if next_stmt.target.name.lower() != var_key:
                        break
                    step = _try_apply_step(next_stmt, var_key, accumulator, compare_mode)
                    if step is None:
                        break
                    accumulator, step_input = step
                    input_size += step_input
                    chain_end = j
                    j += 1
                if chain_end > chain_start:
                    growth = len(accumulator) - input_size
                    if net_growth + growth <= budget:
                        net_growth += growth
                        new_literal = make_string_literal(accumulator)
                        body[chain_end].value = new_literal
                        new_literal.parent = body[chain_end]
                        for k in range(chain_start, chain_end):
                            removals.append((k, body))
                        changed = True
                    i = chain_end + 1
                else:
                    i += 1
        if apply_removals(removals):
            changed = True
        return changed
