"""
The one constant evaluator: the value an expression provably holds, over the operator tables of
`refinery.lib.scripts.au3.analysis.values` and the builtin table of
`refinery.lib.scripts.au3.analysis.builtins`, under a bound the caller chooses.

Three policies share it, one `Policy` each. The fold asks unbounded, because what the source
already spells is already in the tree. The propagation walk asks with its payload bound,
because a value it proves enters its state and may be spelled at every read of the name —
before this module, the walk bound a variable only to a shape the fold leaves behind, so every
literal the fold revealed was consumed by a later pass, one rewrite per full traversal and model
rebuild. The interpreter asks with its own payload bound and a call hook, because a call inside
a body it runs may reach a script function no builtin table owns.

A literal shape is never bounded — what the source spells is already in the tree — so the
walk's recording gate, not the evaluator, keeps an oversized literal out of the values it hands
on. The bound itself is complete over the domain: a string and a binary count their payload, an
array its element count and the recursive payload of its elements, so no kind grows past a bound
the string case closed.

Every policy carries a memo of literal attempts, alive exactly as long as the tree it was
computed over stands: the fold asks the evaluator once per node bottom-up, so a chain nothing
proves pays its literal descent once instead of once per level above it.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import cast

from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.builtins import EMULATED_NAMES, evaluate_builtin
from refinery.lib.scripts.au3.analysis.values import (
    Au3Value,
    Kind,
    apply_binary,
    apply_unary,
    compare,
    literal_value,
    of_bool,
    truthy,
)
from refinery.lib.scripts.au3.model import (
    Au3BinaryExpression,
    Au3Call,
    Au3Ternary,
    Au3UnaryExpression,
    Au3Variable,
    Expression,
)

#: The value a variable read holds where it stands, or `None` when the caller's environment
#: proves none.
Lookup = Callable[[str], Au3Value | None]

#: The value of a call the builtin table does not own — the interpreter's script functions — over
#: already-evaluated arguments, or `None` when the caller refuses the call.
CallHook = Callable[[str, tuple[Au3Value, ...]], Au3Value | None]

#: The value of a subexpression the evaluator owns no rule for — the interpreter's assignments,
#: array accesses, and array literals — or `None` when the caller refuses it.
Fallback = Callable[[Expression], Au3Value | None]

_COMPARISONS = frozenset(('=', '==', '<>', '<', '>', '<=', '>='))


@dataclass
class Policy:
    """
    The question one caller asks: the functions the script declares — a script function shadows
    the builtin of the same name — the lookup that answers a variable read, the payload bound, the
    hook that owns a call the builtin table does not, the fallback for the shapes only the caller
    holds, and the memo of literal attempts, alive exactly as long as the tree it is computed
    over stands.
    """

    functions: frozenset[str]
    lookup: Lookup | None = None
    limit: int | None = None
    call: CallHook | None = None
    fallback: Fallback | None = None
    literals: dict[Expression, Au3Value | None] = field(default_factory=dict)


def constant_value(expression: Expression | None, policy: Policy) -> Au3Value | None:
    """
    The value *expression* provably holds under *policy*, or `None` when nothing does: a literal
    shape, read back uncapped; a variable read through the policy's lookup, within its bound; an
    operator over proven operands; a ternary over a proven condition, evaluating its chosen
    branch alone (probe4 66, 67); or a call — the builtin table's answer when the policy carries
    no hook, refusing a name a script function shadows because the shadow would run foreign
    code, and the hook's otherwise. A shape none of these owns is the policy's fallback's, when
    one is given.

    `And`/`Or` answer their decided side alone once the left operand decides, because AutoIt
    never runs the right side there (probe4 60, 61). Every operator comes from the value tables,
    which refuse each unpinned case; `&`, the one operator whose result grows with its operands,
    refuses over the bound, and so does a builtin's result.
    """
    value = literal_value(expression, policy.functions, policy.literals)
    if value is not None:
        return value
    node = ast.unwrap_parens(expression)
    if isinstance(node, Au3Variable):
        if policy.lookup is None:
            return None
        value = policy.lookup(node.name)
        if value is None or not within_limit(value, policy.limit):
            return None
        return value
    if isinstance(node, Au3UnaryExpression):
        operand = constant_value(node.operand, policy)
        if operand is None:
            return None
        return apply_unary(node.operator, operand)
    if isinstance(node, Au3BinaryExpression):
        return _binary_value(node, policy)
    if isinstance(node, Au3Ternary):
        return _ternary_value(node, policy)
    if isinstance(node, Au3Call):
        return _call_value(node, policy)
    if not isinstance(node, Expression) or policy.fallback is None:
        return None
    return policy.fallback(node)


def within_limit(value: Au3Value, limit: int | None) -> bool:
    """
    Whether *value* stays within *limit*: a string and a binary by payload length, an array by
    its element count and the recursive payload of its elements, and every other kind by being
    scalar. `None` is no limit.
    """
    if limit is None:
        return True
    if value.kind in (Kind.STRING, Kind.BINARY):
        return len(cast(str | bytes, value.payload)) <= limit
    if value.kind is Kind.ARRAY:
        elements = cast(tuple[Au3Value, ...], value.payload)
        return (
            len(elements) <= limit
            and sum(_payload_size(element) for element in elements) <= limit
        )
    return True


def combine(
    operator: str,
    left: Au3Value,
    right: Au3Value,
    limit: int | None,
) -> Au3Value | None:
    """
    The result of one binary operator over two known values, or `None` where the operator is
    refused or an operand or the result leaves *limit*: the step a compound assignment takes,
    where both operands are values a state already holds, so a combination past the bound cannot
    grow the state further.
    """
    if not within_limit(left, limit) or not within_limit(right, limit):
        return None
    result = apply_binary(operator, left, right)
    if result is None or not within_limit(result, limit):
        return None
    return result


def _payload_size(value: Au3Value) -> int:
    if value.kind in (Kind.STRING, Kind.BINARY):
        return len(cast(str | bytes, value.payload))
    if value.kind is Kind.ARRAY:
        return sum(_payload_size(element) for element in cast(tuple[Au3Value, ...], value.payload))
    return 0


def _binary_value(node: Au3BinaryExpression, policy: Policy) -> Au3Value | None:
    if node.left is None or node.right is None:
        return None
    if node.operator in ('and', 'or'):
        left = constant_value(node.left, policy)
        if left is None:
            return None
        verdict = truthy(left)
        if verdict is None:
            return None
        if node.operator == 'and' and not verdict:
            return of_bool(False)
        if node.operator == 'or' and verdict:
            return of_bool(True)
        right = constant_value(node.right, policy)
        if right is None:
            return None
        return apply_binary(node.operator, left, right)
    left = constant_value(node.left, policy)
    right = constant_value(node.right, policy)
    if left is None or right is None:
        return None
    if node.operator in _COMPARISONS:
        return compare(node.operator, left, right)
    result = apply_binary(node.operator, left, right)
    if result is None or not within_limit(result, policy.limit):
        return None
    return result


def _ternary_value(node: Au3Ternary, policy: Policy) -> Au3Value | None:
    condition = constant_value(node.condition, policy)
    if condition is None:
        return None
    verdict = truthy(condition)
    if verdict is None:
        return None
    branch = node.consequent if verdict else node.alternate
    return constant_value(branch, policy)


def _call_value(node: Au3Call, policy: Policy) -> Au3Value | None:
    callee = ast.direct_callee(node)
    if callee is None:
        return None
    if (
        policy.call is None
        and (callee.name in policy.functions or callee.name not in EMULATED_NAMES)
    ):
        return None
    arguments = []
    for argument in node.arguments:
        value = constant_value(argument, policy)
        if value is None:
            return None
        arguments.append(value)
    result = (
        policy.call(callee.name, tuple(arguments))
        if policy.call is not None
        else evaluate_builtin(callee.name, tuple(arguments))
    )
    if result is None or not within_limit(result, policy.limit):
        return None
    return result
