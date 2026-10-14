"""
AutoIt3 operator precedence and parenthesization rules.

The levels follow the official AutoIt operator table
(autoitscript.com/autoit3/docs/intro/lang_operators.htm), which reads, tightest first: `Not` and
unary `+`/`-`; `^`; `*` and `/`; `+` and `-`; `&`; the comparisons as one tier; the ternary `?`;
and `And`/`Or` sharing one tier evaluated left to right. Assignment binds loosest of all and
exists only in statement position. The table deliberately deviates from the reference parsers
(`autoit3-pegjs`, yaad, and the AutoIt deobfuscator grammar all put the ternary loosest and split
`And` from `Or`); the synthesizer does not depend on `Au3ParenExpression` nodes for correctness:
it consults `needs_parens` to decide, from operator precedence, whether a child expression must
be wrapped in its parent context.
"""
from __future__ import annotations

from refinery.lib.scripts import Node
from refinery.lib.scripts.au3.model import (
    Au3ArrayAccess,
    Au3ArrayLiteral,
    Au3Assignment,
    Au3BinaryExpression,
    Au3Call,
    Au3MemberAccess,
    Au3ParenExpression,
    Au3Ternary,
    Au3UnaryExpression,
    Au3Variable,
    Au3WithMember,
)

_BINARY_PRECEDENCE = {
    'or'  : 2,  # noqa
    'and' : 2,  # noqa
    '?'   : 4,  # noqa
    '='   : 6,  # noqa
    '=='  : 6,  # noqa
    '<>'  : 6,  # noqa
    '<'   : 6,  # noqa
    '>'   : 6,  # noqa
    '<='  : 6,  # noqa
    '>='  : 6,  # noqa
    '&'   : 8,  # noqa
    '+'   : 10, # noqa
    '-'   : 10, # noqa
    '*'   : 12, # noqa
    '/'   : 12, # noqa
    '^'   : 14, # noqa
}

_ASSIGN_PRECEDENCE = 1
_UNARY_PRECEDENCE = 16
_PRIMARY_PRECEDENCE = 100


def _expression_precedence(node: Node) -> int:
    """
    The operator precedence of *node* on the scale used by `parens_required`. Primary
    expressions (variables, macros, identifiers, literals, calls, member and array access) return
    a value high enough that they never need parenthesization.
    """
    if isinstance(node, Au3BinaryExpression):
        return _BINARY_PRECEDENCE.get(node.operator, 0)
    if isinstance(node, Au3UnaryExpression):
        return _UNARY_PRECEDENCE
    if isinstance(node, Au3Ternary):
        return _BINARY_PRECEDENCE['?']
    if isinstance(node, Au3Assignment):
        return _ASSIGN_PRECEDENCE
    return _PRIMARY_PRECEDENCE


def _is_primary_receiver(node: Node) -> bool:
    """
    Whether *node* may sit as the receiver, callee, or member of a member access, call, or array
    access without parentheses. Any operator expression in such a position would rebind and must
    keep its parentheses.
    """
    return _expression_precedence(node) >= _PRIMARY_PRECEDENCE


def parens_required(inner: Node, parent: Node | None, paren_node: Node) -> bool:
    """
    Whether *paren_node* (positioned within *parent*, wrapping *inner*) must be parenthesized to
    preserve the program's meaning. *paren_node* is the node actually occupying the slot in
    *parent*; *inner* is the expression whose precedence is examined. When the two are identical
    the question is simply whether *inner* needs parentheses in *parent* — see `needs_parens`.
    """
    if parent is None:
        return False
    inner_p = _expression_precedence(inner)
    if isinstance(parent, Au3BinaryExpression):
        outer_p = _BINARY_PRECEDENCE.get(parent.operator, 0)
        if inner_p > outer_p:
            return False
        if inner_p < outer_p:
            return True
        return parent.right is paren_node
    if isinstance(parent, Au3UnaryExpression):
        return inner_p < _UNARY_PRECEDENCE
    if isinstance(parent, Au3Ternary):
        return inner_p <= _BINARY_PRECEDENCE['?']
    if isinstance(parent, Au3Assignment):
        if parent.target is paren_node:
            return False
        return inner_p < _ASSIGN_PRECEDENCE
    if isinstance(parent, (Au3MemberAccess, Au3WithMember)):
        if getattr(parent, 'object', None) is paren_node:
            return not _is_primary_receiver(inner)
        return False
    if isinstance(parent, Au3ArrayAccess):
        if parent.array is paren_node:
            return not _is_primary_receiver(inner)
        return False
    if isinstance(parent, Au3Call):
        if parent.callee is paren_node:
            return not _is_primary_receiver(inner)
        return False
    if isinstance(parent, Au3ArrayLiteral):
        return False
    return False


def needs_parens(child: Node, parent: Node | None) -> bool:
    """
    Whether *child*, which currently occupies a slot in *parent*, must be wrapped in parentheses
    to preserve precedence. Used by the synthesizer at print time so that correctness does not
    depend on `Au3ParenExpression` nodes being present in the tree.
    """
    if isinstance(child, Au3ParenExpression):
        return False
    return parens_required(child, parent, child)


def _is_assignment_target(node: Node) -> bool:
    """
    Whether *node* is a shape the parser accepts as the target of a statement-position
    assignment: a variable, a `.member` reference, or an array or member access rooted in one.
    """
    if isinstance(node, (Au3Variable, Au3WithMember)):
        return True
    if isinstance(node, Au3ArrayAccess):
        return node.array is not None and _is_assignment_target(node.array)
    if isinstance(node, Au3MemberAccess):
        return node.object is not None and _is_assignment_target(node.object)
    return False


def statement_needs_parens(expr: Node) -> bool:
    """
    Whether an expression statement consisting of *expr* must be parenthesized to keep its
    meaning. AutoIt reads `=` both as assignment and as comparison, and at statement position the
    parser makes an assignment of it whenever the left operand is a writable shape — so a
    comparison whose left operand is one, `$x = side()` comparing rather than storing, must keep
    the parentheses that hold it a comparison. `=` is the only operator the two readings share,
    so the question is whether the statement opens with such a comparison, and every slot that
    prints without parentheses of its own — a ternary's condition, the left operand of an operator
    no tighter than a comparison, and the comparisons chained onto one — can open the statement
    with it.
    """
    cursor = expr
    while True:
        if isinstance(cursor, Au3BinaryExpression):
            left = cursor.left
            if (
                cursor.operator == '='
                and left is not None
                and _is_assignment_target(left)
            ):
                return True
            if (
                left is None
                or _expression_precedence(left) < _BINARY_PRECEDENCE.get(cursor.operator, 0)
            ):
                return False
            cursor = left
        elif isinstance(cursor, Au3Ternary):
            condition = cursor.condition
            if (
                condition is None
                or _expression_precedence(condition) <= _BINARY_PRECEDENCE['?']
            ):
                return False
            cursor = condition
        else:
            return False
