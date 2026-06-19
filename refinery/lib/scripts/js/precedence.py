"""
JavaScript operator precedence and parenthesization rules.

The synthesizer does not rely on `refinery.lib.scripts.js.model.JsParenthesizedExpression` nodes for
correctness: it consults `needs_parens` to decide, from operator precedence, whether a child
expression must be wrapped in its parent context. The
`refinery.lib.scripts.js.deobfuscation.simplify.JsSimplifications` paren-removal pass uses the same
rules (via `parens_required`) so it never strips a paren that is actually required.
"""
from __future__ import annotations

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAwaitExpression,
    JsBinaryExpression,
    JsCallExpression,
    JsClassDeclaration,
    JsClassExpression,
    JsConditionalExpression,
    JsFunctionExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsNewExpression,
    JsNumericLiteral,
    JsObjectExpression,
    JsObjectPattern,
    JsParenthesizedExpression,
    JsSequenceExpression,
    JsTaggedTemplateExpression,
    JsThisExpression,
    JsUnaryExpression,
    JsUpdateExpression,
    JsYieldExpression,
)

_BINARY_PRECEDENCE = {
    '||' : 3,  # noqa
    '??' : 3,  # noqa
    '&&' : 4,  # noqa
    '|'  : 5,  # noqa
    '^'  : 6,  # noqa
    '&'  : 7,  # noqa
    '==' : 8,  # noqa
    '!=' : 8,  # noqa
    '===': 8,
    '!==': 8,
    '<'  : 9,  # noqa
    '>'  : 9,  # noqa
    '<=' : 9,  # noqa
    '>=' : 9,  # noqa
    'in' : 9,  # noqa
    'instanceof': 9,
    '<<' : 10, # noqa
    '>>' : 10, # noqa
    '>>>': 10,
    '+'  : 11, # noqa
    '-'  : 11, # noqa
    '*'  : 12, # noqa
    '/'  : 12, # noqa
    '%'  : 12, # noqa
    '**' : 13, # noqa
}

_SEQUENCE_PRECEDENCE = 1
_ASSIGN_PRECEDENCE = 2
_CONDITIONAL_PRECEDENCE = 2
_UNARY_PRECEDENCE = 14
_PRIMARY_PRECEDENCE = 100


def _expression_precedence(node: Node) -> int:
    """
    Return the operator precedence of *node* on the JavaScript scale used by `parens_required`.
    Primary expressions (literals, identifiers, member access, calls, etc.) return a value high
    enough that they never need parenthesisation.
    """
    if isinstance(node, (JsBinaryExpression, JsLogicalExpression)):
        return _BINARY_PRECEDENCE.get(node.operator, 0)
    if isinstance(node, JsSequenceExpression):
        return _SEQUENCE_PRECEDENCE
    if isinstance(node, (JsAssignmentExpression, JsArrowFunctionExpression, JsYieldExpression)):
        return _ASSIGN_PRECEDENCE
    if isinstance(node, JsConditionalExpression):
        return _CONDITIONAL_PRECEDENCE
    if isinstance(node, (JsUnaryExpression, JsAwaitExpression, JsUpdateExpression)):
        return _UNARY_PRECEDENCE
    return _PRIMARY_PRECEDENCE


def _leading_sign(node: Node) -> str | None:
    """
    Return `+` or `-` if *node* is synthesized starting with that sign character, otherwise `None`.
    Such a node cannot directly follow a prefix `+`/`-` operator without an intervening paren,
    since the synthesizer emits no separator and the two would merge into a `++`/`--` token.
    """
    if isinstance(node, JsUnaryExpression) and node.operator in ('+', '-'):
        return node.operator
    if isinstance(node, JsUpdateExpression) and node.prefix and node.operator in ('++', '--'):
        return node.operator[0]
    return None


def _has_optional_in_spine(node: Node) -> bool:
    """
    Return whether the left spine of *node* contains an optional link (`?.`). Such a node forms an
    optional chain whose short-circuit scope is delimited by parentheses: stripping the parentheses
    around it in an outer member/call/new position would extend the short-circuit and change meaning
    (or, for `new`, produce invalid syntax).
    """
    while True:
        if isinstance(node, JsMemberExpression):
            if node.optional:
                return True
            if node.object is None:
                return False
            node = node.object
        elif isinstance(node, JsCallExpression):
            if node.optional:
                return True
            if node.callee is None:
                return False
            node = node.callee
        elif isinstance(node, JsTaggedTemplateExpression):
            if node.tag is None:
                return False
            node = node.tag
        else:
            return False


def _safe_new_callee(node: Node) -> bool:
    """
    Return whether *node* may serve as the callee of a `new` expression without parentheses. The
    callee of `new` is a member-access chain, so a call anywhere in its left spine (or any operator
    expression) would re-bind the `new` and must keep its parentheses. An optional link (`?.`)
    anywhere in the chain is never a valid `new` callee and likewise requires parentheses.
    """
    while isinstance(node, JsMemberExpression):
        if node.optional or node.object is None:
            return False
        node = node.object
    return isinstance(node, (JsIdentifier, JsThisExpression))


def _nullish_logical_conflict(outer_op: str, inner: Node) -> bool:
    """
    Return whether nesting *inner* directly under a binary operator *outer_op* would put the nullish
    coalescing operator `??` immediately adjacent to `&&` or `||`. The grammar forbids that
    combination without parentheses regardless of precedence, so such a nesting must stay wrapped.
    """
    if not isinstance(inner, (JsBinaryExpression, JsLogicalExpression)):
        return False
    pair = {outer_op, inner.operator}
    return '??' in pair and ('||' in pair or '&&' in pair)


def parens_required(inner: Node, parent: Node | None, paren_node: Node) -> bool:
    """
    Return whether *paren_node* (positioned within *parent*, wrapping *inner*) must be parenthesized
    to preserve the program's meaning. *paren_node* is the node actually occupying the slot in
    *parent*; *inner* is the expression whose precedence is examined. When the two are identical the
    question is simply whether *inner* needs parentheses in *parent* — see `needs_parens`.
    """
    if parent is None:
        return False
    inner_p = _expression_precedence(inner)
    if isinstance(parent, (JsBinaryExpression, JsLogicalExpression)):
        outer_p = _BINARY_PRECEDENCE.get(parent.operator, 0)
        if (
            parent.operator == '**'
            and parent.left is paren_node
            and (
                isinstance(inner, (JsUnaryExpression, JsAwaitExpression))
                or (isinstance(inner, JsUpdateExpression) and inner.prefix)
            )
        ):
            return True
        if _nullish_logical_conflict(parent.operator, inner):
            return True
        if inner_p > outer_p:
            return False
        if inner_p < outer_p:
            return True
        right_associative = parent.operator == '**'
        if right_associative:
            return parent.left is paren_node
        return parent.right is paren_node
    if isinstance(parent, JsUnaryExpression):
        if parent.operator in ('+', '-') and _leading_sign(inner) == parent.operator:
            return True
        return inner_p < _UNARY_PRECEDENCE
    if isinstance(parent, JsAwaitExpression):
        return inner_p < _UNARY_PRECEDENCE
    if isinstance(parent, JsConditionalExpression):
        if parent.test is paren_node:
            return inner_p <= _CONDITIONAL_PRECEDENCE
        return inner_p < _ASSIGN_PRECEDENCE
    if isinstance(parent, JsAssignmentExpression):
        if parent.left is paren_node:
            return False
        return inner_p < _ASSIGN_PRECEDENCE
    if isinstance(parent, JsMemberExpression):
        if parent.object is paren_node:
            if paren_node is not inner and _has_optional_in_spine(inner):
                return True
            if isinstance(inner, JsNumericLiteral):
                return not parent.computed
            if not isinstance(inner, (
                JsIdentifier,
                JsMemberExpression,
                JsCallExpression,
                JsArrayExpression,
            )):
                return inner_p < _PRIMARY_PRECEDENCE
        return False
    if isinstance(parent, JsCallExpression):
        if parent.callee is paren_node:
            if paren_node is not inner and _has_optional_in_spine(inner):
                return True
            return inner_p < _PRIMARY_PRECEDENCE
        return False
    if isinstance(parent, JsTaggedTemplateExpression):
        if parent.tag is paren_node:
            if paren_node is not inner and _has_optional_in_spine(inner):
                return True
            return inner_p < _PRIMARY_PRECEDENCE
        return False
    if isinstance(parent, JsNewExpression):
        if parent.callee is paren_node:
            return not _safe_new_callee(inner)
        return False
    if isinstance(parent, (JsClassExpression, JsClassDeclaration)):
        if parent.super_class is paren_node:
            return inner_p < _PRIMARY_PRECEDENCE
        return False
    return False


def needs_parens(child: Node, parent: Node | None) -> bool:
    """
    Return whether *child*, which currently occupies a slot in *parent*, must be wrapped in
    parentheses to preserve precedence. Used by the synthesizer at print time so that correctness
    does not depend on `refinery.lib.scripts.js.model.JsParenthesizedExpression` nodes being present
    in the tree.
    """
    if isinstance(child, JsParenthesizedExpression):
        return False
    return parens_required(child, parent, child)


def statement_needs_parens(expr: Node) -> bool:
    """
    Return whether an expression statement consisting of *expr* must be parenthesized because its
    leftmost token would otherwise start a block, function declaration, or class declaration. The
    hazard propagates down the left spine, e.g. `({}).x` or `(function(){})()`.
    """
    node: Node | None = expr
    while node is not None:
        if isinstance(node, (JsObjectExpression, JsFunctionExpression, JsClassExpression, JsObjectPattern)):
            return True
        if isinstance(node, JsMemberExpression):
            node = node.object
        elif isinstance(node, JsCallExpression):
            node = node.callee
        elif isinstance(node, JsTaggedTemplateExpression):
            node = node.tag
        elif isinstance(node, (JsBinaryExpression, JsLogicalExpression, JsAssignmentExpression)):
            node = node.left
        elif isinstance(node, JsConditionalExpression):
            node = node.test
        elif isinstance(node, JsSequenceExpression):
            node = node.expressions[0] if node.expressions else None
        elif isinstance(node, JsUpdateExpression) and not node.prefix:
            node = node.argument
        else:
            return False
    return False
