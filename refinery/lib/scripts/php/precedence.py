"""
PHP operator precedence and parenthesization rules.

The precedence levels and associativities are taken from the Zend grammar's operator declarations
(`Zend/zend_language_parser.y`, the `%left`/`%right`/`%nonassoc`/`%precedence` block). As in the
JavaScript module, the synthesizer does not depend on `PhpParenExpression` nodes for correctness: it
consults `needs_parens` to decide, from operator precedence, whether a child expression must be
wrapped in its parent context.

Note the PHP 8 specifics encoded here: `.` (concatenation) sits *below* the shift and additive
operators (it moved in PHP 8), `??` and `**` are right-associative, the word operators `and`/`or`/`xor`
bind *below* assignment, and casts bind *below* `**` so that `(int) $a ** $b` groups as
`(int) ($a ** $b)`.
"""
from __future__ import annotations

from refinery.lib.scripts import Node
from refinery.lib.scripts.php.model import (
    PhpArrayDimFetch,
    PhpArrowFunction,
    PhpAssignment,
    PhpBinaryExpression,
    PhpCastExpression,
    PhpClassConstFetch,
    PhpClone,
    PhpErrorSuppress,
    PhpFunctionCall,
    PhpInclude,
    PhpInstanceof,
    PhpMethodCall,
    PhpNew,
    PhpNewAnonymous,
    PhpParenExpression,
    PhpPrint,
    PhpPropertyFetch,
    PhpStaticCall,
    PhpStaticPropertyFetch,
    PhpTernary,
    PhpThrowExpression,
    PhpUnaryExpression,
    PhpUpdateExpression,
    PhpYield,
    PhpYieldFrom,
)

_BINARY_PRECEDENCE = {
    'or'  : 3,  # noqa
    'xor' : 4,  # noqa
    'and' : 5,  # noqa
    '??'  : 11, # noqa
    '||'  : 12, # noqa
    '&&'  : 13, # noqa
    '|'   : 14, # noqa
    '^'   : 15, # noqa
    '&'   : 16, # noqa
    '=='  : 17, # noqa
    '!='  : 17, # noqa
    '<>'  : 17, # noqa
    '===' : 17, # noqa
    '!==' : 17, # noqa
    '<=>' : 17, # noqa
    '<'   : 18, # noqa
    '<='  : 18, # noqa
    '>'   : 18, # noqa
    '>='  : 18, # noqa
    '|>'  : 19, # noqa
    '.'   : 20, # noqa
    '<<'  : 21, # noqa
    '>>'  : 21, # noqa
    '+'   : 22, # noqa
    '-'   : 22, # noqa
    '*'   : 23, # noqa
    '/'   : 23, # noqa
    '%'   : 23, # noqa
    '**'  : 27, # noqa
}

_RIGHT_ASSOCIATIVE = frozenset({'??', '**'})

_THROW_PRECEDENCE = 1
_ARROW_FUNCTION_PRECEDENCE = 1
_INCLUDE_PRECEDENCE = 2
_PRINT_PRECEDENCE = 6
_YIELD_PRECEDENCE = 7
_ASSIGN_PRECEDENCE = 9
_TERNARY_PRECEDENCE = 10
_LOGICAL_NOT_PRECEDENCE = 24
_INSTANCEOF_PRECEDENCE = 25
_UNARY_PRECEDENCE = 26
_CLONE_PRECEDENCE = 28
_PRIMARY_PRECEDENCE = 100


def _expression_precedence(node: Node) -> int:
    """
    Return the operator precedence of *node* on the PHP scale used by `parens_required`. Primary
    expressions (variables, literals, names, calls, member/array access, and the like) return a
    value high enough that they never need parenthesisation.
    """
    if isinstance(node, PhpBinaryExpression):
        return _BINARY_PRECEDENCE.get(node.operator, 0)
    if isinstance(node, PhpInstanceof):
        return _INSTANCEOF_PRECEDENCE
    if isinstance(node, PhpUnaryExpression):
        if node.operator == '!':
            return _LOGICAL_NOT_PRECEDENCE
        return _UNARY_PRECEDENCE
    if isinstance(node, (PhpCastExpression, PhpErrorSuppress)):
        return _UNARY_PRECEDENCE
    if isinstance(node, PhpClone):
        return _CLONE_PRECEDENCE
    if isinstance(node, PhpAssignment):
        return _ASSIGN_PRECEDENCE
    if isinstance(node, PhpTernary):
        return _TERNARY_PRECEDENCE
    if isinstance(node, PhpThrowExpression):
        return _THROW_PRECEDENCE
    if isinstance(node, PhpArrowFunction):
        return _ARROW_FUNCTION_PRECEDENCE
    if isinstance(node, (PhpYield, PhpYieldFrom)):
        return _YIELD_PRECEDENCE
    if isinstance(node, PhpPrint):
        return _PRINT_PRECEDENCE
    if isinstance(node, PhpInclude):
        return _INCLUDE_PRECEDENCE
    return _PRIMARY_PRECEDENCE


def _leading_sign(node: Node) -> str | None:
    """
    Return `+` or `-` if *node* is synthesized starting with that sign character, otherwise `None`.
    Such a node cannot directly follow a prefix `+`/`-` operator without an intervening paren, since
    the synthesizer emits no separator and the two would merge into a `++`/`--` token.
    """
    if isinstance(node, PhpUnaryExpression) and node.operator in ('+', '-'):
        return node.operator
    if isinstance(node, PhpUpdateExpression) and node.prefix and node.operator in ('++', '--'):
        return node.operator[0]
    return None


def _is_primary_receiver(node: Node) -> bool:
    """
    Return whether *node* may sit as the receiver/callee/class in a member access, call, array
    access, or `new` context without parentheses. Any operator expression in such a position would
    rebind and must keep its parentheses.
    """
    return _expression_precedence(node) >= _PRIMARY_PRECEDENCE


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
    if isinstance(parent, PhpBinaryExpression):
        outer_p = _BINARY_PRECEDENCE.get(parent.operator, 0)
        if inner_p > outer_p:
            return False
        if inner_p < outer_p:
            return True
        if parent.operator in _RIGHT_ASSOCIATIVE:
            return parent.left is paren_node
        return parent.right is paren_node
    if isinstance(parent, PhpInstanceof):
        if parent.operand is paren_node:
            return inner_p < _INSTANCEOF_PRECEDENCE
        return False
    if isinstance(parent, PhpUnaryExpression):
        if parent.operator in ('+', '-') and _leading_sign(inner) == parent.operator:
            return True
        outer_p = _LOGICAL_NOT_PRECEDENCE if parent.operator == '!' else _UNARY_PRECEDENCE
        return inner_p < outer_p
    if isinstance(parent, (PhpCastExpression, PhpErrorSuppress)):
        return inner_p < _UNARY_PRECEDENCE
    if isinstance(parent, PhpClone):
        return inner_p < _CLONE_PRECEDENCE
    if isinstance(parent, PhpTernary):
        return inner_p <= _TERNARY_PRECEDENCE
    if isinstance(parent, PhpAssignment):
        if parent.target is paren_node:
            return False
        return inner_p < _ASSIGN_PRECEDENCE
    if isinstance(parent, (PhpPropertyFetch, PhpMethodCall)):
        if parent.receiver is paren_node:
            return not _is_primary_receiver(inner)
        return False
    if isinstance(parent, PhpArrayDimFetch):
        if parent.receiver is paren_node:
            return not _is_primary_receiver(inner)
        return False
    if isinstance(parent, PhpFunctionCall):
        if parent.callee is paren_node:
            return not _is_primary_receiver(inner)
        return False
    if isinstance(parent, (PhpStaticCall, PhpStaticPropertyFetch, PhpClassConstFetch)):
        if parent.class_name is paren_node:
            return not _is_primary_receiver(inner)
        return False
    if isinstance(parent, PhpNew):
        if parent.class_name is paren_node:
            return not _is_primary_receiver(inner)
        return False
    if isinstance(parent, PhpNewAnonymous):
        return not _is_primary_receiver(inner)
    return False


def needs_parens(child: Node, parent: Node | None) -> bool:
    """
    Return whether *child*, which currently occupies a slot in *parent*, must be wrapped in
    parentheses to preserve precedence. Used by the synthesizer at print time so that correctness
    does not depend on `PhpParenExpression` nodes being present in the tree.
    """
    if isinstance(child, PhpParenExpression):
        return False
    return parens_required(child, parent, child)


def statement_needs_parens(expr: Node) -> bool:
    """
    Return whether an expression statement consisting of *expr* must be parenthesized because of a
    leading-token hazard. PHP delimits statements explicitly and has no object-literal or block
    ambiguity at the start of an expression statement, so no such hazard exists; the function is
    provided for parity with the JavaScript module and always returns `False`.
    """
    del expr
    return False
