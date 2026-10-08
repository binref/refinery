"""
Accessors over the AutoIt3 node model: small, total functions that read a shape out of a
`refinery.lib.scripts.au3.model` node without interpreting it. They live at the language level
because both the analysis substrate (`refinery.lib.scripts.au3.analysis`) and the deobfuscation
transforms (`refinery.lib.scripts.au3.deobfuscation`) need them, and neither subsystem may import
from the other.

Nothing here decides anything. A function that answers a semantic question — which variable a
write targets, what an expression evaluates to, whether a store is dead — belongs to the analysis
layer instead.
"""
from __future__ import annotations

from typing import Iterator, TypeGuard

from refinery.lib.scripts import Node, Statement, child_list_fields
from refinery.lib.scripts.au3.model import (
    Au3Assignment,
    Au3ArrayAccess,
    Au3Call,
    Au3DoUntilStatement,
    Au3EnumDeclarator,
    Au3ExpressionStatement,
    Au3ForInStatement,
    Au3ForStatement,
    Au3FunctionDeclaration,
    Au3Identifier,
    Au3IfStatement,
    Au3MemberAccess,
    Au3Parameter,
    Au3ParenExpression,
    Au3ReDimTarget,
    Au3Script,
    Au3SelectCase,
    Au3Ternary,
    Au3Variable,
    Au3VariableDeclarator,
    Au3VariableDeclaration,
    Au3WhileStatement,
)

_CONDITION_FIELDS = (
    (Au3IfStatement, 'test'),
    (Au3WhileStatement, 'test'),
    (Au3DoUntilStatement, 'test'),
    (Au3SelectCase, 'test'),
    (Au3Ternary, 'condition'),
)


def enclosing_function(node: Node) -> Au3FunctionDeclaration | None:
    """
    The function whose body holds *node*, or `None` at script level.
    """
    cursor = node.parent
    while cursor is not None:
        if isinstance(cursor, Au3FunctionDeclaration):
            return cursor
        cursor = cursor.parent
    return None


def unwrap_parens(node: Node | None) -> Node | None:
    """
    Unwrap nested `Au3ParenExpression` wrappers, stopping at an empty one.
    """
    while isinstance(node, Au3ParenExpression) and node.expression is not None:
        node = node.expression
    return node


def scope_bodies(root: Au3Script) -> list[tuple[Au3FunctionDeclaration | None, list[Statement]]]:
    """
    Every scope's statement list: the script body paired with `None`, then one body per function
    declaration anywhere in it. A function body is a scope of its own, so a walk over one scope
    must not descend into another — see `scope_statements` for the walk that respects that border.
    """
    scopes: list[tuple[Au3FunctionDeclaration | None, list[Statement]]] = [(None, root.body)]
    for node in root.walk():
        if isinstance(node, Au3FunctionDeclaration):
            scopes.append((node, node.body))
    return scopes


def scope_statements(body: list[Statement]) -> Iterator[Statement]:
    """
    Every statement of one scope, in source order, descending into the control-flow constructs the
    scope holds but not into a nested function declaration, which is a scope of its own.
    """
    stack = list(reversed(body))
    while stack:
        stmt = stack.pop()
        yield stmt
        if isinstance(stmt, Au3FunctionDeclaration):
            continue
        for items in reversed(child_statement_lists(stmt)):
            stack.extend(reversed(items))


def scope_nodes(body: list[Statement]) -> Iterator[Node]:
    """
    Every node of one scope's subtree, in source order, descending into the control-flow
    constructs the scope holds but not into a nested function declaration, which is a scope of
    its own. Where `scope_statements` yields the statements, this reaches the expressions,
    declarators, and calls inside them.
    """
    stack: list[Node] = list(reversed(body))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, Au3FunctionDeclaration):
            continue
        stack.extend(reversed(node.children()))


def owning_statement(node: Node) -> Statement | None:
    """
    The innermost statement that holds *node*. A parameter's owning statement is its function
    declaration, the one statement that can hold it.
    """
    cursor: Node | None = node.parent
    while cursor is not None and not isinstance(cursor, Statement):
        cursor = cursor.parent
    return cursor


def is_write_occurrence(node: Au3Variable) -> bool:
    """
    Whether this occurrence of a variable is one a store writes: a declarator, an enum entry, a
    parameter, a loop variable, or a ReDim target binds it, or it is the variable an assignment's
    target chain is rooted in. Every other occurrence reads it.
    """
    parent = node.parent
    if isinstance(parent, (Au3VariableDeclarator, Au3EnumDeclarator, Au3Parameter, Au3ReDimTarget)):
        return parent.variable is node
    if isinstance(parent, (Au3ForStatement, Au3ForInStatement)):
        return parent.variable is node
    if isinstance(parent, Au3Assignment):
        return store_target_variable(parent.target) is node
    return False


def child_statement_lists(stmt: Statement) -> list[list[Statement]]:
    """
    The statement lists *stmt* directly owns: the bodies of the constructs it opens. Call arguments
    and declaration lists hold expressions and declarators rather than statements, so they are not
    among them.
    """
    result = []
    for _, items in child_list_fields(stmt):
        if items and all(isinstance(item, Statement) for item in items):
            result.append(items)
    return result


def store_target_variable(target: Node | None) -> Au3Variable | None:
    """
    The variable a store writes through: a plain variable target is itself, an indexed or member
    target is the variable its chain is rooted in, and a target rooted anywhere else names no
    variable. An indexed store `$a[$i] = $v` answers `$a` — the array it mutates — which is what a
    constant binding has to lose.
    """
    cursor = unwrap_parens(target)
    while True:
        if isinstance(cursor, Au3Variable):
            return cursor
        if isinstance(cursor, (Au3ArrayAccess, Au3MemberAccess)):
            inner = cursor.array if isinstance(cursor, Au3ArrayAccess) else cursor.object
            cursor = unwrap_parens(inner)
            continue
        return None


def direct_callee(call: Au3Call) -> Au3Identifier | None:
    """
    The identifier a call names directly, or `None` for a call through a variable, a member, a
    parenthesized expression, or another call.
    """
    if call.callee is None:
        return None
    callee = unwrap_parens(call.callee)
    if isinstance(callee, Au3Identifier):
        return callee
    return None


def is_indirect_callee(call: Au3Call) -> bool:
    """
    Whether the callee of `call` is anything but a plain identifier — a variable, a member access,
    or a computed expression. Such a call dispatches to whatever the callee evaluates to, so no
    static table can bound what it runs.
    """
    if call.callee is None:
        return True
    return not isinstance(unwrap_parens(call.callee), Au3Identifier)


def is_declaration(node: Node) -> TypeGuard[Au3VariableDeclaration]:
    """
    Whether `node` is a variable declaration, the one statement that binds names through
    declarators rather than through assignment.
    """
    return isinstance(node, Au3VariableDeclaration)


def declarator_variable(node: Node) -> Au3Variable | None:
    """
    The variable a declarator, parameter, or store target declares or writes, or `None` when the
    node is none of these.
    """
    if isinstance(node, Au3VariableDeclarator):
        return node.variable
    if isinstance(node, (Au3Parameter, Au3ReDimTarget)):
        return node.variable
    if isinstance(node, Au3Assignment):
        return store_target_variable(node.target)
    return None


def consumed_as_condition(node: Node) -> bool:
    """
    Whether *node* is the condition an `If`, `While`, `Do..Until`, or `Select` branch tests, or the
    condition of a ternary. Enclosing parentheses are transparent, because a condition wrapped in
    them is still consumed as a truth value and by nothing else.
    """
    cursor = node
    parent = cursor.parent
    while isinstance(parent, Au3ParenExpression):
        cursor = parent
        parent = cursor.parent
    if parent is None:
        return False
    for owner, field in _CONDITION_FIELDS:
        if isinstance(parent, owner) and getattr(parent, field) is cursor:
            return True
    return False


def statement_expression(statement: Node) -> Node | None:
    """
    The expression an expression statement is nothing but, or `None` when the statement is anything
    else or holds no expression.
    """
    if isinstance(statement, Au3ExpressionStatement):
        return statement.expression
    return None


def is_assignment_statement(statement: Node) -> TypeGuard[Au3Assignment]:
    """
    Whether `statement` is an expression statement holding nothing but an assignment.
    """
    return isinstance(statement_expression(statement), Au3Assignment)


def contains_a_call(node: Node) -> bool:
    """
    Whether the subtree at `node` holds an `Au3Call`. A caller that is about to drop one side of a
    construct AutoIt may or may not evaluate — the untaken branch of a ternary, the right side of
    an `And` a short-circuit would skip — asks this rather than the value of that side, because
    only a call can change anything when it does not produce a value the fold needs.
    """
    return any(isinstance(item, Au3Call) for item in node.walk())
