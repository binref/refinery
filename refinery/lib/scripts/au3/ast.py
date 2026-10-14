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

from typing import Iterator, Sequence

from refinery.lib.scripts import Expression, Node, Statement
from refinery.lib.scripts.au3.model import (
    Au3ArrayAccess,
    Au3ArrayLiteral,
    Au3Assignment,
    Au3Call,
    Au3DoUntilStatement,
    Au3EnumDeclarator,
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
    Au3SelectStatement,
    Au3SwitchStatement,
    Au3Variable,
    Au3VariableDeclarator,
    Au3WhileStatement,
    Au3WithStatement,
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
    must not descend into another — see `scope_nodes` for the walk that respects that border.
    """
    scopes: list[tuple[Au3FunctionDeclaration | None, list[Statement]]] = [(None, root.body)]
    for node in root.walk():
        if isinstance(node, Au3FunctionDeclaration):
            scopes.append((node, node.body))
    return scopes


def scope_nodes(body: list[Statement]) -> Iterator[Node]:
    """
    Every node of one scope's subtree, in source order, descending into the control-flow
    constructs the scope holds but not into a nested function declaration, which is a scope of
    its own. A caller that wants only the statements of the scope can filter `Statement` out of
    what this yields.
    """
    stack: list[Node] = list(reversed(body))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, Au3FunctionDeclaration):
            continue
        stack.extend(reversed(node.children()))


def statement_lists(statement: Statement) -> Iterator[tuple[Node, str]]:
    """
    Every nested statement list *statement* holds, as the node owning the list and the attribute
    naming it. The lists of a function declaration are absent: a nested function is a scope of its
    own, so a walk that recurses through these pairs never crosses a scope border. A transform
    that prunes statements pairs this with `refinery.lib.scripts.set_child_list` to write back.
    """
    if isinstance(statement, Au3IfStatement):
        yield statement, 'body'
        for elseif in statement.elseifs:
            yield elseif, 'body'
        if statement.else_body is not None:
            yield statement, 'else_body'
    elif isinstance(statement, (Au3WhileStatement, Au3DoUntilStatement)):
        yield statement, 'body'
    elif isinstance(statement, (Au3ForStatement, Au3ForInStatement, Au3WithStatement)):
        yield statement, 'body'
    elif isinstance(statement, Au3SelectStatement):
        for case in statement.cases:
            yield case, 'body'
    elif isinstance(statement, Au3SwitchStatement):
        for case in statement.cases:
            yield case, 'body'


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
    target is. Every other occurrence reads it — the root of an indexed or member target among
    them: `$a[0] = 1` reads `$a`, and the store writes the array, not the name.
    """
    parent = node.parent
    if isinstance(parent, (Au3VariableDeclarator, Au3EnumDeclarator, Au3Parameter, Au3ReDimTarget)):
        return parent.variable is node
    if isinstance(parent, (Au3ForStatement, Au3ForInStatement)):
        return parent.variable is node
    if isinstance(parent, Au3Assignment):
        return store_target_variable(parent.target) is node
    return False


def reads_what_it_writes(node: Au3Variable) -> bool:
    """
    Whether this write occurrence also reads the name it writes: a compound assignment's target
    reads what it rewrites, a `ReDim` target reads the array it resizes, and a `For...To` loop
    compares and steps on its variable at every iteration, while a `For...In` loop only assigns
    its own. A census that counts reads must count these beside every non-writing occurrence.
    """
    parent = node.parent
    if isinstance(parent, Au3Assignment):
        return parent.operator != '=' and store_target_variable(parent.target) is node
    if isinstance(parent, Au3ReDimTarget):
        return parent.variable is node
    return isinstance(parent, Au3ForStatement) and parent.variable is node


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


def in_callee_position(node: Node) -> bool:
    """
    Whether *node* is the callee of a call, through any number of parentheses. Replacing the node
    there rewrites the caller's shape — `Call("f")(1)` would collapse two calls into one — not
    only the occurrence's own.
    """
    cursor = node
    parent = cursor.parent
    while isinstance(parent, Au3ParenExpression):
        cursor = parent
        parent = cursor.parent
    return isinstance(parent, Au3Call) and parent.callee is cursor


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


def in_declaration_initializer(node: Node) -> bool:
    """
    Whether *node* sits where a declarator initializes: inside its initializer through array
    literals alone, which are the only nesting AutoIt accepts there.
    """
    cursor = node
    parent = cursor.parent
    while isinstance(parent, Au3ArrayLiteral):
        cursor = parent
        parent = cursor.parent
    return isinstance(parent, Au3VariableDeclarator) and parent.initializer is cursor


def contains_a_call(node: Node) -> bool:
    """
    Whether the subtree at `node` holds an `Au3Call`. A caller that is about to drop one side of a
    construct AutoIt may or may not evaluate — the untaken branch of a ternary, the right side of
    an `And` a short-circuit would skip — asks this rather than the value of that side, because
    only a call can change anything when it does not produce a value the fold needs.
    """
    return any(isinstance(item, Au3Call) for item in node.walk())


def contains_an_array_literal(node: Node) -> bool:
    """
    Whether the subtree at `node` holds an `Au3ArrayLiteral`. A caller that is about to splice the
    subtree into an arbitrary position asks this, because an array literal is legal AutoIt only
    where a declaration initializes.
    """
    return any(isinstance(item, Au3ArrayLiteral) for item in node.walk())


def byref_arguments(
    function: Au3FunctionDeclaration,
    arguments: Sequence[Expression],
) -> Iterator[Au3Variable]:
    """
    The variables *arguments* hand into the `ByRef` parameters of *function*, position by
    position, through any number of parentheses.
    """
    for parameter, argument in zip(function.params, arguments):
        if not parameter.by_ref:
            continue
        node = unwrap_parens(argument)
        if isinstance(node, Au3Variable):
            yield node
