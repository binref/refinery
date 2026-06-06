"""
Recover sequential code from control-flow-flattened dispatchers.

Handles the sequential reordering pattern: a `while(true)` loop with `switch(t[i++])` where a
pre-defined array holds the execution sequence.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.js.deobfuscation.helpers import (
    FUNCTION_NODE_TYPES,
    BodyProcessingTransformer,
    access_key,
    has_remaining_references,
    is_while_true,
    string_value,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsBlockStatement,
    JsBreakStatement,
    JsCallExpression,
    JsContinueStatement,
    JsIdentifier,
    JsMemberExpression,
    JsNumericLiteral,
    JsScript,
    JsSwitchCase,
    JsSwitchStatement,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsWhileStatement,
)


def _strip_trailing_flow(stmts: list[Statement]) -> list[Statement]:
    """
    Return a copy of the statement list with a trailing `continue` or `break` removed.
    """
    if not stmts:
        return []
    last = stmts[-1]
    if isinstance(last, (JsContinueStatement, JsBreakStatement)) and last.label is None:
        return stmts[:-1]
    return stmts


class _DispatcherMatch(NamedTuple):
    order_var: str
    counter_var: str
    case_map: dict[str, list[Statement]]
    dispatch: Node


def _match_dispatcher(
    while_node: JsWhileStatement,
) -> _DispatcherMatch | None:
    """
    Test whether *while_node* is a CFF dispatcher. Returns a `_DispatcherMatch` or `None`.

    Expected structure::

        while (true) {
            switch (ORDER[COUNTER++]) {
                case 'N': ...; continue;
                ...
            }
            break;
        }
    """
    if not is_while_true(while_node):
        return None
    body = while_node.body
    if not isinstance(body, JsBlockStatement):
        return None
    stmts = body.body
    if len(stmts) != 2:
        return None
    switch = stmts[0]
    tail = stmts[1]
    if not isinstance(switch, JsSwitchStatement):
        return None
    if not isinstance(tail, JsBreakStatement):
        return None
    disc = switch.discriminant
    if not isinstance(disc, JsMemberExpression) or not disc.computed:
        return None
    if not isinstance(disc.object, JsIdentifier):
        return None
    order_var = disc.object.name
    prop = disc.property
    if not isinstance(prop, JsUpdateExpression):
        return None
    if prop.operator != '++' or prop.prefix:
        return None
    if not isinstance(prop.argument, JsIdentifier):
        return None
    counter_var = prop.argument.name
    case_map: dict[str, list[Statement]] = {}
    for case in switch.cases:
        if not isinstance(case, JsSwitchCase) or case.test is None:
            return None
        label = string_value(case.test)
        if label is None:
            if isinstance(case.test, JsNumericLiteral):
                label = str(int(case.test.value))
            else:
                return None
        case_map[label] = _strip_trailing_flow(case.body)
    return _DispatcherMatch(order_var, counter_var, case_map, disc)


def _extract_order_sequence(node: Node | None) -> list[str] | None:
    """
    Extract the dispatch sequence from the order variable's initializer. Accepts an array literal
    of constants (the canonical form after simplification) or a `'...'['split']('|')` call (the
    raw obfuscator output, as fallback).
    """
    if isinstance(node, JsArrayExpression):
        result: list[str] = []
        for el in node.elements:
            s = string_value(el)
            if s is not None:
                result.append(s)
            elif isinstance(el, JsNumericLiteral):
                result.append(str(int(el.value)))
            else:
                return None
        return result
    if not isinstance(node, JsCallExpression) or len(node.arguments) != 1:
        return None
    sep = string_value(node.arguments[0])
    if sep != '|':
        return None
    callee = node.callee
    if not isinstance(callee, JsMemberExpression):
        return None
    if access_key(callee) != 'split':
        return None
    obj = string_value(callee.object)
    if obj is None:
        return None
    return obj.split('|')


class _OrderSequenceInfo(NamedTuple):
    order_sequence: list[str]
    first_init_idx: int
    strip_declarators: tuple[JsVariableDeclarator, ...]


def _find_order_sequence(
    body: list[Statement],
    end_idx: int,
    order_var: str,
    counter_var: str,
) -> _OrderSequenceInfo | None:
    """
    Scan backwards from *end_idx* in *body* to find the initialization of the order array and the
    counter variable. Both may be declarators in a single multi-declarator `var` statement. Returns
    an `_OrderSequenceInfo` or `None`.
    """
    order_init_idx: int | None = None
    counter_init_idx: int | None = None
    order_sequence: list[str] | None = None
    order_decl: JsVariableDeclarator | None = None
    counter_decl: JsVariableDeclarator | None = None

    for i in range(end_idx - 1, -1, -1):
        stmt = body[i]
        if not isinstance(stmt, JsVariableDeclaration):
            continue
        for decl in stmt.declarations:
            if not isinstance(decl, JsVariableDeclarator) or not isinstance(decl.id, JsIdentifier):
                continue
            name = decl.id.name
            if name == counter_var and counter_decl is None:
                if isinstance(decl.init, JsNumericLiteral) and decl.init.value == 0:
                    counter_decl = decl
                    counter_init_idx = i
            elif name == order_var and order_decl is None:
                seq = _extract_order_sequence(decl.init)
                if seq is not None:
                    order_sequence = seq
                    order_decl = decl
                    order_init_idx = i
        if order_decl is not None and counter_decl is not None:
            break

    if (
        order_sequence is None
        or order_init_idx is None
        or counter_init_idx is None
        or order_decl is None
        or counter_decl is None
    ):
        return None
    first = min(order_init_idx, counter_init_idx)
    return _OrderSequenceInfo(order_sequence, first, (order_decl, counter_decl))


def _enclosing_scope(node: Node) -> Node:
    """
    Return the nearest `JsScript` or function node enclosing *node*, i.e. the scope in which a
    `var` binding declared at *node* would be visible.
    """
    scope = node
    while not isinstance(scope, (JsScript, *FUNCTION_NODE_TYPES)):
        if scope.parent is None:
            break
        scope = scope.parent
    return scope


def _consumed_only_by_dispatcher(
    scope: Node,
    match: _DispatcherMatch,
    info: _OrderSequenceInfo,
) -> bool:
    """
    Check that the order and counter variables are referenced only by the dispatcher machinery that
    the transform removes: their own declarators and the `ORDER[COUNTER++]` access. If any surviving
    statement (a sibling declarator, an inlined case body, code before or after the loop) still
    reads them, recovery would leave a dangling reference, so the dispatcher must be left untouched.
    """
    removed = (*info.strip_declarators, match.dispatch)
    exclude_ids = {id(n) for node in removed for n in node.walk()}
    return not any(
        has_remaining_references(scope, name, exclude_ids=exclude_ids)
        for name in (match.order_var, match.counter_var)
    )


class JsControlFlowUnflattening(BodyProcessingTransformer):
    """
    Detect and recover CFF dispatchers in function bodies and script-level code.
    """

    def _process_body(self, parent: Node, body: list[Statement]) -> None:
        i = 0
        while i < len(body):
            stmt = body[i]
            if not isinstance(stmt, JsWhileStatement):
                i += 1
                continue
            match = _match_dispatcher(stmt)
            if match is None:
                i += 1
                continue
            order_info = _find_order_sequence(body, i, match.order_var, match.counter_var)
            if order_info is None:
                i += 1
                continue
            if not all(label in match.case_map for label in order_info.order_sequence):
                i += 1
                continue
            scope = _enclosing_scope(parent)
            if not _consumed_only_by_dispatcher(scope, match, order_info):
                i += 1
                continue
            recovered: list[Statement] = []
            for j in range(order_info.first_init_idx, i):
                decl_stmt = body[j]
                if isinstance(decl_stmt, JsVariableDeclaration):
                    remaining = [
                        d for d in decl_stmt.declarations
                        if all(d is not s for s in order_info.strip_declarators)
                    ]
                    if not remaining:
                        continue
                    if len(remaining) != len(decl_stmt.declarations):
                        decl_stmt.declarations = remaining
                recovered.append(decl_stmt)
            for label in order_info.order_sequence:
                recovered.extend(match.case_map[label])
            replacement = body[:order_info.first_init_idx] + recovered + body[i + 1:]
            self._replace_body(parent, body, replacement)
            i = order_info.first_init_idx + len(recovered)
