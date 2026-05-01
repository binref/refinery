"""
Recover sequential code from control-flow-flattened dispatchers. The obfuscator replaces a sequence
of statements with a dispatcher loop:

    var _order = ['2', '0', '4', '1', '3'];
    var _idx = 0;
    while (true) {
        switch (_order[_idx++]) {
            case '0': /* block 0 */; continue;
            case '1': /* block 1 */; continue;
            ...
        }
        break;
    }

Recovery reads the order sequence and emits the case bodies in that order, replacing the entire
dispatcher span with the re-sequenced statements.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.js.deobfuscation.helpers import BodyProcessingTransformer, access_key, is_while_true, string_value
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsBlockStatement,
    JsBreakStatement,
    JsCallExpression,
    JsContinueStatement,
    JsIdentifier,
    JsMemberExpression,
    JsNumericLiteral,
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


def _match_dispatcher(
    while_node: JsWhileStatement,
) -> tuple[str, str, dict[str, list[Statement]]] | None:
    """
    Test whether *while_node* is a CFF dispatcher. Returns a tuple

        (order_var, counter_var, case_map)

    or `None`.

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
        case_map[label] = _strip_trailing_flow(case.consequent)
    return order_var, counter_var, case_map


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


def _find_order_sequence(
    body: list[Statement],
    end_idx: int,
    order_var: str,
    counter_var: str,
) -> tuple[list[str], int, int, set[int]] | None:
    """
    Scan backwards from *end_idx* in *body* to find the initialization of the order array and
    the counter variable. Returns a tuple

        (order_sequence, first_init_idx, last_init_idx, init_indices)

    or `None`.
    """
    order_init_idx: int | None = None
    counter_init_idx: int | None = None
    order_sequence: list[str] | None = None

    for i in range(end_idx - 1, -1, -1):
        stmt = body[i]
        if not isinstance(stmt, JsVariableDeclaration):
            continue
        if len(stmt.declarations) != 1:
            continue
        decl = stmt.declarations[0]
        if not isinstance(decl, JsVariableDeclarator) or not isinstance(decl.id, JsIdentifier):
            continue
        name = decl.id.name
        if name == counter_var and counter_init_idx is None:
            if isinstance(decl.init, JsNumericLiteral) and decl.init.value == 0:
                counter_init_idx = i
        elif name == order_var and order_init_idx is None:
            seq = _extract_order_sequence(decl.init)
            if seq is not None:
                order_sequence = seq
                order_init_idx = i
        if order_init_idx is not None and counter_init_idx is not None:
            break

    if order_sequence is None or order_init_idx is None or counter_init_idx is None:
        return None
    first = min(order_init_idx, counter_init_idx)
    last = max(order_init_idx, counter_init_idx)
    return order_sequence, first, last, {order_init_idx, counter_init_idx}


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
            order_var, counter_var, case_map = match
            order_info = _find_order_sequence(body, i, order_var, counter_var)
            if order_info is None:
                i += 1
                continue
            order_sequence, first_init, _, init_indices = order_info
            if not all(label in case_map for label in order_sequence):
                i += 1
                continue
            recovered: list[Statement] = []
            for j in range(first_init, i):
                if j not in init_indices:
                    recovered.append(body[j])
            for label in order_sequence:
                recovered.extend(case_map[label])
            remove_start = first_init
            remove_end = i
            replacement = body[:remove_start] + recovered + body[remove_end + 1:]
            self._replace_body(parent, body, replacement)
            i = remove_start + len(recovered)
