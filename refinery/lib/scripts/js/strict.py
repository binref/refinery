"""
Strict-mode early-error detection for the JavaScript parser. The parser is fully permissive and always
produces the sloppy-mode parse tree; strict mode never changes how source is parsed, only which
already-parsed constructs are illegal. This module is therefore a pure post-parse pass: it walks a
parsed tree, threading strictness down through function bodies, class bodies, and `"use strict"`
prologues, and records a `StrictViolation` at every construct that would be a `SyntaxError` if its
enclosing region ran in strict mode. The tree is never altered.

The intended consumer is the reflection transform, which inlines payloads from always-sloppy surfaces
(`Function`, indirect `eval`, string timers) and must refuse an inlining that a strict destination would
reject. That wiring is deliberately not part of this module: a payload with no strict violation can still
diverge at runtime, so `collect_strict_violations` is necessary but not sufficient for that decision.
"""
from __future__ import annotations

from dataclasses import dataclass

from refinery.lib.scripts import Expression, Node, Statement
from refinery.lib.scripts.js.model import (
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsBlockStatement,
    JsCatchClause,
    JsClassDeclaration,
    JsClassExpression,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsIfStatement,
    JsImportDefaultSpecifier,
    JsImportNamespaceSpecifier,
    JsImportSpecifier,
    JsLabeledStatement,
    JsMemberExpression,
    JsMethodDefinition,
    JsNumericLiteral,
    JsObjectPattern,
    JsProperty,
    JsPropertyDefinition,
    JsRestElement,
    JsScript,
    JsStringLiteral,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsWithStatement,
    strip_parens,
)


@dataclass(frozen=True)
class StrictViolation:
    """
    A single strict-mode early error found in an otherwise sloppy-parsed tree. `rule` is a stable slug
    naming the violated restriction; `name` carries the offending identifier for the name-based rules and
    is empty otherwise. A violation only records that the code at `offset` would be a `SyntaxError` if its
    enclosing region ran in strict mode; the parse tree is never changed.
    """
    offset: int
    rule: str
    name: str = ''


def is_leading_zero_number(raw: str) -> bool:
    return len(raw) >= 2 and raw[0] == '0' and raw[1] in '0123456789'


def has_octal_string_escape(raw: str) -> bool:
    """
    Whether the raw text of a string literal contains a legacy octal or non-octal-decimal escape — a
    backslash followed by `1`-`9`, or by `0` immediately followed by another decimal digit. A plain `\\0`
    (the NUL escape) is legal, as is an escaped backslash `\\\\`, so the scan tracks escaping and only a
    backslash at an even distance from the previous literal character opens an escape.
    """
    body = raw[1:-1] if len(raw) >= 2 else raw
    i = 0
    n = len(body)
    while i < n:
        if body[i] != '\\':
            i += 1
            continue
        if i + 1 >= n:
            break
        nxt = body[i + 1]
        if nxt in '123456789':
            return True
        if nxt == '0':
            if i + 2 < n and body[i + 2] in '0123456789':
                return True
            i += 2
            continue
        i += 2
    return False


def is_use_strict(raw: str) -> bool:
    return len(raw) >= 2 and raw[1:-1] == 'use strict'


_STRICT_RESERVED = frozenset({
    'implements',
    'interface',
    'let',
    'package',
    'private',
    'protected',
    'public',
    'static',
    'yield',
})

_EVAL_ARGS = frozenset({'eval', 'arguments'})


def _has_use_strict_prologue(stmts: list[Statement]) -> bool:
    for stmt in stmts:
        if not isinstance(stmt, JsExpressionStatement):
            return False
        expr = stmt.expression
        if not isinstance(expr, JsStringLiteral):
            return False
        if is_use_strict(expr.raw):
            return True
    return False


def _child_strictness(node: Node, strict: bool) -> bool:
    if isinstance(node, JsScript):
        return strict or _has_use_strict_prologue(node.body)
    if isinstance(node, (JsClassDeclaration, JsClassExpression)):
        return True
    if isinstance(node, JsFunctionDeclaration):
        body = node.body
    elif isinstance(node, JsFunctionExpression):
        body = node.body
    elif isinstance(node, JsArrowFunctionExpression):
        body = node.body
    else:
        return strict
    if isinstance(body, JsBlockStatement):
        return strict or _has_use_strict_prologue(body.body)
    return strict


def _record_nested_function(stmt: Statement | None, out: list[StrictViolation]) -> None:
    if isinstance(stmt, JsFunctionDeclaration):
        out.append(StrictViolation(stmt.offset, 'function-in-statement'))


def _check_node(node: Node, strict: bool, out: list[StrictViolation]) -> None:
    if not strict:
        return
    if isinstance(node, JsNumericLiteral):
        if is_leading_zero_number(node.raw):
            out.append(StrictViolation(node.offset, 'octal-literal'))
    elif isinstance(node, JsStringLiteral):
        if has_octal_string_escape(node.raw):
            out.append(StrictViolation(node.offset, 'octal-escape'))
    elif isinstance(node, JsWithStatement):
        out.append(StrictViolation(node.offset, 'with-statement'))
    elif isinstance(node, JsUnaryExpression):
        if node.operator == 'delete':
            target = strip_parens(node.operand)
            if isinstance(target, JsIdentifier) and target.name != 'super':
                out.append(StrictViolation(node.offset, 'delete-of-reference'))
    elif isinstance(node, JsIfStatement):
        _record_nested_function(node.consequent, out)
        _record_nested_function(node.alternate, out)
    elif isinstance(node, JsLabeledStatement):
        _record_nested_function(node.body, out)
    elif isinstance(node, JsForInStatement):
        left = node.left
        if isinstance(left, JsVariableDeclaration) and left.kind is JsVarKind.VAR:
            declarations = left.declarations
            if len(declarations) == 1 and declarations[0].init is not None:
                out.append(StrictViolation(left.offset, 'for-in-var-init'))


def _target_identifiers(target: Node | None) -> list[JsIdentifier]:
    """
    Every identifier bound or assigned by a binding or assignment target, flattening array and object
    patterns, defaults, and rest elements down to their leaves. A pattern default value and a computed
    property key are references rather than targets, so they are left for the ordinary traversal; only
    the names actually bound by the pattern are returned.
    """
    result: list[JsIdentifier] = []
    stack: list[Node | None] = [target]
    while stack:
        node = stack.pop()
        if isinstance(node, JsIdentifier):
            result.append(node)
        elif isinstance(node, JsArrayPattern):
            stack.extend(node.elements)
        elif isinstance(node, JsObjectPattern):
            for prop in node.properties:
                if isinstance(prop, JsProperty):
                    stack.append(prop.value)
                elif isinstance(prop, JsRestElement):
                    stack.append(prop.argument)
        elif isinstance(node, JsAssignmentPattern):
            stack.append(node.left)
        elif isinstance(node, JsRestElement):
            stack.append(node.argument)
    return result


def _is_property_name_position(node: JsIdentifier) -> bool:
    parent = node.parent
    if isinstance(parent, JsMemberExpression):
        return parent.property is node and not parent.computed
    if isinstance(parent, (JsProperty, JsMethodDefinition, JsPropertyDefinition)):
        return parent.key is node and not parent.computed
    return False


def _flag_name(ident: JsIdentifier, out: list[StrictViolation]) -> None:
    if ident.name in _EVAL_ARGS:
        out.append(StrictViolation(ident.offset, 'eval-arguments-target', ident.name))
    elif ident.name in _STRICT_RESERVED:
        out.append(StrictViolation(ident.offset, 'reserved-word', ident.name))


def _flag_bound(target: Node | None, strict: bool, out: list[StrictViolation], handled: set[int]) -> None:
    for ident in _target_identifiers(target):
        handled.add(id(ident))
        if strict:
            _flag_name(ident, out)


def _check_parameters(
    params: list[Expression],
    strict: bool,
    out: list[StrictViolation],
    handled: set[int],
) -> None:
    seen: set[str] = set()
    for param in params:
        for ident in _target_identifiers(param):
            handled.add(id(ident))
            if not strict:
                continue
            _flag_name(ident, out)
            if ident.name in seen:
                out.append(StrictViolation(ident.offset, 'duplicate-parameter', ident.name))
            else:
                seen.add(ident.name)


def _check_names(
    node: Node,
    cur_strict: bool,
    child_strict: bool,
    out: list[StrictViolation],
    handled: set[int],
) -> None:
    if isinstance(node, (JsFunctionDeclaration, JsFunctionExpression)):
        _check_parameters(node.params, child_strict, out, handled)
        _flag_bound(node.id, child_strict, out, handled)
    elif isinstance(node, JsArrowFunctionExpression):
        _check_parameters(node.params, child_strict, out, handled)
    elif isinstance(node, (JsClassDeclaration, JsClassExpression)):
        _flag_bound(node.id, child_strict, out, handled)
    elif isinstance(node, JsVariableDeclarator):
        _flag_bound(node.id, cur_strict, out, handled)
    elif isinstance(node, JsCatchClause):
        _flag_bound(node.param, cur_strict, out, handled)
    elif isinstance(node, (JsImportSpecifier, JsImportDefaultSpecifier, JsImportNamespaceSpecifier)):
        _flag_bound(node.local, cur_strict, out, handled)
    elif isinstance(node, JsAssignmentExpression):
        _flag_bound(node.left, cur_strict, out, handled)
    elif isinstance(node, JsUpdateExpression):
        _flag_bound(node.argument, cur_strict, out, handled)
    elif isinstance(node, (JsForInStatement, JsForOfStatement)):
        if not isinstance(node.left, JsVariableDeclaration):
            _flag_bound(node.left, cur_strict, out, handled)
    elif isinstance(node, JsIdentifier):
        if (
            id(node) not in handled
            and cur_strict
            and node.name in _STRICT_RESERVED
            and not _is_property_name_position(node)
        ):
            out.append(StrictViolation(node.offset, 'reserved-word', node.name))


def collect_strict_violations(node: Node, *, strict: bool = False) -> list[StrictViolation]:
    """
    Every strict-mode early error in the tree rooted at *node*, in source order. *strict* seeds the
    strictness of *node* itself; the pass then forces strict inside class bodies and inside any function
    whose body opens with a `"use strict"` directive, so a violation is recorded even when the seed is
    sloppy but the offending code sits in an inherently strict region. An empty result means the tree has
    no strict-mode parse error; it does not imply the tree behaves identically in strict mode, since some
    divergences surface only at runtime.
    """
    out: list[StrictViolation] = []
    handled: set[int] = set()
    stack: list[tuple[Node, bool]] = [(node, strict)]
    while stack:
        current, current_strict = stack.pop()
        child_strict = _child_strictness(current, current_strict)
        _check_node(current, current_strict, out)
        _check_names(current, current_strict, child_strict, out, handled)
        for child in current.children():
            stack.append((child, child_strict))
    out.sort(key=lambda violation: violation.offset)
    return out
