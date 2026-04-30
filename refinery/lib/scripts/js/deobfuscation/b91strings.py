"""
The obfuscator replaces string literals with calls to per-scope caching accessor functions. Each
accessor lazily decodes an encoded string from a shared global string table through a base91
decoder that uses a unique shuffled 91-character alphabet. This transformer detects the
infrastructure structurally, decodes every string in Python, replaces accessor calls with string
literals, and removes the dead definitions.
"""
from __future__ import annotations

from typing import NamedTuple, Sequence

from refinery.lib.scripts import Node, Transformer, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.js.deobfuscation.helpers import make_string_literal, remove_declarator
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsArrayExpression,
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNumericLiteral,
    JsObjectExpression,
    JsScript,
    JsStringLiteral,
    JsVarKind,
    JsVariableDeclaration,
    JsVariableDeclarator,
)


def _decode_base91(encoded: str, alphabet: str) -> str:
    """
    Decode a base91-encoded string using the given 91-character alphabet. The encoding pairs
    characters from the alphabet into 13-or-14-bit values that are accumulated into a byte stream,
    which is then interpreted as UTF-8.
    """
    result: list[int] = []
    b = 0
    n = 0
    v = -1
    for ch in encoded:
        p = alphabet.find(ch)
        if p == -1:
            continue
        if v < 0:
            v = p
        else:
            v += p * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                result.append(b & 0xFF)
                b >>= 8
                n -= 8
            v = -1
    if v > -1:
        result.append((b | v << n) & 0xFF)
    return bytes(result).decode('utf-8')


def _is_base91_alphabet(s: str) -> bool:
    return len(s) == 91 and len(set(s)) == 91


class _DecoderInfo(NamedTuple):
    node: JsFunctionDeclaration
    name: str
    alphabet: str


class _AccessorInfo(NamedTuple):
    node: JsFunctionDeclaration
    name: str
    decoder_name: str
    table_name: str
    cache_name: str


class _StringTableInfo(NamedTuple):
    declarator: JsVariableDeclarator | None
    assignment: JsAssignmentExpression | None
    name: str
    strings: list[str]


def _try_string_array(init: Node) -> list[str] | None:
    """
    If *init* is an array of at least 10 string literals, return the string values.
    """
    if not isinstance(init, JsArrayExpression):
        return None
    elements = init.elements
    if len(elements) < 10:
        return None
    strings: list[str] = []
    for el in elements:
        if not isinstance(el, JsStringLiteral):
            return None
        strings.append(el.value)
    return strings


def _find_string_tables(root: Node) -> list[_StringTableInfo]:
    """
    Find string table arrays: either a `var`/`const`/`let` declarator whose initializer is an array
    of 10+ string literals, or a bare assignment `NAME = [...]` with the same shape. The latter
    covers the obfuscator pattern where variables are hoisted as `var NAME;` and later assigned via
    function default arguments.
    """
    tables: list[_StringTableInfo] = []
    seen: set[str] = set()
    for node in root.walk():
        if isinstance(node, JsVariableDeclarator):
            if not isinstance(node.id, JsIdentifier):
                continue
            if node.init is None:
                continue
            strings = _try_string_array(node.init)
            if strings is not None:
                tables.append(_StringTableInfo(node, None, node.id.name, strings))
                seen.add(node.id.name)
        elif isinstance(node, JsAssignmentExpression):
            if not isinstance(node.left, JsIdentifier):
                continue
            name = node.left.name
            if name in seen:
                continue
            rhs = node.right
            if rhs is None:
                continue
            strings = _try_string_array(rhs)
            if strings is not None:
                tables.append(_StringTableInfo(None, node, name, strings))
                seen.add(name)
    return tables


def _find_decoders(root: Node) -> list[_DecoderInfo]:
    """
    Find function declarations that are base91 decoder functions. A decoder is identified by having
    exactly one parameter and containing a local variable initialized to a 91-character string with
    91 unique characters (the shuffled base91 alphabet).
    """
    decoders: list[_DecoderInfo] = []
    for node in root.walk():
        if not isinstance(node, JsFunctionDeclaration):
            continue
        if node.id is None or node.body is None:
            continue
        if len(node.params) != 1:
            continue
        if not isinstance(node.body, JsBlockStatement):
            continue
        alphabet = _extract_alphabet(node.body.body)
        if alphabet is not None:
            decoders.append(_DecoderInfo(node, node.id.name, alphabet))
    return decoders


def _extract_alphabet(body: Sequence[Node]) -> str | None:
    """
    Scan the statements in a function body for a string literal of exactly 91 unique characters —
    the base91 decoder alphabet. Checks variable initializers first, then falls back to any string
    literal in the body (covers the case where constant inlining has folded the variable away).
    """
    for stmt in body:
        if not isinstance(stmt, JsVariableDeclaration):
            continue
        for decl in stmt.declarations:
            if not isinstance(decl, JsVariableDeclarator):
                continue
            if not isinstance(decl.init, JsStringLiteral):
                continue
            if _is_base91_alphabet(decl.init.value):
                return decl.init.value
    for stmt in body:
        for node in stmt.walk():
            if isinstance(node, JsStringLiteral) and _is_base91_alphabet(node.value):
                return node.value
    return None


def _find_accessors(
    root: Node,
    decoder_names: set[str],
    table_names: set[str],
) -> list[_AccessorInfo]:
    """
    Find caching accessor functions. An accessor has exactly one parameter and its body matches::

        if (typeof CACHE[param] === 'undefined') {
            return CACHE[param] = DECODER(TABLE[param]);
        }
        return CACHE[param];

    Detection is structural: the function must reference a known decoder and a known string table.
    """
    accessors: list[_AccessorInfo] = []
    for node in root.walk():
        if not isinstance(node, JsFunctionDeclaration):
            continue
        if node.id is None or node.body is None:
            continue
        if len(node.params) != 1:
            continue
        if not isinstance(node.body, JsBlockStatement):
            continue
        if not isinstance(node.params[0], JsIdentifier):
            continue
        if len(node.body.body) != 2:
            continue
        info = _match_accessor_body(node, decoder_names, table_names)
        if info is not None:
            accessors.append(info)
    return accessors


def _match_accessor_body(
    func: JsFunctionDeclaration,
    decoder_names: set[str],
    table_names: set[str],
) -> _AccessorInfo | None:
    """
    Check if a function body matches the caching accessor pattern. Looks for a call expression of
    the form `DECODER(TABLE[param])` inside the body to structurally identify the decoder and
    table references, and extracts the cache variable name from the member access pattern.
    """
    assert func.id is not None and func.body is not None
    decoder_name: str | None = None
    table_name: str | None = None
    cache_name: str | None = None
    for node in func.body.walk():
        if not isinstance(node, JsCallExpression):
            continue
        if not isinstance(node.callee, JsIdentifier):
            continue
        if node.callee.name not in decoder_names:
            continue
        if len(node.arguments) != 1:
            continue
        arg = node.arguments[0]
        if not isinstance(arg, JsMemberExpression):
            continue
        if not isinstance(arg.object, JsIdentifier):
            continue
        if arg.object.name not in table_names:
            continue
        decoder_name = node.callee.name
        table_name = arg.object.name
        break
    if decoder_name is None or table_name is None:
        return None
    for node in func.body.walk():
        if not isinstance(node, JsMemberExpression):
            continue
        if not isinstance(node.object, JsIdentifier):
            continue
        if node.object.name == table_name:
            continue
        if node.object.name == func.id.name:
            continue
        cache_name = node.object.name
        break
    if cache_name is None:
        return None
    return _AccessorInfo(func, func.id.name, decoder_name, table_name, cache_name)


class _ScopedAccessor(NamedTuple):
    """
    A fully resolved accessor: its function declaration node, the decoder alphabet that applies to
    it (from its sibling decoder in the same scope), and the shared encoded string table.
    """
    node: JsFunctionDeclaration
    name: str
    alphabet: str
    strings: list[str]


def _find_enclosing_body(node: Node) -> list | None:
    """
    Walk up parent pointers from *node* to find the body list that directly contains it. Returns
    the `body` attribute of the nearest `JsBlockStatement` or `JsScript` ancestor whose body
    list includes *node* (or an ancestor of *node*).
    """
    child = node
    parent = node.parent
    while parent is not None:
        if isinstance(parent, (JsBlockStatement, JsScript)):
            if child in parent.body:
                return parent.body
        child = parent
        parent = parent.parent
    return None


def _pair_accessors_with_decoders(
    accessors: list[_AccessorInfo],
    decoders: list[_DecoderInfo],
    tables: list[_StringTableInfo],
) -> list[_ScopedAccessor]:
    """
    Pair each accessor with its decoder by scope proximity. An accessor's `decoder_name` refers
    to a decoder function declared in the same body list. When the same function name is reused
    across nested scopes, this ensures each accessor gets the correct alphabet.
    """
    table_map = {t.name: t.strings for t in tables}
    decoder_by_scope: dict[tuple[int, str], _DecoderInfo] = {}
    for d in decoders:
        body = _find_enclosing_body(d.node)
        if body is not None:
            decoder_by_scope[id(body), d.name] = d
    result: list[_ScopedAccessor] = []
    for a in accessors:
        strings = table_map.get(a.table_name)
        if strings is None:
            continue
        body = _find_enclosing_body(a.node)
        if body is None:
            continue
        decoder = decoder_by_scope.get((id(body), a.decoder_name))
        if decoder is None:
            continue
        result.append(_ScopedAccessor(a.node, a.name, decoder.alphabet, strings))
    return result


def _resolve_calls(
    root: Node,
    scoped_accessors: list[_ScopedAccessor],
) -> int:
    """
    Walk the AST and replace accessor calls `ACCESSOR(numericLiteral)` with the decoded string
    literal. Uses scope-aware matching: for each call, walks up the AST to find the nearest
    enclosing body that contains a function declaration matching a known accessor.
    """
    accessor_by_scope: dict[tuple[int, str], _ScopedAccessor] = {}
    for sa in scoped_accessors:
        body = _find_enclosing_body(sa.node)
        if body is not None:
            accessor_by_scope[id(body), sa.name] = sa
    accessor_names = {sa.name for sa in scoped_accessors}
    count = 0
    for node in list(root.walk()):
        if not isinstance(node, JsCallExpression):
            continue
        if not isinstance(node.callee, JsIdentifier):
            continue
        name = node.callee.name
        if name not in accessor_names:
            continue
        if len(node.arguments) != 1:
            continue
        arg = node.arguments[0]
        if not isinstance(arg, JsNumericLiteral):
            continue
        sa = _find_scoped_accessor(node, name, accessor_by_scope)
        if sa is None:
            continue
        idx = int(arg.value)
        if not (0 <= idx < len(sa.strings)):
            continue
        try:
            decoded = _decode_base91(sa.strings[idx], sa.alphabet)
        except (UnicodeDecodeError, ValueError):
            continue
        _replace_in_parent(node, make_string_literal(decoded))
        count += 1
    return count


def _find_scoped_accessor(
    call_node: Node,
    name: str,
    accessor_by_scope: dict[tuple[int, str], _ScopedAccessor],
) -> _ScopedAccessor | None:
    """
    Walk up from *call_node* through enclosing body lists to find the nearest scope that contains
    an accessor declaration with the given *name*. This implements JavaScript's lexical scoping:
    inner scopes shadow outer ones.
    """
    child = call_node
    parent = call_node.parent
    while parent is not None:
        if isinstance(parent, (JsBlockStatement, JsScript)):
            if child in parent.body:
                sa = accessor_by_scope.get((id(parent.body), name))
                if sa is not None:
                    return sa
        child = parent
        parent = parent.parent
    return None


def _has_references(root: Node, name: str, exclude_ids: set[int]) -> bool:
    """
    Check whether *name* is referenced anywhere in the AST outside of nodes whose `id` is in
    *exclude_ids*. Scope-aware: identifiers inside function bodies that contain a local `var`
    declaration of the same name are considered shadowed and are not counted as references. Bare
    hoisted declarations (`var NAME;` with no initializer) are not counted as references either.
    """
    for node in root.walk():
        if id(node) in exclude_ids:
            continue
        parent = node.parent
        if parent is not None and id(parent) in exclude_ids:
            continue
        if not isinstance(node, JsIdentifier) or node.name != name:
            continue
        # A bare hoisted var declaration (var NAME;) is not a reference
        if (
            isinstance(parent, JsVariableDeclarator)
            and parent.id is node
            and parent.init is None
        ):
            continue
        if _is_shadowed(node, name):
            continue
        return True
    return False


def _is_shadowed(node: Node, name: str) -> bool:
    """
    Walk up from *node* through all enclosing function boundaries and check whether any of them
    contains a `var` declaration of *name*. Because `var` is function-scoped and closures capture
    outer function variables, the identifier is shadowed if **any** enclosing function (not just the
    innermost) declares it.
    """
    parent = node.parent
    while parent is not None:
        if isinstance(parent, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
            body = getattr(parent, 'body', None)
            if isinstance(body, JsBlockStatement):
                if _body_declares_var(body.body, name):
                    return True
        parent = parent.parent
    return False


def _body_declares_var(body: list, name: str) -> bool:
    """
    Check whether a function body's statement list contains a `var` declaration that includes
    a declarator with the given *name*.
    """
    for stmt in body:
        if not isinstance(stmt, JsVariableDeclaration):
            continue
        if stmt.kind != JsVarKind.VAR:
            continue
        for decl in stmt.declarations:
            if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                if decl.id.name == name:
                    return True
    return False


def _remove_assignment_table(table: _StringTableInfo) -> None:
    """
    Remove an assignment-based string table. This handles the pattern where the variable is hoisted
    as `var NAME;` and later assigned as `NAME = [...]`. Removes the expression statement
    containing the assignment and the hoisted declarator (if it has no initializer). The hoisted
    declarator is searched only in the same body as the assignment to avoid removing same-named
    variables in inner scopes.
    """
    assert table.assignment is not None
    stmt = table.assignment.parent
    body = _find_enclosing_body(stmt) if isinstance(stmt, JsExpressionStatement) else None
    if isinstance(stmt, JsExpressionStatement):
        _remove_from_parent(stmt)
    if body is None:
        return
    for item in body:
        if not isinstance(item, JsVariableDeclaration):
            continue
        for decl in item.declarations:
            if (
                isinstance(decl, JsVariableDeclarator)
                and isinstance(decl.id, JsIdentifier)
                and decl.id.name == table.name
                and decl.init is None
            ):
                remove_declarator(decl)
                return


def _cleanup(
    root: Node,
    accessors: list[_AccessorInfo],
    decoders: list[_DecoderInfo],
    tables: list[_StringTableInfo],
    cache_names: set[str],
) -> None:
    """
    Remove accessor functions, decoder functions, string tables, cache objects, and the global
    bufferToString / utf8ArrayToStr / getGlobal infrastructure once all strings have been resolved.
    """
    dead_ids: set[int] = set()
    for a in accessors:
        dead_ids.add(id(a.node))
    for d in decoders:
        dead_ids.add(id(d.node))
    for t in tables:
        if t.declarator is not None:
            dead_ids.add(id(t.declarator))
        if t.assignment is not None:
            dead_ids.add(id(t.assignment))
    for a in accessors:
        _remove_from_parent(a.node)
    for d in decoders:
        _remove_from_parent(d.node)
    for t in tables:
        if not _has_references(root, t.name, dead_ids):
            if t.declarator is not None:
                remove_declarator(t.declarator)
            elif t.assignment is not None:
                _remove_assignment_table(t)
    for node in list(root.walk()):
        if isinstance(node, JsVariableDeclarator) and isinstance(node.id, JsIdentifier):
            if node.id.name in cache_names and isinstance(node.init, JsObjectExpression):
                if not node.init.properties:
                    if not _has_references(root, node.id.name, dead_ids):
                        remove_declarator(node)
    _remove_buffer_infrastructure(root)


def _remove_buffer_infrastructure(root: Node) -> None:
    """
    Remove the bufferToString function, utf8ArrayToStr IIFE, getGlobal function, and related
    scaffolding. Detection is structural: the getGlobal function contains `globalThis` and
    `"return this"`; bufferToString tests for TextDecoder and returns UTF-8 decoded output.
    """
    get_global_name: str | None = None
    get_global_node: JsFunctionDeclaration | None = None
    buffer_to_string_node: JsFunctionDeclaration | None = None
    for node in root.walk():
        if not isinstance(node, JsFunctionDeclaration):
            continue
        if node.id is None or node.body is None:
            continue
        if not isinstance(node.body, JsBlockStatement):
            continue
        has_global_this = False
        has_return_this = False
        has_utf8 = False
        has_typeof_undef = False
        for child in node.body.walk():
            if isinstance(child, JsIdentifier) and child.name == 'globalThis':
                has_global_this = True
            if isinstance(child, JsStringLiteral) and child.value == 'return this':
                has_return_this = True
            if isinstance(child, JsStringLiteral) and child.value == 'utf-8':
                has_utf8 = True
            if isinstance(child, JsStringLiteral) and child.value == 'undefined':
                has_typeof_undef = True
        if has_global_this and has_return_this:
            get_global_name = node.id.name
            get_global_node = node
        elif has_utf8 and has_typeof_undef and len(node.params) == 1:
            buffer_to_string_node = node
    if get_global_node is not None:
        _remove_from_parent(get_global_node)
    if buffer_to_string_node is not None:
        _remove_from_parent(buffer_to_string_node)
    if not isinstance(root, JsScript) or get_global_name is None:
        return
    for stmt in list(root.body):
        if isinstance(stmt, JsVariableDeclaration):
            for decl in list(stmt.declarations):
                if not isinstance(decl, JsVariableDeclarator):
                    continue
                if not isinstance(decl.id, JsIdentifier):
                    continue
                if isinstance(decl.init, JsCallExpression):
                    if (
                        isinstance(decl.init.callee, JsIdentifier)
                        and decl.init.callee.name == get_global_name
                    ):
                        remove_declarator(decl)
                        continue
                    if isinstance(decl.init.callee, JsFunctionExpression):
                        for child in decl.init.callee.walk():
                            if (
                                isinstance(child, JsStringLiteral)
                                and child.value == 'fromCodePoint'
                            ):
                                remove_declarator(decl)
                                break
        if not isinstance(stmt, JsExpressionStatement):
            continue
        expr = stmt.expression
        if not isinstance(expr, JsAssignmentExpression) or not isinstance(expr.left, JsIdentifier):
            continue
        for child in (expr.right.walk() if expr.right is not None else ()):
            if not isinstance(child, JsCallExpression):
                continue
            callee = child.callee
            if isinstance(callee, JsIdentifier) and callee.name == get_global_name:
                _remove_from_parent(stmt)
                break
            if isinstance(callee, JsFunctionExpression):
                if any(
                    isinstance(n, JsStringLiteral) and n.value == 'fromCodePoint'
                    for n in callee.walk()
                ):
                    _remove_from_parent(stmt)
                    break


class JsBase91StringDecoder(Transformer):
    """
    Resolve per-scope b91 string obfuscation. Detects the shared encoded string table, per-scope
    base91 decoders with shuffled alphabets, and caching accessor functions. Decodes all strings in
    Python and replaces accessor calls with string literals.
    """

    def visit_JsScript(self, node: JsScript):
        tables = _find_string_tables(node)
        if not tables:
            return None
        decoders = _find_decoders(node)
        if not decoders:
            return None
        decoder_names = {d.name for d in decoders}
        table_names = {t.name for t in tables}
        accessors = _find_accessors(node, decoder_names, table_names)
        if not accessors:
            return None
        scoped_accessors = _pair_accessors_with_decoders(accessors, decoders, tables)
        if not scoped_accessors:
            return None
        count = _resolve_calls(node, scoped_accessors)
        if count == 0:
            return None
        cache_names = {a.cache_name for a in accessors}
        resolved_accessor_nodes = {id(sa.node) for sa in scoped_accessors}
        resolved_accessors = [a for a in accessors if id(a.node) in resolved_accessor_nodes]
        resolved_decoder_names = {a.decoder_name for a in resolved_accessors}
        resolved_decoders = [d for d in decoders if d.name in resolved_decoder_names]
        _cleanup(node, resolved_accessors, resolved_decoders, tables, cache_names)
        self.mark_changed()
        return None

    def generic_visit(self, node: Node):
        pass
