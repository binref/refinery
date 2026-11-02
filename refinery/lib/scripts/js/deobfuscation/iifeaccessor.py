"""
Promote IIFE-bound function accessors to plain function declarations.

Recognizes the pattern

    var X = function () {
        var c1 = <literal>;
        var c2 = <literal-array>;
        return function (p) { ... uses c1, c2 ... };
    }();

and rewrites it as

    function X(p) {
        var c1 = <literal>;
        var c2 = <literal-array>;
        ... uses c1, c2 ...
    }

This is a common obfuscator pattern where a string-decoding accessor is built once and bound to a
variable through the result of an IIFE that closes over a constant lookup table and a few scalar
parameters. `refinery.lib.scripts.js.deobfuscation.evaluator.JsFunctionEvaluator` only registers
`refinery.lib.scripts.js.model.JsFunctionDeclaration` nodes in its scope tree, so call sites like
`X(0x3a2)` are otherwise never folded. The rewrite is only applied when the returned function
assigns no captured variable and only reads through a captured list or object, and no list or
object such a read answers leaves the call (`_closed_over_containers_stay_unchanged`); under that
condition building the captured values afresh at every call computes what the one build the IIFE
ran did. After the rewrite, the function evaluator folds each call site to its computed string
literal.

The declaration has to stand at the top level of a function, a module or a script, exported or
not, where a function declaration names the scope the declarator named. In a block it would name
the block, which strict code keeps it in and sloppy code copies it out of (Annex B.3.3), and neither
is where a `var`, a `let` or a `const` there puts its name.
"""
from __future__ import annotations

from typing import Iterable, Iterator, NamedTuple

from refinery.lib.scripts import (
    Node,
    _clone_node,
    _replace_in_parent,
)
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    Binding,
    ContainerRole,
    container_reference_role,
    enclosing_operator,
    hoists_its_functions,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    extract_identifier_params,
    is_literal,
    references_receiver_this,
    walk_receiver_scope,
    walk_scope,
)
from refinery.lib.scripts.js.keys import key_text
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsExportNamedDeclaration,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsObjectExpression,
    JsProperty,
    JsReturnStatement,
    JsScript,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    is_async_function,
    is_generator_function,
    object_sets_prototype,
    strip_parens,
    wraps_return,
)
from refinery.lib.scripts.js.strict import directive_prologue


def _is_literal_initializer(node: Node | None) -> bool:
    if node is None:
        return False
    if is_literal(node):
        return True
    if isinstance(node, JsArrayExpression):
        return all(el is not None and _is_literal_initializer(el) for el in node.elements)
    if isinstance(node, JsObjectExpression):
        for prop in node.properties:
            if not isinstance(prop, JsProperty):
                return False
            if prop.value is None or not _is_literal_initializer(prop.value):
                return False
        return True
    return False


class _Pattern(NamedTuple):
    declaration: JsVariableDeclaration
    name: str
    closure_decls: list[JsVariableDeclaration]
    inner_func: JsFunctionExpression | JsArrowFunctionExpression


def _detect(declarator: JsVariableDeclarator) -> _Pattern | None:
    if not isinstance(declarator.id, JsIdentifier):
        return None
    declaration = declarator.parent
    if not isinstance(declaration, JsVariableDeclaration):
        return None
    if len(declaration.declarations) != 1:
        return None
    statement: Node = declaration
    if isinstance(statement.parent, JsExportNamedDeclaration):
        statement = statement.parent
    if (holder := statement.parent) is None or not hoists_its_functions(holder):
        return None
    init = strip_parens(declarator.init)
    if not isinstance(init, JsCallExpression):
        return None
    if init.arguments:
        return None
    callee = strip_parens(init.callee)
    if not isinstance(callee, (JsFunctionExpression, JsArrowFunctionExpression)):
        return None
    if wraps_return(callee):
        return None
    if callee.params:
        return None
    body = callee.body
    if not isinstance(body, JsBlockStatement) or not body.body:
        return None
    closure_decls: list[JsVariableDeclaration] = []
    inner_func: JsFunctionExpression | JsArrowFunctionExpression | None = None
    for stmt in body.body:
        if inner_func is not None:
            return None
        if isinstance(stmt, JsVariableDeclaration):
            for decl in stmt.declarations:
                if not isinstance(decl, JsVariableDeclarator):
                    return None
                if not isinstance(decl.id, JsIdentifier):
                    return None
                if not _is_literal_initializer(decl.init):
                    return None
            closure_decls.append(stmt)
            continue
        if isinstance(stmt, JsReturnStatement):
            ret_arg = strip_parens(stmt.argument)
            if not isinstance(ret_arg, (JsFunctionExpression, JsArrowFunctionExpression)):
                return None
            if not isinstance(ret_arg.body, JsBlockStatement):
                return None
            inner_func = ret_arg
            continue
        return None
    if inner_func is None:
        return None
    return _Pattern(declaration, declarator.id.name, closure_decls, inner_func)


def _closure_names(closure_decls: list[JsVariableDeclaration]) -> set[str]:
    names: set[str] = set()
    for decl in closure_decls:
        for d in decl.declarations:
            if isinstance(d, JsVariableDeclarator) and isinstance(d.id, JsIdentifier):
                names.add(d.id.name)
    return names


def _is_safe_to_promote(
    inner: JsFunctionExpression | JsArrowFunctionExpression,
    closure_names: set[str],
) -> bool:
    param_names = extract_identifier_params(inner.params)
    if param_names is None:
        return False
    if any(p in closure_names for p in param_names):
        return False
    body = inner.body
    if not isinstance(body, JsBlockStatement):
        return False
    inner_name: str | None = None
    if isinstance(inner, JsFunctionExpression) and isinstance(inner.id, JsIdentifier):
        inner_name = inner.id.name
    if references_receiver_this(body):
        return False
    for node in walk_receiver_scope(body):
        if isinstance(node, JsIdentifier) and node.name == 'arguments':
            return False
    for node in walk_scope(body):
        if inner_name is not None and isinstance(node, JsIdentifier) and node.name == inner_name:
            return False
    for node in body.walk():
        if isinstance(node, JsAssignmentExpression):
            if isinstance(node.left, JsIdentifier) and node.left.name in closure_names:
                return False
        if isinstance(node, JsUpdateExpression):
            if (
                isinstance(node.argument, JsIdentifier)
                and node.argument.name in closure_names
            ):
                return False
        if isinstance(node, JsVariableDeclarator):
            if isinstance(node.id, JsIdentifier) and node.id.name in closure_names:
                return False
        if isinstance(node, FUNCTION_NODES) and node is not inner:
            for p in node.params:
                if isinstance(p, JsIdentifier) and p.name in closure_names:
                    return False
            if (
                isinstance(node, JsFunctionDeclaration)
                and isinstance(node.id, JsIdentifier)
                and node.id.name in closure_names
            ):
                return False
    return True


_Container = JsArrayExpression | JsObjectExpression


def _containers(values: Iterable[Node]) -> list[_Container]:
    return [value for value in values if isinstance(value, (JsArrayExpression, JsObjectExpression))]


def _held_values(literal: _Container) -> list[Node]:
    if isinstance(literal, JsArrayExpression):
        return [element for element in literal.elements if element is not None]
    return [
        prop.value for prop in literal.properties
        if isinstance(prop, JsProperty) and prop.value is not None
    ]


def _containers_within(literal: _Container) -> Iterator[_Container]:
    yield literal
    for held in _containers(_held_values(literal)):
        yield from _containers_within(held)


def _values_read_under(literal: _Container, key: str | None) -> list[Node]:
    """
    The values the closure built that a read of *key* off *literal* may answer: the one it holds
    under that key, or every one it holds where the key has no text. A key the literal does not hold
    answers a primitive or a value of the language, such as `length` or a method of a prototype,
    which no call of the accessor builds.
    """
    if key is None:
        return _held_values(literal)
    if isinstance(literal, JsArrayExpression):
        if not key.isascii() or not key.isdigit() or str(int(key)) != key:
            return []
        index = int(key)
        elements = literal.elements
        if index >= len(elements) or (element := elements[index]) is None:
            return []
        return [element]
    return [
        prop.value for prop in literal.properties
        if isinstance(prop, JsProperty) and prop.value is not None and key_text(prop) in (key, None)
    ]


def _read_values_stay_in_the_call(cache: ModelCache, binding: Binding, held: list[_Container]) -> bool:
    """
    Whether no list or object the closure built leaves a call through a read of *binding*, which
    holds one of *held*. Every reference reads through the binding or only tests it, and a read that
    may answer such a list or object is only tested, read through in turn, or the value of a
    variable that is itself only read through (`_stored_where_it_is_only_read_through`).
    """
    if binding.dynamic_refs:
        return False
    for reference in cache.model.references(binding):
        role = container_reference_role(reference)
        if role is ContainerRole.VERDICT_READ:
            continue
        if role is not ContainerRole.MEMBER_READ:
            return False
        read: Node = reference
        values: list[Node] = list(held)
        while (
            isinstance(member := enclosing_operator(read), JsMemberExpression)
            and strip_parens(member.object) is read
        ):
            key = key_text(member)
            values = [value for container in _containers(values) for value in _values_read_under(container, key)]
            read = member
        if not (answered := _containers(values)):
            continue
        if not isinstance(read, JsMemberExpression):
            return False
        if container_reference_role(read) is ContainerRole.VERDICT_READ:
            continue
        if not _stored_where_it_is_only_read_through(cache, read, answered):
            return False
    return True


def _stored_where_it_is_only_read_through(
    cache: ModelCache,
    read: JsMemberExpression,
    answered: list[_Container],
) -> bool:
    """
    Whether *read*, which may answer one of the lists or objects *answered*, initializes a variable
    nothing else writes and that is only read through
    (`refinery.lib.scripts.js.analysis.effects.EffectModel.binding_is_immutable_container`), with no
    list or object its own reads answer leaving the call either.
    """
    declarator = enclosing_operator(read)
    if not isinstance(declarator, JsVariableDeclarator) or strip_parens(declarator.init) is not read:
        return False
    if not isinstance(name := declarator.id, JsIdentifier):
        return False
    variable = cache.model.binding_of(name)
    return (
        variable is not None
        and not variable.writes
        and cache.effects.binding_is_immutable_container(variable)
        and _read_values_stay_in_the_call(cache, variable, answered)
    )


def _closed_over_containers_stay_unchanged(
    cache: ModelCache,
    closure_decls: list[JsVariableDeclaration],
) -> bool:
    """
    Whether every list or object the closure builds stays as it was and inside each call. The IIFE
    builds such a value once, so what one call writes into it, and its identity, reach the next
    call, which the promoted declaration starts from a fresh value instead. The list or object a
    captured variable holds is only read through: never written into, given to a method that may
    change it, or handed out
    (`refinery.lib.scripts.js.analysis.effects.EffectModel.binding_is_immutable_container`). A call
    on a value it holds is vouched for where every such value is a primitive, which no call can
    change. A list or object it holds is one the closure built as well, so no read may hand one out
    (`_read_values_stay_in_the_call`); an object literal setting its prototype is declined, because a
    read of a key it does not hold may then answer a value the prototype holds.
    """
    for statement in closure_decls:
        for declarator in statement.declarations:
            if not isinstance(declarator, JsVariableDeclarator):
                return False
            literal = declarator.init
            if not isinstance(literal, (JsArrayExpression, JsObjectExpression)):
                continue
            if not isinstance(name := declarator.id, JsIdentifier):
                return False
            if (binding := cache.model.binding_of(name)) is None:
                return False
            nested = bool(_containers(_held_values(literal)))
            inert = None if nested else frozenset()
            if not cache.effects.binding_is_immutable_container(binding, inert_methods=inert):
                return False
            if not nested:
                continue
            if any(
                isinstance(container, JsObjectExpression) and object_sets_prototype(container)
                for container in _containers_within(literal)
            ):
                return False
            if not _read_values_stay_in_the_call(cache, binding, [literal]):
                return False
    return True


class JsIIFEAccessorPromoter(ScriptLevelTransformer):
    """
    Detect accessor variables built from an IIFE that closes over literal lookup tables, and
    rewrite each one into a plain named function declaration so that the function evaluator can
    fold its call sites.
    """

    def _process_script(self, node: JsScript) -> None:
        """
        Every accessor is decided against the tree the pass entered on and promoted afterwards, so
        no decision reads models of a tree an earlier promotion already changed.
        """
        cache = model_cache(self, node)
        promotions: list[_Pattern] = []
        for declarator in list(node.walk()):
            if not isinstance(declarator, JsVariableDeclarator):
                continue
            pattern = _detect(declarator)
            if pattern is None:
                continue
            closure_names = _closure_names(pattern.closure_decls)
            if not _is_safe_to_promote(pattern.inner_func, closure_names):
                continue
            if not _closed_over_containers_stay_unchanged(cache, pattern.closure_decls):
                continue
            promotions.append(pattern)
        for pattern in promotions:
            self._promote(pattern)

    def _promote(self, pattern: _Pattern) -> None:
        """
        Rewrite the accessor as a function declaration of the same kind, moving the closure's
        declarations into the inner function's body. The kind is carried rather than defaulted: an
        accessor that was `async` returns a promise and one that was a generator returns an iterator,
        and a declaration that dropped either would compute a different value — a `yield` left in a
        body no longer marked `*` does not even parse.

        They go behind that body's Directive Prologue rather than at its head. A declaration written
        above a `'use strict'` ends the prologue before it is reached, and the promoted function runs
        sloppy where the source wrote it strict. Behind the prologue is a position the declarations
        can always take: a prologue is string literals, which read nothing and so cannot observe a
        binding that is now introduced after them. That is the reason, and not that the declarations
        happen to be `var`s — `_detect` accepts any `JsVariableDeclaration`, `let` and `const`
        included.
        """
        inner = pattern.inner_func
        inner_body = inner.body
        if not isinstance(inner_body, JsBlockStatement):
            return
        carried = [_clone_node(s) for s in inner_body.body]
        prologue = len(directive_prologue(inner_body))
        new_body_stmts = carried[:prologue]
        new_body_stmts.extend(_clone_node(d) for d in pattern.closure_decls)
        new_body_stmts.extend(carried[prologue:])
        new_func = JsFunctionDeclaration(
            id=JsIdentifier(name=pattern.name),
            params=[_clone_node(p) for p in inner.params],
            body=JsBlockStatement(body=new_body_stmts),
            generator=is_generator_function(inner),
            is_async=is_async_function(inner),
        )
        _replace_in_parent(pattern.declaration, new_func)
        self.mark_changed()
