"""
Remove the obfuscator.io self-defending anti-tamper pattern.

The obfuscator emits a run-once wrapper factory and one or more guard sites. Each guard hands the
global object and a payload function to the factory and invokes the result:

    FACTORY = (function () {
        var flag = true;
        return function (recv, payload) {
            var run = flag
                ? function () { if (payload) { var x = payload.apply(recv, arguments); return payload = null, x; } }
                : function () {};
            return flag = false, run;
        };
    }());
    var guard = FACTORY(this, function () { /* anti-analysis payload */ });
    guard();

This transformer detects the pattern in two independent ways and removes the factory and each guard
invocation:

- By the ReDoS signature string `(((.+)+)+)+$` carried by the payload.
- Structurally, by the run-once `apply`-payload factory template together with a positive
  anti-analysis marker in the guard's payload, which covers payloads that do not carry the ReDoS
  string: the console-disable payload writes `console` members, and the debug-protection payload
  tests function source text with a regular expression.

Both detectors feed the same shared removal executor.
"""
from __future__ import annotations

from refinery.lib.scripts import _remove_from_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    binding_has_references,
    remove_declarator,
    value_is_discarded,
)
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsConditionalExpression,
    JsExpressionStatement,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNullLiteral,
    JsParenthesizedExpression,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsThisExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    strip_parens,
)

_REDOS_SIGNATURE = '(((.+)+)+)+$'


def _is_global_receiver(node) -> bool:
    node = strip_parens(node)
    if isinstance(node, JsThisExpression):
        return True
    return isinstance(node, JsIdentifier) and node.name in ('globalThis', 'window', 'self', 'global')


def _is_empty_function(node) -> bool:
    node = strip_parens(node)
    return isinstance(node, JsFunctionExpression) and node.body is not None and not node.body.body


def _holds_apply_and_nulling(model, fn, recv_b, payload_b) -> bool:
    """
    Whether `fn` contains both actions the template's run-once branch performs on the factory's
    parameters: an invocation `payload.apply(recv, ...)` or `payload.call(recv, ...)`, and a
    `payload = null` assignment, each resolved through the param bindings rather than by name.
    """
    apply_shape = False
    payload_nulled = False
    for n in fn.walk():
        if isinstance(n, JsCallExpression):
            callee = strip_parens(n.callee)
            if isinstance(callee, JsMemberExpression):
                prop = callee.property
                prop_name = getattr(prop, 'name', None) or getattr(prop, 'value', None)
                base = strip_parens(callee.object)
                arg0 = strip_parens(n.arguments[0]) if n.arguments else None
                if (
                    prop_name in ('apply', 'call')
                    and isinstance(base, JsIdentifier)
                    and model.resolve(base) is payload_b
                    and isinstance(arg0, JsIdentifier)
                    and model.resolve(arg0) is recv_b
                ):
                    apply_shape = True
        if isinstance(n, JsAssignmentExpression) and n.operator == '=':
            lhs = strip_parens(n.left)
            rhs = strip_parens(n.right)
            if (
                isinstance(lhs, JsIdentifier)
                and model.resolve(lhs) is payload_b
                and isinstance(rhs, JsNullLiteral)
            ):
                payload_nulled = True
    return apply_shape and payload_nulled


def _matches_self_defending_factory(model, fn) -> bool:
    """
    True when `fn` matches the run-once `apply`-payload factory template: exactly two plain-identifier
    params `(recv, payload)`, and one conditional tying the template's shapes to a single run-once
    branch — an empty function expression as its alternate, a consequent function holding both a
    `payload.apply(recv, ...)` (or `.call`) invocation and a `payload = null` assignment resolved
    through the param bindings, and a test naming the run-once flag: a binding that is not a
    parameter, is declared outside `fn`, and is written inside it. A wrapper whose conditional tests
    its payload parameter — the shape a benign `once` utility takes — has no such flag and does not
    match.
    """
    if not isinstance(fn, FUNCTION_NODES) or len(fn.params) != 2:
        return False
    if not all(isinstance(p, JsIdentifier) for p in fn.params):
        return False
    recv_b = model.binding_of(fn.params[0])
    payload_b = model.binding_of(fn.params[1])
    if recv_b is None or payload_b is None:
        return False
    for n in fn.walk():
        if not isinstance(n, JsConditionalExpression):
            continue
        if not _is_empty_function(n.alternate):
            continue
        consequent = strip_parens(n.consequent)
        if not isinstance(consequent, FUNCTION_NODES):
            continue
        if not _holds_apply_and_nulling(model, consequent, recv_b, payload_b):
            continue
        test = strip_parens(n.test)
        if not isinstance(test, JsIdentifier):
            continue
        flag = model.resolve(test)
        if flag is None or flag is recv_b or flag is payload_b:
            continue
        if any(declaration.is_descendant_of(fn) for declaration in flag.declarations):
            continue
        if not any(write.is_descendant_of(fn) for write in flag.writes):
            continue
        return True
    return False


_SOURCE_SHAPE_REGEX = 'function *\\('


def _payload_carries_anti_analysis_marker(payload) -> bool:
    """
    Whether the function handed to a matched factory carries positive evidence of an anti-analysis
    payload. Real obfuscator.io guard payloads — measured over the self-defending, console-disable,
    and debug-protection features of versions 0.28.5, 2.19.1, and 5.6.0 — each carry at least one
    of: the ReDoS signature string; an assignment through a `console` member, which the
    console-disable payload uses to overwrite every log method; or a string literal spelling a
    regular expression over function source text, which the debug-protection payload tests its
    callers with. A benign run-once wrapper's payload carries none, so the structural remover
    demands one before it deletes a guard. Reading a `console` member is not a marker: a benign
    payload logs, only an anti-analysis one overwrites.
    """
    payload = strip_parens(payload)
    if payload is None:
        return False
    for n in payload.walk():
        if isinstance(n, JsStringLiteral) and n.value is not None:
            if _REDOS_SIGNATURE in n.value or _SOURCE_SHAPE_REGEX in n.value:
                return True
        if isinstance(n, JsAssignmentExpression):
            target = strip_parens(n.left)
            if not isinstance(target, JsMemberExpression):
                continue
            prop = target.property
            prop_name = getattr(prop, 'name', None) or getattr(prop, 'value', None)
            base = strip_parens(target.object)
            if prop_name == 'console' or (isinstance(base, JsIdentifier) and base.name == 'console'):
                return True
    return False


def _removal_unit(call: JsCallExpression) -> JsCallExpression:
    """
    Return the IIFE call that wraps `call` when `call` is the sole statement of an immediately-invoked
    function body, otherwise return `call` itself.
    """
    es = call.parent
    if not isinstance(es, JsExpressionStatement):
        return call
    block = es.parent
    if not isinstance(block, JsBlockStatement) or len(block.body) != 1:
        return call
    fn = block.parent
    if not isinstance(fn, FUNCTION_NODES):
        return call
    outer = fn.parent
    while isinstance(outer, JsParenthesizedExpression):
        outer = outer.parent
    if isinstance(outer, JsCallExpression) and strip_parens(outer.callee) is fn:
        return outer
    return call


def _remove_expr(node) -> None:
    """
    Remove `node` as an expression: strips to the innermost non-paren ancestor, then removes the
    sequence operand, the enclosing expression statement, or the node itself.
    """
    cur = node
    p = cur.parent
    while isinstance(p, JsParenthesizedExpression):
        cur, p = p, p.parent
    if isinstance(p, JsSequenceExpression):
        _remove_from_parent(cur)
    elif isinstance(p, JsExpressionStatement):
        _remove_from_parent(p)
    else:
        _remove_from_parent(cur)


def _invocation_of(reference) -> JsCallExpression | None:
    """
    The call `reference` is the callee of, looking through parentheses, or `None` when `reference` is
    used for anything other than being called. This is the one reference shape whose removal
    `_remove_structural` can make clean.
    """
    call = reference.parent
    while isinstance(call, JsParenthesizedExpression):
        call = call.parent
    if isinstance(call, JsCallExpression) and strip_parens(call.callee) is reference:
        return call
    return None


def _discardable_guard_invocations(model, binding, declarator) -> list[JsCallExpression] | None:
    """
    The guard invocations to excise when the guard binding stored in `declarator` can be removed
    whole, or `None` when it cannot. Every reference outside the declarator must be a call whose
    result is discarded, so `_remove_expr` can excise it and leave the program running the same; a
    binding with any other outside reference cannot go, since removing its declaration would leave
    that reference naming an undeclared name. A reference inside the declarator is the payload
    closing over its own guard — the self-defending payload reads its guard's source through it —
    and vanishes with the declaration, so it neither blocks the removal nor needs excising. A
    binding no invocation reaches is left alone.
    """
    if binding is None or binding.dynamic_refs or binding.exported:
        return None
    calls: list[JsCallExpression] = []
    for reference in model.references(binding):
        if reference.is_descendant_of(declarator):
            continue
        call = _invocation_of(reference)
        if call is None or not value_is_discarded(call):
            return None
        calls.append(call)
    return calls if calls else None


class JsRemoveSelfDefending(ScriptLevelTransformer):
    """
    Detect and remove the obfuscator.io self-defending factory+guard pattern, keyed both by the ReDoS
    signature string and by the structural run-once `apply`-payload template.
    """

    def _process_script(self, node: JsScript):
        for literal in list(node.walk()):
            if isinstance(literal, JsStringLiteral) and literal.value is not None:
                if _REDOS_SIGNATURE in literal.value:
                    self._remove_redos(literal, node)
        self._remove_structural(node)

    def _remove_redos(self, redos_literal: JsStringLiteral, root: JsScript) -> None:
        guard_decl = redos_literal.parent
        while guard_decl is not None and not isinstance(guard_decl, JsVariableDeclarator):
            guard_decl = guard_decl.parent
        if guard_decl is None or not isinstance(guard_decl.id, JsIdentifier):
            return
        if not isinstance(guard_decl.init, JsCallExpression):
            return
        callee = guard_decl.init.callee
        if isinstance(callee, JsIdentifier):
            factory_name = callee.name
        elif isinstance(callee, JsFunctionExpression):
            factory_name = None
        else:
            return
        co_names: set[str] = set()
        if factory_name is None:
            for arg in guard_decl.init.arguments:
                if isinstance(arg, JsIdentifier):
                    co_names.add(arg.name)
        var_decl = guard_decl.parent
        if not isinstance(var_decl, JsVariableDeclaration):
            return
        body_parent = var_decl.parent
        if isinstance(body_parent, JsScript):
            body = body_parent.body
        elif isinstance(body_parent, JsBlockStatement):
            body = body_parent.body
        else:
            return
        model = model_cache(self, root).model
        binding = model.binding_of(guard_decl.id)
        calls = _discardable_guard_invocations(model, binding, guard_decl)
        if calls is None:
            return
        for call in calls:
            _remove_expr(call)
        remove_declarator(guard_decl)
        cleanup_names = {factory_name} if factory_name is not None else co_names
        for name in cleanup_names:
            model = model_cache(self, root).model
            for stmt in list(body):
                if not isinstance(stmt, JsVariableDeclaration):
                    continue
                for d in list(stmt.declarations):
                    if (
                        isinstance(d, JsVariableDeclarator)
                        and isinstance(d.id, JsIdentifier)
                        and d.id.name == name
                    ):
                        binding = model.binding_of(d.id)
                        if not binding_has_references(model, binding):
                            remove_declarator(d)
        self.mark_changed()

    def _remove_structural(self, root: JsScript) -> None:
        model = model_cache(self, root).model
        immediate_guards: list[JsCallExpression] = []
        stored_guards: list[tuple[JsVariableDeclarator, list[JsCallExpression]]] = []
        factory_names: set[str] = set()

        for node in list(root.walk()):
            if not isinstance(node, JsCallExpression) or len(node.arguments) < 2:
                continue
            if not _is_global_receiver(node.arguments[0]):
                continue
            fn = model.target_function_of_call(node)
            if fn is None or not _matches_self_defending_factory(model, fn):
                continue
            if not _payload_carries_anti_analysis_marker(node.arguments[1]):
                continue
            callee = strip_parens(node.callee)
            if isinstance(callee, JsIdentifier):
                factory_names.add(callee.name)
            parent = node.parent
            while isinstance(parent, JsParenthesizedExpression):
                parent = parent.parent
            if isinstance(parent, JsCallExpression) and strip_parens(parent.callee) is node:
                immediate_guards.append(parent)
            elif isinstance(parent, JsVariableDeclarator) and isinstance(parent.id, JsIdentifier):
                binding = model.binding_of(parent.id)
                calls = _discardable_guard_invocations(model, binding, parent)
                if calls is not None:
                    stored_guards.append((parent, calls))

        if not immediate_guards and not stored_guards:
            return

        for guard_call in immediate_guards:
            unit = _removal_unit(guard_call)
            if value_is_discarded(unit):
                _remove_expr(unit)

        for declarator, calls in stored_guards:
            for call in calls:
                _remove_expr(call)
            remove_declarator(declarator)

        model = model_cache(self, root).model
        for binding in list(model.root_scope.bindings.values()):
            if binding.name not in factory_names:
                continue
            if not binding_has_references(model, binding):
                for decl_site in list(binding.declarations):
                    d = decl_site.parent
                    if isinstance(d, JsVariableDeclarator):
                        remove_declarator(d)

        self.mark_changed()
