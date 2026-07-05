"""
Inline reflectively executed JavaScript code: eval, Function constructor, constructor chains, and
setTimeout/setInterval with string arguments. An obfuscator which wraps the entire program in

    Function(param, code)(proxyObject)

is handled as a special case with automatic proxy object resolution.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Expression, Node, _clone_node, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.effects import side_effect_free
from refinery.lib.scripts.js.analysis.model import (
    GLOBAL_OBJECT_ALIASES,
    TIMER_NAMES,
    Binding,
    BindingKind,
    FUNCTION_NODES,
    Scope,
    SemanticModel,
    build_semantic_model,
    is_member_write_target,
    is_simple_assignment_target,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    access_key,
    get_body,
    property_key,
    references_receiver_this,
    string_value,
    walk_scope,
)
from refinery.lib.scripts.js.deobfuscation.options import DeobfuscationOptions
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAwaitExpression,
    JsBlockStatement,
    JsCallExpression,
    JsClassDeclaration,
    JsClassExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNewExpression,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsProperty,
    JsPropertyKind,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsThisExpression,
    JsUnaryExpression,
    JsVariableDeclaration,
    Statement,
)


def _unwrap_parens(node: Expression) -> Expression:
    while isinstance(node, JsParenthesizedExpression) and node.expression is not None:
        node = node.expression
    return node


def _try_parse(code: str) -> JsScript | None:
    try:
        from refinery.lib.scripts.js.parser import JsParser
        parsed = JsParser(code).parse()
    except Exception:
        return None
    if not parsed.body:
        return None
    return parsed


def _declares_top_level_names(body: list[Statement]) -> bool:
    """
    Whether *body* — statements parsed from an evaluated code string — declares any name at its top
    level (a `var`/`let`/`const`, function, or class declaration). Indirect eval and string timers
    evaluate their code in the global scope, so such a declaration binds a global; inlining the body
    at the call site would instead bind it wherever the deobfuscated output runs — a module scope
    under the module model, or the enclosing function or block when the call site is not the global
    scope — neither of which reaches the global object. The declaration's target scope is therefore
    not reproducible by textual inlining there. The `Function` constructor is not among these: a
    declaration in its body binds a local of the created function, not a global, so inlining it into
    any scope is sound and it is exempt from this gate.
    """
    return any(
        isinstance(stmt, (JsVariableDeclaration, JsFunctionDeclaration, JsClassDeclaration))
        for stmt in body
    )


def _try_eval_string_arg(node: Expression) -> str | None:
    from refinery.lib.scripts.js.deobfuscation.interpreter import (
        InterpreterError,
        IrreducibleExpression,
        JsInterpreter,
        _ThrowSignal,
    )
    try:
        result = JsInterpreter().eval_expression(node)
    except (InterpreterError, IrreducibleExpression, _ThrowSignal, RecursionError, ValueError, OverflowError):
        return None
    if isinstance(result, str):
        return result
    return None


def _is_identifier(node: Node, name: str) -> bool:
    return isinstance(node, JsIdentifier) and node.name == name


def _is_function_identifier(node: Expression) -> bool:
    return _is_identifier(_unwrap_parens(node), 'Function')


def _global_alias_member_name(callee: Expression | None) -> str | None:
    """
    The property named on a global-object alias by *callee*, or `None` when *callee* is not a
    non-computed dot access on a well-known alias: `window.eval` yields `'eval'`,
    `globalThis.setTimeout` yields `'setTimeout'`. This is the reflective reach through the global
    object that resolves to the same intrinsic as the bare name, shared by the indirect-eval and timer
    extractors so both recognize the same aliases as the model's reflection detector.
    """
    if callee is None:
        return None
    callee = _unwrap_parens(callee)
    if (
        isinstance(callee, JsMemberExpression)
        and not callee.computed
        and isinstance(callee.object, JsIdentifier)
        and callee.object.name in GLOBAL_OBJECT_ALIASES
        and isinstance(callee.property, JsIdentifier)
    ):
        return callee.property.name
    return None


def _extract_eval_code(node: JsCallExpression) -> str | None:
    """
    Extract the code string from `eval("code")` or `(eval)("code")`.
    """
    if node.callee is None:
        return None
    callee = _unwrap_parens(node.callee)
    if not _is_identifier(callee, 'eval'):
        return None
    if len(node.arguments) != 1:
        return None
    return string_value(node.arguments[0]) or _try_eval_string_arg(node.arguments[0])


def _extract_indirect_eval_code(node: JsCallExpression) -> str | None:
    """
    Extract the code string from indirect eval patterns:
    - `(0, eval)("code")`
    - `window.eval("code")` / `globalThis.eval("code")`
    """
    if len(node.arguments) != 1:
        return None
    callee = _unwrap_parens(node.callee) if node.callee is not None else None
    if isinstance(callee, JsSequenceExpression):
        exprs = callee.expressions
        if len(exprs) >= 2 and _is_identifier(exprs[-1], 'eval'):
            if all(side_effect_free(e) for e in exprs[:-1]):
                return string_value(node.arguments[0]) or _try_eval_string_arg(node.arguments[0])
    if _global_alias_member_name(callee) == 'eval':
        return string_value(node.arguments[0]) or _try_eval_string_arg(node.arguments[0])
    return None


def _extract_timer_code(node: JsCallExpression) -> str | None:
    """
    Extract the code string from a string-valued timer call — `setTimeout("code", ...)`,
    `setInterval("code", ...)`, and the `setImmediate`/`execScript` variants — whether the timer is
    named directly or through a global-object alias (`window.setTimeout("code", ...)`), both of which
    reach the same evaluating global.
    """
    if node.callee is None:
        return None
    callee = _unwrap_parens(node.callee)
    if isinstance(callee, JsIdentifier):
        name = callee.name
    else:
        name = _global_alias_member_name(callee)
    if name not in TIMER_NAMES:
        return None
    if not node.arguments:
        return None
    return string_value(node.arguments[0]) or _try_eval_string_arg(node.arguments[0])


def _extract_function_body_code(
    constructor_call: JsCallExpression | JsNewExpression,
) -> str | None:
    """
    Extract the body code string from Function constructor calls:

        Function("code")
        Function("a", "b", "code")
        new Function("code")

    The last string argument is the function body; preceding string arguments are parameter
    names (ignored for now).
    """
    callee = constructor_call.callee
    if callee is None:
        return None
    if not _is_function_identifier(callee):
        return None
    args = constructor_call.arguments
    if not args:
        return None
    last = args[-1]
    body = string_value(last) or _try_eval_string_arg(last)
    if body is None:
        return None
    if not all(isinstance(a, JsStringLiteral) for a in args[:-1]):
        return None
    return body


def _is_constructor_chain(node: JsCallExpression | JsNewExpression) -> bool:
    """
    Detect a constructor chain callee pattern equivalent to `Function`:

        <literal>.constructor.constructor
    """
    callee = node.callee
    if not isinstance(callee, JsMemberExpression):
        return False
    if access_key(callee) != 'constructor':
        return False
    inner = callee.object
    if not isinstance(inner, JsMemberExpression):
        return False
    if access_key(inner) != 'constructor':
        return False
    base = inner.object
    if base is None:
        return False
    return isinstance(base, (JsStringLiteral, JsIdentifier)) or side_effect_free(base)


def _extract_constructor_chain_code(node: JsCallExpression) -> str | None:
    """
    Extract code from constructor chain IIFE patterns:

        "".constructor.constructor("code")()
        [].constructor.constructor("code")()
    """
    inner_call = node.callee
    if not isinstance(inner_call, JsCallExpression):
        return None
    if not _is_constructor_chain(inner_call):
        return None
    if len(inner_call.arguments) != 1:
        return None
    return string_value(inner_call.arguments[0]) or _try_eval_string_arg(inner_call.arguments[0])


def _invoked_function_constructor_code(node: JsCallExpression) -> tuple[str, bool] | None:
    """
    If *node* immediately invokes a `Function` constructor — `Function("code")()`,
    `new Function("code")()`, or the `<x>.constructor.constructor("code")()` chain — return its body
    code together with whether the constructor binds parameters or is passed call arguments. A
    `Function`-constructed function runs in the global scope with `this` bound to the global object and
    its parameters bound to the call arguments, so inlining its body into the caller is sound only when
    it binds neither.
    """
    inner = node.callee
    if isinstance(inner, (JsCallExpression, JsNewExpression)):
        code = _extract_function_body_code(inner)
        if code is not None:
            return code, len(inner.arguments) > 1 or bool(node.arguments)
    chain = _extract_constructor_chain_code(node)
    if chain is not None:
        return chain, bool(node.arguments)
    return None


def _extract_getter_target(func: Expression | None) -> str | JsUnaryExpression | None:
    """
    Extract the value returned by a getter. Expected patterns:
    - `{ return <identifier>; }` -> returns the identifier name as `str`
    - a `typeof` expression -> returns a `refinery.lib.scripts.js.model.JsUnaryExpression` clone
    """
    if not isinstance(func, JsFunctionExpression):
        return None
    if func.body is None or not isinstance(func.body, JsBlockStatement):
        return None
    body = func.body.body
    if len(body) != 1:
        return None
    stmt = body[0]
    if not isinstance(stmt, JsReturnStatement) or stmt.argument is None:
        return None
    arg = stmt.argument
    if isinstance(arg, JsIdentifier):
        return arg.name
    if (
        isinstance(arg, JsUnaryExpression)
        and arg.operator == 'typeof'
        and isinstance(arg.operand, JsIdentifier)
    ):
        return arg
    return None


def _extract_setter_target(func: Expression | None) -> str | None:
    """
    Extract the global assigned in a setter. Expected pattern:

        { return <global> = <param>; }

    where the function has exactly one parameter.
    """
    if not isinstance(func, JsFunctionExpression):
        return None
    if len(func.params) != 1 or not isinstance(func.params[0], JsIdentifier):
        return None
    param_name = func.params[0].name
    if func.body is None or not isinstance(func.body, JsBlockStatement):
        return None
    body = func.body.body
    if len(body) != 1:
        return None
    stmt = body[0]
    if isinstance(stmt, JsReturnStatement):
        expr = stmt.argument
    elif isinstance(stmt, JsExpressionStatement):
        expr = stmt.expression
    else:
        return None
    if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
        return None
    if not isinstance(expr.left, JsIdentifier):
        return None
    if not isinstance(expr.right, JsIdentifier) or expr.right.name != param_name:
        return None
    return expr.left.name


class _ProxyMapping(NamedTuple):
    getters: dict[str, str | JsUnaryExpression]
    setters: dict[str, str]


def _build_proxy_mapping(
    obj: JsObjectExpression,
) -> _ProxyMapping | None:
    """
    Build getter and setter mappings from a pack proxy object. Returns `(getters, setters)` or
    `None` if any property is malformed.
    """
    getters: dict[str, str | JsUnaryExpression] = {}
    setters: dict[str, str] = {}
    for prop in obj.properties:
        if not isinstance(prop, JsProperty):
            return None
        key = property_key(prop)
        if key is None:
            return None
        if prop.kind == JsPropertyKind.GET:
            target = _extract_getter_target(prop.value)
            if target is None:
                return None
            getters[key] = target
        elif prop.kind == JsPropertyKind.SET:
            target = _extract_setter_target(prop.value)
            if target is None:
                return None
            setters[key] = target
        else:
            return None
    return _ProxyMapping(getters, setters)


def _substitute_proxy_accesses(
    parsed: JsScript,
    param_name: str,
    getters: dict[str, str | JsUnaryExpression],
    setters: dict[str, str],
) -> bool:
    """
    Replace all `param[key]` accesses in the parsed code with the resolved globals from the proxy
    mapping. A plain read resolves to the getter target and a simple `key = v` write to the setter
    target; a compound, update, or delete access reads via the getter AND writes via the setter, which
    no single global substitution preserves, so it makes resolution fail. Returns `True` if every
    access was resolved successfully.
    """
    for node in list(parsed.walk()):
        if not isinstance(node, JsMemberExpression):
            continue
        if not isinstance(node.object, JsIdentifier) or node.object.name != param_name:
            continue
        key = access_key(node)
        if key is None:
            return False
        if is_simple_assignment_target(node):
            if key not in setters:
                return False
            _replace_in_parent(node, JsIdentifier(name=setters[key]))
        elif is_member_write_target(node):
            return False
        else:
            if key not in getters:
                return False
            target = getters[key]
            if isinstance(target, str):
                _replace_in_parent(node, JsIdentifier(name=target))
            else:
                _replace_in_parent(node, _clone_node(target))
    return True


def _try_unpack_function_constructor(
    node: JsCallExpression,
) -> list[Statement] | None:
    """
    Unpack an immediately-invoked `Function` constructor whose single argument is a proxy object
    with getter/setter properties that redirect to global variables:

        Function("p", "p.abc = p.def(p.ghi)")(
            {get abc() { return x }, set abc(v) { x = v }, get def() { return y }, ...}
        )

    Parses the code string, resolves all `p.key` accesses through the proxy mapping back to their
    original global identifiers, and returns the recovered statement list. Returns `None` if the
    node does not match or if any proxy access cannot be resolved.
    """
    inner = node.callee
    if not isinstance(inner, JsCallExpression):
        return None
    if inner.callee is None or not _is_function_identifier(inner.callee):
        return None
    if len(node.arguments) != 1 or not isinstance(node.arguments[0], JsObjectExpression):
        return None
    proxy_obj = node.arguments[0]
    inner_args = inner.arguments
    if len(inner_args) == 1:
        param_name = ''
        code = string_value(inner_args[0])
    elif len(inner_args) == 2:
        param_name = string_value(inner_args[0])
        code = string_value(inner_args[1])
        if param_name is None:
            return None
    else:
        return None
    if code is None:
        return None
    mapping = _build_proxy_mapping(proxy_obj)
    if mapping is None:
        return None
    getters, setters = mapping
    parsed = _try_parse(code)
    if parsed is None:
        return None
    if param_name and not _substitute_proxy_accesses(parsed, param_name, getters, setters):
        return None
    return list(parsed.body)


def _is_pack_shaped(node: JsCallExpression) -> bool:
    """
    Return `True` when the call has the shape of a pack pattern: the callee is a `Function()`
    call and the outer argument is an object expression. When this shape is detected, the generic
    function-body extraction should be skipped to avoid inlining code with unresolved proxy
    references.
    """
    inner = node.callee
    if not isinstance(inner, JsCallExpression) or inner.callee is None:
        return False
    if not _is_function_identifier(inner.callee):
        return False
    return len(node.arguments) == 1 and isinstance(node.arguments[0], JsObjectExpression)


def _has_top_level_await(stmts: list[Statement]) -> bool:
    """
    Return `True` if any `refinery.lib.scripts.js.model.JsAwaitExpression` in `stmts` is at the top
    level, i.e. not inside a nested function boundary.
    """
    return any(isinstance(n, JsAwaitExpression) for s in stmts for n in walk_scope(s))


def _wrap_in_async_iife(stmts: list[Statement]) -> list[Statement]:
    iife = JsExpressionStatement(
        expression=JsCallExpression(
            callee=JsParenthesizedExpression(
                expression=JsArrowFunctionExpression(
                    is_async=True,
                    params=[],
                    body=JsBlockStatement(body=stmts),
                ),
            ),
            arguments=[],
        ),
    )
    return [iife]


def _has_use_strict_directive(stmts: list[Statement]) -> bool:
    """
    Whether *stmts* opens with a `"use strict"` directive prologue. A strict `Function`-constructed
    body cannot be spliced into a possibly-sloppy caller without changing meaning: an assignment to an
    undeclared name throws under strict but silently creates a global under sloppy, and the directive
    stops governing the code once the body is no longer the first thing its scope runs.
    """
    for stmt in stmts:
        if not isinstance(stmt, JsExpressionStatement):
            return False
        if not isinstance(stmt.expression, JsStringLiteral):
            return False
        if stmt.expression.value == 'use strict':
            return True
    return False


def _site_in_strict_context(site: Node, root: JsScript) -> bool:
    """
    Whether *site* runs in strict mode, because the script opens with a `"use strict"` directive, an
    enclosing function does, or an enclosing class body (always strict) contains it. A
    `Function`-constructed body is always sloppy, so splicing it into a strict context could turn
    sloppy-only code — an octal literal, an unqualified `delete`, an assignment to an undeclared name
    or to `eval`/`arguments` — into a strict-mode SyntaxError or a behavior change; declining keeps
    the inlining sound.
    """
    if _has_use_strict_directive(root.body):
        return True
    cursor = site.parent
    while cursor is not None:
        if isinstance(cursor, (JsClassDeclaration, JsClassExpression)):
            return True
        if isinstance(cursor, FUNCTION_NODES):
            body = cursor.body
            if isinstance(body, JsBlockStatement) and _has_use_strict_directive(body.body):
                return True
        cursor = cursor.parent
    return False


def _references_new_target(root: Node) -> bool:
    """
    Whether *root* reads the `new.target` meta-property, which the parser models as a member access
    whose object is the reserved word `new`. A `Function`-constructed function is invoked as a call,
    so its `new.target` is always `undefined`; splicing the body into a real function would rebind
    `new.target` to the caller's, so a body that reads it cannot be inlined.
    """
    for node in root.walk():
        if (
            isinstance(node, JsMemberExpression)
            and isinstance(node.object, JsIdentifier)
            and node.object.name == 'new'
        ):
            return True
    return False


def _body_free_names(body_model: SemanticModel, parsed: JsScript) -> set[str]:
    """
    The names *parsed* reads or writes without binding them locally — the names a
    `Function`-constructed body resolves against the global scope. A name bound inside the body is
    excluded (inlining carries its binding along), as is a property name or key; an implicit-global
    write the body performs is included, since it targets a global rather than a local binding.
    """
    free: set[str] = set()
    for ident in parsed.walk():
        if not isinstance(ident, JsIdentifier) or not body_model.is_reference(ident):
            continue
        binding = body_model.resolve(ident)
        if binding is None or binding.kind is BindingKind.IMPLICIT_GLOBAL:
            free.add(ident.name)
    return free


def _body_declared_names(body_model: SemanticModel) -> set[str]:
    """
    The names a `Function`-constructed body declares at its top level — the `var`, function, `let`,
    `const`, and `class` bindings that inlining would hoist into the caller's scope. Implicit globals
    are excluded: those are writes to globals, covered by the free-name check rather than introduced as
    new bindings.
    """
    return {
        name for name, binding in body_model.root_scope.bindings.items()
        if binding.kind is not BindingKind.IMPLICIT_GLOBAL
    }


def _is_global_equivalent(binding: Binding, root_scope: Scope) -> bool:
    """
    Whether *binding* is the global a `Function`-constructed body would resolve a free name to at
    runtime: an implicit global, or a `var`/function declared at the script's top level, which in a
    sloppy script scope is itself a property of the global object. A top-level `let`/`const`/`class`,
    or any binding nested below the script, is a distinct lexical binding the global-scope body would
    not see, so a body free name resolving to one still declines the inlining.
    """
    if binding.kind is BindingKind.IMPLICIT_GLOBAL:
        return True
    return binding.scope is root_scope and binding.kind in (BindingKind.VAR, BindingKind.FUNCTION)


def _hoist_path_is_clear(names: set[str], site_scope: Scope, var_scope: Scope) -> bool:
    """
    Whether each hoisted `var`/function name can rise from the call site to *var_scope* without
    crossing a lexical binding of the same name. A `var` spliced into a block still hoists to the
    enclosing function or script, but it is a redeclaration SyntaxError if any block it passes
    through — from the site's own scope up to, but not including, *var_scope* — lexically binds the
    same name. Conflicts with a binding declared directly in *var_scope* are already caught by the
    capture check.
    """
    scope: Scope | None = site_scope
    while scope is not None and scope is not var_scope:
        if any(name in scope.bindings for name in names):
            return False
        scope = scope.parent
    return True


def _inlined_declarations_safe(
    body_model: SemanticModel,
    root_model: SemanticModel,
    site_scope: Scope,
) -> bool:
    """
    Whether the names a `Function`-constructed body declares at its top level can be introduced at the
    call site without capturing an identifier already meaningful there. Such declarations are local to
    the constructed function; inlining lifts `var` and function declarations into the caller's function
    or script scope and `let`/`const`/`class` into the caller's immediate block, where a same-named
    reference, an inherited binding, or a redeclaration would silently rebind to the inlined declaration
    or produce a duplicate lexical declaration. Each name is checked against the scope it would actually
    land in.
    """
    bindings = body_model.root_scope.bindings
    hoisted = {
        name for name, binding in bindings.items()
        if binding.kind in (BindingKind.VAR, BindingKind.FUNCTION)
    }
    lexical = {
        name for name, binding in bindings.items()
        if binding.kind not in (BindingKind.VAR, BindingKind.FUNCTION, BindingKind.IMPLICIT_GLOBAL)
    }
    if hoisted:
        var_scope = site_scope
        while var_scope is not None and not var_scope.is_var_scope:
            var_scope = var_scope.parent
        if var_scope is None or root_model.would_capture(hoisted, var_scope):
            return False
        if not _hoist_path_is_clear(hoisted, site_scope, var_scope):
            return False
    if lexical and root_model.would_capture(lexical, site_scope):
        return False
    return True


class JsReflectionInlining(ScriptLevelTransformer):
    """
    Inline reflective code execution: `eval`, `Function` constructor, constructor chains, and
    indirect invocation via `setTimeout` and `setInterval`.
    """

    def _process_script(self, node: JsScript) -> None:
        self._inline_statements(node)
        self._inline_expressions(node)

    def _inline_statements(self, root: JsScript) -> None:
        for container in list(root.walk()):
            body = get_body(container)
            if body is None:
                continue
            i = 0
            while i < len(body):
                parsed = self._try_resolve_statement(body[i], root, container is root)
                if parsed is None:
                    i += 1
                    continue
                parsed = self._sanitize_inlined_body(parsed)
                if parsed is None:
                    i += 1
                    continue
                for stmt in parsed:
                    stmt.parent = container
                body[i:i + 1] = parsed
                self.mark_changed()
                i += len(parsed)

    @staticmethod
    def _sanitize_inlined_body(stmts: list[Statement]) -> list[Statement] | None:
        """
        Adapt a reflective body's statements for the statement position they replace, where the call's
        return value is discarded and no `return` may escape into the container. A trailing `return x`
        becomes the bare expression `x` (its value was already being thrown away) and a trailing
        valueless `return` is dropped; a `return` before the last statement declines the inlining
        (`None`), since its early exit cannot be reproduced without reordering and declining is always
        sound. This holds for every container, not only the script: a `return` spliced into a function
        body would return from that enclosing function, and into the script would be a syntax error.
        """
        for stmt in stmts[:-1] if stmts else ():
            if isinstance(stmt, JsReturnStatement):
                return None
        if stmts and isinstance(stmts[-1], JsReturnStatement):
            last = stmts[-1]
            if last.argument is not None:
                stmts = stmts[:-1] + [JsExpressionStatement(expression=last.argument)]
            else:
                stmts = stmts[:-1]
        return stmts

    def _inline_expressions(self, root: JsScript) -> None:
        for node in list(root.walk()):
            if not isinstance(node, JsCallExpression):
                continue
            if isinstance(node.parent, JsExpressionStatement):
                continue
            replacement = self._try_resolve_expression(node, root)
            if replacement is None:
                continue
            _replace_in_parent(node, replacement)
            self.mark_changed()

    @property
    def _module_scope(self) -> bool:
        """
        Whether the caller selected the module execution model (see
        `refinery.lib.scripts.js.deobfuscation.options.DeobfuscationOptions`), under which a top-level
        declaration is scoped to the module and does not reach the global object.
        """
        options = self.options
        return isinstance(options, DeobfuscationOptions) and options.module

    def _try_resolve_statement(
        self, stmt: Statement, root: JsScript, at_global_scope: bool,
    ) -> list[Statement] | None:
        if not isinstance(stmt, JsExpressionStatement) or stmt.expression is None:
            return None
        node = stmt.expression
        had_await = isinstance(node, JsAwaitExpression)
        if had_await:
            node = node.argument
        if not isinstance(node, JsCallExpression):
            return None
        pack_result = _try_unpack_function_constructor(node)
        if pack_result is not None:
            return pack_result
        if _is_pack_shaped(node):
            return None
        constructor = _invoked_function_constructor_code(node)
        if constructor is not None:
            code, binds = constructor
            parsed = self._resolve_constructor_body(code, binds, stmt, root)
            global_scoped = False
        else:
            direct = _extract_eval_code(node)
            if direct is not None:
                parsed = _try_parse(direct)
                global_scoped = False
            else:
                code = _extract_indirect_eval_code(node) or _extract_timer_code(node)
                parsed = _try_parse(code) if code is not None else None
                global_scoped = True
        if parsed is None:
            return None
        if (
            global_scoped
            and _declares_top_level_names(parsed.body)
            and (self._module_scope or not at_global_scope)
        ):
            return None
        result = parsed.body
        if had_await and _has_top_level_await(result):
            return _wrap_in_async_iife(result)
        return result

    def _try_resolve_expression(self, node: JsCallExpression, root: JsScript) -> Expression | None:
        constructor = _invoked_function_constructor_code(node)
        if constructor is not None:
            code, binds = constructor
            parsed = self._resolve_constructor_body(code, binds, node, root)
        else:
            code = _extract_eval_code(node) or _extract_indirect_eval_code(node)
            parsed = _try_parse(code) if code is not None else None
        if parsed is None:
            return None
        body = parsed.body
        if len(body) == 1:
            stmt = body[0]
            if isinstance(stmt, JsExpressionStatement) and stmt.expression is not None:
                return stmt.expression
            if isinstance(stmt, JsReturnStatement) and stmt.argument is not None:
                return stmt.argument
        return None

    def _resolve_constructor_body(
        self, code: str, binds: bool, site: Node, root: JsScript,
    ) -> JsScript | None:
        """
        Parse a `Function`-constructor body and decide whether inlining it at *site* preserves meaning.
        The exact global-accessor idiom `return this` becomes `return globalThis`, since a
        `Function`-constructed function's `this` is always the global object; the rewritten `globalThis`
        is then held to the same free-name check as any other global reference, so a binding named
        `globalThis` in scope at *site* declines the inlining. Otherwise the body must run in the global
        sloppy mode the constructed function has: a strict context at *site* declines the inlining (the
        always-sloppy body would inherit the caller's strictness), as does a `"use strict"` prologue in
        the body itself. The body must also be self-contained in both directions: it binds no parameters
        or arguments and references no `this`, `arguments`, or `new.target`; every free name it reads
        still denotes the same global at *site*; and every name it declares can be hoisted into the scope
        at *site* without capturing an identifier already meaningful there. Anything else is left intact
        (returns `None`) — declining is always sound.
        """
        if binds:
            return None
        if _site_in_strict_context(site, root):
            return None
        parsed = _try_parse(code)
        if parsed is None:
            return None
        if _has_use_strict_directive(parsed.body):
            return None
        if len(parsed.body) == 1:
            only = parsed.body[0]
            if isinstance(only, JsReturnStatement) and isinstance(only.argument, JsThisExpression):
                _replace_in_parent(only.argument, JsIdentifier(name='globalThis'))
        if references_receiver_this(parsed) or _references_new_target(parsed):
            return None
        body_model = build_semantic_model(parsed)
        free = _body_free_names(body_model, parsed)
        if 'arguments' in free:
            return None
        declared = _body_declared_names(body_model)
        if not free and not declared:
            return parsed
        root_model = model_cache(self, root).model
        site_scope = root_model.scope_of(site)
        if site_scope is None:
            return None
        for name in free:
            binding = root_model.lookup(name, site_scope)
            if binding is not None and not _is_global_equivalent(binding, root_model.root_scope):
                return None
        if declared and not _inlined_declarations_safe(body_model, root_model, site_scope):
            return None
        return parsed
