"""
Inline reflectively executed JavaScript code: eval, Function constructor, constructor chains, and
setTimeout/setInterval with string arguments. An obfuscator which wraps the entire program in

    Function(param, code)(proxyObject)

is handled as a special case with automatic proxy object resolution.
"""
from __future__ import annotations

import enum

from typing import Callable, NamedTuple

from refinery.lib.scripts import Expression, Node, _clone_node, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.effects import side_effect_free
from refinery.lib.scripts.js.analysis.model import (
    TIMER_NAMES,
    Binding,
    BindingKind,
    FUNCTION_NODES,
    Scope,
    SemanticModel,
    build_semantic_model,
    is_member_write_target,
    is_simple_assignment_target,
    is_use_position,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    access_key,
    get_body,
    property_key,
    references_receiver_this,
    string_value,
    walk_receiver_scope,
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
    Statement,
)


class ReflectedScope(enum.Enum):
    """
    The execution scope of reflectively evaluated code, which decides how its free names, `this`, and
    top-level declarations must be treated when the code is inlined at its call site. A
    `Function`-constructed function and indirect `eval`/string-timer code run in the global sloppy
    scope; a direct `eval` runs in the caller's scope, which is the inline site itself, so its
    references and `this` are already correct there and only its declarations need care.
    """
    FUNCTION_CONSTRUCTOR = enum.auto()
    GLOBAL_EVAL = enum.auto()
    DIRECT_EVAL = enum.auto()


def _unwrap_parens(node: Expression) -> Expression:
    while isinstance(node, JsParenthesizedExpression) and node.expression is not None:
        node = node.expression
    return node


def _try_parse(code: str) -> JsScript | None:
    try:
        from refinery.lib.scripts.js.parser import JsParser
        parsed = JsParser(code, top_level_await=True).parse()
    except Exception:
        return None
    if not parsed.body:
        return None
    return parsed


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


def _extract_eval_code(
    node: JsCallExpression,
    *,
    free_global_name: Callable[[Expression | None], str | None],
) -> str | None:
    """
    Extract the code string from a direct `eval("code")` / `(eval)("code")`. The callee must be the
    free global `eval`; a locally-shadowed `eval` names an ordinary value whose call is left intact.
    """
    if free_global_name(node.callee) != 'eval':
        return None
    if len(node.arguments) != 1:
        return None
    return string_value(node.arguments[0]) or _try_eval_string_arg(node.arguments[0])


def _extract_indirect_eval_code(
    node: JsCallExpression,
    read_effect: Callable[[Node], bool] | None = None,
    *,
    alias_name: Callable[[Expression | None], str | None],
    free_global_name: Callable[[Expression | None], str | None],
) -> str | None:
    """
    Extract the code string from indirect eval patterns:
    - `(0, eval)("code")`
    - `window.eval("code")` / `globalThis.eval("code")` / `window['eval']("code")`

    Inlining discards the comma-sequence prefix, so it is admitted only when dropping it is
    side-effect free; *read_effect* rejects a prefix read that resolves through a `with` body's dynamic
    scope (firing a getter or throwing), which the model-free check cannot see. *free_global_name*
    confirms the sequence tail is the free global `eval` and *alias_name* resolves a global-object-alias
    member to the intrinsic it names, both declining a shadowed name or a dynamic scope.
    """
    if len(node.arguments) != 1:
        return None
    callee = _unwrap_parens(node.callee) if node.callee is not None else None
    if isinstance(callee, JsSequenceExpression):
        exprs = callee.expressions
        if len(exprs) >= 2 and free_global_name(exprs[-1]) == 'eval':
            if all(side_effect_free(e, read_effect=read_effect) for e in exprs[:-1]):
                return string_value(node.arguments[0]) or _try_eval_string_arg(node.arguments[0])
    if alias_name(callee) == 'eval':
        return string_value(node.arguments[0]) or _try_eval_string_arg(node.arguments[0])
    return None


def _extract_timer_code(
    node: JsCallExpression,
    *,
    alias_name: Callable[[Expression | None], str | None],
    free_global_name: Callable[[Expression | None], str | None],
) -> str | None:
    """
    Extract the code string from a string-valued timer call — `setTimeout("code", ...)`,
    `setInterval("code", ...)`, and the `setImmediate`/`execScript` variants — whether the timer is
    named directly or through a global-object alias (`window.setTimeout("code", ...)`), both of which
    reach the same evaluating global. The callee must denote the free global timer: *free_global_name*
    resolves a bare name and *alias_name* a global-object-alias member, each declining a locally
    shadowed name or a dynamic scope.
    """
    if node.callee is None:
        return None
    name = free_global_name(node.callee) or alias_name(node.callee)
    if name not in TIMER_NAMES:
        return None
    if not node.arguments:
        return None
    return string_value(node.arguments[0]) or _try_eval_string_arg(node.arguments[0])


def _extract_function_body_code(
    constructor_call: JsCallExpression | JsNewExpression,
    *,
    free_global_name: Callable[[Expression | None], str | None],
) -> str | None:
    """
    Extract the body code string from Function constructor calls:

        Function("code")
        Function("a", "b", "code")
        new Function("code")

    The callee must be the free global `Function`; a locally-shadowed `Function` names an ordinary
    value and is left alone. The last string argument is the function body; preceding string arguments
    are parameter names (ignored for now).
    """
    if free_global_name(constructor_call.callee) != 'Function':
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


def _is_constructor_chain(
    node: JsCallExpression | JsNewExpression, read_effect: Callable[[Node], bool] | None = None,
) -> bool:
    """
    Detect a constructor chain callee pattern equivalent to `Function`:

        <literal>.constructor.constructor

    Inlining discards the evaluation of the chain base, so the base must be side-effect free;
    *read_effect* rejects a bare-identifier base that resolves through a `with` body's dynamic scope
    (firing a getter or throwing), which the model-free check cannot see.
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
    return side_effect_free(base, read_effect=read_effect)


def _extract_constructor_chain_code(
    node: JsCallExpression, read_effect: Callable[[Node], bool] | None = None,
) -> str | None:
    """
    Extract code from constructor chain IIFE patterns:

        "".constructor.constructor("code")()
        [].constructor.constructor("code")()
    """
    inner_call = node.callee
    if not isinstance(inner_call, JsCallExpression):
        return None
    if not _is_constructor_chain(inner_call, read_effect):
        return None
    if len(inner_call.arguments) != 1:
        return None
    return string_value(inner_call.arguments[0]) or _try_eval_string_arg(inner_call.arguments[0])


def _invoked_function_constructor_code(
    node: JsCallExpression,
    read_effect: Callable[[Node], bool] | None = None,
    *,
    free_global_name: Callable[[Expression | None], str | None],
) -> tuple[str, bool] | None:
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
        code = _extract_function_body_code(inner, free_global_name=free_global_name)
        if code is not None:
            return code, len(inner.arguments) > 1 or bool(node.arguments)
    chain = _extract_constructor_chain_code(node, read_effect)
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
    *,
    free_global_name: Callable[[Expression | None], str | None],
) -> list[Statement] | None:
    """
    Unpack an immediately-invoked `Function` constructor whose single argument is a proxy object
    with getter/setter properties that redirect to global variables:

        Function("p", "p.abc = p.def(p.ghi)")(
            {get abc() { return x }, set abc(v) { x = v }, get def() { return y }, ...}
        )

    Parses the code string, resolves all `p.key` accesses through the proxy mapping back to their
    original global identifiers, and returns the recovered statement list. Returns `None` if the node
    does not match — including when the inner callee is not the free global `Function` — or if any
    proxy access cannot be resolved.
    """
    inner = node.callee
    if not isinstance(inner, JsCallExpression):
        return None
    if free_global_name(inner.callee) != 'Function':
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


def _has_top_level_return(stmts: list[Statement]) -> bool:
    """
    Whether *stmts* — an evaluated code string's body — has a `return` at its own top level, outside any
    nested function. A `return` outside a function is a SyntaxError in `eval` and string-timer code, so
    such a body throws when evaluated and must not be inlined as if it produced a value or ran to
    completion. The `Function` constructor is exempt: its body is a real function body, where a
    top-level `return` is the function's own return.
    """
    return any(isinstance(n, JsReturnStatement) for s in stmts for n in walk_scope(s))


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


def _rewrite_receiver_this_to_global(root: JsScript) -> None:
    """
    Replace every `this` bound to the constructed function's own receiver with a `globalThis` reference.
    A `Function`-constructed function is invoked here with no receiver, so its `this` is the global
    object; rewriting each occurrence lets the body inline as ordinary global-scope code rather than
    declining the moment a `this` appears. The rewrite descends the same receiver boundary
    `references_receiver_this` uses — through arrow functions and a class's `extends` clause and computed
    keys, but not into a nested regular or generator function, whose `this` is its own — so only the
    constructed function's own `this` is rewritten. The synthesized `globalThis` identifiers are then
    held to the body free-name check like any other global reference, so a binding named `globalThis` in
    scope at the call site still declines the inlining.
    """
    for node in list(walk_receiver_scope(root)):
        if isinstance(node, JsThisExpression):
            _replace_in_parent(node, JsIdentifier(name='globalThis'))


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


def _is_global_equivalent(binding: Binding, root_scope: Scope, module_scope: bool) -> bool:
    """
    Whether *binding* is the global a `Function`-constructed body would resolve a free name to at
    runtime. A `Function`-constructed function is always a sloppy global-scope function, so its free
    names resolve against the true global object. An implicit global is a property of that object, so
    it is always equivalent. A `var`/function declared at the script's top level is equivalent only
    under the script model, where a top-level declaration is itself a property of the global object;
    under the module model (*module_scope*) it is scoped to the module and never reaches the global, so
    the global-scope body would not resolve its free name to it. A top-level `let`/`const`/`class`, or
    any binding nested below the script, is a distinct lexical binding the global-scope body would not
    see. A body free name resolving to any of these non-equivalent bindings declines the inlining.
    """
    if binding.kind is BindingKind.IMPLICIT_GLOBAL:
        return True
    if module_scope:
        return False
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


def _site_crosses_dynamic_scope(site_scope: Scope) -> bool:
    """
    Whether *site_scope* lies inside a dynamically-scoped (`with`) region. Global-scope reflected code
    resolves its free names against the global scope, but a `with` on the path from the inline site to
    the root binds those names dynamically: `lookup` stops at the `with` boundary and cannot tell
    whether the object captures a name, so an inlined free name could resolve to the object's property
    rather than the global. Declining whenever such a region encloses the site keeps the inlining sound.
    """
    scope: Scope | None = site_scope
    while scope is not None:
        if scope.is_dynamic:
            return True
        scope = scope.parent
    return False


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
        self._lower_timers(node)

    def _dynamic_read_effect(self, root: JsScript) -> Callable[[Node], bool]:
        """
        A predicate reporting whether reading a node crosses a `with` body's dynamic scope, resolved
        against *root*'s current model. Threaded into the reflective-inlining safety checks so a read
        that may fire a `with` object's getter or throw is never dropped as if it were pure. Resolved
        lazily through the shared cache, so a script with no reflective site builds no model.
        """
        return lambda node: model_cache(self, root).model.read_has_dynamic_effect(node)

    def _alias_member_name(self, root: JsScript) -> Callable[[Expression | None], str | None]:
        """
        A resolver reporting the intrinsic a global-object-alias member names — `window.eval` yields
        `'eval'`, `globalThis['setTimeout']` yields `'setTimeout'` — or `None` when the base is not the
        real, unshadowed global object. A local `window` (a parameter, a `var`, a `with`-object
        property) names an ordinary object whose member is not the reflective intrinsic and must not be
        inlined; the model's shadow- and dynamic-scope-aware check is the single source of that judgment.
        Resolved lazily against *root*'s current model, mirroring `_dynamic_read_effect`.
        """
        def resolve(callee: Expression | None) -> str | None:
            if callee is None:
                return None
            member = _unwrap_parens(callee)
            if not isinstance(member, JsMemberExpression):
                return None
            model = model_cache(self, root).model
            if model.scope_of(member) is None:
                return None
            return model.global_alias_member_name(member)
        return resolve

    def _free_global_name(self, root: JsScript) -> Callable[[Expression | None], str | None]:
        """
        A resolver reporting the intrinsic a bare callee identifier denotes — `eval` yields `'eval'`,
        `Function` yields `'Function'` — or `None` when the name is not a free, unshadowed global. A
        local binding (a parameter, a `var`, a `with`-object property) of the name is an ordinary value,
        not the intrinsic, and must not drive an inline; the model resolves a reference to its binding
        for a shadow and to `None` for a free global, and `read_has_dynamic_effect` rejects a name read
        through a dynamic scope. Resolved lazily against *root*'s current model, mirroring
        `_dynamic_read_effect`.
        """
        def resolve(callee: Expression | None) -> str | None:
            if callee is None:
                return None
            ident = _unwrap_parens(callee)
            if not isinstance(ident, JsIdentifier):
                return None
            model = model_cache(self, root).model
            if model.scope_of(ident) is None:
                return None
            if model.resolve(ident) is None and not model.read_has_dynamic_effect(ident):
                return ident.name
            return None
        return resolve

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

    def _lower_timers(self, root: JsScript) -> None:
        """
        Rewrite a string-argument timer — `setTimeout("code", delay)`, `setInterval`, and their
        `setImmediate`/`execScript`/global-alias variants — into a deferred function call
        `setTimeout(function () { code }, delay)`, so the evaluated code is deobfuscated without changing
        when or how often it runs. Unlike the eval and constructor paths, a timer is not inlined at the
        call site: its value is a handle and its execution is deferred, so only its code string is
        lowered.
        """
        for node in list(root.walk()):
            if isinstance(node, JsCallExpression):
                self._try_lower_timer(node, root)

    def _try_lower_timer(self, node: JsCallExpression, root: JsScript) -> None:
        """
        Replace a string timer's code argument with a function wrapping the parsed code, when that code
        runs safely in the global scope the timer would give it. The wrapper is defined at the call site,
        so it is held to the same global-scope safety as an indirect eval — its `this` is rewritten to
        `globalThis`, its free names must still denote the same global, and a top-level declaration
        (whose global or transient environment a local function cannot reproduce) or a `return`/`await`
        that a plain function body cannot host declines the lowering, leaving the string timer intact.
        """
        code = _extract_timer_code(
            node,
            alias_name=self._alias_member_name(root),
            free_global_name=self._free_global_name(root),
        )
        if code is None:
            return
        resolved = self._resolve_reflected_body(
            code, node, root, ReflectedScope.GLOBAL_EVAL, at_global_scope=False,
        )
        if resolved is None or _has_top_level_await(resolved.body):
            return
        block = JsBlockStatement(body=resolved.body)
        wrapper = JsFunctionExpression(params=[], body=block)
        block.parent = wrapper
        for stmt in resolved.body:
            stmt.parent = block
        _replace_in_parent(node.arguments[0], wrapper)
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
        pack_result = _try_unpack_function_constructor(
            node, free_global_name=self._free_global_name(root))
        if pack_result is not None:
            return pack_result
        if _is_pack_shaped(node):
            return None
        resolved = self._resolve_reflected_call(node, stmt, root, at_global_scope)
        if resolved is None:
            return None
        result = resolved[1].body
        if had_await and _has_top_level_await(result):
            return _wrap_in_async_iife(result)
        return result

    def _try_resolve_expression(self, node: JsCallExpression, root: JsScript) -> Expression | None:
        resolved = self._resolve_reflected_call(node, node, root, at_global_scope=False)
        if resolved is None:
            return None
        scope, parsed = resolved
        body = parsed.body
        if len(body) != 1:
            return None
        stmt = body[0]
        if scope is ReflectedScope.FUNCTION_CONSTRUCTOR:
            if isinstance(stmt, JsReturnStatement) and stmt.argument is not None:
                return stmt.argument
            return None
        if isinstance(stmt, JsExpressionStatement) and stmt.expression is not None:
            return stmt.expression
        return None

    def _resolve_reflected_call(
        self,
        node: JsCallExpression,
        site: Node,
        root: JsScript,
        at_global_scope: bool,
    ) -> tuple[ReflectedScope, JsScript] | None:
        """
        Dispatch a reflective call to the safety gate for its execution scope, pairing the resolved body
        with that scope or returning `None` to decline. A `Function` constructor or constructor chain is
        a fresh global-scope function; a direct `eval` runs in the caller's scope; an indirect `eval`
        runs in the global scope. A string timer is not inlined here: its value is a handle, not the
        code's completion value, and its deferred execution is preserved instead by `_lower_timers`.
        """
        read_effect = self._dynamic_read_effect(root)
        alias_name = self._alias_member_name(root)
        free_global_name = self._free_global_name(root)
        constructor = _invoked_function_constructor_code(
            node, read_effect, free_global_name=free_global_name)
        if constructor is not None:
            code, binds = constructor
            parsed = self._resolve_reflected_body(
                code, site, root, ReflectedScope.FUNCTION_CONSTRUCTOR, at_global_scope, binds=binds,
            )
            return (ReflectedScope.FUNCTION_CONSTRUCTOR, parsed) if parsed is not None else None
        direct = _extract_eval_code(node, free_global_name=free_global_name)
        if direct is not None:
            parsed = self._resolve_reflected_body(
                direct, site, root, ReflectedScope.DIRECT_EVAL, at_global_scope,
            )
            return (ReflectedScope.DIRECT_EVAL, parsed) if parsed is not None else None
        code = _extract_indirect_eval_code(
            node, read_effect, alias_name=alias_name, free_global_name=free_global_name)
        if code is not None:
            parsed = self._resolve_reflected_body(
                code, site, root, ReflectedScope.GLOBAL_EVAL, at_global_scope,
            )
            return (ReflectedScope.GLOBAL_EVAL, parsed) if parsed is not None else None
        return None

    def _resolve_reflected_body(
        self,
        code: str,
        site: Node,
        root: JsScript,
        scope: ReflectedScope,
        at_global_scope: bool,
        *,
        binds: bool = False,
    ) -> JsScript | None:
        """
        Parse reflectively evaluated *code* and decide whether inlining its body at *site* preserves
        meaning, given the `ReflectedScope` it runs in. Global-scope code — a `Function`-constructed
        body or indirect `eval`/string-timer code — must run in the global sloppy mode it would have: a
        strict context at *site* declines the inlining, as does a `"use strict"` prologue; every receiver
        `this` becomes `globalThis`; and a body reading `arguments`, `super`, or `new.target`, or a free
        name that no longer denotes the same global at *site* — including one a `with` on the path could
        capture — declines. Direct `eval` runs in the caller's scope, which is *site* itself, so its
        references and `this` are already correct there and only the checks below apply. A top-level
        `return` is a SyntaxError in evaluated code, so an eval body with one declines. Declaration
        handling is delegated to `_reflected_declarations_safe`. Anything not provably safe is left
        intact (returns `None`) — declining is always sound.
        """
        if binds:
            return None
        resolves_globally = scope is not ReflectedScope.DIRECT_EVAL
        if resolves_globally and _site_in_strict_context(site, root):
            return None
        parsed = _try_parse(code)
        if parsed is None:
            return None
        if resolves_globally and _has_use_strict_directive(parsed.body):
            return None
        if resolves_globally:
            _rewrite_receiver_this_to_global(parsed)
            if references_receiver_this(parsed) or _references_new_target(parsed):
                return None
        if scope is not ReflectedScope.FUNCTION_CONSTRUCTOR and _has_top_level_return(parsed.body):
            return None
        body_model = build_semantic_model(parsed)
        free = _body_free_names(body_model, parsed)
        if resolves_globally and 'arguments' in free:
            return None
        declared = _body_declared_names(body_model)
        if not free and not declared:
            return parsed
        root_model = model_cache(self, root).model
        site_scope = root_model.scope_of(site)
        if site_scope is None:
            return None
        if resolves_globally and free:
            if _site_crosses_dynamic_scope(site_scope):
                return None
            for name in free:
                binding = root_model.lookup(name, site_scope)
                if binding is not None and not _is_global_equivalent(
                    binding, root_model.root_scope, self._module_scope,
                ):
                    return None
        if declared and not self._reflected_declarations_safe(
            body_model, root_model, site_scope, site, scope, at_global_scope,
        ):
            return None
        return parsed

    def _reflected_declarations_safe(
        self,
        body_model: SemanticModel,
        root_model: SemanticModel,
        site_scope: Scope,
        site: Node,
        scope: ReflectedScope,
        at_global_scope: bool,
    ) -> bool:
        """
        Whether the top-level declarations of a reflected body can be reproduced by inlining it at the
        call site. A `Function`-constructed body's declarations are local to the created function and
        lift into the caller's scopes (`_inlined_declarations_safe`); evaluated code declares in its
        execution scope and is handled by `_eval_declarations_safe`.
        """
        if scope is ReflectedScope.FUNCTION_CONSTRUCTOR:
            return _inlined_declarations_safe(body_model, root_model, site_scope)
        return self._eval_declarations_safe(
            body_model, root_model, site_scope, site, scope, at_global_scope,
        )

    def _eval_declarations_safe(
        self,
        body_model: SemanticModel,
        root_model: SemanticModel,
        site_scope: Scope,
        site: Node,
        scope: ReflectedScope,
        at_global_scope: bool,
    ) -> bool:
        """
        Whether an `eval` body's top-level declarations can be inlined at the call site. A
        `let`/`const`/`class` lives in a declarative environment discarded when the evaluation
        returns, so a persistent inlined binding differs only if a name it declares is referenced
        outside the body; it is declined exactly when introducing it at the site would capture such a
        reference. A `var` or function persists: under indirect eval it becomes a global-object
        property, reproducible only at top-level script scope and never under the module model; under
        direct eval it lands in the caller's variable scope, but never under a strict direct eval,
        whose `var` stays local to the eval. Such a declaration hoists to the head of its variable
        scope, so it is inlined only when the eval site strictly dominates every reference to the name
        already there — one that runs before it or shares its statement, or reads the name through a
        closure, would be rebound.
        """
        root = root_model.root
        bindings = body_model.root_scope.bindings
        lexical = {
            name for name, binding in bindings.items()
            if binding.kind not in (BindingKind.VAR, BindingKind.FUNCTION, BindingKind.IMPLICIT_GLOBAL)
        }
        if lexical and root_model.would_capture(lexical, site_scope):
            return False
        hoisted = {
            name for name, binding in bindings.items()
            if binding.kind in (BindingKind.VAR, BindingKind.FUNCTION)
        }
        if not hoisted:
            return True
        if scope is ReflectedScope.GLOBAL_EVAL:
            if self._module_scope or not at_global_scope:
                return False
        elif _site_in_strict_context(site, root) or _has_use_strict_directive(body_model.root.body):
            return False
        var_scope = site_scope.var_scope
        if var_scope is None:
            return False
        dominance = model_cache(self, root).dominance
        return all(
            dominance.strictly_dominates(site, node)
            for node in var_scope.node.walk()
            if isinstance(node, JsIdentifier) and node.name in hoisted and is_use_position(node)
        )
