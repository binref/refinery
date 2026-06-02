"""
Inline reflectively executed JavaScript code: eval, Function constructor, constructor chains, and
setTimeout/setInterval with string arguments. An obfuscator which wraps the entire program in

    Function(param, code)(proxyObject)

is handled as a special case with automatic proxy object resolution.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Expression, Node, _clone_node, _replace_in_parent
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    access_key,
    get_body,
    is_side_effect_free,
    property_key,
    string_value,
    walk_scope,
)
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAwaitExpression,
    JsBlockStatement,
    JsCallExpression,
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
    JsUnaryExpression,
    Statement,
)

_GLOBAL_OBJECTS = frozenset({'window', 'globalThis', 'self', 'global'})

_TIMER_FUNCTIONS = frozenset({'setTimeout', 'setInterval'})


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


def _try_eval_string_arg(node: Expression) -> str | None:
    from refinery.lib.scripts.js.deobfuscation.interpreter import (
        InterpreterError,
        IrreducibleExpression,
        JsInterpreter,
    )
    try:
        result = JsInterpreter().eval_expression(node)
    except (InterpreterError, IrreducibleExpression, RecursionError, ValueError, OverflowError):
        return None
    if isinstance(result, str):
        return result
    return None


def _is_identifier(node: Node, name: str) -> bool:
    return isinstance(node, JsIdentifier) and node.name == name


def _is_function_identifier(node: Expression) -> bool:
    return _is_identifier(_unwrap_parens(node), 'Function')


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
            if all(is_side_effect_free(e) for e in exprs[:-1]):
                return string_value(node.arguments[0]) or _try_eval_string_arg(node.arguments[0])
    if (
        isinstance(callee, JsMemberExpression)
        and isinstance(callee.object, JsIdentifier)
        and callee.object.name in _GLOBAL_OBJECTS
        and isinstance(callee.property, JsIdentifier)
        and callee.property.name == 'eval'
        and not callee.computed
    ):
        return string_value(node.arguments[0]) or _try_eval_string_arg(node.arguments[0])
    return None


def _extract_timer_code(node: JsCallExpression) -> str | None:
    """
    Extract the code string from `setTimeout("code", ...)` or `setInterval("code", ...)`.
    """
    if node.callee is None:
        return None
    callee = _unwrap_parens(node.callee)
    if not isinstance(callee, JsIdentifier) or callee.name not in _TIMER_FUNCTIONS:
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
    return isinstance(base, (JsStringLiteral, JsIdentifier)) or is_side_effect_free(base)


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


def _extract_invoked_function_body(node: JsCallExpression) -> str | None:
    """
    Extract code from immediately-invoked Function constructors:

        Function("code")()
        new Function("code")()
        Function("a", "b", "code")(args)
    """
    inner = node.callee
    if not isinstance(inner, (JsCallExpression, JsNewExpression)):
        return None
    return _extract_function_body_code(inner)


def _extract_getter_target(func: Expression | None) -> str | JsUnaryExpression | None:
    """
    Extract the value returned by a getter. Expected patterns:
    - `{ return <identifier>; }` -> returns the identifier name as `str`
    - a `typeof` expression -> returns a `JsUnaryExpression` clone
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
    mapping. Returns `True` if every access was resolved successfully.
    """
    for node in list(parsed.walk()):
        if not isinstance(node, JsMemberExpression):
            continue
        if not isinstance(node.object, JsIdentifier) or node.object.name != param_name:
            continue
        key = access_key(node)
        if key is None:
            return False
        parent = node.parent
        if (
            isinstance(parent, JsAssignmentExpression)
            and parent.left is node
            and parent.operator == '='
        ):
            if key not in setters:
                return False
            _replace_in_parent(node, JsIdentifier(name=setters[key]))
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
    Return `True` if any `JsAwaitExpression` in `stmts` is at the top level, i.e. not inside a
    nested function boundary.
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
            is_script = isinstance(container, JsScript)
            i = 0
            while i < len(body):
                parsed = self._try_resolve_statement(body[i])
                if parsed is None:
                    i += 1
                    continue
                if is_script:
                    parsed = self._sanitize_for_script_scope(parsed)
                    if parsed is None:
                        i += 1
                        continue
                for stmt in parsed:
                    stmt.parent = container
                body[i:i + 1] = parsed
                self.mark_changed()
                i += len(parsed)

    @staticmethod
    def _sanitize_for_script_scope(stmts: list[Statement]) -> list[Statement] | None:
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
            replacement = self._try_resolve_expression(node)
            if replacement is None:
                continue
            _replace_in_parent(node, replacement)
            self.mark_changed()

    def _try_resolve_statement(self, stmt: Statement) -> list[Statement] | None:
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
        code = (
            _extract_eval_code(node)
            or _extract_indirect_eval_code(node)
            or _extract_invoked_function_body(node)
            or _extract_constructor_chain_code(node)
            or _extract_timer_code(node)
        )
        if code is None:
            return None
        parsed = _try_parse(code)
        if parsed is None:
            return None
        result = parsed.body
        if had_await and _has_top_level_await(result):
            return _wrap_in_async_iife(result)
        return result

    @staticmethod
    def _try_resolve_expression(node: JsCallExpression) -> Expression | None:
        code = (
            _extract_eval_code(node)
            or _extract_indirect_eval_code(node)
            or _extract_invoked_function_body(node)
            or _extract_constructor_chain_code(node)
        )
        if code is None:
            return None
        parsed = _try_parse(code)
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
