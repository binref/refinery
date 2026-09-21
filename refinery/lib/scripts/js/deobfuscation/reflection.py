"""
Inline reflectively executed JavaScript code: eval, Function constructor, constructor chains, and
setTimeout/setInterval with string arguments. An obfuscator which wraps the entire program in

    Function(param, code)(proxyObject)

is handled as a special case with automatic proxy object resolution.
"""
from __future__ import annotations

import enum

from typing import Callable, Collection, NamedTuple

from refinery.lib.scripts import (
    Expression,
    Node,
    _clone_node,
    _replace_in_parent,
    set_body,
    spells_its_source,
)
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.effects import EffectModel, side_effect_free
from refinery.lib.scripts.js.analysis.model import (
    REFLECTIVE_INTRINSICS,
    SYNC_EVAL_NAMES,
    TIMER_NAMES,
    Binding,
    BindingKind,
    Role,
    Scope,
    SemanticModel,
    build_semantic_model,
    crosses_dynamic_scope,
    is_member_write_target,
    is_simple_assignment_target,
    name_uses_in_scope,
    reference_role,
)
from refinery.lib.scripts.js.analysis.tampering import denotes_function_intrinsic, function_intrinsic_aliases
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    a_host_reaches_the_binding,
    access_key,
    body_returns_undefined,
    definitely_answers_the_completion,
    extract_literal_value,
    get_body,
    inlined_declarations_safe,
    names_this_realms_global_object,
    nothing_still_names,
    preserve_script_end_value,
    property_key,
    references_new_target,
    references_receiver_this,
    remove_declarator,
    replace_with_value,
    rewrite_receiver_this_to_global,
    sanitize_inlined_body,
    string_value,
    walk_scope,
)
from refinery.lib.scripts.js.deobfuscation.strict_divergence import diverges_under_strict
from refinery.lib.scripts.js.model import (
    SCRIPT_CONTEXT,
    CodeContext,
    JsAssignmentExpression,
    JsAwaitExpression,
    JsBlockStatement,
    JsCallExpression,
    JsExpressionStatement,
    JsForOfStatement,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNewExpression,
    JsObjectExpression,
    JsProperty,
    JsPropertyKind,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    Statement,
    code_context_at,
    function_context,
    strip_parens,
)
from refinery.lib.scripts.js.numbers import TRIMMABLE_WHITESPACE
from refinery.lib.scripts.js.options import preserves_script_return, runs_as_module
from refinery.lib.scripts.js.strict import (
    collect_strict_violations,
    declares_use_strict,
    strict_mode_at,
)

_REFLECTIVE_CALLEE_NAMES = REFLECTIVE_INTRINSICS | TIMER_NAMES | SYNC_EVAL_NAMES


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


def _try_parse(
    code: str,
    *,
    strict: bool,
    module: bool = False,
    context: CodeContext = SCRIPT_CONTEXT,
) -> JsScript | None:
    """
    The tree the reflected code spells, or `None` where it spells no program. Inlining is the one
    place a parse has to be believed rather than merely used: what comes back is printed into the
    file around it, so text the parser did not read would be printed as source it never agreed to,
    and a literal the code left open would run on into whatever follows it at the call site.

    Recovery makes the parser total, so raising is not the test. The test is whether the tree
    spells its source, which `refinery.lib.scripts.spells_its_source` decides and which is
    precisely the domain over which printing it back means what it said. A payload cut off in the
    middle of a construct is the case that makes the difference: the parser finishes it by writing
    the token it was waiting for, so `x = f(1, 2` reads as a call that runs, and only the repair the
    parser records keeps that from being spliced into the file as though it had been written whole.

    Spelling its source is not the whole of it. A text can spell a tree the printer reproduces
    exactly and still be one the language refuses to read — a repeated parameter where the grammar
    wants a unique list, an accessor of the wrong arity, a Use Strict Directive under a parameter
    list that may hold none. Evaluated, such a text is a `SyntaxError` the call site catches and
    the program carries on from; spliced into the file, it takes the whole file down with it, and
    nothing runs at all. So it is refused here, which leaves the `eval` or `Function` call standing
    to throw exactly what it threw before.

    Every surface evaluates its text with the Script goal — a direct `eval` inside an `async`
    function included (§19.2.1.1) — so `await` is a name throughout the text and a `for await`
    head stands only inside an `async` function written in it. A text awaiting at its own top level
    is therefore a `SyntaxError` the call site catches, whatever the destination reads `await` as,
    and `_has_top_level_await` refuses it so that the call stands to throw as it did. The text is
    read the way a file is, and a file's top level reads a `for await` head, which is why that gate
    is asked after the parse rather than of it.

    *context* is what the splice site reads `await`, `yield` and `arguments` as, seeded into the
    collector so that a payload legal as a script is refused where the site would refuse it: a
    reference to `arguments` from a class field initializer, `await` bound in a static block,
    `typeof yield` in a generator body, `typeof await` in an `async` one.

    *strict* is the mode at the destination, and it is the mode the text has to be legal in, whichever
    mode it would have run in where it stood. A body a `Function` constructor builds runs sloppy in the
    global scope, but inlining it puts its text where the destination's mode governs; a direct `eval`
    already runs in the destination's mode, and a text that mode refuses is a `SyntaxError` the call
    site catches and carries on from. The two arrive by different routes at the same requirement, which
    is why one seed answers for every surface.

    *module* is the destination's goal symbol, told apart from its mode because a module carries two
    rules beyond a strict script: `await` names nothing in it, and the HTML-like comment delimiters
    open no comment. The reflected text runs its code as a script wherever it stood, so a payload
    naming `await` is legal there and a `SyntaxError` only once inlined into a module — the very
    throw that would take the file down where the call it replaced merely raised one the site
    caught. So it is refused here, on the same seed and for the same reason as a strict violation,
    whichever surface the text reached the file through.

    Module-only syntax is refused for the same reason and needs no mode to decide it. Every surface
    that reaches here evaluates its text as a Script, where an `import` or `export` declaration is a
    `SyntaxError` the call site catches; spliced into the file it is a `SyntaxError` the file cannot
    survive, and where the host does load the file as a module it is a declaration the program never
    made. It is read off the mark the parser left rather than walked for again, so this gate and the
    mode `refinery.lib.scripts.js.strict.strict_mode_at` reads for the same tree cannot part
    company.

    Refusing is free: the `eval` or `Function` call is left standing to throw exactly what it threw
    before. Whether such a body would additionally *behave* differently at a strict destination is a
    separate question, and one only the surfaces that run sloppy have to ask; `diverges_under_strict`
    owns it.
    """
    try:
        from refinery.lib.scripts.js.parser import JsParser
        parsed = JsParser(code).parse()
    except Exception:
        return None
    if not parsed.body or parsed.module or not spells_its_source(parsed):
        return None
    if _has_top_level_await(parsed.body):
        return None
    if collect_strict_violations(parsed, strict=strict, module=module, context=context):
        return None
    return parsed


def _try_eval_string_arg(node: Expression, model: SemanticModel, effects: EffectModel) -> str | None:
    """
    Fold an expression to the string it denotes by interpreting it, or `None` where that refuses.
    The interpreter runs with the real effect model — every caller here is an extraction arm on a
    file that carries a reflection surface by definition, so a builtin the program may have replaced
    is not one this fold may trust on the strength of having no question to ask. The model answers
    name resolution alone: a caller that holds only the semantic model passes it and pays no effect
    model it never consults, which is why the two arrive separately.
    """
    from refinery.lib.scripts.js.deobfuscation.interpreter import (
        InterpreterError,
        IrreducibleExpression,
        JsInterpreter,
        _ThrowSignal,
    )
    try:
        result = JsInterpreter(model=model, effects=effects).eval_expression(node)
    except (InterpreterError, IrreducibleExpression, _ThrowSignal, RecursionError, ValueError, OverflowError):
        return None
    if isinstance(result, str):
        return result
    return None


def _extract_eval_code(
    node: JsCallExpression,
    *,
    free_global_name: Callable[[Expression | None], str | None],
    eval_string: Callable[[Expression | None], str | None],
) -> str | None:
    """
    Extract the code string from a direct `eval("code")` / `(eval)("code")`. The callee must be the
    free global `eval`; a locally-shadowed `eval` names an ordinary value whose call is left intact.
    """
    if free_global_name(node.callee) != 'eval':
        return None
    if len(node.arguments) != 1:
        return None
    return string_value(node.arguments[0]) or eval_string(node.arguments[0])


def _extract_indirect_eval_code(
    node: JsCallExpression,
    read_effect: Callable[[Node], bool] | None = None,
    *,
    alias_name: Callable[[Expression | None], str | None],
    free_global_name: Callable[[Expression | None], str | None],
    eval_string: Callable[[Expression | None], str | None],
    base_droppable: Callable[[Expression | None], bool] | None = None,
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

    Inlining `<alias>.eval(code)` to `code` discards the base read and runs the code where the fold
    stands rather than off the alias, so *base_droppable* gates it: the base must resolve, or its
    `ReferenceError` where the host lacks the alias is dropped, and it must name *this* realm's global
    object, or code that ran in another realm through `top`/`frames` is moved into this one.
    """
    if len(node.arguments) != 1:
        return None
    callee = strip_parens(node.callee) if node.callee is not None else None
    if isinstance(callee, JsSequenceExpression):
        exprs = callee.expressions
        if len(exprs) >= 2 and free_global_name(exprs[-1]) == 'eval':
            if all(side_effect_free(e, read_effect=read_effect) for e in exprs[:-1]):
                return string_value(node.arguments[0]) or eval_string(node.arguments[0])
    if alias_name(node.callee) == 'eval':
        if base_droppable is None or not base_droppable(node.callee):
            return None
        return string_value(node.arguments[0]) or eval_string(node.arguments[0])
    return None


def _extract_string_call_code(
    node: JsCallExpression,
    names: frozenset[str],
    *,
    alias_name: Callable[[Expression | None], str | None],
    free_global_name: Callable[[Expression | None], str | None],
    eval_string: Callable[[Expression | None], str | None],
) -> str | None:
    """
    Extract the code string a named global string-call evaluates — a deferred timer
    (`setTimeout("code", ...)`, `setInterval`, `setImmediate`) or a synchronous global eval
    (`execScript("code")`) — whether the global is named directly or through a global-object alias
    (`window.setTimeout("code", ...)`), both of which reach the same evaluating global. *names* selects
    which globals qualify. The callee must denote the free global: *free_global_name* resolves a bare
    name and *alias_name* a global-object-alias member, each declining a locally shadowed name or a
    dynamic scope.
    """
    if node.callee is None:
        return None
    name = free_global_name(node.callee) or alias_name(node.callee)
    if name not in names:
        return None
    if not node.arguments:
        return None
    return string_value(node.arguments[0]) or eval_string(node.arguments[0])


def _extract_function_body_code(
    constructor_call: JsCallExpression | JsNewExpression,
    *,
    intrinsic_callee: Callable[[Expression | None], bool],
    eval_string: Callable[[Expression | None], str | None],
) -> tuple[str, bool] | None:
    """
    The body code string of a `Function` construction together with whether the construction binds
    parameters, or `None` when it is not one. The shapes are the ones the callee can take:

        Function("code")                          the free global, by name
        new Function("code")                      the same, constructed
        (function(){}).constructor("code")        a `.constructor` navigation
        var g = f.constructor; g("code")          a name holding one of those

    The last string argument is the function body; every preceding argument must be a string literal,
    because those name parameters. A single leading argument that is empty or whitespace names a
    zero-parameter function (`Function(" ", code)` — the parameter text is trimmed before the list is
    parsed) and binds nothing; anything else the leading arguments spell is taken as binding, which
    declines the inline rather than guessing the parameter list.
    """
    if not intrinsic_callee(constructor_call.callee):
        return None
    args = constructor_call.arguments
    if not args:
        return None
    last = args[-1]
    body = string_value(last) or eval_string(last)
    if body is None:
        return None
    if not all(isinstance(a, JsStringLiteral) for a in args[:-1]):
        return None
    return body, _leading_arguments_bind_parameters(args[:-1])


def _leading_arguments_bind_parameters(leading: list[Node]) -> bool:
    """
    Whether the leading string arguments of a `Function` construction bind parameters. None do when
    there are none — `Function(code)` is zero-parameter — and none when there is exactly one that is
    empty or whitespace. Two empty arguments are parameter
    text `','`, a `SyntaxError` the construction itself raises, and a construction that may not parse
    is left standing rather than replaced by its body.
    """
    if len(leading) != 1:
        return bool(leading)
    text = string_value(leading[0])
    return bool(text and text.strip(TRIMMABLE_WHITESPACE))


def _function_constructor_body(
    ctor_call: Node,
    *,
    intrinsic_callee: Callable[[Expression | None], bool],
    eval_string: Callable[[Expression | None], str | None],
) -> tuple[str, bool] | None:
    """
    Given the construction *ctor_call* itself — `Function("code")`, `new Function("code")`, or any
    other spelling of the intrinsic its callee denotes — return its body code together with whether
    the construction binds parameters. Returns `None` when *ctor_call* is not such a construction.
    The caller decides how the constructed function is invoked and ORs in whether that invocation
    passes arguments, since a body that binds either a parameter or a call argument cannot be inlined.
    """
    if not isinstance(ctor_call, (JsCallExpression, JsNewExpression)):
        return None
    return _extract_function_body_code(
        ctor_call, intrinsic_callee=intrinsic_callee, eval_string=eval_string)


def _parse_construction_function(ctor_call: Node, code: str) -> tuple[JsScript, JsFunctionExpression] | None:
    """
    The script wrapping a `Function` construction's body as the function the construction builds,
    together with that script, or `None` where the body is not one this package can execute: it does
    not parse as a plain function's body, its parameters — the construction's leading string
    arguments, spliced into the wrapper's parameter list — are not a plain comma-separated
    identifier list, or it declares strict mode, which changes what `arguments`, `this` and a
    global assignment mean in ways the execution below does not model.

    The wrapper is a function expression rather than a bare statement list so the fragment model
    built over it sees the function's own scope: the `arguments` binding the body reads lives there,
    and the execution's question — may this call hand the body an arguments object — is one the
    model can answer only for a function it placed.
    """
    leading = [string_value(argument) for argument in ctor_call.arguments[:-1]]
    if any(text is None for text in leading):
        return None
    parameters = ','.join(text for text in leading if text is not None)
    parsed = _try_parse(
        F'(function ({parameters}) {{ {code} }})',
        strict=False,
        module=False,
        context=function_context(False, False),
    )
    if parsed is None or not parsed.body:
        return None
    statement = parsed.body[0]
    if not isinstance(statement, JsExpressionStatement) or statement.expression is None:
        return None
    function = strip_parens(statement.expression)
    if not isinstance(function, JsFunctionExpression):
        return None
    if not all(isinstance(param, JsIdentifier) for param in function.params):
        return None
    if declares_use_strict(function.body):
        return None
    return parsed, function


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

    where the function has exactly one parameter. A setter assigning its own parameter names
    nothing outside the setter, so it yields no target.
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
    if not isinstance(expr.left, JsIdentifier) or expr.left.name == param_name:
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
    body_model: SemanticModel,
    param_name: str,
    getters: dict[str, str | JsUnaryExpression],
    setters: dict[str, str],
) -> list[JsIdentifier] | None:
    """
    Replace every free `param[key]` access in the parsed code with the name the proxy mapping
    resolves it to, returning the replacement identifiers (a `typeof` target's operand for that
    getter form) or `None` where resolution fails. Only a reference the body leaves free is the
    constructed function's parameter: one a nested function binds is that function's own and is
    left alone, while a top-level binding of the name aliases the parameter itself, which no script
    splice reproduces, so it fails resolution — as does a free use that is not a member access,
    since it uses the proxy object as a value. A plain read resolves to the getter target and a
    simple `key = v` write to the setter target; a compound, update, or delete access reads via the
    getter AND writes via the setter, which no single substitution preserves, so it fails too.
    """
    bound = body_model.root_scope.bindings.get(param_name)
    if bound is not None and bound.kind is not BindingKind.IMPLICIT_GLOBAL:
        return None
    replaced: list[JsIdentifier] = []
    for node in list(parsed.walk()):
        if not isinstance(node, JsIdentifier) or node.name != param_name:
            continue
        if not body_model.is_reference(node):
            continue
        binding = body_model.resolve(node)
        if binding is not None and binding.kind is not BindingKind.IMPLICIT_GLOBAL:
            continue
        member = node.parent
        if not isinstance(member, JsMemberExpression) or member.object is not node:
            return None
        key = access_key(member)
        if key is None:
            return None
        if is_simple_assignment_target(member):
            if key not in setters:
                return None
            replacement: JsIdentifier | JsUnaryExpression = JsIdentifier(name=setters[key])
        elif is_member_write_target(member):
            return None
        else:
            target = getters.get(key)
            if target is None:
                return None
            if isinstance(target, str):
                replacement = JsIdentifier(name=target)
            else:
                replacement = _clone_node(target)
        _replace_in_parent(member, replacement)
        if isinstance(replacement, JsIdentifier):
            replaced.append(replacement)
        elif isinstance(replacement.operand, JsIdentifier):
            replaced.append(replacement.operand)
        else:
            return None
    return replaced


def _try_unpack_function_constructor(
    node: JsCallExpression,
    *,
    free_global_name: Callable[[Expression | None], str | None],
    module: bool = False,
) -> tuple[JsScript, frozenset[str]] | None:
    """
    Unpack an immediately-invoked `Function` constructor whose single argument is a proxy object
    with getter/setter properties that redirect to global variables:

        Function("p", "p.abc = p.def(p.ghi)")(
            {get abc() { return x }, set abc(v) { x = v }, get def() { return y }, ...}
        )

    Parses the code string and resolves all free `p.key` accesses through the proxy mapping back to
    their original identifiers. Returns the substituted body paired with the names whose site
    resolution the substitution has already settled, or `None` if the node does not match —
    including when the inner callee is not the free global `Function` — or if any proxy access
    cannot be resolved. The caller must still admit the body the way every reflected body is
    admitted; this function earns only the one exemption it returns. A getter or setter target is
    spelled inside an accessor defined at the call site itself, so it resolves at the site exactly
    as the accessor does, provided the substituted occurrence is still free where it lands in the
    body — a body binding capturing one fails here — and provided the packed code did not also read
    the name freely, in which case it stays held to the global-resolution rule and is not returned.
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
    parsed = _try_parse(
        code,
        strict=strict_mode_at(node) or module,
        module=module,
        context=code_context_at(node),
    )
    if parsed is None:
        return None
    if not param_name:
        return parsed, frozenset()
    body_model = build_semantic_model(parsed)
    originally_free = _body_free_names(body_model, parsed)
    replaced = _substitute_proxy_accesses(parsed, body_model, param_name, getters, setters)
    if replaced is None:
        return None
    substituted_model = build_semantic_model(parsed)
    for ident in replaced:
        binding = substituted_model.resolve(ident)
        if binding is not None and binding.kind is not BindingKind.IMPLICIT_GLOBAL:
            return None
    introduced = {ident.name for ident in replaced}
    return parsed, frozenset(introduced - (originally_free - {param_name}))


def _is_pack_shaped(
    node: JsCallExpression,
    *,
    free_global_name: Callable[[Expression | None], str | None],
) -> bool:
    """
    Return `True` when the call has the shape of a pack pattern: the callee is a free-global `Function()`
    call and the outer argument is an object expression. When this shape is detected, the generic
    function-body extraction should be skipped to avoid inlining code with unresolved proxy references.
    The callee is identified through the model, so a locally shadowed `Function` is not mistaken for the
    intrinsic.
    """
    inner = node.callee
    if not isinstance(inner, JsCallExpression) or inner.callee is None:
        return False
    if free_global_name(inner.callee) != 'Function':
        return False
    return len(node.arguments) == 1 and isinstance(node.arguments[0], JsObjectExpression)


def _has_top_level_await(stmts: list[Statement]) -> bool:
    """
    Whether *stmts* await outside every function written in them: an `await` expression or a
    `for await` head that no `async` function within the text encloses. Reflected text is read
    with the Script goal, which has no top-level `await`, so such a text is a `SyntaxError` at the
    call that evaluates it, whatever the destination would read.
    """
    return any(
        isinstance(n, JsAwaitExpression) or (isinstance(n, JsForOfStatement) and n.is_await)
        for s in stmts
        for n in walk_scope(s)
    )


def _has_top_level_return(stmts: list[Statement]) -> bool:
    """
    Whether *stmts* — an evaluated code string's body — has a `return` at its own top level, outside any
    nested function. A `return` outside a function is a SyntaxError in `eval` and string-timer code, so
    such a body throws when evaluated and must not be inlined as if it produced a value or ran to
    completion. The `Function` constructor is exempt: its body is a real function body, where a
    top-level `return` is the function's own return.
    """
    return any(isinstance(n, JsReturnStatement) for s in stmts for n in walk_scope(s))


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


def _body_written_free_names(body_model: SemanticModel, parsed: JsScript) -> set[str]:
    """
    The names *parsed* writes without binding them locally — the subset of `_body_free_names` whose
    reference is an assignment target rather than a read. A body that only reads a free name changes
    nothing about what the name denotes elsewhere, while one that writes it gives every later
    consultation of that name a value the pinned model has never seen.
    """
    written: set[str] = set()
    for ident in parsed.walk():
        if not isinstance(ident, JsIdentifier) or not body_model.is_reference(ident):
            continue
        if reference_role(ident) is Role.READ:
            continue
        binding = body_model.resolve(ident)
        if binding is None or binding.kind is BindingKind.IMPLICIT_GLOBAL:
            written.add(ident.name)
    return written


class JsReflectionInlining(ScriptLevelTransformer):
    """
    Inline reflective code execution: `eval`, `Function` constructor, constructor chains, and
    indirect invocation via `setTimeout` and `setInterval`.
    """

    _read_effect: Callable[[Node], bool]
    _alias_name: Callable[[Expression | None], str | None]
    _free_global: Callable[[Expression | None], str | None]
    _eval_string: Callable[[Expression | None], str | None]
    _intrinsic_callee: Callable[[Expression | None], bool]
    _pending_retire: dict[int, Binding]
    _retire_candidates: dict[int, JsIdentifier]
    _pending_atomic: dict[int, list[JsVariableDeclarator]]
    _spliced_names: set[str]

    def _process_script(self, node: JsScript) -> None:
        """
        Inline every reflective site in the script, holding the semantic model for the whole pass.

        Each inline splices in code that was a string, so this pass *can* reveal facts its held model
        predates — `eval('Math.floor = f')` makes a write visible that no pre-inline model could see. What
        makes holding the model sound is the precondition rather than the absence of such reveals: this
        transform only ever does work on a script that has a reflective surface — the eval, `Function`,
        timer, and constructor-chain sites it inlines are themselves read surfaces — and
        `has_reflection_surface`
        being true withdraws trust from every intrinsic (see
        `refinery.lib.scripts.js.analysis.effects.EffectModel.trusted_intrinsic`). No fold against a
        built-in can be admitted anywhere inside this window, so a write revealed here cannot be acted on
        before the pin is released and the model rebuilt. Inlining can only turn that flag off, never on,
        which leaves the held answer the stricter one. The write-side refusal
        (`SemanticModel.has_opaque_global_write`) does not share that never-on property — a splice can
        write one (`eval('globalThis[k] = f')`) — but it does not need it: while the read surface
        stands, the same folds are refused under either fact, and the work sites keep the read
        surface standing for as long as there is work to do.

        The retirement of consumed temporaries is the one decision that argument cannot carry — whether a
        temporary is still named is a structural fact the splices themselves change — so it runs after the
        pin is released, against the model rebuilt over the post-splice tree. That rebuild is the second
        root-model build a pass with a retirement candidate pays, and the only one.

        Should this transform ever run on a script with no reflective surface, or should that flag stop
        gating intrinsic trust, this argument does not hold and the pin must be reconsidered. The
        tampering oracle (`ModelCache.builtins_intact_at`) is that reconsideration for the consumers
        that hold an anchor: its site enumeration is model-backed and fails closed on nodes the pinned
        models cannot place, which is the two-leg argument
        `refinery.lib.scripts.js.analysis.tampering` states in full — the pin holds for the questions
        asked through it, and the consumer that does not ask keeps the program-wide refusal above.
        """
        cache = model_cache(self, node)
        with cache.pinned():
            # The resolvers below fetch the models lazily, per resolved site, which can fall after
            # the first splice's edit. Warming the root-reading models at entry keeps each late
            # build a pure function of held bases, so none reads a tree the pin's edits moved.
            cache.warm()
            self._spliced_names = set()
            self._read_effect = self._dynamic_read_effect(node)
            self._alias_name = self._alias_member_name(node)
            self._free_global = self._free_global_name(node)
            self._base_droppable = self._reflective_base_droppable(node)
            self._eval_string = self._string_argument_value(node)
            self._intrinsic_callee = self._function_intrinsic_callee(node)
            self._pending_retire = {}
            self._retire_candidates = {}
            self._pending_atomic = {}
            self._inline_statements(node)
            self._inline_expressions(node)
            self._lower_timers(node)
        self._retire_consumed_temporaries(node)

    def _note_retirement(self, site: Node, binding: Binding | None) -> None:
        """
        Record that inlining the reflective call at *site* would retire the single-use temporary
        *binding* — the local whose sole value is the `Function` construction the call invokes. The note
        is provisional: it is keyed by the site and only acted on once `_confirm_retirement` sees the
        inlining committed, so a resolution the caller declines (a body that could not be reduced to an
        expression, a statement `_sanitize_inlined_body` rejects) retires nothing.
        """
        if binding is not None:
            self._pending_retire[id(site)] = binding

    def _confirm_retirement(self, site: Node) -> None:
        """
        Acknowledge that the inlining at *site* was committed, marking its temporary a retirement
        candidate. Whether the candidate may actually go is decided by `_retire_consumed_temporaries`
        against the model rebuilt after the pin, where every read the splices added is visible.
        """
        binding = self._pending_retire.pop(id(site), None)
        if binding is None or len(binding.declarations) != 1:
            return
        declaration = binding.declarations[0]
        self._retire_candidates[id(declaration)] = declaration

    def _retire_consumed_temporaries(self, root: JsScript) -> None:
        """
        Drop the declarator of each single-assignment temporary whose construction invocations this
        pass inlined and which nothing in the post-splice tree still names. The construction itself is
        side-effect-free precisely because the inlining succeeded — `_resolve_reflected_body` parses the
        code and declines a body it cannot, so a construction whose body was inlined provably parses and
        cannot throw — which is the judgment `refinery.lib.scripts.js.analysis.effects.EffectModel`
        withholds from an intrinsic under a live reflection surface and only this pass, having parsed
        the code, can make. That judgment covers the construction alone: its arguments are ordinary
        expressions whose effects the retirement would delete, so each must be droppable on its own.

        Every question is asked of the model rebuilt after the pin, because the splices this pass
        committed are exactly what the pinned model cannot see: a spliced `eval` body or lowered timer
        that names the temporary, the handed-over global object a folded finder minted through which a
        callee reads it as a property (both counted by `nothing_still_names`), and the name the analyst
        declared a host reaches (`a_host_reaches_the_binding`). A reflective surface that survives the
        pass — an `eval` this pass declined, a string timer it could not lower — can name the temporary
        at runtime with no reference any model records, so any such site outside the candidates' own
        constructions refuses the retirement; the constructions themselves are the one surface whose
        code this pass parsed, which is what makes them transparent rather than opaque.
        """
        if not self._retire_candidates:
            return
        cache = model_cache(self, root)
        model = cache.model
        transparent: set[int] = set()
        candidates: list[tuple[Binding, JsVariableDeclarator, JsCallExpression | JsNewExpression]] = []
        for declaration in self._retire_candidates.values():
            binding = model.binding_of(declaration)
            if binding is None or binding.exported or len(binding.declarations) != 1:
                continue
            declarator = binding.declarations[0].parent
            if not isinstance(declarator, JsVariableDeclarator) or declarator.init is None:
                continue
            construction = strip_parens(declarator.init)
            if not isinstance(construction, (JsCallExpression, JsNewExpression)):
                continue
            transparent.add(id(construction.callee))
            candidates.append((binding, declarator, construction))
        retired: list[JsVariableDeclarator] = []
        for binding, declarator, construction in candidates:
            if not nothing_still_names(model, [declarator]):
                continue
            if a_host_reaches_the_binding(model, binding, self.options):
                continue
            if any(
                id(site) not in transparent
                for site in model.reflection_surface_sites(binding)
            ):
                continue
            if not all(
                cache.effects.is_side_effect_free(
                    argument, None,
                    call_established=cache.call_established, discarded=True,
                    reads_may_throw=True, read_established=cache.read_established)
                for argument in construction.arguments
            ):
                continue
            retired.append(declarator)
        for declarator in retired:
            remove_declarator(declarator)
            self.mark_changed()

    def _dynamic_read_effect(self, root: JsScript) -> Callable[[Node], bool]:
        """
        A predicate reporting whether reading a node fires a `with` object's getter or may throw a
        `ReferenceError` a creating write has not certainly completed for, resolved against *root*'s
        current model. Threaded into the reflective-inlining safety checks so a read that may fire a
        getter or throw is never dropped as if it were pure — the same throwing read leaf every
        other discarding context asks
        (`refinery.lib.scripts.js.analysis.effects.EffectModel.throwing_read_effect` over the shared
        establishment proof). Resolved lazily through the shared cache, so a script with no
        reflective site builds no model.
        """
        def read_effect(node: Node) -> bool:
            cache = model_cache(self, root)
            return cache.effects.read_throws(node, cache.read_established)
        return read_effect

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
            member = strip_parens(callee)
            if not isinstance(member, JsMemberExpression):
                return None
            base = strip_parens(member.object)
            if isinstance(base, JsIdentifier) and base.name in self._spliced_names:
                return None
            model = model_cache(self, root).model
            if model.scope_of(member) is None:
                return None
            name = model.global_alias_member_name(
                member, module_scope=runs_as_module(self.options, root))
            if name is not None and name in self._spliced_names:
                return None
            return name
        return resolve

    def _reflective_base_droppable(self, root: JsScript) -> Callable[[Expression | None], bool]:
        """
        Whether the base of a global-object-alias `eval` member may be discarded when its call is
        inlined. The base must name *this* realm's global object (`names_this_realms_global_object`, the
        shared same-realm-alias predicate the finder fold and the alias-member collapse also key on),
        never the cross-realm `top`/`frames`, whose `eval` runs code in another realm the inline would
        move it out of; and it must resolve without throwing under the pinned host
        (`SemanticModel.read_may_throw`), so the `ReferenceError` a lacking host raises reading it is not
        dropped. Resolved lazily against *root*'s current model like `_alias_member_name`.
        """
        def resolve(callee: Expression | None) -> bool:
            member = strip_parens(callee) if callee is not None else None
            if not isinstance(member, JsMemberExpression):
                return False
            model = model_cache(self, root).model
            base = strip_parens(member.object)
            if not isinstance(base, JsIdentifier) or not names_this_realms_global_object(model, base):
                return False
            return not model.read_may_throw(base)
        return resolve

    def _free_global_name(self, root: JsScript) -> Callable[[Expression | None], str | None]:
        """
        A resolver reporting the reflective intrinsic a bare callee identifier denotes — `eval` yields
        `'eval'`, `Function` yields `'Function'`, a timer or `execScript` its own name — or `None`. Only
        a name that could name such a callee is resolved; any other identifier is declined before any
        model lookup, since no caller acts on a non-reflective name. A local binding (a parameter, a
        `var`, a `with`-object property) of the name is an ordinary value, not the intrinsic, and must
        not drive an inline; the model resolves a reference to its binding for a shadow and to `None` for
        a free global, and `read_has_dynamic_effect` rejects a name read through a dynamic scope.
        Resolved lazily against *root*'s current model, mirroring `_dynamic_read_effect`.
        """
        def resolve(callee: Expression | None) -> str | None:
            if callee is None:
                return None
            ident = strip_parens(callee)
            if not isinstance(ident, JsIdentifier) or ident.name not in _REFLECTIVE_CALLEE_NAMES:
                return None
            if ident.name in self._spliced_names:
                return None
            model = model_cache(self, root).model
            if model.scope_of(ident) is None:
                return None
            if model.resolve(ident) is None and not model.read_has_dynamic_effect(ident):
                return ident.name
            return None
        return resolve

    def _string_argument_value(self, root: JsScript) -> Callable[[Expression | None], str | None]:
        """
        A resolver folding an argument expression to the string it denotes — `atob('...')` to the code
        it decodes — or `None`. The interpreter is given *root*'s semantic model, because a call it
        answers from the built-in registry is the built-in only where nothing has bound that name,
        and the run's effect model, because whether it is the built-in at all is the trust question
        no model-free fold may skip. Resolved lazily against *root*'s current models, mirroring
        `_dynamic_read_effect`.
        """
        def resolve(node: Expression | None) -> str | None:
            if node is None:
                return None
            if self._spliced_names and any(
                isinstance(ident, JsIdentifier) and ident.name in self._spliced_names
                for ident in node.walk()
            ):
                return None
            cache = model_cache(self, root)
            if cache.model.scope_of(node) is None:
                return None
            return _try_eval_string_arg(node, cache.model, cache.effects)
        return resolve

    def _function_intrinsic_callee(self, root: JsScript) -> Callable[[Expression | None], bool]:
        """
        A resolver reporting whether a callee expression denotes the `Function` intrinsic — the
        bare free global, a `.constructor` navigation (from a literal, or from a name the model pins
        to one function), or a name holding one of those, transitively. This is the callee half of
        every `Function`-construction extraction: a construction spelled with any of those
        spellings builds the function the named intrinsic does, from the same arguments.

        The recognition itself is the one shared vocabulary
        (`refinery.lib.scripts.js.analysis.tampering.denotes_function_intrinsic`), consumed here
        with the model's facts and this pass's own string resolution and effect checks: the same
        recognizer answers the tampering oracle's construction sites. The alias hops resolve with
        the position supplied — the cache's tampering model, its `singular_value_at` — so a
        volatile alias the run can order answers where the stock question declines. A resolver it
        cannot decide declines the inline, which is the safe answer for both consumers of it.
        """
        def resolve(callee: Expression | None) -> bool:
            cache = model_cache(self, root)
            return denotes_function_intrinsic(
                callee,
                cache.model,
                cache.effects,
                cache.dominance,
                eval_string=self._eval_string,
                read_effect=self._read_effect,
                positioned_value=cache.tampering.singular_value_at,
                spliced_names=self._spliced_names,
            ) is True

        return resolve

    def _inline_statements(self, root: JsScript) -> None:
        for container in list(root.walk()):
            body = get_body(container)
            if body is None:
                continue
            i = 0
            while i < len(body):
                original = body[i]
                resolved = self._try_resolve_statement(original, root, container is root)
                if resolved is None:
                    i += 1
                    continue
                returns_undefined, parsed = resolved
                parsed = sanitize_inlined_body(parsed)
                if parsed is None:
                    self._pending_atomic.pop(id(original), None)
                    i += 1
                    continue
                if container is root and preserves_script_return(self.options):
                    at_script_end = not any(
                        definitely_answers_the_completion(later) for later in body[i + 1:]
                    )
                    parsed = preserve_script_end_value(
                        parsed,
                        returns_undefined=returns_undefined,
                        at_script_end=at_script_end,
                    )
                # The deletions an atomically admitted fold carries run before the splice, so the
                # statements the loop still holds keep their positions.
                i -= self._remove_consumed_temporaries_of(original, container, i)
                set_body(container, [*body[:i], *parsed, *body[i + 1:]])
                self._confirm_retirement(original)
                self.mark_changed()
                i += len(parsed)

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
            self._remove_consumed_temporaries_of(node, None, 0)
            self._confirm_retirement(node)
            self.mark_changed()

    def _lower_timers(self, root: JsScript) -> None:
        """
        Rewrite a string-argument timer — `setTimeout("code", delay)`, `setInterval`, and their
        `setImmediate`/global-alias variants — into a deferred function call
        `setTimeout(function () { code }, delay)`, so the evaluated code is deobfuscated without changing
        when or how often it runs. Unlike the eval and constructor paths, a timer is not inlined at the
        call site: its value is a handle and its execution is deferred, so only its code string is
        lowered. `execScript` is not a timer — it evaluates synchronously — so it is inlined in place by
        `_try_resolve_statement` instead of lowered here.
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
        The body lands inside that wrapper and not as text at the site, so the words it is weighed
        against are those a plain function reads: `await` and `yield` are names there, and
        `arguments` is the wrapper's own, whatever the site reads them as.
        """
        code = _extract_string_call_code(
            node,
            TIMER_NAMES,
            alias_name=self._alias_name,
            free_global_name=self._free_global,
            eval_string=self._eval_string,
        )
        if code is None:
            return
        resolved = self._resolve_reflected_body(
            code,
            node,
            root,
            ReflectedScope.GLOBAL_EVAL,
            at_global_scope=False,
            destination=function_context(False, False),
        )
        if resolved is None:
            return
        block = JsBlockStatement(body=resolved.body)
        wrapper = JsFunctionExpression(params=[], body=block)
        block.parent = wrapper
        for stmt in resolved.body:
            stmt.parent = block
        _replace_in_parent(node.arguments[0], wrapper)
        self.mark_changed()

    def _try_resolve_statement(
        self, stmt: Statement, root: JsScript, at_global_scope: bool,
    ) -> tuple[bool, list[Statement]] | None:
        """
        Resolve a statement-position reflective call to the statements it should become, paired with
        whether the call handed back `undefined`, or `None`. A `Function`-constructor pack is unpacked
        and its substituted body admitted like any constructed body; a direct or indirect `eval` and a
        `Function` body are handled by `_resolve_reflected_call`; `execScript("code")` runs its code
        synchronously in the global scope and discards the value, so at statement position it is
        replaced by that code inlined in place. An `await`-ed call is not a plain call expression here,
        so it is left for the expression pass, which rewrites the `eval` inside `await eval("expr")` to
        `await (expr)` without dropping the `await`.

        The first element is what the call's value was: a constructed function and `execScript` hand
        back `undefined` (a constructed function unless its body ends in a value `return`), while an
        `eval` hands back the completion of its own code, which the inlined body reproduces — so only
        the first kind can leave a value in a script-end position the call did not.
        """
        if not isinstance(stmt, JsExpressionStatement) or stmt.expression is None:
            return None
        node = stmt.expression
        if not isinstance(node, JsCallExpression):
            return None
        sync = _extract_string_call_code(
            node,
            SYNC_EVAL_NAMES,
            alias_name=self._alias_name,
            free_global_name=self._free_global,
            eval_string=self._eval_string,
        )
        if sync is not None:
            parsed = self._resolve_reflected_body(
                sync, stmt, root, ReflectedScope.GLOBAL_EVAL, at_global_scope,
            )
            if parsed is None:
                return None
            return True, parsed.body
        pack = _try_unpack_function_constructor(
            node,
            free_global_name=self._free_global,
            module=runs_as_module(self.options, root),
        )
        if pack is not None:
            packed, site_resolved = pack
            admitted = self._admit_reflected_body(
                packed, stmt, root, ReflectedScope.FUNCTION_CONSTRUCTOR, at_global_scope,
                site_resolved=site_resolved,
            )
            if admitted is None:
                return None
            return body_returns_undefined(admitted.body), list(admitted.body)
        if _is_pack_shaped(node, free_global_name=self._free_global):
            return None
        resolved = self._resolve_reflected_call(node, stmt, root, at_global_scope)
        if resolved is None:
            return None
        scope, script = resolved
        returns_undefined = (
            scope is ReflectedScope.FUNCTION_CONSTRUCTOR
            and body_returns_undefined(script.body)
        )
        return returns_undefined, script.body

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

        A construction whose body the inline route declines — one that binds parameters or reads its
        `arguments`, or a call that passes any — is not the end: `_try_evaluate_construction` executes
        the constructed body over the call's argument values, so a body too entangled to splice as
        text can still resolve the call to the value it answers.
        """
        read_effect = self._read_effect
        alias_name = self._alias_name
        free_global_name = self._free_global
        resolved = self._resolved_constructor_call(node, root)
        if resolved is not None:
            ctor_call, retire = resolved
            body = _function_constructor_body(
                ctor_call, intrinsic_callee=self._intrinsic_callee,
                eval_string=self._eval_string)
            if body is not None:
                code, ctor_binds = body
                parsed = self._resolve_reflected_body(
                    code, site, root, ReflectedScope.FUNCTION_CONSTRUCTOR, at_global_scope,
                    binds=ctor_binds,
                    invocation_arguments=node.arguments,
                )
                if parsed is not None:
                    self._note_retirement(site, retire)
                    return ReflectedScope.FUNCTION_CONSTRUCTOR, parsed
                parsed = self._try_atomic_construction_inline(
                    node, site, ctor_call, retire, code, root, at_global_scope,
                    binds=ctor_binds)
                if parsed is not None:
                    return ReflectedScope.FUNCTION_CONSTRUCTOR, parsed
                self._try_evaluate_construction(node, site, ctor_call, code, retire, root)
                return None
        direct = _extract_eval_code(
            node, free_global_name=free_global_name, eval_string=self._eval_string)
        if direct is not None:
            parsed = self._resolve_reflected_body(
                direct, site, root, ReflectedScope.DIRECT_EVAL, at_global_scope,
            )
            return (ReflectedScope.DIRECT_EVAL, parsed) if parsed is not None else None
        code = _extract_indirect_eval_code(
            node, read_effect, alias_name=alias_name, free_global_name=free_global_name,
            eval_string=self._eval_string, base_droppable=self._base_droppable)
        if code is not None:
            parsed = self._resolve_reflected_body(
                code, site, root, ReflectedScope.GLOBAL_EVAL, at_global_scope,
            )
            return (ReflectedScope.GLOBAL_EVAL, parsed) if parsed is not None else None
        return None

    def _resolved_constructor_call(
        self, node: JsCallExpression, root: JsScript,
    ) -> tuple[Node, Binding | None] | None:
        """
        The `Function` construction that *node* invokes, paired with the single-use temporary to retire
        once its sole read is inlined (or `None` to retire nothing). For the immediate forms —
        `Function("code")()`, `new Function(...)()`, `(function(){}).constructor("code")()` — the
        construction is `node`'s own callee. When the callee is a bare identifier, the construction is
        the value the name provably holds (`SemanticModel.singular_value`, which already declines a
        reassigned or dynamically rebindable binding), taken only where that value is established before
        *node* (`DominanceModel.binding_established_before`) so the invocation cannot read it out of its
        temporal dead zone — and not at all for a script-scope name while the program stores a property
        on the global object under a runtime key (`SemanticModel.has_opaque_global_write`) that the
        tampering oracle does not clear at *node* (`ModelCache.builtins_intact_at`): under the script
        execution model such a name is a property of that object, the one such a write may rebind, so
        its spelled value is not what the call runs — unless every write is guaranteed to follow the
        invocation. A value that is not itself a construction declines, whatever it denotes: a name
        holding the intrinsic (`var g = f.constructor`) makes a call through it a construction —
        one that *builds* a function and never runs it — so there is no invocation for this to
        resolve, and the call stays standing. The body is inlined at *node*, never the
        construction relocated, so a `Function` reference in the initializer keeps its original scope;
        retiring the dead temporary is
        left to `_retire_consumed_temporaries` on the model rebuilt after the pass.
        """
        callee = strip_parens(node.callee)
        if isinstance(callee, (JsCallExpression, JsNewExpression)):
            return callee, None
        if not isinstance(callee, JsIdentifier):
            return None
        if callee.name in self._spliced_names:
            return None
        cache = model_cache(self, root)
        binding = cache.model.resolve(callee)
        if (
            binding is not None
            and binding.scope is cache.model.root_scope
            and cache.model.has_opaque_global_write()
            and not cache.builtins_intact_at(node)
        ):
            return None
        value = strip_parens(cache.model.singular_value(binding))
        if not isinstance(value, (JsCallExpression, JsNewExpression)):
            return None
        if not cache.dominance.binding_established_before(binding, node):
            return None
        return value, binding

    def _try_atomic_construction_inline(
        self,
        node: JsCallExpression,
        site: Node,
        ctor_call: Node,
        retire: Binding | None,
        code: str,
        root: JsScript,
        at_global_scope: bool,
        *,
        binds: bool = False,
    ) -> JsScript | None:
        """
        The atomic route: splice the constructed body at the invocation and delete the temporaries
        that spell the construction in the same edit, admitting the body against the tree that edit
        leaves. The plain route holds every site-scope binding of a spliced body's names to the
        global-resolution rule and every declaration to the capture rule, which is sound — but a
        body whose injected dead code names exactly the holder (`var h = … .constructor`) or the
        construction temporary (`var f = h(code)`) collides only with bindings the fold itself
        consumes, and the collision is an artifact of asking before the edit. This route asks
        after it: the bindings are excluded from the model's answers, so a name they occupy resolves
        past it and a use resolving to one is carried off.

        Only the temporaries may be deleted this way. Everything else the plain route refuses for
        stays refused — a free name resolving to a binding the fold keeps, a declaration capturing
        a live reference — because the exclusion covers no binding but the consumed ones.

        The route runs only where the plain admission declined, so a construction whose argument
        is not droppable (`atob(…)`) keeps every fold the plain route already gives it: the atomic
        gates — a droppable initializer for each holder, arguments no other fold must keep — are
        asked of no construction that inlines without them. A body that binds parameters keeps
        declining with the plain route, which is where the evaluation route below picks it up.
        """
        if binds:
            return None
        cache = model_cache(self, root)
        aliases = function_intrinsic_aliases(
            ctor_call.callee, cache.model, cache.effects, cache.dominance,
            eval_string=self._eval_string, read_effect=self._read_effect,
            positioned_value=cache.tampering.singular_value_at,
            spliced_names=self._spliced_names,
        )
        if aliases is None:
            return None
        consumed = list(aliases)
        if retire is not None:
            consumed.append(retire)
        if not consumed:
            return None
        declarators = self._consumed_temporaries_may_go(cache, consumed, ctor_call, site)
        if declarators is None:
            return None
        parsed = self._resolve_reflected_body(
            code, site, root, ReflectedScope.FUNCTION_CONSTRUCTOR, at_global_scope,
            invocation_arguments=node.arguments,
            exclude=frozenset(consumed),
        )
        if parsed is None:
            return None
        self._spliced_names |= {binding.name for binding in consumed}
        self._pending_atomic[id(site)] = declarators
        return parsed

    def _consumed_temporaries_may_go(
        self,
        cache: ModelCache,
        consumed: list[Binding],
        ctor_call: Node,
        site: Node,
    ) -> list[JsVariableDeclarator] | None:
        """
        Whether every temporary the fold consumes — the holder names the construction's callee
        resolves through and the construction binding itself — may be deleted together with the
        splice, returning their declarators or `None`. The questions are the ones
        `_retire_consumed_temporaries` asks after the pin, asked here against the pinned model
        because this deletion rides the same edit as the splice rather than following it: nothing
        outside the region the edit replaces may still name a temporary (a second read, a
        `with`-body use, an alias through a form no pass matches), no host the analyst named
        reaches one, and no opaque reflective surface the edit does not carry off could name one
        at runtime with no reference any model records. The construction itself is the one surface
        whose code this fold parsed, which is what makes deleting it side-effect-free; its
        arguments and each holder's initializer must be droppable on their own — a `.constructor`
        read is a property read, droppable only while the chain it consults is intact. The hop
        ordering the recognizer proves is what makes each declarator hold the value the
        construction read, so no establishment question is asked here again.
        """
        model = cache.model
        declarators: list[JsVariableDeclarator] = []
        for binding in consumed:
            if binding.exported or len(binding.declarations) != 1:
                return None
            declaration = binding.declarations[0]
            declarator = declaration.parent
            if not isinstance(declarator, JsVariableDeclarator) or declarator.init is None:
                return None
            if a_host_reaches_the_binding(model, binding, self.options):
                return None
            declarators.append(declarator)
        region = [site, *declarators]
        if not nothing_still_names(model, region):
            return None
        for binding in consumed:
            if any(
                not any(
                    surface is removed or surface.is_descendant_of(removed)
                    for removed in region
                )
                for surface in model.reflection_surface_sites(binding)
            ):
                return None
        for declarator in declarators:
            init = strip_parens(declarator.init)
            if init is ctor_call:
                continue
            if not self._droppable_within_region(cache, init, region):
                return None
        if not all(
            self._droppable_within_region(cache, argument, region)
            for argument in ctor_call.arguments
        ):
            return None
        return declarators

    def _droppable_within_region(
        self, cache: ModelCache, node: Node, region: list[Node],
    ) -> bool:
        """
        Whether dropping the evaluation of *node* — an initializer or construction argument
        inside *region* — removes nothing observable, with every member read judged on the tree
        the edit deleting *region* leaves standing rather than the one the pass is pinned to.
        The reads this asks about all live inside the region, so each one's chain question
        reaches `getter_free_read_dropped_with`, which forgives exactly the opaque surfaces the
        same edit carries off and none of those it leaves.
        """
        return cache.effects.is_side_effect_free(
            node, None,
            member_safe=lambda member: cache.effects.getter_free_read_dropped_with(member, region),
            call_established=cache.call_established, discarded=True,
            reads_may_throw=True, read_established=cache.read_established,
        )

    def _remove_consumed_temporaries_of(
        self, site: Node, container: Node | None, index: int,
    ) -> int:
        """
        Delete the declarators the committed splice at *site* consumes — the second half of the one
        edit `_try_atomic_construction_inline` admitted against — returning how many statements
        vanished from the body of *container* before *index*, so a caller splicing at that index
        splices at the shifted one. Where the splice does not replace a statement of *container*'s
        body — *container* is `None` — the declarators' parents are untouched by the replacement
        and no shift is returned. A declaration left with other declarators keeps its statement,
        which is why only a sole declarator counts as taking one away.
        """
        removed = self._pending_atomic.pop(id(site), [])
        vanished = 0
        body = get_body(container) if container is not None else None
        for declarator in removed:
            declaration = declarator.parent
            if (
                body is not None
                and isinstance(declaration, JsVariableDeclaration)
                and declaration.parent is container
                and len(declaration.declarations) == 1
                and next((k for k, s in enumerate(body) if s is declaration), len(body)) < index
            ):
                vanished += 1
            remove_declarator(declarator)
        return vanished

    def _try_evaluate_construction(
        self,
        node: JsCallExpression,
        site: Node,
        ctor_call: Node,
        code: str,
        retire: Binding | None,
        root: JsScript,
    ) -> None:
        """
        The evaluation route: execute the body a `Function` construction builds over the argument
        values the call passes, and replace the call with the value it answers. Where the inline
        route splices the body's text — sound only where nothing in it binds parameters, reads
        `arguments`, or observes the call's arguments — this route runs the body as an interpreter
        would, so exactly the bodies the inline route exists for are the ones this one resolves:
        the decoders that fold their arguments through `arguments[p]`.

        The interpreter runs the parsed fragment against two models, one question per model. The
        real program's effect model answers name integrity — which built-in is still the built-in
        — and the tampering oracle vouches for it at *node*, the anchor: a construction a later
        tampering site would not reach may trust what the program-wide questions refuse. The
        fragment model over the parsed body answers name resolution, so a free name in the fragment
        denotes the host global or nothing, never a binding of the real tree.

        Two static gates refuse before anything runs. The fragment may not write a free name —
        every write form, through the role machinery — for an execution that replaced the call
        would drop the write the real program performs. And the fragment's free names must be
        disjoint from the real tree's root-scope bindings: script-level `let`, `const`, `class`
        and `var` names live in the global lexical environment, visible to a `Function`-constructed
        body, so a fragment reading one answers a binding this route cannot see. Root scope only —
        a binding nested inside a function is invisible to code the global scope runs, and reading
        it as though it were reachable is what the tree-binding gate exists to stop.

        A third gate refuses a fragment reading a name this pass has spliced in. The route runs
        inside the pass's pinned-model window, so a statement an earlier site of the same pass
        inlined — the write an `eval` carried, spliced after the models were built — is one no
        pinned fact records: the name's write is invisible to the effect model that would refuse
        it, and the fragment would answer a value the program replaced. The names the pass has
        spliced are the gate's own record, the same one the inline route refuses through.

        The route's remaining safety is the two-leg argument
        `refinery.lib.scripts.js.analysis.tampering` states — the model-backed site enumeration
        that fails closed on the nodes this pass splices in.
        """
        fragment = _parse_construction_function(ctor_call, code)
        if fragment is None:
            return
        fragment_script, function = fragment
        cache = model_cache(self, root)
        fragment_model = build_semantic_model(fragment_script)
        if _body_written_free_names(fragment_model, fragment_script):
            return
        free = _body_free_names(fragment_model, fragment_script)
        if not free.isdisjoint(cache.model.root_scope.bindings):
            return
        if not free.isdisjoint(self._spliced_names):
            return
        argument_values = self._construction_argument_values(node, root)
        if argument_values is None:
            return
        from refinery.lib.scripts.js.deobfuscation.interpreter import (
            InterpreterError,
            IrreducibleExpression,
            JsInterpreter,
            _ThrowSignal,
        )
        interpreter = JsInterpreter(
            effects=cache.effects,
            model=fragment_model,
            anchor=node,
            tampering=cache.tampering,
        )
        try:
            result = interpreter.execute(function, argument_values)
        except (InterpreterError, IrreducibleExpression, _ThrowSignal, RecursionError, ValueError, OverflowError):
            return
        if not replace_with_value(node, result):
            return
        self._note_retirement(site, retire)
        self._confirm_retirement(site)
        self.mark_changed()

    def _construction_argument_values(
        self, node: JsCallExpression, root: JsScript,
    ) -> list | None:
        """
        The values of *node*'s arguments, extracted under the evaluator's gates: a literal value,
        or an interpreter evaluation — anchored at *node*, like the execution it feeds — of an
        argument whose evaluation is side-effect free and cannot throw before the body runs.
        `None` refuses the call: an argument with an effect or a throw is the program's business,
        not a value this route may consume silently. Passing the values, rather than substituting
        their text, is what keeps call-time binding — the value is read at the call, whatever the
        name held when the fragment was written.
        """
        cache = model_cache(self, root)
        values: list = []
        for argument in node.arguments:
            if argument is None:
                return None
            ok, value = extract_literal_value(argument)
            if ok:
                values.append(value)
                continue
            if not cache.effects.is_side_effect_free(
                argument, None,
                call_established=cache.call_established, discarded=True,
                reads_may_throw=True, read_established=cache.read_established,
            ):
                return None
            from refinery.lib.scripts.js.deobfuscation.interpreter import (
                InterpreterError,
                IrreducibleExpression,
                JsInterpreter,
                _ThrowSignal,
            )
            interpreter = JsInterpreter(
                effects=cache.effects,
                anchor=node,
                tampering=cache.tampering,
                established=lambda callee: cache.dominance.established_before(callee, node),
            )
            try:
                values.append(interpreter.eval_expression(argument))
            except (InterpreterError, IrreducibleExpression, _ThrowSignal, RecursionError, ValueError, OverflowError):
                return None
        return values

    def _argument_may_be_dropped(self, argument: Node, root: JsScript) -> bool:
        """
        Whether replacing a call that passes *argument* with the body it invokes may drop the
        argument's evaluation. A literal is required — the value the call reads is one no splice of
        the body reproduces, so anything that reads a name or runs a call keeps the call standing —
        and the literal must additionally be one whose evaluation is side-effect free and cannot
        throw, the same question `_retire_consumed_temporaries` asks of the arguments of a
        construction it drops: a fold never mutes the program's own effects. The second gate holds
        of every literal the first admits today, and is what keeps the first one sound to widen.
        """
        ok, _ = extract_literal_value(argument)
        if not ok:
            return False
        cache = model_cache(self, root)
        return cache.effects.is_side_effect_free(
            argument, None,
            call_established=cache.call_established,
            discarded=True,
            reads_may_throw=True,
            read_established=cache.read_established,
        )

    def _destination_may_be_strict(self, site: Node, root: JsScript) -> bool:
        """
        Whether the destination of an inline could run the spliced text in strict mode. A
        syntactically strict site is strict; and the module execution model is strictness-ambiguous —
        `DeobfuscationOptions.module` covers a strict ES module and a sloppy CommonJS file alike, and
        nothing here tells the two apart — so a module destination is treated as possibly strict.

        This is the one mode the reflected text must be legal and mode-invariant in, because inlining
        must be sound for the strict reading too: a sloppy-only body spliced into what turns out to be
        an ES module is a `SyntaxError` that takes the whole file down, or behaves differently, where
        the call it replaced merely raised one the site caught. The sloppy reading only ever inlines a
        strict subset of what this admits, so declining here costs a CommonJS-only recall and never a
        soundness. This is why it is asked at every reflection strictness gate rather than left to
        `strict_mode_at`, whose pure-tree answer is blind to the module option, and why the
        complementary sloppy-conservative gates — a mapped `arguments` object, a rest unpacking — read
        `strict_mode_at` alone: their soundness runs the other way, so they must assume the sloppy
        CommonJS reading, not the strict one.
        """
        return strict_mode_at(site) or runs_as_module(self.options, root)

    def _resolve_reflected_body(
        self,
        code: str,
        site: Node,
        root: JsScript,
        scope: ReflectedScope,
        at_global_scope: bool,
        *,
        binds: bool = False,
        destination: CodeContext | None = None,
        invocation_arguments: list[Node] | None = None,
        exclude: Collection[Binding] = (),
    ) -> JsScript | None:
        """
        Parse reflectively evaluated *code* and admit it through `_admit_reflected_body`, or decline
        (`None`). A body that binds parameters (*binds*) cannot be inlined as text, so it declines
        before the parse; a body that observes its arguments declines in the admission, which has
        the parsed body to ask. *invocation_arguments* is the argument list of the call the splice
        would replace, where the code is a construction's body and the call is the invocation of
        what it built — `None` where the site is no call that passes any. *destination* is the
        context the text is read in once spliced, where that is not *site*'s own: a string timer's
        body lands inside a plain function of its own. *exclude* is the set of bindings the same
        edit deletes, handed to the admission as its post-rewrite view.
        """
        if binds:
            return None
        parsed = _try_parse(
            code,
            strict=self._destination_may_be_strict(site, root),
            module=runs_as_module(self.options, root),
            context=code_context_at(site) if destination is None else destination,
        )
        if parsed is None:
            return None
        return self._admit_reflected_body(
            parsed, site, root, scope, at_global_scope,
            invocation_arguments=invocation_arguments,
            exclude=exclude,
        )

    def _admit_reflected_body(
        self,
        parsed: JsScript,
        site: Node,
        root: JsScript,
        scope: ReflectedScope,
        at_global_scope: bool,
        *,
        site_resolved: frozenset[str] = frozenset(),
        invocation_arguments: list[Node] | None = None,
        exclude: Collection[Binding] = (),
    ) -> JsScript | None:
        """
        Decide whether inlining the reflected body *parsed* at *site* preserves meaning, given the
        `ReflectedScope` it runs in. Global-scope code — a `Function`-constructed body or indirect
        `eval`/string-timer code — must run in the global sloppy mode it would have: a strict
        context at *site* declines a body that would diverge under strict mode
        (`diverges_under_strict`), as does a `"use strict"` prologue; every receiver `this` becomes
        `globalThis`; and a body reading `arguments`, `super`, or `new.target`, or a free
        name that no longer denotes the same global at *site* — including one a `with` on the path could
        capture — declines. Direct `eval` runs in the caller's scope, which is *site* itself, so its
        references and `this` are already correct there and only the checks below apply. A top-level
        `return` is a SyntaxError in evaluated code, so an eval body with one declines. Declaration
        handling is delegated to `_reflected_declarations_safe`. Anything not provably safe is left
        intact (returns `None`) — declining is always sound.

        *invocation_arguments* is the argument list of the call the splice replaces, where the site
        is the invocation of a construction: the call evaluates those arguments before the body
        runs, so a splice that drops them may mute an effect or a throw. Every one of them must be
        droppable — `_argument_may_be_dropped` — and a body reading its `arguments` declines below,
        for the call's arguments are exactly what such a body observes.

        *site_resolved* is the one exemption the pack route earns: a name its proxy substitution
        introduced resolves at the site by construction, the accessor spelling it being defined
        there, so it is not held to the global-resolution rule the reflected code's own free names
        must meet. Every other check still applies to it.

        Every name-based answer above is read from the model pinned before any splice, so a body
        naming what an earlier splice this pass declared or wrote is declined outright: for such a
        name the pinned lookup, capture, and dominance answers describe a tree that no longer
        exists. The declined site is untouched and inlines on the next pass, whose model has seen
        the splice. A body that only reads names no splice bound contributes nothing to that veto,
        so a chain of sites sharing free reads still inlines in one pass.
        """
        resolves_globally = scope is not ReflectedScope.DIRECT_EVAL
        site_is_strict = strict_mode_at(site)
        if declares_use_strict(parsed) and (resolves_globally or not site_is_strict):
            return None
        if resolves_globally:
            rewrite_receiver_this_to_global(parsed)
            if references_receiver_this(parsed) or references_new_target(parsed):
                return None
        if scope is not ReflectedScope.FUNCTION_CONSTRUCTOR and _has_top_level_return(parsed.body):
            return None
        if invocation_arguments and any(
            argument is not None and not self._argument_may_be_dropped(argument, root)
            for argument in invocation_arguments
        ):
            return None
        body_model = build_semantic_model(parsed)
        if resolves_globally and self._destination_may_be_strict(site, root) and diverges_under_strict(
            parsed, body_model, site_resolved,
        ):
            return None
        free = _body_free_names(body_model, parsed)
        if resolves_globally and 'arguments' in free:
            return None
        declared = _body_declared_names(body_model)
        if not self._spliced_names.isdisjoint(free | declared):
            return None
        if not free and not declared:
            return parsed
        root_model = model_cache(self, root).model
        site_scope = root_model.scope_of(site)
        if site_scope is None:
            return None
        if resolves_globally and free:
            if crosses_dynamic_scope(site_scope):
                return None
            for name in free:
                if name in site_resolved:
                    continue
                binding = root_model.lookup(name, site_scope, exclude=exclude)
                if binding is not None and not root_model.reaches_global_object(
                    binding, module_scope=runs_as_module(self.options, root),
                ):
                    return None
        if declared and not self._reflected_declarations_safe(
            body_model, root_model, site_scope, site, scope, at_global_scope, exclude,
        ):
            return None
        self._spliced_names |= declared | _body_written_free_names(body_model, parsed)
        return parsed

    def _reflected_declarations_safe(
        self,
        body_model: SemanticModel,
        root_model: SemanticModel,
        site_scope: Scope,
        site: Node,
        scope: ReflectedScope,
        at_global_scope: bool,
        exclude: Collection[Binding] = (),
    ) -> bool:
        """
        Whether the top-level declarations of a reflected body can be reproduced by inlining it at the
        call site. A `Function`-constructed body's declarations are local to the created function and
        lift into the caller's scopes (`inlined_declarations_safe`); evaluated code declares in its
        execution scope and is handled by `_eval_declarations_safe`. *exclude* carries the atomic
        fold's post-rewrite view to the lift check.
        """
        if scope is ReflectedScope.FUNCTION_CONSTRUCTOR:
            return inlined_declarations_safe(
                body_model.root_scope, root_model, site_scope, exclude=exclude)
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
        whose `var` stays local to the eval. The module execution model could be a strict ES module,
        where the `var` is ephemeral, so `_destination_may_be_strict` treats a module direct eval as
        possibly strict and declines the inline; the sloppy CommonJS reading would leak the `var` and
        keep the inline, but declining is sound for both. Such a declaration hoists to the head of its
        variable scope, so it is inlined only when the eval site strictly dominates every reference to
        the name already there — one that runs before it or shares its statement, or reads the name
        through a closure, would be rebound.
        """
        root = root_model.root
        bindings = body_model.root_scope.bindings
        lexical = {name for name, binding in bindings.items() if binding.is_lexical}
        if lexical and root_model.would_capture(lexical, site_scope):
            return False
        hoisted = {name for name, binding in bindings.items() if binding.is_hoisted}
        if not hoisted:
            return True
        if scope is ReflectedScope.GLOBAL_EVAL:
            if runs_as_module(self.options, root) or not at_global_scope:
                return False
        elif self._destination_may_be_strict(site, root) or declares_use_strict(body_model.root):
            return False
        var_scope = site_scope.var_scope
        if var_scope is None:
            return False
        dominance = model_cache(self, root).dominance
        return all(
            dominance.strictly_dominates(site, node)
            for node in name_uses_in_scope(hoisted, var_scope)
        )
