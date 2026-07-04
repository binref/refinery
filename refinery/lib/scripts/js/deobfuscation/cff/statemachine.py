"""
Recover original code from generator-based state-machine CFF dispatchers.

Handles the pattern where a function body is replaced with a generator function containing a
while/switch state machine driven by multiple state variables whose sum is the switch
discriminant. Each case updates the state via relative `+=` assignments.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, NamedTuple

from refinery.lib.scripts import Expression, Node, Statement, _clone_node, _replace_in_parent
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BodyProcessingTransformer,
    access_key,
    eval_binary_op,
    is_reference,
    make_numeric_literal,
    member_key,
    property_key,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsBreakStatement,
    JsCallExpression,
    JsCatchClause,
    JsContinueStatement,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsIfStatement,
    JsLabeledStatement,
    JsLogicalExpression,
    JsMemberExpression,
    JsNumericLiteral,
    JsObjectExpression,
    JsObjectPattern,
    JsProperty,
    JsRestElement,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsStringLiteral,
    JsSwitchCase,
    JsSwitchStatement,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsWhileStatement,
    JsWithStatement,
)

if TYPE_CHECKING:
    _StateEnv = dict[str, int | float]

_MAX_STEPS = 2000


class _CallSiteInfo(NamedTuple):
    initial_state: list[int | float]
    did_return_var: str | None
    result_var: str | None
    scaffolding_end: int


class _WrapperFunctionInfo(NamedTuple):
    initial_state: list[int | float]
    rest_param_name: str | None


@dataclass
class _SMRawAssignment:
    """
    A single unevaluated state variable assignment: `name op= rhs`.
    """
    name: str
    operator: str
    rhs: Expression


@dataclass
class _SMLinearTransition:
    """
    Unconditional state transition: a sequence of `+=` or `=` assignments to state variables.
    """
    assignments: list[_SMRawAssignment]


@dataclass
class _SMConditionalTransition:
    """
    Conditional state transition: an if/else where each branch sets different state values.
    """
    condition: Expression
    true_assignments: list[_SMRawAssignment]
    false_assignments: list[_SMRawAssignment]
    true_prefix: list[Statement] = field(default_factory=list)
    false_prefix: list[Statement] = field(default_factory=list)


@dataclass
class _SMExitTransition:
    """
    The state machine reaches the end state after this block.
    """
    pass


if TYPE_CHECKING:
    _SMTransition = _SMLinearTransition | _SMConditionalTransition | _SMExitTransition


@dataclass
class _SMBlock:
    """
    A single state in the machine: payload statements plus a transition.
    """
    state_id: int | float
    payload: list[Statement]
    transition: _SMTransition


@dataclass
class _GeneratorCFFMatch:
    """
    Structural match result for a generator-based state-machine CFF pattern.
    """
    generator_name: str
    state_var_names: list[str]
    initial_state: list[int | float]
    end_state: int | float
    switch_stmt: JsSwitchStatement
    switch_label: str | None
    scope_param_name: str | None
    arg_var_name: str | None
    did_return_var: str | None
    result_var: str | None
    gen_decl_index: int
    scaffolding_end: int
    with_redirect_var: str | None = None
    scope_default_props: list[str] = field(default_factory=list)
    scope_default_inits: dict[str, Expression] = field(default_factory=dict)
    arg_params: list[str] = field(default_factory=list)
    scope_prop_names: set[str] = field(default_factory=set)
    namespaces: set[str] = field(default_factory=set)
    namespace_homes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    scope_arg_namespaces: dict[str, Expression] = field(default_factory=dict)


def _eval_expr(node: Expression, env: _StateEnv) -> int | float | None:
    """
    Recursively evaluate an arithmetic expression against a variable environment. Returns `None`
    when the expression cannot be resolved.
    """
    if isinstance(node, JsNumericLiteral):
        return node.value
    if isinstance(node, JsIdentifier):
        return env.get(node.name)
    if isinstance(node, JsMemberExpression):
        key = member_key(node)
        if key is not None:
            return env.get(key)
        return None
    if isinstance(node, JsUnaryExpression) and node.prefix and node.operand is not None:
        if node.operator == '-':
            inner = _eval_expr(node.operand, env)
            return -inner if inner is not None else None
        if node.operator == '+':
            return _eval_expr(node.operand, env)
    if isinstance(node, JsLogicalExpression) and node.left is not None and node.right is not None:
        if node.operator == '&&':
            lhs = _eval_expr(node.left, env)
            if lhs is None:
                return None
            if not lhs:
                return lhs
            return _eval_expr(node.right, env)
        if node.operator == '||':
            lhs = _eval_expr(node.left, env)
            if lhs is None:
                return None
            if lhs:
                return lhs
            return _eval_expr(node.right, env)
    if isinstance(node, JsBinaryExpression) and node.left is not None and node.right is not None:
        lhs = _eval_expr(node.left, env)
        rhs = _eval_expr(node.right, env)
        if lhs is None or rhs is None:
            return None
        result = eval_binary_op(node.operator, lhs, rhs)
        if result is None:
            return None
        if isinstance(result, bool):
            return int(result)
        if isinstance(result, float):
            try:
                int_val = int(result)
            except (OverflowError, ValueError):
                return None
            if result == int_val:
                return int_val
        return result
    return None


def _is_discriminant_sum(node: Expression, var_names: list[str]) -> bool:
    """
    Check whether an expression is the sum of the given state variable identifiers.
    """
    collected: list[str] = []
    _collect_sum_idents(node, collected)
    return sorted(collected) == sorted(var_names)


def _collect_sum_idents(node: Expression, out: list[str]) -> bool:
    if isinstance(node, JsIdentifier):
        out.append(node.name)
        return True
    if isinstance(node, JsBinaryExpression) and node.operator == '+':
        if node.left is not None and node.right is not None:
            return _collect_sum_idents(node.left, out) and _collect_sum_idents(node.right, out)
    return False


def _extract_with_redirect_var(
    with_obj: Expression | None,
    scope_param_name: str | None,
) -> str | None:
    """
    Parse the `with(scope.W || scope)` pattern to extract the redirect property name `W`.
    """
    if scope_param_name is None or with_obj is None:
        return None
    if not isinstance(with_obj, JsLogicalExpression) or with_obj.operator != '||':
        return None
    lhs = with_obj.left
    rhs = with_obj.right
    if not isinstance(rhs, JsIdentifier) or rhs.name != scope_param_name:
        return None
    if not isinstance(lhs, JsMemberExpression):
        return None
    if not isinstance(lhs.object, JsIdentifier) or lhs.object.name != scope_param_name:
        return None
    if lhs.computed:
        if not isinstance(lhs.property, JsStringLiteral):
            return None
        return lhs.property.value
    if not isinstance(lhs.property, JsIdentifier):
        return None
    return lhs.property.name


class _ScopeDefaults(NamedTuple):
    prop_names: list[str]
    initializers: dict[str, Expression]


def _extract_scope_default_props(
    params: list, scope_param_name: str | None,
) -> _ScopeDefaults:
    """
    Extract namespace property names and their initializer expressions from the scope parameter's
    default value. For the pattern `scope = { MpAqdCF: {} }` this returns a tuple of the form

        (['MpAqdCF'], {'MpAqdCF': <JsObjectExpression>})
    """
    if scope_param_name is None:
        return _ScopeDefaults([], {})
    for p in params:
        if not isinstance(p, JsAssignmentPattern):
            continue
        if not isinstance(p.left, JsIdentifier) or p.left.name != scope_param_name:
            continue
        if not isinstance(p.right, JsObjectExpression):
            return _ScopeDefaults([], {})
        names: list[str] = []
        inits: dict[str, Expression] = {}
        for prop in p.right.properties:
            if not isinstance(prop, JsProperty):
                continue
            key = property_key(prop)
            if key is not None:
                names.append(key)
                if prop.value is not None:
                    inits[key] = prop.value
        return _ScopeDefaults(names, inits)
    return _ScopeDefaults([], {})


def _namespace_member_home(
    node: Expression | None,
    scope_param_name: str | None,
    ns_names: set[str],
) -> tuple[str, str] | None:
    """
    If *node* is an assignment target that defines a namespace-local slot — either `NS.prop` on a
    bare namespace identifier or `scope.NS.prop` on the scope parameter — return the pair
    `(member_name, home_namespace)`. Any other target yields `None`.
    """
    if not isinstance(node, JsMemberExpression):
        return None
    obj = node.object
    if isinstance(obj, JsIdentifier):
        if obj.name in ns_names:
            member = access_key(node)
            if member is not None:
                return (member, obj.name)
        return None
    if (
        scope_param_name is not None
        and isinstance(obj, JsMemberExpression)
        and isinstance(obj.object, JsIdentifier)
        and obj.object.name == scope_param_name
    ):
        home = access_key(obj)
        if home is not None and home in ns_names:
            member = access_key(node)
            if member is not None:
                return (member, home)
    return None


def _collect_assignment_targets(
    target: Expression | None,
    scope_param_name: str | None,
    ns_names: set[str],
    out: dict[str, set[str]],
) -> None:
    """
    Record the home namespace of every namespace-local slot written by *target*, mapping each member
    name to the set of namespaces it is written under. Recurses through array and object
    destructuring patterns so that `[NS.a, NS.b] = …` and `({p: NS.c} = …)` are covered, including
    the object-literal spelling the parser leaves as an expression for a nested property value, so
    that a namespace member destructured at any depth still contributes its home.
    """
    home = _namespace_member_home(target, scope_param_name, ns_names)
    if home is not None:
        member, namespace = home
        out.setdefault(member, set()).add(namespace)
        return
    if isinstance(target, (JsArrayPattern, JsArrayExpression)):
        for elem in target.elements:
            if elem is not None:
                _collect_assignment_targets(elem, scope_param_name, ns_names, out)
    elif isinstance(target, (JsObjectPattern, JsObjectExpression)):
        for prop in target.properties:
            if isinstance(prop, JsProperty):
                _collect_assignment_targets(prop.value, scope_param_name, ns_names, out)
            elif isinstance(prop, (JsRestElement, JsSpreadElement)):
                _collect_assignment_targets(prop.argument, scope_param_name, ns_names, out)
    elif isinstance(target, JsAssignmentPattern):
        _collect_assignment_targets(target.left, scope_param_name, ns_names, out)
    elif isinstance(target, (JsRestElement, JsSpreadElement)):
        _collect_assignment_targets(target.argument, scope_param_name, ns_names, out)


def _redirect_assignment_target(
    expr: Expression,
    scope_param_name: str,
    redirect_var: str,
) -> str | None:
    """
    If *expr* is the single redirect-routing assignment `scope.redirect_var = scope.TARGET` (dot or
    computed on either side), return the TARGET namespace name. Any other expression yields `None`.
    """
    if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
        return None
    lhs = expr.left
    if not isinstance(lhs, JsMemberExpression):
        return None
    if not isinstance(lhs.object, JsIdentifier) or lhs.object.name != scope_param_name:
        return None
    if access_key(lhs) != redirect_var:
        return None
    rhs = expr.right
    if not isinstance(rhs, JsMemberExpression):
        return None
    if not isinstance(rhs.object, JsIdentifier) or rhs.object.name != scope_param_name:
        return None
    return access_key(rhs)


def _scope_arg_object(
    node: Node,
    generator_name: str,
    num_state_vars: int,
) -> JsObjectExpression | None:
    """
    If *node* is a call `generator_name(states…, scopeObj, …)` whose argument at the scope position
    (index *num_state_vars*) is an object literal, return that object literal. This is the
    structural scope argument threaded through the shared generator by its wrapper functions.
    """
    if not isinstance(node, JsCallExpression):
        return None
    if not isinstance(node.callee, JsIdentifier) or node.callee.name != generator_name:
        return None
    args = node.arguments
    if len(args) <= num_state_vars:
        return None
    candidate = args[num_state_vars]
    if isinstance(candidate, JsObjectExpression):
        return candidate
    return None


def _collect_namespaces(
    switch_stmt: JsSwitchStatement,
    scope_param_name: str | None,
    scope_default_props: list[str],
    redirect_var: str | None,
    generator_name: str,
    num_state_vars: int,
) -> tuple[set[str], dict[str, Expression]]:
    """
    Collect the sibling namespace objects on the scope and the structural scope-argument namespaces.
    A namespace is any of: a scope default, a redirect target `scope.redirect_var = scope.TARGET`
    found anywhere in the switch (including inside nested functions), or a key of an object-literal
    scope argument passed to the shared generator. The second return value maps each object-literal
    scope-argument key whose value is an empty object literal to that initializer, identifying the
    namespaces that must be materialized as `var X = {}` beyond the scope defaults.
    """
    namespaces: set[str] = set(scope_default_props)
    scope_arg_inits: dict[str, Expression] = {}
    for node in switch_stmt.walk():
        if (
            scope_param_name is not None
            and redirect_var is not None
            and isinstance(node, JsAssignmentExpression)
        ):
            target = _redirect_assignment_target(node, scope_param_name, redirect_var)
            if target is not None:
                namespaces.add(target)
        scope_arg = _scope_arg_object(node, generator_name, num_state_vars)
        if scope_arg is None:
            continue
        for prop in scope_arg.properties:
            if not isinstance(prop, JsProperty):
                continue
            key = property_key(prop)
            if key is None:
                continue
            namespaces.add(key)
            if isinstance(prop.value, JsObjectExpression) and not prop.value.properties:
                scope_arg_inits.setdefault(key, prop.value)
    return namespaces, scope_arg_inits


def _collect_namespace_homes(
    switch_stmt: JsSwitchStatement,
    scope_param_name: str | None,
    ns_names: set[str],
) -> dict[str, tuple[str, ...]]:
    """
    Determine the canonical home namespace of every proven namespace-local member. Each `=`
    assignment target in the switch — at any nesting depth, since the scope and namespace objects
    are closed over — is fed through the destructuring collector to accumulate `member -> {home…}`.
    A member written under exactly one namespace maps to that namespace as its home path; a member
    written under two or more namespaces is ambiguous and omitted, leaving it bare. A name with no
    namespace-defining write at all is genuinely free/global and is likewise absent, so it stays
    bare and resolves to its outer binding once the `with` is dissolved. Any assignment operator
    (plain, compound, or logical) and the update operators (`++`/`--`) count as a defining write,
    since each names the slot as living on its namespace.
    """
    accumulated: dict[str, set[str]] = {}
    for node in switch_stmt.walk():
        if isinstance(node, JsAssignmentExpression):
            _collect_assignment_targets(node.left, scope_param_name, ns_names, accumulated)
        elif isinstance(node, JsUpdateExpression):
            _collect_assignment_targets(node.argument, scope_param_name, ns_names, accumulated)
    homes: dict[str, tuple[str, ...]] = {}
    for member, home_set in accumulated.items():
        if len(home_set) == 1:
            homes[member] = (next(iter(home_set)),)
    return homes


def _match_generator_cff(body: list[Statement], idx: int) -> _GeneratorCFFMatch | None:
    """
    Starting at index *idx* in *body*, test whether the statement is a generator function
    declaration matching the state machine CFF pattern, with its call site following.
    """
    stmt = body[idx]
    if not isinstance(stmt, JsFunctionDeclaration):
        return None
    if not stmt.generator:
        return None
    if stmt.id is None:
        return None
    gen_name = stmt.id.name
    if stmt.body is None:
        return None
    params = stmt.params
    if len(params) < 3:
        return None
    scope_param_name: str | None = None
    arg_var_name: str | None = None
    state_var_names: list[str] = []
    for p in params:
        if isinstance(p, JsIdentifier):
            if scope_param_name is not None:
                arg_var_name = p.name
                break
            state_var_names.append(p.name)
        elif isinstance(p, JsAssignmentPattern) and isinstance(p.left, JsIdentifier):
            scope_param_name = p.left.name
        else:
            return None
    if not state_var_names:
        return None
    gen_body = stmt.body.body
    if len(gen_body) != 1:
        return None
    while_stmt = gen_body[0]
    if not isinstance(while_stmt, JsWhileStatement):
        return None
    if while_stmt.test is None or while_stmt.body is None:
        return None
    if not isinstance(while_stmt.test, JsBinaryExpression):
        return None
    if while_stmt.test.operator != '!==':
        return None
    lhs = while_stmt.test.left
    rhs = while_stmt.test.right
    if lhs is None or rhs is None:
        return None
    end_state: int | float | None = None
    if _is_discriminant_sum(lhs, state_var_names):
        end_state = _eval_expr(rhs, {})
    elif _is_discriminant_sum(rhs, state_var_names):
        end_state = _eval_expr(lhs, {})
    if end_state is None:
        return None
    inner: Statement | None = while_stmt.body
    if isinstance(inner, JsBlockStatement) and len(inner.body) == 1:
        inner = inner.body[0]
    with_redirect_var: str | None = None
    scope_default_props: list[str] = []
    scope_default_inits: dict[str, Expression] = {}
    if isinstance(inner, JsWithStatement):
        with_redirect_var = _extract_with_redirect_var(inner.object, scope_param_name)
        scope_default_props, scope_default_inits = _extract_scope_default_props(params, scope_param_name)
        inner = inner.body
    if isinstance(inner, JsBlockStatement) and len(inner.body) == 1:
        inner = inner.body[0]
    switch_label: str | None = None
    if isinstance(inner, JsLabeledStatement):
        if inner.label is not None:
            switch_label = inner.label.name
        inner = inner.body
    if not isinstance(inner, JsSwitchStatement):
        return None
    if inner.discriminant is None:
        return None
    if not _is_discriminant_sum(inner.discriminant, state_var_names):
        return None
    switch_stmt = inner
    call_info = _find_generator_call_site(body, idx, gen_name)
    if call_info is None:
        return None
    if len(call_info.initial_state) != len(state_var_names):
        return None
    namespaces: set[str] = set()
    namespace_homes: dict[str, tuple[str, ...]] = {}
    scope_arg_namespaces: dict[str, Expression] = {}
    if with_redirect_var is not None and len(scope_default_props) == 1:
        namespaces, scope_arg_namespaces = _collect_namespaces(
            switch_stmt,
            scope_param_name,
            scope_default_props,
            with_redirect_var,
            gen_name,
            len(state_var_names),
        )
        namespace_homes = _collect_namespace_homes(switch_stmt, scope_param_name, namespaces)
    return _GeneratorCFFMatch(
        generator_name=gen_name,
        state_var_names=state_var_names,
        initial_state=call_info.initial_state,
        end_state=end_state,
        switch_stmt=switch_stmt,
        switch_label=switch_label,
        scope_param_name=scope_param_name,
        arg_var_name=arg_var_name,
        did_return_var=call_info.did_return_var,
        result_var=call_info.result_var,
        gen_decl_index=idx,
        scaffolding_end=call_info.scaffolding_end,
        with_redirect_var=with_redirect_var,
        scope_default_props=scope_default_props,
        scope_default_inits=scope_default_inits,
        namespaces=namespaces,
        namespace_homes=namespace_homes,
        scope_arg_namespaces=scope_arg_namespaces,
    )


def _find_generator_call_site(
    body: list[Statement],
    gen_idx: int,
    gen_name: str,
) -> _CallSiteInfo | None:
    """
    Scan forward from *gen_idx* to find the call site pattern:

        var didReturn;
        var result = genName(args)["next"]()["value"];
        if (didReturn) { return result; }

    Returns a `_CallSiteInfo` or `None`.
    Skips over intervening declarations (function declarations, other var decls) that are not
    part of the generator scaffolding.
    """
    pos = gen_idx + 1
    did_return_var: str | None = None
    result_var: str | None = None
    while pos < len(body):
        candidate = body[pos]
        if isinstance(candidate, JsVariableDeclaration):
            decls = candidate.declarations
            if (
                len(decls) == 1
                and isinstance(decls[0], JsVariableDeclarator)
                and isinstance(decls[0].id, JsIdentifier)
                and decls[0].init is None
            ):
                did_return_var = decls[0].id.name
                pos += 1
                continue
        if isinstance(candidate, JsFunctionDeclaration):
            pos += 1
            continue
        if isinstance(candidate, JsExpressionStatement):
            expr = candidate.expression
            if (
                isinstance(expr, JsAssignmentExpression)
                and expr.operator == '='
                and isinstance(expr.left, JsIdentifier)
                and isinstance(expr.right, JsUnaryExpression)
                and expr.right.operator == 'void'
            ):
                did_return_var = expr.left.name
                pos += 1
                continue
        break
    if pos >= len(body):
        return None
    call_expr = _extract_generator_call(body[pos], gen_name)
    if call_expr is None:
        return None
    call_node, result_var = call_expr
    initial_state: list[int | float] = []
    for arg in call_node.arguments:
        val = _eval_expr(arg, {})
        if val is None:
            return None
        initial_state.append(val)
    scaffolding_end = pos
    if scaffolding_end + 1 < len(body) and did_return_var is not None:
        guard = body[scaffolding_end + 1]
        if (
            isinstance(guard, JsIfStatement)
            and isinstance(guard.test, JsIdentifier)
            and guard.test.name == did_return_var
        ):
            scaffolding_end += 1
    return _CallSiteInfo(initial_state, did_return_var, result_var, scaffolding_end)


class _GeneratorCallInfo(NamedTuple):
    call_node: JsCallExpression
    result_var: str | None


def _extract_generator_call(
    stmt: Statement,
    gen_name: str,
) -> _GeneratorCallInfo | None:
    """
    Extract a generator call from a statement. Handles:
    - var X = gen(...)["next"]()["value"];
    - gen(...)["next"]()["value"];
    - return gen(...)["next"]()["value"];

    Returns a `(call, name)` pair (the inner call to gen and the result variable name) or `None`.
    """
    result_name: str | None = None
    expr: Expression | None = None
    if isinstance(stmt, JsVariableDeclaration):
        if len(stmt.declarations) != 1:
            return None
        decl = stmt.declarations[0]
        if not isinstance(decl, JsVariableDeclarator):
            return None
        if isinstance(decl.id, JsIdentifier):
            result_name = decl.id.name
        expr = decl.init
    elif isinstance(stmt, JsExpressionStatement):
        expr = stmt.expression
        if isinstance(expr, JsAssignmentExpression) and expr.operator == '=':
            if isinstance(expr.left, JsIdentifier):
                result_name = expr.left.name
            expr = expr.right
    elif isinstance(stmt, JsReturnStatement):
        expr = stmt.argument
    else:
        return None
    if expr is None:
        return None
    gen_call = _unwrap_next_value(expr)
    if gen_call is None:
        if isinstance(expr, JsCallExpression):
            gen_call = expr
        else:
            return None
    if not isinstance(gen_call, JsCallExpression):
        return None
    if not isinstance(gen_call.callee, JsIdentifier):
        return None
    if gen_call.callee.name != gen_name:
        return None
    return _GeneratorCallInfo(gen_call, result_name)


def _unwrap_next_value(node: Expression) -> JsCallExpression | None:
    """
    Unwrap the `gen(...)` call from `gen(...).next().value`. Works when `next` and `value` are
    accessed as properties or as keys.
    """
    if not isinstance(node, JsMemberExpression):
        return None
    key = access_key(node)
    if key != 'value':
        return None
    next_call = node.object
    if not isinstance(next_call, JsCallExpression) or next_call.arguments:
        return None
    next_access = next_call.callee
    if not isinstance(next_access, JsMemberExpression):
        return None
    if access_key(next_access) != 'next':
        return None
    gen_call = next_access.object
    if not isinstance(gen_call, JsCallExpression):
        return None
    return gen_call


def _detect_wrapper_function(
    node: Expression,
    gen_name: str,
    num_state_vars: int,
) -> _WrapperFunctionInfo | None:
    """
    Test whether *node* is a wrapper function expression of the form:

        function(...rest) { return gen(states..., scope, rest)["next"]()["value"]; }

    Returns a `_WrapperFunctionInfo` or `None`.
    """
    if not isinstance(node, JsFunctionExpression):
        return None
    if node.body is None:
        return None
    body = node.body.body
    if len(body) != 1:
        return None
    stmt = body[0]
    if not isinstance(stmt, JsReturnStatement) or stmt.argument is None:
        return None
    gen_call = _unwrap_next_value(stmt.argument)
    if gen_call is None:
        return None
    if not isinstance(gen_call.callee, JsIdentifier):
        return None
    if gen_call.callee.name != gen_name:
        return None
    args = gen_call.arguments
    if len(args) < num_state_vars + 1:
        return None
    initial_state: list[int | float] = []
    for arg in args[:num_state_vars]:
        val = _eval_expr(arg, {})
        if val is None:
            return None
        initial_state.append(val)
    rest_param_name: str | None = None
    params = node.params
    if params:
        last_param = params[-1]
        if isinstance(last_param, JsRestElement) and isinstance(last_param.argument, JsIdentifier):
            rest_param_name = last_param.argument.name
        elif isinstance(last_param, JsIdentifier):
            rest_param_name = last_param.name
    return _WrapperFunctionInfo(initial_state, rest_param_name)


@dataclass
class _StateMachine:
    """
    Complete parsed state machine with both statically-resolved and predicate-gated cases.
    """
    blocks: dict[int | float, _SMBlock]
    predicate_cases: list[tuple[Expression, _SMBlock]]
    default_block: _SMBlock | None = None


def _extract_state_blocks(
    match: _GeneratorCFFMatch,
) -> _StateMachine | None:
    """
    Parse the switch cases into a state machine. Cases with statically resolvable tests go into
    `blocks`; those with predicate tests (referencing state vars) go into `predicate_cases` for
    runtime resolution. A `default:` case becomes the fallback block.
    """
    var_names = match.state_var_names
    label = match.switch_label
    end_state = match.end_state
    blocks: dict[int | float, _SMBlock] = {}
    predicate_cases: list[tuple[Expression, _SMBlock]] = []
    default_block: _SMBlock | None = None
    pending_tests: list[JsSwitchCase] = []
    for case in match.switch_stmt.cases:
        if not isinstance(case, JsSwitchCase):
            return None
        if not case.body:
            pending_tests.append(case)
            continue
        all_cases = list(pending_tests) + [case]
        pending_tests.clear()
        stmts = list(case.body)
        parsed = _parse_case_body(stmts, var_names, label)
        if parsed is None:
            continue
        payload, transition = parsed
        has_default = any(c.test is None for c in all_cases)
        resolved = False
        block_obj = _SMBlock(state_id=0, payload=payload, transition=transition)
        for c in all_cases:
            if c.test is None:
                continue
            val = _eval_expr(c.test, {})
            if val is not None:
                if val != end_state and val not in blocks:
                    if block_obj.state_id == 0:
                        block_obj.state_id = val
                    blocks[val] = block_obj
                resolved = True
            else:
                predicate_cases.append((c.test, block_obj))
        if has_default:
            default_block = block_obj
        if not resolved and not has_default and not any(
            c.test is not None and _eval_expr(c.test, {}) is None for c in all_cases
        ):
            continue
    if not blocks and not predicate_cases and default_block is None:
        return None
    return _StateMachine(blocks=blocks, predicate_cases=predicate_cases, default_block=default_block)


def _parse_case_body(
    stmts: list[Statement],
    var_names: list[str],
    switch_label: str | None,
) -> tuple[list[Statement], _SMTransition] | None:
    """
    Separate a case body into payload statements and a state transition.
    """
    if not stmts:
        return None
    stmts = _strip_trailing_labeled_break(stmts, switch_label)
    if not stmts:
        return ([], _SMExitTransition())
    last = stmts[-1]
    if isinstance(last, JsExpressionStatement) and isinstance(last.expression, JsSequenceExpression):
        assignments = _extract_state_assignments(last.expression, var_names)
        if assignments is not None:
            non_state = _extract_non_state_expressions(last.expression, var_names)
            payload = list(stmts[:-1])
            if non_state:
                payload.append(JsExpressionStatement(expression=non_state))
            return (payload, _SMLinearTransition(assignments=assignments))
    trailing = _collect_trailing_state_assignments(stmts, var_names)
    if trailing is not None:
        assignments, split_idx = trailing
        return (stmts[:split_idx], _SMLinearTransition(assignments=assignments))
    if isinstance(last, JsIfStatement) and last.consequent is not None and last.alternate is not None:
        cond_result = _parse_conditional_transition(last, var_names, switch_label)
        if cond_result is not None:
            payload = stmts[:-1]
            return (payload, cond_result)
    if isinstance(last, JsReturnStatement):
        return (stmts, _SMExitTransition())
    return None


def _strip_trailing_labeled_break(stmts: list[Statement], label: str | None) -> list[Statement]:
    """
    Remove a trailing `break label;` that targets the switch label.
    """
    if not stmts:
        return stmts
    last = stmts[-1]
    if isinstance(last, JsBreakStatement):
        if last.label is None or (label is not None and last.label.name == label):
            return stmts[:-1]
    return stmts


def _extract_state_assignments(
    seq: JsSequenceExpression,
    var_names: list[str],
) -> list[_SMRawAssignment] | None:
    """
    Extract state variable assignments from a sequence expression without evaluating them.
    Non-state assignments (scope/with updates) are skipped.
    """
    result: list[_SMRawAssignment] = []
    for expr in seq.expressions:
        if not isinstance(expr, JsAssignmentExpression):
            continue
        if not isinstance(expr.left, JsIdentifier):
            continue
        name = expr.left.name
        if name not in var_names:
            continue
        if expr.right is None:
            return None
        if expr.operator not in ('=', '+='):
            return None
        result.append(_SMRawAssignment(name=name, operator=expr.operator, rhs=expr.right))
    if not result:
        return None
    return result


def _extract_non_state_expressions(
    seq: JsSequenceExpression,
    var_names: list[str],
) -> Expression | None:
    """
    Collect non-state-variable expressions from a sequence. Returns a single expression (or
    sequence expression) for the payload, or None if all expressions are state assignments.
    """
    remaining: list[Expression] = []
    for expr in seq.expressions:
        if isinstance(expr, JsAssignmentExpression) and isinstance(expr.left, JsIdentifier):
            if expr.left.name in var_names:
                continue
        remaining.append(expr)
    if not remaining:
        return None
    if len(remaining) == 1:
        return remaining[0]
    return JsSequenceExpression(expressions=remaining)


def _collect_trailing_state_assignments(
    stmts: list[Statement],
    var_names: list[str],
) -> tuple[list[_SMRawAssignment], int] | None:
    """
    Scan backwards from the end of the statement list to collect all consecutive state-variable
    assignment statements. Returns the collected assignments and the split index (where payload
    ends), or None if no trailing state assignments found.
    """
    assignments: list[_SMRawAssignment] = []
    i = len(stmts) - 1
    while i >= 0:
        stmt = stmts[i]
        if not isinstance(stmt, JsExpressionStatement):
            break
        if not isinstance(stmt.expression, JsAssignmentExpression):
            break
        expr = stmt.expression
        if not isinstance(expr.left, JsIdentifier):
            break
        if expr.left.name not in var_names:
            break
        if expr.right is None:
            break
        if expr.operator not in ('=', '+='):
            break
        assignments.append(_SMRawAssignment(name=expr.left.name, operator=expr.operator, rhs=expr.right))
        i -= 1
    if not assignments:
        return None
    assignments.reverse()
    return (assignments, i + 1)


def _extract_single_assignment(
    expr: JsAssignmentExpression,
    var_names: list[str],
) -> list[_SMRawAssignment] | None:
    """
    Extract a single state variable assignment.
    """
    if not isinstance(expr.left, JsIdentifier):
        return None
    name = expr.left.name
    if name not in var_names:
        return None
    if expr.right is None:
        return None
    if expr.operator not in ('=', '+='):
        return None
    return [_SMRawAssignment(name=name, operator=expr.operator, rhs=expr.right)]


def _apply_raw_transition(
    assignments: list[_SMRawAssignment],
    current: _StateEnv,
) -> _StateEnv | None:
    """
    Evaluate raw assignments against the current state to produce the new state.
    Left-to-right sequential semantics: each assignment sees the results of prior ones.
    """
    env: _StateEnv = dict(current)
    for assign in assignments:
        val = _eval_expr(assign.rhs, env)
        if val is None:
            return None
        if assign.operator == '+=':
            env[assign.name] = env.get(assign.name, 0) + val
        else:
            env[assign.name] = val
    return env


def _block_stmts(node: Statement) -> list[Statement] | None:
    if isinstance(node, JsBlockStatement):
        return list(node.body)
    return [node]


def _extract_trailing_assignments(
    stmts: list[Statement],
    var_names: list[str],
) -> tuple[list[_SMRawAssignment], list[Statement]] | None:
    """
    Extract the trailing state assignment from a list of statements and return
    (raw_assignments, prefix_statements). For mixed sequence expressions, non-state expressions
    are preserved in the prefix.
    """
    if not stmts:
        return None
    last = stmts[-1]
    if isinstance(last, JsExpressionStatement):
        if isinstance(last.expression, JsSequenceExpression):
            assigns = _extract_state_assignments(last.expression, var_names)
            if assigns is not None:
                non_state = _extract_non_state_expressions(last.expression, var_names)
                prefix = list(stmts[:-1])
                if non_state:
                    prefix.append(JsExpressionStatement(expression=non_state))
                return (assigns, prefix)
        elif isinstance(last.expression, JsAssignmentExpression):
            assigns = _extract_single_assignment(last.expression, var_names)
            if assigns is not None:
                return (assigns, stmts[:-1])
    return None


def _parse_conditional_transition(
    if_stmt: JsIfStatement,
    var_names: list[str],
    switch_label: str | None,
) -> _SMConditionalTransition | None:
    """
    Parse an if/else whose branches both perform state transitions.
    """
    if if_stmt.test is None:
        return None
    true_block = if_stmt.consequent
    false_block = if_stmt.alternate
    if true_block is None or false_block is None:
        return None
    true_stmts = _block_stmts(true_block)
    false_stmts = _block_stmts(false_block)
    if true_stmts is None or false_stmts is None:
        return None
    true_stmts = _strip_trailing_labeled_break(true_stmts, switch_label)
    false_stmts = _strip_trailing_labeled_break(false_stmts, switch_label)
    true_state = _extract_trailing_assignments(true_stmts, var_names)
    false_state = _extract_trailing_assignments(false_stmts, var_names)
    if true_state is None or false_state is None:
        return None
    true_assigns, true_prefix = true_state
    false_assigns, false_prefix = false_state
    return _SMConditionalTransition(
        condition=if_stmt.test,
        true_assignments=true_assigns,
        false_assignments=false_assigns,
        true_prefix=true_prefix,
        false_prefix=false_prefix,
    )


def _compute_discriminant(state: _StateEnv, var_names: list[str]) -> int | float:
    return sum(state.get(n, 0) for n in var_names)


def _lookup_block(machine: _StateMachine, disc: int | float, state: _StateEnv) -> _SMBlock | None:
    """
    Find the block matching the given discriminant. Tries static blocks first, then evaluates
    predicate tests against the current state, then falls back to the default block.
    """
    if disc in machine.blocks:
        return machine.blocks[disc]
    for test_expr, block in machine.predicate_cases:
        val = _eval_expr(test_expr, state)
        if val is not None and val == disc:
            return block
    return machine.default_block


def _apply_initial_state(var_names: list[str], values: list[int | float]) -> _StateEnv:
    return dict(zip(var_names, values))


def _is_state_var_assignment(expr: Expression, var_set: set[str]) -> bool:
    return (
        isinstance(expr, JsAssignmentExpression)
        and isinstance(expr.left, JsIdentifier)
        and expr.left.name in var_set
    )


def _apply_prefix_state_changes(
    prefix: list[Statement],
    var_names: list[str],
    env: _StateEnv,
) -> _StateEnv:
    """
    Scan prefix statements for assignments to state variables and apply them sequentially. This
    handles cases where a conditional's prefix modifies state variables before the trailing
    transition assignment.
    """
    result = dict(env)
    var_set = set(var_names)
    for stmt in prefix:
        if not isinstance(stmt, JsExpressionStatement):
            continue
        expr = stmt.expression
        exprs = expr.expressions if isinstance(expr, JsSequenceExpression) else [expr]
        for e in exprs:
            if not isinstance(e, JsAssignmentExpression):
                continue
            if not isinstance(e.left, JsIdentifier):
                continue
            if e.left.name not in var_set:
                continue
            if e.right is None:
                continue
            rhs_val = _eval_expr(e.right, result)
            if rhs_val is None:
                continue
            name = e.left.name
            if e.operator == '=':
                result[name] = rhs_val
            elif e.operator == '+=':
                result[name] = result.get(name, 0) + rhs_val
            elif e.operator == '-=':
                result[name] = result.get(name, 0) - rhs_val
    return result


def _strip_state_var_assignments(stmts: list[Statement], var_names: list[str]) -> list[Statement]:
    """
    Remove statements that are pure assignments to state variables. These are routing bookkeeping
    that should not appear in the recovered output. For sequence expressions, state var assignments
    are removed while preserving remaining payload expressions.
    """
    var_set = set(var_names)
    result: list[Statement] = []
    for stmt in stmts:
        if not isinstance(stmt, JsExpressionStatement):
            result.append(stmt)
            continue
        expr = stmt.expression
        if expr is None:
            result.append(stmt)
            continue
        if isinstance(expr, JsSequenceExpression):
            remaining = [e for e in expr.expressions if not _is_state_var_assignment(e, var_set)]
            if not remaining:
                continue
            if len(remaining) == 1:
                result.append(JsExpressionStatement(expression=remaining[0]))
            else:
                result.append(JsExpressionStatement(
                    expression=JsSequenceExpression(expressions=remaining),
                ))
        elif _is_state_var_assignment(expr, var_set):
            continue
        else:
            result.append(stmt)
    return result


def _process_branch_prefix(
    prefix: list[Statement],
    var_names: list[str],
    state: _StateEnv,
    match: _GeneratorCFFMatch,
) -> list[Statement]:
    """
    Process a conditional transition's branch prefix through the standard pipeline (strip state
    vars, substitute, filter bookkeeping, strip scope, qualify). Returns the processed statements
    ready for emission as branch-specific payload.
    """
    result = _strip_state_var_assignments(prefix, var_names)
    if not result:
        return []
    result = _substitute_state_vars(result, state)
    if not match.arg_params:
        for s in result:
            params = _extract_arg_param_names(s, match.arg_var_name)
            if params is not None:
                match.arg_params = params
                break
    _collect_scope_props(result, match.scope_param_name, match.scope_prop_names)
    result = [
        s for s in result
        if _extract_arg_param_names(s, match.arg_var_name) is None
    ]
    result = _strip_scope_param_prefix(result, match.scope_param_name)
    result = _qualify_with_identifiers(result, match)
    result = _filter_redirect_var_assignments(result, match)
    return result


_VIRTUAL_EXIT: int = -1


@dataclass
class _CFGNode:
    """
    A node in the control flow graph derived from the state machine. Keyed by block object
    identity (`id(block)`) so that the same logical block visited with different discriminants
    is recognized as a single CFG node — enabling loop detection.
    """
    node_id: int
    payload: list[Statement]
    condition: Expression | None
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    true_prefix_payload: list[Statement] = field(default_factory=list)
    false_prefix_payload: list[Statement] = field(default_factory=list)


@dataclass
class _CFG:
    """
    Control flow graph built from symbolic execution of state machine transitions.
    """
    nodes: dict[int, _CFGNode]
    entry: int
    exit: int


@dataclass
class _NaturalLoop:
    """
    A natural loop identified by a back-edge in the CFG.
    """
    header: int
    body: set[int]
    tails: list[int]
    exits: set[int]


def _build_cfg(
    machine: _StateMachine,
    initial_state: _StateEnv,
    var_names: list[str],
    end_state: int | float,
    match: _GeneratorCFFMatch,
) -> tuple[_CFG, _StateEnv] | None:
    """
    Build a control flow graph by BFS from the initial state. Nodes are keyed by the identity
    of the `_SMBlock` object they correspond to, so the same block reached with different
    discriminants (as happens in loops with relative `+=` transitions) creates a single node
    with a back-edge. Returns the CFG and the accumulated state (including scope routing values).
    """
    entry_state = dict(initial_state)
    entry_disc = _compute_discriminant(entry_state, var_names)
    entry_block = _lookup_block(machine, entry_disc, entry_state)
    if entry_block is None:
        return None

    nodes: dict[int, _CFGNode] = {}
    routing_state: _StateEnv = dict(initial_state)
    node_envs: dict[int, _StateEnv] = {}
    queue: deque[tuple[_SMBlock, _StateEnv]] = deque()
    queue.append((entry_block, entry_state))
    steps = 0

    while queue and steps < _MAX_STEPS:
        steps += 1
        block, state = queue.popleft()
        node_id = id(block)

        if node_id in nodes:
            continue

        payload = _substitute_state_vars(block.payload, state)
        _track_scope_routing(payload, state)
        _track_scope_routing(payload, routing_state)
        if not match.arg_params:
            for s in payload:
                params = _extract_arg_param_names(s, match.arg_var_name)
                if params is not None:
                    match.arg_params = params
                    break
        _collect_scope_props(payload, match.scope_param_name, match.scope_prop_names)
        payload = [
            s for s in payload
            if _extract_arg_param_names(s, match.arg_var_name) is None
        ]
        payload = _strip_scope_param_prefix(payload, match.scope_param_name)
        payload = _qualify_with_identifiers(payload, match)
        payload = _filter_redirect_var_assignments(payload, match)

        condition: Expression | None = None
        successors: list[int] = []
        true_prefix_payload: list[Statement] = []
        false_prefix_payload: list[Statement] = []
        transition = block.transition

        if isinstance(transition, _SMExitTransition):
            successors = [_VIRTUAL_EXIT]
        elif isinstance(transition, _SMLinearTransition):
            new_env = _apply_raw_transition(transition.assignments, state)
            if new_env is None:
                return None
            next_disc = _compute_discriminant(new_env, var_names)
            if next_disc == end_state:
                successors = [_VIRTUAL_EXIT]
            else:
                next_block = _lookup_block(machine, next_disc, new_env)
                if next_block is None:
                    return None
                next_id = id(next_block)
                successors = [next_id]
                if next_id not in nodes:
                    queue.append((next_block, new_env))
        elif isinstance(transition, _SMConditionalTransition):
            condition = transition.condition
            true_base = _apply_prefix_state_changes(transition.true_prefix, var_names, state)
            false_base = _apply_prefix_state_changes(transition.false_prefix, var_names, state)
            true_env = _apply_raw_transition(transition.true_assignments, true_base)
            false_env = _apply_raw_transition(transition.false_assignments, false_base)
            if true_env is None or false_env is None:
                return None
            true_disc = _compute_discriminant(true_env, var_names)
            false_disc = _compute_discriminant(false_env, var_names)

            if true_disc == end_state:
                true_id = _VIRTUAL_EXIT
            else:
                true_block = _lookup_block(machine, true_disc, true_env)
                if true_block is None:
                    return None
                true_id = id(true_block)
                if true_id not in nodes:
                    queue.append((true_block, true_env))

            if false_disc == end_state:
                false_id = _VIRTUAL_EXIT
            else:
                false_block = _lookup_block(machine, false_disc, false_env)
                if false_block is None:
                    return None
                false_id = id(false_block)
                if false_id not in nodes:
                    queue.append((false_block, false_env))

            successors = [true_id, false_id]
            true_prefix_payload = _process_branch_prefix(
                transition.true_prefix, var_names, state, match,
            )
            false_prefix_payload = _process_branch_prefix(
                transition.false_prefix, var_names, state, match,
            )
            if match.with_redirect_var and match.scope_default_props:
                condition = _qualify_condition(condition, state, match)
            else:
                wrapper = JsExpressionStatement(expression=_clone_node(condition))
                _substitute_in_scope(wrapper, state)
                if match.scope_param_name:
                    _strip_scope_prefix_walk(wrapper, match.scope_param_name)
                condition = wrapper.expression  # type: ignore[assignment]

        node = _CFGNode(
            node_id=node_id,
            payload=payload,
            condition=condition,
            successors=successors,
            true_prefix_payload=true_prefix_payload,
            false_prefix_payload=false_prefix_payload,
        )
        nodes[node_id] = node
        node_envs[node_id] = state

    entry_id = id(entry_block)
    if entry_id not in nodes:
        return None

    exit_node = _CFGNode(node_id=_VIRTUAL_EXIT, payload=[], condition=None)
    nodes[_VIRTUAL_EXIT] = exit_node

    for n in nodes.values():
        for succ_id in n.successors:
            if succ_id in nodes:
                nodes[succ_id].predecessors.append(n.node_id)

    return (_CFG(nodes=nodes, entry=entry_id, exit=_VIRTUAL_EXIT), routing_state)


def _compute_idom(cfg: _CFG) -> dict[int, int | None]:
    """
    Compute immediate dominators using the Cooper-Harvey-Kennedy iterative algorithm.
    """
    entry = cfg.entry
    order = _reverse_postorder(cfg)
    node_to_idx = {d: i for i, d in enumerate(order)}
    idom: dict[int, int | None] = {entry: None}

    def intersect(a: int, b: int) -> int:
        ai = node_to_idx[a]
        bi = node_to_idx[b]
        while ai != bi:
            while ai > bi:
                a = idom[a]  # type: ignore
                ai = node_to_idx[a]
            while bi > ai:
                b = idom[b]  # type: ignore
                bi = node_to_idx[b]
        return a

    changed = True
    while changed:
        changed = False
        for disc in order:
            if disc == entry:
                continue
            node = cfg.nodes[disc]
            preds = [p for p in node.predecessors if p in idom]
            if not preds:
                continue
            new_idom = preds[0]
            for p in preds[1:]:
                new_idom = intersect(new_idom, p)
            if idom.get(disc) != new_idom:
                idom[disc] = new_idom
                changed = True

    return idom


def _reverse_postorder(cfg: _CFG) -> list[int]:
    """
    Compute reverse postorder traversal of the CFG from entry.
    """
    visited: set[int] = set()
    order: list[int] = []

    def dfs(disc: int):
        stack: list[tuple[int, int]] = [(disc, 0)]
        while stack:
            current, idx = stack.pop()
            if idx == 0:
                if current in visited:
                    continue
                visited.add(current)
            node = cfg.nodes.get(current)
            if node is None:
                order.append(current)
                continue
            succs = [s for s in node.successors if s in cfg.nodes]
            if idx < len(succs):
                stack.append((current, idx + 1))
                s = succs[idx]
                if s not in visited:
                    stack.append((s, 0))
            else:
                order.append(current)

    dfs(cfg.entry)
    order.reverse()
    return order


def _dominates(idom: dict[int, int | None], a: int, b: int) -> bool:
    """
    Check if node `a` dominates node `b`.
    """
    current = b
    while current is not None:
        if current == a:
            return True
        current = idom.get(current)
    return False


def _compute_ipdom(
    cfg: _CFG,
    exit_id: int,
    region: set[int] | None = None,
) -> dict[int, int | None]:
    """
    Compute immediate post-dominators using Cooper-Harvey-Kennedy on the reverse CFG.
    Post-dominator of X = first node Y that ALL paths from X to exit must pass through.
    """
    exit_preds: list[int] = []
    if exit_id not in cfg.nodes:
        for nid, node in cfg.nodes.items():
            if region is not None and nid not in region:
                continue
            if exit_id in node.successors:
                exit_preds.append(nid)

    visited: set[int] = set()
    rpo: list[int] = []

    def _get_reverse_succs(nid: int) -> list[int]:
        node = cfg.nodes.get(nid)
        if node is None:
            if nid == exit_id:
                return exit_preds
            return []
        preds = node.predecessors
        if region is not None:
            preds = [p for p in preds if p in region]
        return preds

    stack: list[tuple[int, int]] = [(exit_id, 0)]
    while stack:
        current, idx = stack.pop()
        if idx == 0:
            if current in visited:
                continue
            visited.add(current)
        preds = _get_reverse_succs(current)
        if idx < len(preds):
            stack.append((current, idx + 1))
            p = preds[idx]
            if p not in visited:
                stack.append((p, 0))
        else:
            rpo.append(current)

    rpo.reverse()
    node_to_idx = {d: i for i, d in enumerate(rpo)}
    ipdom: dict[int, int | None] = {exit_id: None}

    def intersect(a: int, b: int) -> int:
        ai: int = node_to_idx[a]
        bi: int = node_to_idx[b]
        while ai != bi:
            while ai > bi:
                a = ipdom[a]  # type: ignore
                ai = node_to_idx[a]
            while bi > ai:
                b = ipdom[b]  # type: ignore
                bi = node_to_idx[b]
        return a

    changed = True
    while changed:
        changed = False
        for disc in rpo:
            if disc == exit_id:
                continue
            node = cfg.nodes.get(disc)
            if node is None:
                continue
            succs = [s for s in node.successors if s in ipdom]
            if region is not None:
                succs = [s for s in succs if s in region or s == exit_id]
            if not succs:
                continue
            new_ipdom = succs[0]
            for s in succs[1:]:
                new_ipdom = intersect(new_ipdom, s)
            if ipdom.get(disc) != new_ipdom:
                ipdom[disc] = new_ipdom
                changed = True

    return ipdom


def _find_loops(cfg: _CFG, idom: dict[int, int | None]) -> list[_NaturalLoop]:
    """
    Identify natural loops from back-edges. A back-edge is (tail -> header) where header
    dominates tail. The loop body is the set of nodes that can reach the tail without leaving
    the header's dominance.
    """
    back_edges: list[tuple[int, int]] = []
    for disc, node in cfg.nodes.items():
        for succ in node.successors:
            if succ in cfg.nodes and _dominates(idom, succ, disc):
                back_edges.append((disc, succ))

    loops_by_header: dict[int, _NaturalLoop] = {}
    for tail, header in back_edges:
        if header not in loops_by_header:
            body = _compute_loop_body(cfg, header, tail)
            exits: set[int] = set()
            for b in body:
                n = cfg.nodes[b]
                for s in n.successors:
                    if s not in body and s in cfg.nodes:
                        exits.add(b)
            loops_by_header[header] = _NaturalLoop(
                header=header, body=body, tails=[tail], exits=exits,
            )
        else:
            loop = loops_by_header[header]
            loop.tails.append(tail)
            extra = _compute_loop_body(cfg, header, tail)
            loop.body |= extra
            for b in loop.body:
                n = cfg.nodes[b]
                for s in n.successors:
                    if s not in loop.body and s in cfg.nodes:
                        loop.exits.add(b)

    return list(loops_by_header.values())


def _compute_loop_body(cfg: _CFG, header: int, tail: int) -> set[int]:
    """
    Compute the natural loop body: all nodes that can reach `tail` without going through
    `header`, plus `header` itself.
    """
    body: set[int] = {header}
    if tail == header:
        return body
    body.add(tail)
    worklist: list[int] = [tail]
    while worklist:
        node_disc = worklist.pop()
        n = cfg.nodes.get(node_disc)
        if n is None:
            continue
        for pred in n.predecessors:
            if pred not in body and pred in cfg.nodes:
                body.add(pred)
                worklist.append(pred)
    return body


def _structural_analysis(
    cfg: _CFG,
    idom: dict[int, int | None],
    loops: list[_NaturalLoop],
) -> list[Statement]:
    """
    Recover structured control flow from the CFG using region-based structural analysis.
    Process loops innermost-first, then structure acyclic regions.
    """
    sorted_loops = _sort_loops_innermost_first(loops)
    collapsed: dict[int, list[Statement]] = {}
    loop_headers: set[int] = set()

    for loop in sorted_loops:
        loop_headers.add(loop.header)
        body_stmts = _structure_loop(cfg, loop, idom, collapsed)
        collapsed[loop.header] = body_stmts
        for body_node in loop.body:
            if body_node != loop.header and body_node not in collapsed:
                collapsed[body_node] = []

    return _structure_acyclic_region(cfg, cfg.entry, cfg.exit, idom, collapsed, loop_headers)


def _sort_loops_innermost_first(loops: list[_NaturalLoop]) -> list[_NaturalLoop]:
    """
    Sort loops so that inner (smaller body) loops are processed before outer ones.
    """
    return sorted(loops, key=lambda lp: len(lp.body))


def _structure_loop(
    cfg: _CFG,
    loop: _NaturalLoop,
    idom: dict[int, int | None],
    collapsed: dict[int, list[Statement]],
) -> list[Statement]:
    """
    Structure a single natural loop into a while/do-while statement.
    """
    header = loop.header
    header_node = cfg.nodes[header]

    if (
        header_node.condition is not None
        and len(header_node.successors) == 2
        and not header_node.payload
    ):
        true_succ, false_succ = header_node.successors
        if true_succ not in loop.body and true_succ in cfg.nodes:
            body_entry = false_succ
            condition = JsUnaryExpression(operator='!', operand=header_node.condition, prefix=True)
            body_prefix = header_node.false_prefix_payload
            exit_prefix = header_node.true_prefix_payload
        elif false_succ not in loop.body and false_succ in cfg.nodes:
            body_entry = true_succ
            condition = header_node.condition
            body_prefix = header_node.true_prefix_payload
            exit_prefix = header_node.false_prefix_payload
        else:
            return _structure_loop_infinite(cfg, loop, idom, collapsed)

        body_stmts = _structure_acyclic_region(
            cfg, body_entry, header, idom, collapsed, set(),
            loop_body=loop.body,
        )
        body_stmts = list(header_node.payload) + list(body_prefix) + body_stmts
        while_stmt = JsWhileStatement(
            test=condition,
            body=JsBlockStatement(body=body_stmts),
        )
        return [while_stmt] + list(exit_prefix)

    return _structure_loop_infinite(cfg, loop, idom, collapsed)


def _structure_loop_infinite(
    cfg: _CFG,
    loop: _NaturalLoop,
    idom: dict[int, int | None],
    collapsed: dict[int, list[Statement]],
) -> list[Statement]:
    """
    Structure a loop that doesn't have a simple while-condition as `while(true)` with breaks.
    """
    header = loop.header
    body_stmts = _structure_region_nodes(cfg, header, idom, collapsed, loop.body)
    while_stmt = JsWhileStatement(
        test=JsBooleanLiteral(value=True),
        body=JsBlockStatement(body=body_stmts),
    )
    return [while_stmt]


def _structure_acyclic_region(
    cfg: _CFG,
    entry: int,
    exit_disc: int,
    idom: dict[int, int | None],
    collapsed: dict[int, list[Statement]],
    loop_headers: set[int],
    loop_body: set[int] | None = None,
    _visited: set[int] | None = None,
) -> list[Statement]:
    """
    Structure an acyclic region from `entry` to `exit_disc` into a statement sequence.
    Handles if/else patterns using post-dominator-based join detection.
    """
    result: list[Statement] = []
    visited: set[int] = _visited if _visited is not None else set()
    worklist: deque[int] = deque([entry])

    while worklist:
        disc = worklist.popleft()
        if disc == exit_disc or disc == _VIRTUAL_EXIT:
            continue
        if disc in visited:
            continue
        if loop_body is not None and disc not in loop_body:
            continue
        visited.add(disc)

        if disc in collapsed:
            result.extend(collapsed[disc])
            node = cfg.nodes[disc]
            for s in node.successors:
                if s not in visited and s != exit_disc and s != _VIRTUAL_EXIT:
                    if loop_body is None or s in loop_body:
                        worklist.append(s)
            continue

        node = cfg.nodes.get(disc)
        if node is None:
            continue

        if node.condition is not None and len(node.successors) == 2:
            result.extend(node.payload)
            true_succ, false_succ = node.successors
            join = _find_acyclic_join(cfg, disc, exit_disc, loop_body)

            true_stmts: list[Statement] = list(node.true_prefix_payload)
            true_visited = set(visited)
            if true_succ != join and true_succ not in visited:
                true_stmts.extend(_structure_acyclic_region(
                    cfg, true_succ, join, idom, collapsed, loop_headers, loop_body, true_visited,
                ))
            false_stmts: list[Statement] = list(node.false_prefix_payload)
            false_visited = set(visited)
            if false_succ != join and false_succ not in visited:
                false_stmts.extend(_structure_acyclic_region(
                    cfg, false_succ, join, idom, collapsed, loop_headers, loop_body, false_visited,
                ))
            visited.update(true_visited)
            visited.update(false_visited)

            if_stmt = _build_js_if(node.condition, true_stmts, false_stmts)
            if if_stmt is not None:
                result.append(if_stmt)

            if join != _VIRTUAL_EXIT and join != exit_disc and join not in visited:
                worklist.appendleft(join)
        else:
            result.extend(node.payload)
            for s in node.successors:
                if s == exit_disc or s == _VIRTUAL_EXIT:
                    continue
                if s in visited:
                    continue
                if loop_body is not None and s not in loop_body:
                    result.append(JsBreakStatement())
                    continue
                worklist.append(s)

    return result


def _find_acyclic_join(
    cfg: _CFG,
    cond_disc: int,
    region_exit: int,
    loop_body: set[int] | None,
) -> int:
    """
    Find the join point of a conditional by computing its immediate post-dominator within
    the region. The ipdom is the first node where ALL paths from both successors converge.
    """
    region: set[int] = set()
    queue: deque[int] = deque([cond_disc])
    while queue:
        d = queue.popleft()
        if d in region or d == _VIRTUAL_EXIT:
            continue
        if d == region_exit:
            region.add(d)
            continue
        if loop_body is not None and d not in loop_body:
            continue
        region.add(d)
        node = cfg.nodes.get(d)
        if node is not None:
            for s in node.successors:
                if s not in region:
                    queue.append(s)

    if not region or cond_disc not in region:
        return region_exit

    region.add(region_exit)
    ipdom = _compute_ipdom(cfg, region_exit, region)
    join = ipdom.get(cond_disc)
    if join is None or (loop_body is not None and join not in loop_body and join != region_exit):
        return region_exit
    return join


def _structure_region_nodes(
    cfg: _CFG,
    header: int,
    idom: dict[int, int | None],
    collapsed: dict[int, list[Statement]],
    loop_body: set[int],
) -> list[Statement]:
    """
    Structure a set of CFG nodes that form a loop body, starting from the header.
    """
    result: list[Statement] = []
    visited: set[int] = set()
    worklist: deque[int] = deque([header])

    while worklist:
        disc = worklist.popleft()
        if disc in visited:
            continue
        if disc not in loop_body:
            result.append(JsBreakStatement())
            continue
        visited.add(disc)

        if disc in collapsed:
            result.extend(collapsed[disc])
            node = cfg.nodes[disc]
            for s in node.successors:
                if s not in visited and s in loop_body:
                    worklist.append(s)
            continue

        node = cfg.nodes.get(disc)
        if node is None:
            continue

        if node.condition is not None and len(node.successors) == 2:
            result.extend(node.payload)
            true_succ, false_succ = node.successors

            true_in_loop = true_succ in loop_body
            false_in_loop = false_succ in loop_body

            if true_succ == header:
                if false_succ not in loop_body:
                    neg = JsUnaryExpression(operator='!', operand=node.condition, prefix=True)
                    break_body = list(node.false_prefix_payload) + [JsBreakStatement()]
                    result.append(JsIfStatement(
                        test=neg,
                        consequent=JsBlockStatement(body=break_body),
                    ))
                    result.extend(node.true_prefix_payload)
                else:
                    continue_body = list(node.true_prefix_payload) + [JsContinueStatement()]
                    result.append(JsIfStatement(
                        test=node.condition,
                        consequent=JsBlockStatement(body=continue_body),
                    ))
                    result.extend(node.false_prefix_payload)
                    worklist.append(false_succ)
                continue
            elif false_succ == header:
                if true_succ not in loop_body:
                    break_body = list(node.true_prefix_payload) + [JsBreakStatement()]
                    result.append(JsIfStatement(
                        test=node.condition,
                        consequent=JsBlockStatement(body=break_body),
                    ))
                    result.extend(node.false_prefix_payload)
                else:
                    neg = JsUnaryExpression(operator='!', operand=node.condition, prefix=True)
                    continue_body = list(node.false_prefix_payload) + [JsContinueStatement()]
                    result.append(JsIfStatement(
                        test=neg,
                        consequent=JsBlockStatement(body=continue_body),
                    ))
                    result.extend(node.true_prefix_payload)
                    worklist.append(true_succ)
                continue

            if not true_in_loop and not false_in_loop:
                if node.true_prefix_payload or node.false_prefix_payload:
                    true_body = list(node.true_prefix_payload) + [JsBreakStatement()]
                    false_body = list(node.false_prefix_payload) + [JsBreakStatement()]
                    if_stmt = _build_js_if(node.condition, true_body, false_body)
                    if if_stmt is not None:
                        result.append(if_stmt)
                    else:
                        result.append(JsBreakStatement())
                else:
                    result.append(JsBreakStatement())
                continue
            if not true_in_loop:
                break_body = list(node.true_prefix_payload) + [JsBreakStatement()]
                result.append(JsIfStatement(
                    test=node.condition,
                    consequent=JsBlockStatement(body=break_body),
                ))
                result.extend(node.false_prefix_payload)
                worklist.append(false_succ)
                continue
            if not false_in_loop:
                neg = JsUnaryExpression(operator='!', operand=node.condition, prefix=True)
                break_body = list(node.false_prefix_payload) + [JsBreakStatement()]
                result.append(JsIfStatement(
                    test=neg,
                    consequent=JsBlockStatement(body=break_body),
                ))
                result.extend(node.true_prefix_payload)
                worklist.append(true_succ)
                continue

            join = _find_acyclic_join(cfg, disc, header, loop_body)
            true_stmts: list[Statement] = list(node.true_prefix_payload)
            true_visited = set(visited)
            if true_succ != join and true_succ not in visited:
                true_stmts.extend(_structure_acyclic_region(
                    cfg, true_succ, join, idom, collapsed, set(), loop_body, true_visited,
                ))
            false_stmts: list[Statement] = list(node.false_prefix_payload)
            false_visited = set(visited)
            if false_succ != join and false_succ not in visited:
                false_stmts.extend(_structure_acyclic_region(
                    cfg, false_succ, join, idom, collapsed, set(), loop_body, false_visited,
                ))
            visited.update(true_visited)
            visited.update(false_visited)
            if_stmt = _build_js_if(node.condition, true_stmts, false_stmts)
            if if_stmt is not None:
                result.append(if_stmt)
            if join != header and join in loop_body and join not in visited:
                worklist.appendleft(join)
        else:
            result.extend(node.payload)
            for s in node.successors:
                if s == header:
                    continue
                if s not in loop_body:
                    result.append(JsBreakStatement())
                    continue
                if s in visited:
                    continue
                worklist.append(s)

    return result


def _substitute_state_vars(stmts: list[Statement], env: _StateEnv) -> list[Statement]:
    """
    Clone statements and replace state variable identifiers with numeric literals. Stops at
    function boundaries to avoid replacing reused names in nested scopes.
    """
    result: list[Statement] = []
    for stmt in stmts:
        cloned = _clone_node(stmt)
        _substitute_in_scope(cloned, env)
        result.append(cloned)
    return result


def _substitute_in_scope(node: Node, env: _StateEnv) -> None:
    """
    Replace state variable identifiers with numeric literals, skipping into nested functions.
    """
    for child in node.children():
        if isinstance(child, (JsFunctionExpression, JsFunctionDeclaration)):
            continue
        if isinstance(child, JsIdentifier) and child.name in env:
            _replace_in_parent(child, make_numeric_literal(env[child.name]))
        else:
            _substitute_in_scope(child, env)


def _strip_scope_param_prefix(
    stmts: list[Statement],
    scope_param_name: str | None,
) -> list[Statement]:
    """
    Rewrite every `scope.X` member access to the bare identifier `X`, dissolving the scope-parameter
    prefix unconditionally. Where a name actually lives is decided afterwards by home-driven
    qualification, which is independent of the momentary `with`-redirect state, so the strip carries
    no namespace and never depends on the traversal's redirect target.
    """
    if scope_param_name is None:
        return stmts
    for stmt in stmts:
        _strip_scope_prefix_walk(stmt, scope_param_name)
    return stmts


def _strip_scope_prefix_walk(node: Node, scope_param_name: str) -> None:
    for child in node.children():
        if isinstance(child, JsMemberExpression) and isinstance(child.object, JsIdentifier):
            if child.object.name != scope_param_name:
                _strip_scope_prefix_walk(child, scope_param_name)
                continue
            if child.computed:
                if not isinstance(child.property, JsStringLiteral):
                    _strip_scope_prefix_walk(child, scope_param_name)
                    continue
                prop_name = child.property.value
            else:
                if not isinstance(child.property, JsIdentifier):
                    _strip_scope_prefix_walk(child, scope_param_name)
                    continue
                prop_name = child.property.name
            _replace_in_parent(child, JsIdentifier(name=prop_name))
            continue
        _strip_scope_prefix_walk(child, scope_param_name)


def _qualify_exempt(match: _GeneratorCFFMatch) -> set[str]:
    """
    The set of names that home-driven qualification must leave bare: the state variables, the
    JavaScript built-in globals, every namespace object, and the compiler-introduced scaffolding
    identifiers (generator, scope parameter, argument holder, return flag, redirect variable).
    """
    exempt: set[str] = set(match.state_var_names) | _JS_BUILTIN_GLOBALS | set(match.namespaces)
    for name in (
        match.generator_name,
        match.scope_param_name,
        match.arg_var_name,
        match.did_return_var,
        match.with_redirect_var,
    ):
        if name is not None:
            exempt.add(name)
    return exempt


def _qualify_condition(
    condition: Expression,
    state: _StateEnv,
    match: _GeneratorCFFMatch,
) -> Expression:
    """
    Clone, substitute, strip, and qualify a transition condition expression using the same
    pipeline as block payloads. Wraps in a synthetic statement so that root-node scope members
    and identifiers are processed correctly.
    """
    wrapper = JsExpressionStatement(expression=_clone_node(condition))
    _substitute_in_scope(wrapper, state)
    if match.scope_param_name:
        _strip_scope_prefix_walk(wrapper, match.scope_param_name)
    if match.with_redirect_var and len(match.scope_default_props) == 1:
        _qualify_bare_walk(wrapper, match.namespace_homes, _qualify_exempt(match))
    return wrapper.expression  # type: ignore[return-value]


_JS_BUILTIN_GLOBALS: frozenset[str] = frozenset({
    'globalThis',
    'global',
    'self',
    'window',
    'undefined',
    'NaN',
    'Infinity',
    'eval',
    'isNaN',
    'isFinite',
    'parseInt',
    'parseFloat',
    'decodeURI',
    'decodeURIComponent',
    'encodeURI',
    'encodeURIComponent',
    'Object',
    'Function',
    'Boolean',
    'Symbol',
    'Number',
    'BigInt',
    'Math',
    'Date',
    'String',
    'RegExp',
    'Array',
    'Map',
    'Set',
    'WeakMap',
    'WeakSet',
    'ArrayBuffer',
    'SharedArrayBuffer',
    'DataView',
    'JSON',
    'Promise',
    'Reflect',
    'Proxy',
    'Error',
    'TypeError',
    'RangeError',
    'ReferenceError',
    'SyntaxError',
    'URIError',
    'EvalError',
    'console',
    'setTimeout',
    'setInterval',
    'clearTimeout',
    'clearInterval',
    'require',
    'module',
    'exports',
    'process',
    'Buffer',
    'URL',
    'URLSearchParams',
    'Intl',
    'Atomics',
    'WebAssembly',
})


def _qualify_with_identifiers(
    stmts: list[Statement],
    match: _GeneratorCFFMatch,
) -> list[Statement]:
    """
    Qualify each bare identifier that names a proven namespace-local by prepending its canonical
    home namespace: a bare `x` whose home is `H` becomes `H.x`. The home is fixed at match time and
    is independent of the momentary `with`-redirect, so a slot referenced qualified in one position
    and bare in another canonicalizes to the same `H.x` in both. Only applies under the
    with-redirect pattern with exactly one scope default.
    """
    if not match.with_redirect_var or len(match.scope_default_props) != 1:
        return stmts
    exempt = _qualify_exempt(match)
    for stmt in stmts:
        _qualify_bare_walk(stmt, match.namespace_homes, exempt)
    _convert_function_declarations(stmts, match.namespace_homes, exempt)
    return stmts


def _convert_function_declarations(
    stmts: list[Statement],
    homes: dict[str, tuple[str, ...]],
    exempt: set[str],
    owner: Node | None = None,
) -> None:
    """
    Convert a function declaration whose name is a proven namespace-local into a namespace property
    assignment, so every reference to the function goes through its canonical home: a
    `function foo(...)` with home `H` becomes `H.foo = function(...)`. A name with no home is left
    as a free declaration. Recurses into block bodies but not function bodies.
    """
    for i, stmt in enumerate(stmts):
        if isinstance(stmt, JsFunctionDeclaration):
            if stmt.id is not None and stmt.id.name in homes and stmt.id.name not in exempt:
                name = stmt.id.name
                func_expr = JsFunctionExpression(
                    id=None,
                    params=stmt.params,
                    body=stmt.body,
                )
                target = _make_namespace_node([*homes[name], name])
                assignment = JsAssignmentExpression(operator='=', left=target, right=func_expr)
                stmts[i] = JsExpressionStatement(expression=assignment)
                if owner is not None:
                    stmts[i].parent = owner
            continue
        if isinstance(stmt, (JsFunctionExpression, JsBlockStatement)):
            continue
        for child in stmt.children():
            if isinstance(child, JsBlockStatement):
                _convert_function_declarations(child.body, homes, exempt, owner=child)


def _make_namespace_node(ns_path: list[str]) -> Expression:
    """
    Build an AST node for a namespace path: single identifier for length 1,
    nested member expressions for longer paths.
    """
    node: Expression = JsIdentifier(name=ns_path[0])
    for segment in ns_path[1:]:
        node = JsMemberExpression(
            object=node,
            property=JsIdentifier(name=segment),
            computed=False,
        )
    return node


def _qualify_bare_walk(node: Node, homes: dict[str, tuple[str, ...]], exempt: set[str]) -> None:
    for child in node.children():
        if isinstance(child, (JsFunctionExpression, JsFunctionDeclaration, JsArrowFunctionExpression)):
            inner_exempt = exempt | _collect_declared_names(child)
            _qualify_bare_walk(child, homes, inner_exempt)
            continue
        if isinstance(child, JsCatchClause):
            inner_exempt = exempt
            if child.param is not None:
                param_names: set[str] = set()
                _collect_binding_names(child.param, param_names)
                inner_exempt = exempt | param_names
            _qualify_bare_walk(child, homes, inner_exempt)
            continue
        if isinstance(child, JsIdentifier) and child.name in homes and child.name not in exempt:
            parent = child.parent
            if isinstance(parent, JsMemberExpression) and parent.property is child and not parent.computed:
                continue
            if isinstance(parent, JsProperty) and not parent.computed:
                if parent.shorthand and parent.value is child:
                    replacement = _make_namespace_node([*homes[child.name], child.name])
                    replacement.parent = parent
                    parent.value = replacement
                    parent.shorthand = False
                    continue
                if parent.key is child:
                    continue
            if isinstance(parent, (JsVariableDeclarator, JsRestElement)):
                exempt.add(child.name)
                continue
            if isinstance(parent, (JsLabeledStatement, JsContinueStatement, JsBreakStatement)):
                if getattr(parent, 'label', None) is child:
                    continue
            _replace_in_parent(child, _make_namespace_node([*homes[child.name], child.name]))
            continue
        _qualify_bare_walk(child, homes, exempt)


def _collect_declared_names(
    func: JsFunctionExpression | JsFunctionDeclaration | JsArrowFunctionExpression,
) -> set[str]:
    """
    Collect parameter names and var-declared names from a function for exemption. Only collects
    declarations at the function's own scope level — does not descend into nested functions. An
    arrow with an expression body (rather than a block) contributes only its parameter names.
    """
    names: set[str] = set()
    if isinstance(func, JsFunctionDeclaration) and func.id is not None:
        names.add(func.id.name)
    for p in (func.params or []):
        _collect_binding_names(p, names)
    body = func.body
    if isinstance(body, JsBlockStatement):
        queue: deque[Node] = deque(body.body)
        while queue:
            node = queue.popleft()
            if isinstance(node, (JsFunctionExpression, JsFunctionDeclaration, JsArrowFunctionExpression)):
                if isinstance(node, JsFunctionDeclaration) and node.id is not None:
                    names.add(node.id.name)
                continue
            if isinstance(node, JsVariableDeclaration):
                for decl in node.declarations:
                    if isinstance(decl, JsVariableDeclarator):
                        _collect_binding_names(decl.id, names)
            for child in node.children():
                queue.append(child)
    return names


def _collect_binding_names(pattern: Expression | None, out: set[str]) -> None:
    """
    Recursively extract bound identifier names from a binding pattern (simple identifier,
    array pattern, object pattern, rest element, or assignment pattern with default).
    """
    if pattern is None:
        return
    if isinstance(pattern, JsIdentifier):
        out.add(pattern.name)
    elif isinstance(pattern, JsRestElement):
        _collect_binding_names(pattern.argument, out)
    elif isinstance(pattern, JsAssignmentPattern):
        _collect_binding_names(pattern.left, out)
    elif isinstance(pattern, JsArrayPattern):
        for el in pattern.elements:
            _collect_binding_names(el, out)
    elif isinstance(pattern, JsObjectPattern):
        for prop in pattern.properties:
            if isinstance(prop, JsRestElement):
                _collect_binding_names(prop.argument, out)
            elif isinstance(prop, JsProperty) and prop.value is not None:
                _collect_binding_names(prop.value, out)


def _is_did_return_assignment(expr: Expression, did_return_var: str | None) -> bool:
    """
    Check whether an expression is `didReturnVar = true`.
    """
    if did_return_var is None:
        return False
    if not isinstance(expr, JsAssignmentExpression):
        return False
    if not isinstance(expr.left, JsIdentifier):
        return False
    return expr.left.name == did_return_var and expr.operator == '='


def _recover_returns(stmts: list[Statement], did_return_var: str | None) -> list[Statement]:
    """
    Convert sequence expressions of the form

        (didReturn = true, value)

    into JsReturnStatement nodes. Also handles explicit return with the same pattern. Recurses
    into nested structures (if/else branches, while bodies) so that return patterns at any depth
    are recovered.
    """
    if did_return_var is None:
        return stmts
    result: list[Statement] = []
    for stmt in stmts:
        if isinstance(stmt, JsReturnStatement) and stmt.argument is not None:
            arg = stmt.argument
            if isinstance(arg, JsSequenceExpression) and len(arg.expressions) >= 2:
                if _is_did_return_assignment(arg.expressions[0], did_return_var):
                    ret_val = (
                        arg.expressions[1] if len(arg.expressions) == 2
                        else JsSequenceExpression(expressions=arg.expressions[1:])
                    )
                    result.append(JsReturnStatement(argument=ret_val))
                    continue
            result.append(stmt)
            continue
        if isinstance(stmt, JsExpressionStatement) and isinstance(stmt.expression, JsSequenceExpression):
            seq = stmt.expression
            if len(seq.expressions) >= 2 and _is_did_return_assignment(seq.expressions[0], did_return_var):
                ret_val = (
                    seq.expressions[1] if len(seq.expressions) == 2
                    else JsSequenceExpression(expressions=seq.expressions[1:])
                )
                result.append(JsReturnStatement(argument=ret_val))
                continue
        if isinstance(stmt, JsIfStatement):
            if stmt.consequent is not None and isinstance(stmt.consequent, JsBlockStatement):
                stmt.consequent.body = _recover_returns(stmt.consequent.body, did_return_var)
            if stmt.alternate is not None and isinstance(stmt.alternate, JsBlockStatement):
                stmt.alternate.body = _recover_returns(stmt.alternate.body, did_return_var)
            elif isinstance(stmt.alternate, JsIfStatement):
                recovered = _recover_returns([stmt.alternate], did_return_var)
                if recovered:
                    stmt.alternate = recovered[0]
        elif isinstance(stmt, JsWhileStatement):
            if stmt.body is not None and isinstance(stmt.body, JsBlockStatement):
                stmt.body.body = _recover_returns(stmt.body.body, did_return_var)
        result.append(stmt)
    return result


def _is_direct_scope_member(node: Expression | None, scope_param_name: str) -> bool:
    """
    Check if an expression is a depth-1 member access on the scope parameter, i.e. `scope.X` or
    `scope["X"]` but NOT `scope.X.Y`. Only direct slots are CFF routing state; deeper chains are
    semantic writes.
    """
    if not isinstance(node, JsMemberExpression):
        return False
    if not isinstance(node.object, JsIdentifier) or node.object.name != scope_param_name:
        return False
    if node.computed:
        return isinstance(node.property, JsStringLiteral)
    return True


def _extract_arg_param_names(
    stmt: Statement,
    arg_var_name: str | None,
) -> list[str] | None:
    """
    If *stmt* is the argument-destructuring pattern:

        [elem1, elem2, ...] = argVar

    extract parameter names from the LHS elements. Each element is expected to be a
    member-expression chain; the deepest property name is returned. Returns `None` if the
    statement is not the arg-destructuring pattern.
    """
    if arg_var_name is None:
        return None
    if not isinstance(stmt, JsExpressionStatement):
        return None
    expr = stmt.expression
    if not isinstance(expr, JsAssignmentExpression):
        return None
    if not isinstance(expr.left, (JsArrayExpression, JsArrayPattern)):
        return None
    if not isinstance(expr.right, JsIdentifier) or expr.right.name != arg_var_name:
        return None
    names: list[str] = []
    for elem in expr.left.elements:
        if elem is None:
            return None
        name = _deepest_property_name(elem)
        if name is None:
            return None
        names.append(name)
    return names


def _deepest_property_name(node: Node) -> str | None:
    """
    Walk a member-expression chain and return the deepest (rightmost) property name.
    """
    if isinstance(node, JsIdentifier):
        return node.name
    if isinstance(node, JsMemberExpression):
        if isinstance(node.property, JsIdentifier):
            return node.property.name
        if isinstance(node.property, JsStringLiteral):
            return node.property.value
    return None


def _is_bare_redirect_assignment(expr: Expression, redirect_var: str) -> bool:
    """
    Whether *expr* is a stripped redirect-routing write `redirect_var = <namespace>` on the bare
    redirect identifier. Once the scope prefix is dissolved unconditionally, `scope.redirect_var =
    scope.X` survives as this bare assignment of one identifier to another; it is pure routing
    bookkeeping with no consumer in the recovered code. The right-hand side must be a bare
    identifier — the only shape a stripped `scope.X` target can take — so that a coincidental
    side-effecting write to a same-named variable is never discarded.
    """
    return (
        isinstance(expr, JsAssignmentExpression)
        and expr.operator == '='
        and isinstance(expr.left, JsIdentifier)
        and expr.left.name == redirect_var
        and isinstance(expr.right, JsIdentifier)
    )


def _filter_redirect_var_assignments(
    stmts: list[Statement],
    match: _GeneratorCFFMatch,
) -> list[Statement]:
    redirect_var = match.with_redirect_var
    if not redirect_var or len(match.scope_default_props) != 1:
        return stmts
    result: list[Statement] = []
    for stmt in stmts:
        if not isinstance(stmt, JsExpressionStatement) or stmt.expression is None:
            result.append(stmt)
            continue
        expr = stmt.expression
        if isinstance(expr, JsSequenceExpression):
            remaining = [
                e for e in expr.expressions
                if not _is_bare_redirect_assignment(e, redirect_var)
            ]
            if len(remaining) == len(expr.expressions):
                result.append(stmt)
            elif not remaining:
                continue
            elif len(remaining) == 1:
                result.append(JsExpressionStatement(expression=remaining[0]))
            else:
                result.append(JsExpressionStatement(
                    expression=JsSequenceExpression(expressions=remaining),
                ))
            continue
        if _is_bare_redirect_assignment(expr, redirect_var):
            continue
        result.append(stmt)
    return result


def _track_scope_routing(payload: list[Statement], state: _StateEnv) -> None:
    """
    Scan payload for assignments to scope member expressions with evaluable RHS values and record
    them in the state environment. This captures routing variables stored on scope objects.
    """
    for stmt in payload:
        if not isinstance(stmt, JsExpressionStatement):
            continue
        expr = stmt.expression
        if isinstance(expr, JsSequenceExpression):
            exprs = expr.expressions
        else:
            exprs = [expr]
        for e in exprs:
            if not isinstance(e, JsAssignmentExpression):
                continue
            if not isinstance(e.left, JsMemberExpression):
                continue
            if e.operator != '=':
                continue
            key = member_key(e.left)
            if key is None or e.right is None:
                continue
            val = _eval_expr(e.right, state)
            if val is not None:
                state[key] = val


def _execute_machine(
    machine: _StateMachine,
    match: _GeneratorCFFMatch,
    inherited_state: _StateEnv | None = None,
) -> tuple[list[Statement], _StateEnv] | None:
    """
    Recover structured code from the state machine using CFG-based structural analysis.
    Builds a control flow graph, identifies loops via dominator analysis, and emits
    structured control flow (while, if/else, break).
    """
    var_names = match.state_var_names
    state = _apply_initial_state(var_names, match.initial_state)
    if inherited_state:
        for k, v in inherited_state.items():
            if k not in var_names:
                state[k] = v

    cfg_result = _build_cfg(machine, state, var_names, match.end_state, match)
    if cfg_result is None:
        return None

    cfg, final_state = cfg_result
    idom = _compute_idom(cfg)
    loops = _find_loops(cfg, idom)
    stmts = _structural_analysis(cfg, idom, loops)
    recovered = _recover_returns(stmts, match.did_return_var)
    return (recovered, final_state)


def _build_js_if(
    condition: Expression,
    true_body: list[Statement],
    false_body: list[Statement],
) -> JsIfStatement | None:
    """
    Build a JsIfStatement, omitting empty branches.
    """
    if not true_body and not false_body:
        return None
    if not true_body:
        neg = JsUnaryExpression(operator='!', operand=condition, prefix=True)
        return JsIfStatement(
            test=neg,
            consequent=JsBlockStatement(body=false_body),
        )
    if not false_body:
        return JsIfStatement(
            test=condition,
            consequent=JsBlockStatement(body=true_body),
        )
    return JsIfStatement(
        test=condition,
        consequent=JsBlockStatement(body=true_body),
        alternate=JsBlockStatement(body=false_body),
    )


def _resolve_shared_wrappers(
    stmts: list[Statement],
    machine: _StateMachine,
    match: _GeneratorCFFMatch,
    outer_state: _StateEnv,
) -> list[Statement]:
    """
    Walk recovered statements looking for function expressions that are wrappers around the same
    shared generator. For each wrapper found, execute the state machine from its entry point and
    replace the wrapper with a proper function containing the recovered body. The *outer_state*
    carries scope routing values from the primary execution so that predicate-gated cases in
    wrapper paths can resolve. Iterates until no more wrappers are resolved (handles nesting).
    """
    gen_name = match.generator_name
    num_vars = len(match.state_var_names)
    attempted: set[int] = set()

    while True:
        resolved_any = False
        for node in list(_walk_all(stmts)):
            if not isinstance(node, JsFunctionExpression):
                continue
            node_id = id(node)
            if node_id in attempted:
                continue
            wrapper_info = _detect_wrapper_function(node, gen_name, num_vars)
            if wrapper_info is None:
                continue
            synthetic = _GeneratorCFFMatch(
                generator_name=gen_name,
                state_var_names=match.state_var_names,
                initial_state=wrapper_info.initial_state,
                end_state=match.end_state,
                switch_stmt=match.switch_stmt,
                switch_label=match.switch_label,
                scope_param_name=match.scope_param_name,
                arg_var_name=match.arg_var_name,
                did_return_var=match.did_return_var,
                result_var=None,
                gen_decl_index=0,
                scaffolding_end=0,
                with_redirect_var=match.with_redirect_var,
                scope_default_props=match.scope_default_props,
                namespaces=match.namespaces,
                namespace_homes=match.namespace_homes,
            )
            result = _execute_machine(machine, synthetic, inherited_state=outer_state)
            if result is None:
                attempted.add(node_id)
                continue
            recovered, _ = result
            target = _wrapper_arg_param_name(match, wrapper_info, recovered)
            if match.arg_var_name and target and match.arg_var_name != target:
                recovered = _rebind_free_arg_var(recovered, match.arg_var_name, target)
            node.body = JsBlockStatement(body=recovered)
            node.body.parent = node
            for s in recovered:
                s.parent = node.body
            if synthetic.arg_params:
                node.params = [JsIdentifier(name=n) for n in synthetic.arg_params]
            elif target is not None and target != wrapper_info.rest_param_name:
                node.params = _rebind_wrapper_param(node.params, target)
            resolved_any = True
        if not resolved_any:
            break

    return stmts


def _walk_all(stmts: list[Statement]):
    """
    Yield all nodes reachable from a list of statements.
    """
    for stmt in stmts:
        yield from stmt.walk()


def _fresh_arg_name(base: str, taken: set[str]) -> str:
    """
    Derive an identifier based on *base* that does not appear in *taken*.
    """
    candidate = base
    suffix = 0
    while candidate in taken:
        suffix += 1
        candidate = F'{base}_{suffix}'
    return candidate


def _rebind_wrapper_param(params: list[Expression], target: str) -> list[Expression]:
    """
    Rename the binding of a wrapper's last parameter to *target*, preserving any leading parameters
    and whether that last parameter is a rest element or a plain identifier. A rest wrapper
    `(...rest)` becomes `(...target)` and a plain wrapper `(p)` becomes `(target)`, so the recovered
    body — whose argument-variable references were rebound onto *target* — keeps the wrapper's
    original arity and its rest-versus-scalar argument mapping. A parameterless wrapper gains a
    single rest parameter.
    """
    if not params:
        return [JsRestElement(argument=JsIdentifier(name=target))]
    result = list(params)
    last = result[-1]
    if isinstance(last, JsRestElement):
        result[-1] = JsRestElement(argument=JsIdentifier(name=target))
    else:
        result[-1] = JsIdentifier(name=target)
    return result


def _wrapper_arg_param_name(
    match: _GeneratorCFFMatch,
    wrapper_info: _WrapperFunctionInfo,
    recovered: list[Statement],
) -> str | None:
    """
    Choose the identifier a wrapper's recovered body should use for the shared generator's argument
    variable, or `None` when the body never references it in a value position. The wrapper's own
    rest-parameter name is preferred, but only when it neither collides with a state-machine
    variable nor occurs anywhere in the recovered body: any occurrence there — a nested binding of
    the name or a free reference to an outer one — would be captured once the argument variable is
    rebound onto it. When the rest-param is unusable (or absent), a fresh identifier not present in
    the recovered body is minted instead.
    """
    if match.arg_var_name is None:
        return None
    taken: set[str] = set()
    referenced: set[str] = set()
    for node in _walk_all(recovered):
        if isinstance(node, JsIdentifier):
            taken.add(node.name)
            if is_reference(node):
                referenced.add(node.name)
    if match.arg_var_name not in referenced:
        return None
    rest = wrapper_info.rest_param_name
    if rest is not None and rest not in match.state_var_names and rest not in taken:
        return rest
    return _fresh_arg_name(match.arg_var_name, taken)


def _rebind_free_arg_var(
    stmts: list[Statement],
    arg_var_name: str,
    param_name: str,
) -> list[Statement]:
    """
    Rename free references to the shared generator's argument variable to a wrapper's parameter
    name. A nested function whose own declarations (`_collect_declared_names`) bind either name owns
    that identifier and is left untouched; a function binding neither is descended into, so a
    genuine closure over the wrapper arguments is still rebound. Member-property and object-key
    positions are skipped because a name there is not a variable reference; an object shorthand
    `{arg}` is expanded to `{arg: param}` so the value read is rebound without renaming the key.
    """
    for stmt in stmts:
        _rebind_arg_var_in_scope(stmt, arg_var_name, param_name)
    return stmts


def _rebind_arg_var_in_scope(node: Node, arg_var_name: str, param_name: str) -> None:
    for child in node.children():
        if isinstance(child, (JsFunctionExpression, JsFunctionDeclaration)):
            declared = _collect_declared_names(child)
            if arg_var_name not in declared and param_name not in declared:
                _rebind_arg_var_in_scope(child, arg_var_name, param_name)
            continue
        if isinstance(child, JsIdentifier) and child.name == arg_var_name:
            parent = child.parent
            if isinstance(parent, JsMemberExpression) and parent.property is child and not parent.computed:
                continue
            if isinstance(parent, JsProperty) and not parent.computed:
                if parent.shorthand and parent.value is child:
                    replacement = JsIdentifier(name=param_name)
                    replacement.parent = parent
                    parent.value = replacement
                    parent.shorthand = False
                    continue
                if parent.key is child:
                    continue
            child.name = param_name
            continue
        _rebind_arg_var_in_scope(child, arg_var_name, param_name)


def _structural_namespaces(match: _GeneratorCFFMatch) -> list[str]:
    """
    The namespaces that must be materialized as `var X = {}`: the scope-parameter defaults and the
    object-literal scope-argument keys, in that order and deduplicated. Namespaces that exist only
    because an in-body `scope.X = {}` write created them are excluded — the recovered body declares
    and initializes those itself.
    """
    names: list[str] = list(match.scope_default_props)
    seen = set(names)
    for name in match.scope_arg_namespaces:
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


def _emit_scope_namespace_declarations(
    match: _GeneratorCFFMatch,
    recovered: list[Statement],
) -> list[Statement]:
    """
    Emit `var X = {}` for each structural namespace (scope default or object-literal scope-argument
    key), but only for namespaces still referenced in the recovered body. Once free names are left
    bare, a namespace whose every member turned out free has no surviving reference, so its
    declaration would be dead; a surviving `X.member` keeps it.
    """
    referenced = {node.name for node in _walk_all(recovered) if isinstance(node, JsIdentifier)}
    declarations: list[Statement] = []
    for name in _structural_namespaces(match):
        if name not in referenced:
            continue
        init = match.scope_default_inits.get(name)
        if init is None:
            init = match.scope_arg_namespaces.get(name)
        if init is None:
            init = JsObjectExpression(properties=[])
        decl = JsVariableDeclaration(
            declarations=[JsVariableDeclarator(
                id=JsIdentifier(name=name),
                init=_clone_node(init),
            )],
            kind=JsVarKind.VAR,
        )
        declarations.append(decl)
    return declarations


def _emit_arg_param_declarations(match: _GeneratorCFFMatch) -> list[Statement]:
    declarations: list[JsVariableDeclarator] = []
    for name in match.arg_params:
        declarations.append(JsVariableDeclarator(id=JsIdentifier(name=name), init=None))
    if not declarations:
        return []
    return [JsVariableDeclaration(declarations=declarations, kind=JsVarKind.VAR)]


def _collect_scope_props(
    stmts: list[Statement],
    scope_param_name: str | None,
    out: set[str],
) -> None:
    """
    Record the property names of depth-1 scope-member accesses (`scope.X` / `scope["X"]`) in *stmts*.
    These identify which bare identifiers in the recovered code originated as variables stored on the
    scope object, so the recovery can declare the live ones and drop write-only routing slots.
    """
    if scope_param_name is None:
        return
    for stmt in stmts:
        for node in stmt.walk():
            if _is_direct_scope_member(node, scope_param_name):
                name = _deepest_property_name(node)
                if name is not None:
                    out.add(name)


def _collect_read_names(node: Node | None, out: set[str]) -> None:
    """
    Collect names of identifiers that are read (appear in a value position) within *node*. Assignment
    targets, declaration ids, and non-computed member property names do not count as reads.
    """
    if node is None:
        return
    if isinstance(node, JsAssignmentExpression):
        if isinstance(node.left, JsIdentifier):
            if node.operator != '=':
                out.add(node.left.name)
        else:
            _collect_read_names(node.left, out)
        if node.right is not None:
            _collect_read_names(node.right, out)
        return
    if isinstance(node, JsVariableDeclarator):
        if node.init is not None:
            _collect_read_names(node.init, out)
        return
    if isinstance(node, JsMemberExpression):
        _collect_read_names(node.object, out)
        if node.computed:
            _collect_read_names(node.property, out)
        return
    if isinstance(node, JsProperty):
        if node.computed:
            _collect_read_names(node.key, out)
        _collect_read_names(node.value, out)
        return
    if isinstance(node, JsIdentifier):
        out.add(node.name)
        return
    for child in node.children():
        _collect_read_names(child, out)


def _is_pure_rhs(node: Node) -> bool:
    """
    Conservative purity check for dead-store removal: the expression must contain no calls or nested
    assignments, so dropping the statement cannot discard an observable side effect.
    """
    for n in node.walk():
        if isinstance(n, (JsCallExpression, JsAssignmentExpression)):
            return False
    return True


def _remove_dead_scope_writes(stmts: list[Statement], dead: set[str]) -> list[Statement]:
    """
    Remove pure `name = value` writes (and such sub-expressions of sequences) where *name* is a
    write-only scope slot, i.e. routing bookkeeping that is never read. Writes with side-effecting
    right-hand sides are preserved.
    """
    if not dead:
        return stmts

    def is_dead_write(e: Expression) -> bool:
        return (
            isinstance(e, JsAssignmentExpression)
            and e.operator == '='
            and isinstance(e.left, JsIdentifier)
            and e.left.name in dead
            and e.right is not None
            and _is_pure_rhs(e.right)
        )

    result: list[Statement] = []
    for stmt in stmts:
        if isinstance(stmt, JsExpressionStatement) and stmt.expression is not None:
            expr = stmt.expression
            if isinstance(expr, JsSequenceExpression):
                remaining = [e for e in expr.expressions if not is_dead_write(e)]
                if not remaining:
                    continue
                if len(remaining) == 1:
                    result.append(JsExpressionStatement(expression=remaining[0]))
                else:
                    result.append(JsExpressionStatement(
                        expression=JsSequenceExpression(expressions=remaining),
                    ))
                continue
            if is_dead_write(expr):
                continue
        result.append(stmt)
    return result


def _declared_names_in_stmts(stmts: list[Statement]) -> set[str]:
    """
    Collect var-declared binding names appearing anywhere in *stmts*.
    """
    names: set[str] = set()
    for stmt in stmts:
        for node in stmt.walk():
            if isinstance(node, JsVariableDeclaration):
                for decl in node.declarations:
                    if isinstance(decl, JsVariableDeclarator):
                        _collect_binding_names(decl.id, names)
    return names


def _declare_recovered_scope_vars(
    recovered: list[Statement],
    match: _GeneratorCFFMatch,
) -> list[Statement]:
    """
    Hoisted scope variables survive recovery as bare identifiers. Declare the ones that are read as
    locals of the recovered function, and drop the writes of slots that are pure routing bookkeeping
    (written but never read). Slots already declared, the structural namespaces, and resolved
    argument parameters are left to their dedicated emitters; an in-body namespace (created by a
    `scope.X = {}` write) is not structural, so it is declared here.
    """
    props = match.scope_prop_names
    if not props:
        return recovered
    reads: set[str] = set()
    for stmt in recovered:
        _collect_read_names(stmt, reads)
    dead = {p for p in props if p not in reads}
    recovered = _remove_dead_scope_writes(recovered, dead)
    present: set[str] = set()
    for stmt in recovered:
        for node in stmt.walk():
            if isinstance(node, JsIdentifier):
                present.add(node.name)
    exclude = _declared_names_in_stmts(recovered)
    exclude |= set(match.arg_params)
    exclude |= set(_structural_namespaces(match))
    to_declare = sorted(p for p in props if p in present and p not in exclude)
    if not to_declare:
        return recovered
    decl = JsVariableDeclaration(
        declarations=[JsVariableDeclarator(id=JsIdentifier(name=n), init=None) for n in to_declare],
        kind=JsVarKind.VAR,
    )
    return [decl] + recovered


class JsGeneratorCFFUnflattening(BodyProcessingTransformer):
    """
    Recover original code from generator-based state-machine CFF dispatchers. Handles the pattern
    where a function body is replaced with a generator function containing a while/switch state
    machine driven by multiple state variables.
    """

    def _process_body(self, parent: Node, body: list[Statement]) -> None:
        is_script = isinstance(parent, JsScript)
        i = 0
        while i < len(body):
            match = _match_generator_cff(body, i)
            if match is None:
                i += 1
                continue
            machine = _extract_state_blocks(match)
            if machine is None:
                i += 1
                continue
            result = _execute_machine(machine, match)
            if result is None:
                i += 1
                continue
            recovered, outer_state = result
            if match.arg_var_name is not None:
                recovered = _resolve_shared_wrappers(recovered, machine, match, outer_state)
            recovered = _declare_recovered_scope_vars(recovered, match)
            if match.scope_default_props:
                recovered = _emit_scope_namespace_declarations(match, recovered) + recovered
            if match.arg_params:
                recovered = _emit_arg_param_declarations(match) + recovered
            if is_script:
                recovered = self._sanitize_for_script_scope(recovered)
                if recovered is None:
                    i += 1
                    continue
            for s in recovered:
                s.parent = parent
            start = match.gen_decl_index
            end = match.scaffolding_end
            replacement = body[:start] + recovered + body[end + 1:]
            self._replace_body(parent, body, replacement)
            i = start + len(recovered)

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
