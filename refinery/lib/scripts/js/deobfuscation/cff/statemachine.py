"""
Recover original code from generator-based state-machine CFF dispatchers.

Handles the pattern where a function body is replaced with a generator function containing a
while/switch state machine driven by multiple state variables whose sum is the switch
discriminant. Each case updates the state via relative `+=` assignments.
"""
from __future__ import annotations

import math

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterator, NamedTuple

from refinery.lib.scripts import (
    Expression,
    Node,
    Statement,
    _clone_node,
    _remove_from_parent,
    _replace_in_parent,
    set_child,
    set_child_list,
)
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.model import (
    annex_b_var_home,
    is_member_write_target,
    is_use_position,
    lexically_declared_names,
    references_own_arguments,
    walk_receiver_scope,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BodyProcessingTransformer,
    access_key,
    eval_binary_op,
    is_literal,
    is_reference,
    is_valid_identifier,
    make_numeric_literal,
    make_undefined_expression,
    member_key,
    property_key,
    sanitize_inlined_body,
    substitute_use_position,
    walk_scope,
)
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsArrayExpression,
    JsArrayPattern,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsAwaitExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsBreakStatement,
    JsCallExpression,
    JsCatchClause,
    JsClassDeclaration,
    JsClassExpression,
    JsContinueStatement,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsFunctionNode,
    JsIdentifier,
    JsIfStatement,
    JsLabeledStatement,
    JsLogicalExpression,
    JsMemberExpression,
    JsMetaProperty,
    JsNewExpression,
    JsNumericLiteral,
    JsObjectExpression,
    JsObjectPattern,
    JsProperty,
    JsPropertyKind,
    JsRestElement,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsStringLiteral,
    JsSwitchCase,
    JsSwitchStatement,
    JsTaggedTemplateExpression,
    JsThisExpression,
    JsThrowStatement,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsWhileStatement,
    JsWithStatement,
    JsYieldExpression,
    is_async_function,
    is_generator_function,
    static_string,
)
from refinery.lib.scripts.js.strict import (
    directive_prologue,
    keeping_directives,
    strict_mode_at,
)

if TYPE_CHECKING:
    from refinery.lib.scripts.js.analysis.model import Binding, SemanticModel

    _StateEnv = dict[str, int | float]

_MAX_STEPS = 2000


class _CallSiteInfo(NamedTuple):
    initial_state: list[int | float]
    did_return_var: str | None
    result_var: str | None
    scaffolding_end: int
    returns_value: bool
    guarded: bool


class _WrapperFunctionInfo(NamedTuple):
    initial_state: list[int | float]
    rest_param_name: str | None
    scope_arg: Expression


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
    returns_value: bool = False
    guarded: bool = False
    scope_default_props: list[str] = field(default_factory=list)
    scope_default_inits: dict[str, Expression] = field(default_factory=dict)
    scope_prop_names: set[str] = field(default_factory=set)
    namespaces: set[str] = field(default_factory=set)
    namespace_homes: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def qualifies_namespaces(self) -> bool:
        """
        Whether this generator uses the with-redirect namespace-qualification path: a single scope
        default namespace together with a redirect variable. When false, bare identifiers inside the
        `with` are left unqualified.
        """
        return self.with_redirect_var is not None and len(self.scope_default_props) == 1


def _eval_expr(node: Expression, env: _StateEnv) -> float | None:
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
        state = float(result)
        if not math.isfinite(state):
            return None
        return state
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


def _scope_object_properties(scope: JsObjectExpression) -> dict[str, Expression] | None:
    """
    The properties a scope object literal creates, by key, or `None` where one of them is not a
    plain data property under a key known before it runs: a spread, a method or accessor, a computed
    key that is not a constant string, or a non-computed `__proto__`, which sets the prototype of
    the object rather than creating a property. `{["K"]: {}}` creates `K` as surely as `{K: {}}`.
    A key written twice gives `None` as well: the literal evaluates both values and keeps the
    second, and only the kept one is read here.
    """
    properties: dict[str, Expression] = {}
    for prop in scope.properties:
        if not isinstance(prop, JsProperty) or prop.method or prop.kind is not JsPropertyKind.INIT:
            return None
        if prop.computed:
            key = static_string(prop.key)
        elif (key := property_key(prop)) == '__proto__' and not prop.shorthand:
            return None
        if key is None or prop.value is None or key in properties:
            return None
        properties[key] = prop.value
    return properties


def _is_inert(node: Node | None) -> bool:
    """
    Whether evaluating *node* does nothing but make its value: a literal, a function, or an object
    or array literal of such values. The recovery declares a namespace only where the recovered code
    still refers to it, which drops the evaluation of an initializer nothing refers to.
    """
    if isinstance(node, JsObjectExpression):
        return all(
            isinstance(prop, JsProperty) and not prop.computed and _is_inert(prop.value)
            for prop in node.properties
        )
    if isinstance(node, JsArrayExpression):
        return all(element is None or _is_inert(element) for element in node.elements)
    return isinstance(node, FUNCTION_NODES) or node is not None and is_literal(node)


def _extract_scope_default_props(
    params: list, scope_param_name: str | None,
) -> _ScopeDefaults | None:
    """
    Extract namespace property names and their initializer expressions from the scope parameter's
    default value. For the pattern `scope = { MpAqdCF: {} }` this returns a tuple of the form

        (['MpAqdCF'], {'MpAqdCF': <JsObjectExpression>})

    A default that is not an object literal whose properties `_scope_object_properties` reads gives
    `None`: the recovery cannot know which names the scope object carries. So does one holding a
    value whose evaluation does more than make it (`_is_inert`).
    """
    if scope_param_name is None:
        return _ScopeDefaults([], {})
    for p in params:
        if not isinstance(p, JsAssignmentPattern):
            continue
        if not isinstance(p.left, JsIdentifier) or p.left.name != scope_param_name:
            continue
        if not isinstance(p.right, JsObjectExpression):
            return None
        properties = _scope_object_properties(p.right)
        if properties is None or not all(map(_is_inert, properties.values())):
            return None
        return _ScopeDefaults(list(properties), properties)
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
) -> set[str] | None:
    """
    Collect the sibling namespace objects on the scope. A namespace is any of: a scope default, a
    redirect target `scope.redirect_var = scope.TARGET` found anywhere in the switch (including
    inside nested functions), or a key of an object-literal scope argument passed to the shared
    generator. A scope argument whose keys `_scope_object_properties` cannot read gives `None`.
    """
    namespaces: set[str] = set(scope_default_props)
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
        if (properties := _scope_object_properties(scope_arg)) is None:
            return None
        namespaces.update(properties)
    return namespaces


def _collect_namespace_homes(
    switch_stmt: JsSwitchStatement,
    scope_param_name: str | None,
    ns_names: set[str],
) -> dict[str, tuple[str, ...]] | None:
    """
    Determine the canonical home namespace of every proven namespace-local member, or `None` to
    decline recovery when a member is written under two or more namespaces: under the `with`-redirect
    its home depends on where the routing variable points when each use runs, which
    redirect-independent qualification cannot express, so qualifying it could resolve to the wrong
    binding. A member written under exactly one namespace maps to it; a name with no
    namespace-defining write is free and stays bare once the `with` is dissolved.
    """
    accumulated: dict[str, set[str]] = {}
    for node in switch_stmt.walk():
        if isinstance(node, JsAssignmentExpression):
            _collect_assignment_targets(node.left, scope_param_name, ns_names, accumulated)
        elif isinstance(node, JsUpdateExpression):
            _collect_assignment_targets(node.argument, scope_param_name, ns_names, accumulated)
    homes: dict[str, tuple[str, ...]] = {}
    for member, home_set in accumulated.items():
        if len(home_set) >= 2:
            return None
        homes[member] = (next(iter(home_set)),)
    return homes


def _match_generator_cff(body: list[Statement], idx: int) -> _GeneratorCFFMatch | None:
    """
    Starting at index *idx* in *body*, test whether the statement is a generator function
    declaration matching the state machine CFF pattern, with its call site following. Its parameters
    are the state variables, the scope parameter with its default, and at most the argument holder
    behind it. A generator whose own code reads what its invocation binds
    (`_reads_its_own_invocation`) does not match, and neither does one in strict code that declares
    a function inside a block: the recovered code is read apart from the tree, where it cannot tell
    that it is strict, so `_hoisted_names` would give such a function the Annex B copy only sloppy
    code makes.
    """
    stmt = body[idx]
    if not isinstance(stmt, JsFunctionDeclaration):
        return None
    if not is_generator_function(stmt) or is_async_function(stmt):
        return None
    if stmt.id is None:
        return None
    gen_name = stmt.id.name
    if stmt.body is None:
        return None
    params = stmt.params
    if len(params) < 3:
        return None
    if _reads_its_own_invocation(stmt):
        return None
    if strict_mode_at(stmt) and _holds_a_block_function(stmt.body):
        return None
    scope_param_name: str | None = None
    arg_var_name: str | None = None
    state_var_names: list[str] = []
    for p in params:
        if not isinstance(p, JsIdentifier):
            if (
                scope_param_name is not None
                or not isinstance(p, JsAssignmentPattern)
                or not isinstance(p.left, JsIdentifier)
            ):
                return None
            scope_param_name = p.left.name
        elif scope_param_name is None:
            state_var_names.append(p.name)
        elif arg_var_name is None:
            arg_var_name = p.name
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
    if (scope_defaults := _extract_scope_default_props(params, scope_param_name)) is None:
        return None
    scope_default_props, scope_default_inits = scope_defaults
    with_redirect_var: str | None = None
    routed = isinstance(inner, JsWithStatement)
    if isinstance(inner, JsWithStatement):
        with_redirect_var = _extract_with_redirect_var(inner.object, scope_param_name)
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
    if not routed and _spells_a_slot_bare(switch_stmt, scope_param_name, scope_default_props):
        return None
    call_info = _find_generator_call_site(body, idx, gen_name)
    if call_info is None:
        return None
    if len(call_info.initial_state) != len(state_var_names):
        return None
    namespaces: set[str] = set()
    namespace_homes: dict[str, tuple[str, ...]] = {}
    if with_redirect_var is not None and len(scope_default_props) == 1:
        collected = _collect_namespaces(
            switch_stmt,
            scope_param_name,
            scope_default_props,
            with_redirect_var,
            gen_name,
            len(state_var_names),
        )
        if collected is None:
            return None
        namespaces = collected
        homes = _collect_namespace_homes(switch_stmt, scope_param_name, namespaces)
        if homes is None:
            return None
        namespace_homes = homes
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
        returns_value=call_info.returns_value,
        guarded=call_info.guarded,
        scope_default_props=scope_default_props,
        scope_default_inits=scope_default_inits,
        namespaces=namespaces,
        namespace_homes=namespace_homes,
    )


def _reads_its_own_invocation(generator: JsFunctionDeclaration) -> bool:
    """
    Whether the code of *generator* reads what its own invocation binds: its receiver `this`, a
    `super` reference, its `arguments` object or `new.target`, or whether it suspends with `yield`.
    The recovery moves that code into the function around the call, or into a wrapper, where each
    of these means that function's own.
    """
    for node in walk_receiver_scope(generator):
        if isinstance(node, (JsThisExpression, JsYieldExpression, JsMetaProperty)):
            return True
        if (
            isinstance(node, JsIdentifier)
            and node.name in ('arguments', 'super', 'new')
            and is_use_position(node)
        ):
            return True
    return False


def _spells_a_slot_bare(
    switch_stmt: JsSwitchStatement,
    scope_param_name: str | None,
    defaults: list[str],
) -> bool:
    """
    Whether the code of a generator that reads its scope object through no `with` body spells the
    name of a slot of that object bare. There the bare name means some other binding, and once the
    strip turns `scope.K` into `K` it would name the slot instead.
    """
    slots = set(defaults)
    if scope_param_name is not None:
        for member in _scope_members(switch_stmt, scope_param_name):
            if (name := _deepest_property_name(member)) is not None:
                slots.add(name)
    return any(
        isinstance(node, JsIdentifier) and node.name in slots and is_use_position(node)
        for node in switch_stmt.walk()
    )


def _holds_a_block_function(root: Node) -> bool:
    """
    Whether a function is declared inside a block anywhere below *root*, where sloppy code would
    copy its name into the function around the block.
    """
    for node in root.walk():
        if not isinstance(node, JsFunctionDeclaration):
            continue
        holder = node.parent
        if isinstance(holder, JsScript):
            continue
        if isinstance(holder, JsBlockStatement) and isinstance(holder.parent, FUNCTION_NODES):
            continue
        return True
    return False


def _did_return_reset(stmt: Statement) -> str | None:
    """
    The flag *stmt* resets ahead of the generator's call, as `var didReturn;` or as
    `didReturn = void 0;`, or `None`.
    """
    if isinstance(stmt, JsVariableDeclaration):
        decls = stmt.declarations
        if (
            len(decls) == 1
            and isinstance(decls[0], JsVariableDeclarator)
            and isinstance(decls[0].id, JsIdentifier)
            and decls[0].init is None
        ):
            return decls[0].id.name
    if isinstance(stmt, JsExpressionStatement):
        expr = stmt.expression
        if (
            isinstance(expr, JsAssignmentExpression)
            and expr.operator == '='
            and isinstance(expr.left, JsIdentifier)
            and isinstance(expr.right, JsUnaryExpression)
            and expr.right.operator == 'void'
            and isinstance(expr.right.operand, JsNumericLiteral)
        ):
            return expr.left.name
    return None


def _is_result_guard(stmt: Statement, did_return_var: str, result_var: str) -> bool:
    """
    Whether *stmt* is the guard `if (didReturn) { return result; }` and nothing more.
    """
    if not isinstance(stmt, JsIfStatement) or stmt.alternate is not None:
        return False
    if not isinstance(stmt.test, JsIdentifier) or stmt.test.name != did_return_var:
        return False
    consequent = stmt.consequent
    if isinstance(consequent, JsBlockStatement) and len(consequent.body) == 1:
        consequent = consequent.body[0]
    return (
        isinstance(consequent, JsReturnStatement)
        and isinstance(consequent.argument, JsIdentifier)
        and consequent.argument.name == result_var
    )


def _find_generator_call_site(
    body: list[Statement],
    gen_idx: int,
    gen_name: str,
) -> _CallSiteInfo | None:
    """
    Read the call of the generator declared at *gen_idx*, which the obfuscator writes right behind
    the declaration:

        var didReturn;
        var result = genName(args)["next"]()["value"];
        if (didReturn) { return result; }

    The flag may be reset with `didReturn = void 0;` instead, the result assigned to a variable
    declared elsewhere, and the call returned directly or made for nothing. The guard is part of
    the scaffolding in exactly this form: one that does anything else stays, and the flag it reads
    keeps the recovery from going ahead (`_scaffolding_is_private`). Returns a `_CallSiteInfo` or
    `None`.
    """
    pos = gen_idx + 1
    did_return_var: str | None = None
    if pos < len(body) and (did_return_var := _did_return_reset(body[pos])) is not None:
        pos += 1
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
    guarded = (
        did_return_var is not None
        and result_var is not None
        and scaffolding_end + 1 < len(body)
        and _is_result_guard(body[scaffolding_end + 1], did_return_var, result_var)
    )
    if guarded:
        scaffolding_end += 1
    return _CallSiteInfo(
        initial_state,
        did_return_var,
        result_var,
        scaffolding_end,
        isinstance(body[pos], JsReturnStatement),
        guarded,
    )


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
    - X = gen(...)["next"]()["value"];
    - gen(...)["next"]()["value"];
    - return gen(...)["next"]()["value"];

    Returns a `(call, name)` pair (the inner call to gen and the result variable name) or `None`. A
    result stored anywhere but in a plain name is refused: the recovery would drop the store.
    """
    result_name: str | None = None
    expr: Expression | None = None
    if isinstance(stmt, JsVariableDeclaration):
        if len(stmt.declarations) != 1:
            return None
        decl = stmt.declarations[0]
        if not isinstance(decl, JsVariableDeclarator) or not isinstance(decl.id, JsIdentifier):
            return None
        result_name = decl.id.name
        expr = decl.init
    elif isinstance(stmt, JsExpressionStatement):
        expr = stmt.expression
        if isinstance(expr, JsAssignmentExpression):
            if expr.operator != '=' or not isinstance(expr.left, JsIdentifier):
                return None
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

    The argument handed on after the scope has to be the wrapper's own last parameter, which is
    what the recovered body reads the generator's argument holder as. Returns a
    `_WrapperFunctionInfo` or `None`.
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
    if (
        len(args) != num_state_vars + 2
        or not isinstance(handed := args[-1], JsIdentifier)
        or handed.name != rest_param_name
    ):
        return None
    return _WrapperFunctionInfo(initial_state, rest_param_name, args[num_state_vars])


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
    cases = match.switch_stmt.cases
    last_body = max(
        (i for i, case in enumerate(cases) if isinstance(case, JsSwitchCase) and case.body),
        default=-1,
    )
    for index, case in enumerate(cases):
        if not isinstance(case, JsSwitchCase):
            return None
        if not case.body:
            pending_tests.append(case)
            continue
        all_cases = list(pending_tests) + [case]
        pending_tests.clear()
        stmts = list(case.body)
        parsed = _parse_case_body(stmts, var_names, label, index == last_body)
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
    last: bool,
) -> tuple[list[Statement], _SMTransition] | None:
    """
    Separate a case body into payload statements and the state transition the obfuscator ends it
    with. A `return` or `throw` at the top level ends the block, and nothing behind it runs. Any
    other body ends in the assignments of its transition, directly or in both branches of a final
    `if` statement, and then in a `break` of the switch, which only the *last* body may leave out:
    every other body runs on into the next one without it. A body with no transition, which would
    dispatch the same state again forever, or one that writes a state variable anywhere but in its
    transition gives `None`.
    """
    for index, stmt in enumerate(stmts):
        if isinstance(stmt, (JsReturnStatement, JsThrowStatement)):
            payload = stmts[:index + 1]
            if _writes_a_state_variable(payload, var_names):
                return None
            return (payload, _SMExitTransition())
    stmts, terminated = _strip_trailing_break(stmts, switch_label)
    transition: _SMTransition
    if stmts and isinstance(final := stmts[-1], JsIfStatement) and final.alternate is not None:
        if (conditional := _parse_conditional_transition(final, var_names, switch_label)) is None:
            return None
        transition, branches_terminated = conditional
        terminated = terminated or branches_terminated
        payload = stmts[:-1]
    elif (split := _split_transition(stmts, var_names)) is not None:
        payload, assignments = split
        transition = _SMLinearTransition(assignments=assignments)
    else:
        return None
    if not terminated and not last:
        return None
    if _writes_a_state_variable(payload, var_names):
        return None
    return (payload, transition)


def _strip_trailing_break(
    stmts: list[Statement],
    label: str | None,
) -> tuple[list[Statement], bool]:
    """
    Remove a trailing `break` that leaves the switch, unlabeled or naming the switch *label*, and
    tell whether there was one.
    """
    if stmts and isinstance(last := stmts[-1], JsBreakStatement):
        if last.label is None or (label is not None and last.label.name == label):
            return stmts[:-1], True
    return stmts, False


def _state_assignment(expr: Expression, var_names: list[str]) -> _SMRawAssignment | None:
    """
    The assignment *expr* makes to a state variable with `=` or `+=`, or `None`.
    """
    if (
        isinstance(expr, JsAssignmentExpression)
        and isinstance(expr.left, JsIdentifier)
        and expr.left.name in var_names
        and expr.operator in ('=', '+=')
        and expr.right is not None
    ):
        return _SMRawAssignment(name=expr.left.name, operator=expr.operator, rhs=expr.right)
    return None


def _split_transition(
    stmts: list[Statement],
    var_names: list[str],
) -> tuple[list[Statement], list[_SMRawAssignment]] | None:
    """
    Split statements that end in the assignments of a transition into the statements before them
    and those assignments, in the order they run. The transition is the longest run of state
    variable assignments at the end, as statements of their own or as the last expressions of a
    comma sequence, like the redirect store and state updates in

        scope.W = scope.NS, a += 5, b += -3;

    whose leading expressions stay behind as a statement of their own. Returns `None` where the
    statements do not end in such an assignment.
    """
    assignments: list[_SMRawAssignment] = []
    index = len(stmts)
    while index > 0:
        stmt = stmts[index - 1]
        if not isinstance(stmt, JsExpressionStatement) or stmt.expression is None:
            break
        expr = stmt.expression
        parts = list(expr.expressions) if isinstance(expr, JsSequenceExpression) else [expr]
        split = len(parts)
        run: list[_SMRawAssignment] = []
        while split > 0 and (assignment := _state_assignment(parts[split - 1], var_names)):
            run.append(assignment)
            split -= 1
        if not run:
            break
        run.reverse()
        assignments[:0] = run
        index -= 1
        if split > 0:
            head = parts[0] if split == 1 else JsSequenceExpression(expressions=parts[:split])
            return [*stmts[:index], JsExpressionStatement(expression=head)], assignments
    if not assignments:
        return None
    return stmts[:index], assignments


def _writes_a_state_variable(stmts: list[Statement], var_names: list[str]) -> bool:
    """
    Whether *stmts* store to or declare a state variable where nothing between them and the store
    binds its name anew. The recovery reads the state only from the transition that ends a block,
    and puts each state variable's value at entry in place of its every read.
    """
    watched = frozenset(var_names)
    for stmt in stmts:
        for node, shadowed in _walk_scoped(stmt, watched):
            if isinstance(node, JsVariableDeclarator):
                declared: set[str] = set()
                _collect_binding_names(node.id, declared)
                if declared & watched - shadowed:
                    return True
            elif isinstance(node, JsIdentifier) and node.name in watched - shadowed:
                if is_member_write_target(node):
                    return True
                if (
                    isinstance(parent := node.parent, (JsFunctionDeclaration, JsClassDeclaration))
                    and parent.id is node
                ):
                    return True
    return False


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


def _block_stmts(node: Statement) -> list[Statement]:
    if isinstance(node, JsBlockStatement):
        return list(node.body)
    return [node]


def _parse_conditional_transition(
    if_stmt: JsIfStatement,
    var_names: list[str],
    switch_label: str | None,
) -> tuple[_SMConditionalTransition, bool] | None:
    """
    Parse an if/else whose branches both end in the assignments of a transition, and tell whether
    both branches then leave the switch with a `break`. The statements a branch runs before its
    transition may not write a state variable (`_writes_a_state_variable`).
    """
    if if_stmt.test is None or if_stmt.consequent is None or if_stmt.alternate is None:
        return None
    true_stmts, true_terminated = _strip_trailing_break(
        _block_stmts(if_stmt.consequent), switch_label
    )
    false_stmts, false_terminated = _strip_trailing_break(
        _block_stmts(if_stmt.alternate), switch_label
    )
    true_split = _split_transition(true_stmts, var_names)
    false_split = _split_transition(false_stmts, var_names)
    if true_split is None or false_split is None:
        return None
    true_prefix, true_assigns = true_split
    false_prefix, false_assigns = false_split
    if _writes_a_state_variable(true_prefix + false_prefix, var_names):
        return None
    transition = _SMConditionalTransition(
        condition=if_stmt.test,
        true_assignments=true_assigns,
        false_assignments=false_assigns,
        true_prefix=true_prefix,
        false_prefix=false_prefix,
    )
    return transition, true_terminated and false_terminated


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


def _process_branch_prefix(
    prefix: list[Statement],
    state: _StateEnv,
    match: _GeneratorCFFMatch,
) -> list[Statement]:
    """
    Process a conditional transition's branch prefix through the standard pipeline (substitute,
    filter bookkeeping, strip scope, qualify). Returns the processed statements ready for emission
    as branch-specific payload.
    """
    if not prefix:
        return []
    result = _substitute_state_vars(prefix, state)
    _collect_scope_props(result, match)
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
        _collect_scope_props(payload, match)
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
            true_env = _apply_raw_transition(transition.true_assignments, state)
            false_env = _apply_raw_transition(transition.false_assignments, state)
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
            true_prefix_payload = _process_branch_prefix(transition.true_prefix, state, match)
            false_prefix_payload = _process_branch_prefix(transition.false_prefix, state, match)
            condition = _qualify_condition(condition, state, match)

        node = _CFGNode(
            node_id=node_id,
            payload=payload,
            condition=condition,
            successors=successors,
            true_prefix_payload=true_prefix_payload,
            false_prefix_payload=false_prefix_payload,
        )
        nodes[node_id] = node

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


def _parameter_names(func: JsFunctionNode) -> set[str]:
    """
    The names *func* binds for its parameter list: its parameters and the name of a function
    expression. A default value is evaluated in a scope of its own and does not see what the body
    declares.
    """
    names: set[str] = set()
    if isinstance(func, JsFunctionExpression) and func.id is not None:
        names.add(func.id.name)
    for param in func.params:
        _collect_binding_names(param, names)
    return names


def _hoisted_names(statements: list[Statement], home: JsFunctionNode | None) -> set[str]:
    """
    The names the statements of a body bind for the whole function beyond their own lexical
    declarations: every `var` outside nested functions and classes, and every function declared in
    a nested block whose name Annex B copies into the function *home* (`annex_b_var_home`). A list
    of statements not yet standing in the function it becomes the body of is given no such copy.
    """
    names: set[str] = set()
    queue: deque[Node] = deque(statements)
    while queue:
        node = queue.popleft()
        if isinstance(node, JsFunctionDeclaration):
            if (
                home is not None
                and node.id is not None
                and not is_generator_function(node)
                and not is_async_function(node)
                and annex_b_var_home(node) is home
            ):
                names.add(node.id.name)
            continue
        if isinstance(node, (*FUNCTION_NODES, JsClassDeclaration, JsClassExpression)):
            continue
        if isinstance(node, JsVariableDeclaration) and node.kind is JsVarKind.VAR:
            for declarator in node.declarations:
                if isinstance(declarator, JsVariableDeclarator):
                    _collect_binding_names(declarator.id, names)
        queue.extend(node.children())
    return names


def _function_bound_names(func: JsFunctionNode) -> set[str]:
    """
    The names *func* binds for the code of its body: its parameter names (`_parameter_names`), the
    `let`, `const`, class and function declarations of the body itself, and what the body hoists
    (`_hoisted_names`).
    """
    names = _parameter_names(func)
    body = func.body
    if not isinstance(body, JsBlockStatement):
        return names
    return names | _block_bound_names(body.body) | _hoisted_names(body.body, func)


def _block_bound_names(statements: list[Statement]) -> set[str]:
    """
    The names a statement list binds for its own block: its `let`, `const`, class and function
    declarations.
    """
    names = set(lexically_declared_names(statements))
    for statement in statements:
        if isinstance(statement, JsFunctionDeclaration) and statement.id is not None:
            names.add(statement.id.name)
    return names


def _names_bound_by(node: Node) -> set[str]:
    """
    The names *node* binds for the code of all its children, beyond what the code around it binds:
    a catch parameter, a block's declarations, the `let` or `const` head of a loop, and the name of
    a class inside the class.
    """
    names: set[str] = set()
    if isinstance(node, JsCatchClause):
        _collect_binding_names(node.param, names)
    elif isinstance(node, JsBlockStatement):
        names = _block_bound_names(node.body)
    elif isinstance(node, (JsForStatement, JsForInStatement, JsForOfStatement)):
        head = node.init if isinstance(node, JsForStatement) else node.left
        if isinstance(head, JsVariableDeclaration) and head.kind is not JsVarKind.VAR:
            for declarator in head.declarations:
                if isinstance(declarator, JsVariableDeclarator):
                    _collect_binding_names(declarator.id, names)
    elif isinstance(node, (JsClassDeclaration, JsClassExpression)) and node.id is not None:
        names.add(node.id.name)
    return names


def _scoped_children(node: Node) -> Iterator[tuple[Node, set[str]]]:
    """
    Each child of *node* together with the names *node* binds for that child. A function binds its
    parameter names for its parameter list (`_parameter_names`) and everything it declares for its
    body (`_function_bound_names`). The declarations of a `switch` bind for its cases, not for the
    discriminant evaluated before the block is entered.
    """
    if isinstance(node, FUNCTION_NODES):
        head = _parameter_names(node)
        whole = _function_bound_names(node)
        for child in node.children():
            yield child, whole if child is node.body else head
        return
    if isinstance(node, JsSwitchStatement):
        names = _block_bound_names([
            statement for case in node.cases if isinstance(case, JsSwitchCase)
            for statement in case.body
        ])
        for child in node.children():
            yield child, names if isinstance(child, JsSwitchCase) else set()
        return
    names = _names_bound_by(node)
    for child in node.children():
        yield child, names


def _walk_scoped(
    node: Node,
    watched: frozenset[str],
    shadowed: frozenset[str] = frozenset(),
) -> Iterator[tuple[Node, frozenset[str]]]:
    """
    Every node under *node*, *node* included, in source order, with the names of *watched* that
    something between *node* and it binds anew: where a name is in that set, the name no longer
    refers to what it refers to at *node*.
    """
    stack: list[tuple[Node, frozenset[str]]] = [(node, shadowed)]
    while stack:
        current, hidden = stack.pop()
        yield current, hidden
        stack.extend(
            (child, hidden | (watched & bound) if bound else hidden)
            for child, bound in reversed(list(_scoped_children(current)))
        )


def _references_to(stmts: list[Statement], names: frozenset[str]) -> Iterator[JsIdentifier]:
    """
    Every identifier in *stmts* that reads or writes one of *names* as the body *stmts* becomes
    binds it: a name the statements declare for that body themselves (`_declared_names_in_stmts`)
    is theirs, and any other one is bound by the code around them.
    """
    own = names & frozenset(_declared_names_in_stmts(stmts))
    for stmt in stmts:
        for node, shadowed in _walk_scoped(stmt, names, own):
            if (
                isinstance(node, JsIdentifier)
                and node.name in names
                and node.name not in shadowed
                and is_reference(node)
            ):
                yield node


def _substitute_in_scope(node: Node, env: _StateEnv) -> None:
    """
    Replace state variable identifiers with numeric literals. A nested function is not entered: it
    reads the state variable when it is called, not at the state being recovered.
    """
    for child, bound in _scoped_children(node):
        if isinstance(child, FUNCTION_NODES):
            continue
        if isinstance(child, JsIdentifier) and child.name in env and child.name not in bound:
            literal = make_numeric_literal(env[child.name])
            if literal is not None:
                substitute_use_position(child, literal)
        elif bound.isdisjoint(env):
            _substitute_in_scope(child, env)
        else:
            _substitute_in_scope(child, {k: v for k, v in env.items() if k not in bound})


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


def _scope_members(node: Node, scope_param_name: str) -> list[JsMemberExpression]:
    """
    The direct scope members `scope.X` under *node* whose `scope` is the generator's scope
    parameter and whose key a declaration may bind as a name (`is_valid_identifier`), leaving out
    those below a construct that binds the scope parameter's name anew. A member under any other key
    keeps its `scope`, which `_leaves_the_generator` then refuses.
    """
    return [
        member for member, shadowed in _walk_scoped(node, frozenset({scope_param_name}))
        if not shadowed
        and isinstance(member, JsMemberExpression)
        and _is_direct_scope_member(member, scope_param_name)
        and (name := _deepest_property_name(member)) is not None
        and is_valid_identifier(name)
    ]


def _strip_scope_prefix_walk(node: Node, scope_param_name: str) -> None:
    for member in _scope_members(node, scope_param_name):
        name = _deepest_property_name(member)
        assert name is not None
        _replace_in_parent(member, JsIdentifier(name=name))


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

    A `scope.X` a condition reads is recorded in `scope_prop_names` before the strip, exactly as
    the payload and branch-prefix paths record theirs. A scope member read only in a condition —
    `if (scope.x)` on the empty default scope — is `undefined`, and the strip that turns it into a
    bare `x` would leave an unbound free read were the name not then declared as a local reading
    `undefined`; recording it here is what lets `_declare_recovered_scope_vars` declare it.
    """
    wrapper = JsExpressionStatement(expression=_clone_node(condition))
    _substitute_in_scope(wrapper, state)
    if match.scope_param_name:
        _collect_scope_props([wrapper], match)
        _strip_scope_prefix_walk(wrapper, match.scope_param_name)
    if match.qualifies_namespaces:
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
    if not match.qualifies_namespaces:
        return stmts
    exempt = _qualify_exempt(match)
    _convert_function_declarations(
        stmts,
        match.namespace_homes,
        exempt | _hoisted_names(stmts, None),
    )
    for stmt in stmts:
        _qualify_bare_walk(stmt, match.namespace_homes, exempt)
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
                    generator=is_generator_function(stmt),
                    is_async=is_async_function(stmt),
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


def _qualify_bare_walk(
    node: Node,
    homes: dict[str, tuple[str, ...]],
    exempt: set[str],
    shadowed: frozenset[str] = frozenset(),
) -> None:
    """
    Qualify the bare names under *node* that have a home. A name something between *node* and the
    identifier binds anew (*shadowed*) is left alone there, and a name the payload declares for the
    generator itself joins *exempt* from its declaration on, which is shared by the whole payload.
    """
    for child, bound in _scoped_children(node):
        hidden = shadowed | bound if bound else shadowed
        if (
            isinstance(child, JsIdentifier)
            and child.name in homes
            and child.name not in exempt
            and child.name not in hidden
        ):
            parent = child.parent
            if isinstance(parent, (JsVariableDeclarator, JsRestElement)):
                exempt.add(child.name)
                continue
            if isinstance(parent, (JsFunctionDeclaration, JsClassDeclaration)):
                if parent.id is child:
                    continue
            if isinstance(parent, (JsLabeledStatement, JsContinueStatement, JsBreakStatement)):
                if getattr(parent, 'label', None) is child:
                    continue
            substitute_use_position(
                child,
                _make_namespace_node([*homes[child.name], child.name]),
                as_spelled=True,
            )
            continue
        _qualify_bare_walk(child, homes, exempt, hidden)


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
    Rewrite each return that raises the flag,

        return didReturn = true, value;

    to the return of its value. Recurses into if/else branches and while bodies; a flagged return
    anywhere else keeps its flag, which `_leaves_the_generator` then refuses.
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
        if isinstance(stmt, JsIfStatement):
            if stmt.consequent is not None and isinstance(stmt.consequent, JsBlockStatement):
                set_child_list(stmt.consequent, 'body', _recover_returns(
                    stmt.consequent.body, did_return_var
                ))
            if stmt.alternate is not None and isinstance(stmt.alternate, JsBlockStatement):
                set_child_list(stmt.alternate, 'body', _recover_returns(
                    stmt.alternate.body, did_return_var
                ))
            elif isinstance(stmt.alternate, JsIfStatement):
                recovered = _recover_returns([stmt.alternate], did_return_var)
                if recovered:
                    set_child(stmt, 'alternate', recovered[0])
        elif isinstance(stmt, JsWhileStatement):
            if stmt.body is not None and isinstance(stmt.body, JsBlockStatement):
                set_child_list(stmt.body, 'body', _recover_returns(stmt.body.body, did_return_var))
        result.append(stmt)
    return result


def _is_direct_scope_member(node: Node, scope_param_name: str) -> bool:
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
    if not match.qualifies_namespaces:
        return stmts
    redirect_var = match.with_redirect_var
    assert redirect_var is not None
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


@dataclass
class _Activation:
    """
    A run of the generator that the recovery turns into the body of one function: the run of the
    main call, recovered in place of the call, or the run of a wrapper's call, recovered as the
    wrapper's body. A run owns a scope object, and whatever that object holds lives as long as the
    object does: the namespaces it is created with and the variables a run stores on it are declared
    in the function whose call creates it. A wrapper that hands on the scope parameter itself
    shares the object of the run that created the wrapper, and so shares its activation.
    """
    function: JsFunctionExpression | None
    namespaces: dict[str, Expression]
    inherited: set[str] = field(default_factory=set)
    props: set[str] = field(default_factory=set)

    def holds(self, name: str) -> bool:
        return name in self.namespaces or name in self.inherited or name in self.props


def _creating_activation(
    node: Node,
    activations: dict[int, _Activation],
    main: _Activation,
) -> _Activation:
    """
    The activation of the run that creates the wrapper *node*: that of the innermost resolved
    wrapper whose recovered body holds it, or the main one.
    """
    cursor = node.parent
    while cursor is not None:
        if (activation := activations.get(id(cursor))) is not None:
            return activation
        cursor = cursor.parent
    return main


def _wrapper_activation(
    node: JsFunctionExpression,
    scope_arg: Expression,
    creator: _Activation,
    match: _GeneratorCFFMatch,
) -> _Activation | None:
    """
    The activation of the run a wrapper's call starts, read off the scope argument it hands the
    generator, in the recovered code the creating run's payload became. The scope parameter itself
    shares *creator*'s scope object. An object literal is a fresh scope object per call: each
    property holding an inert object literal (`_is_inert`) that reads no name is a namespace created
    with it, and a property `scope.K` under its own key `K`, which the strip of the creating run's
    payload left as a bare `K`, hands on the creating run's `K`, which that run has to hold. A
    namespace is declared in the wrapper's body only once the recovery has renamed the wrapper's
    parameters, so a name its value read could no longer mean what it meant. Where something between
    the generator and the scope argument binds the scope parameter's name anew, the argument is not
    the creator's scope object. Any other scope argument gives `None`.
    """
    if isinstance(scope_arg, JsIdentifier) and scope_arg.name == match.scope_param_name:
        return None if _bound_on_the_way_to(scope_arg, scope_arg.name) else creator
    if not isinstance(scope_arg, JsObjectExpression):
        return None
    if (properties := _scope_object_properties(scope_arg)) is None:
        return None
    activation = _Activation(node, {})
    for key, value in properties.items():
        if (
            isinstance(value, JsObjectExpression)
            and _is_inert(value)
            and not _reads_a_name(value)
        ):
            activation.namespaces[key] = value
        elif isinstance(value, JsIdentifier) and value.name == key and creator.holds(key):
            activation.inherited.add(key)
        else:
            return None
    return activation


def _reads_a_name(node: Node) -> bool:
    """
    Whether evaluating *node* reads a name anywhere below it.
    """
    return any(isinstance(part, JsIdentifier) and is_reference(part) for part in node.walk())


def _bound_on_the_way_to(node: Node, name: str) -> bool:
    """
    Whether something between the top of the tree that holds *node* and *node* binds *name* anew
    (`_scoped_children`).
    """
    cursor = node
    while (parent := cursor.parent) is not None:
        for child, bound in _scoped_children(parent):
            if child is cursor:
                if name in bound:
                    return True
                break
        cursor = parent
    return False


def _resolve_shared_wrappers(
    stmts: list[Statement],
    machine: _StateMachine,
    match: _GeneratorCFFMatch,
    outer_state: _StateEnv,
    main: _Activation,
) -> list[_Activation] | None:
    """
    Walk recovered statements looking for function expressions that are wrappers around the same
    shared generator. For each wrapper found, execute the state machine from its entry point and
    replace the wrapper with a proper function containing the recovered body. The *outer_state*
    carries scope routing values from the primary execution so that predicate-gated cases in
    wrapper paths can resolve. Iterates until no more wrappers are resolved (handles nesting).

    Returns the activations of the resolved wrappers, each one once and *main* among them where a
    wrapper shares its scope object, or `None` where a wrapper cannot be resolved: it would be left
    calling the generator the recovery removes. So is a wrapper nested in the recovered body of one
    that enters the machine at the same state, whose resolution would recover the same wrapper again
    without end, and a key a wrapper hands on from its creator (`_wrapper_activation`) that any run
    stores to (`_stores_to_any`): the wrapper's scope object holds a copy of the creator's value
    made when it is called, which the recovered code can only share with the creator.
    """
    gen_name = match.generator_name
    num_vars = len(match.state_var_names)
    activations: dict[int, _Activation] = {}
    entries: dict[int, list[int | float]] = {}

    while True:
        resolved_any = False
        for node in list(_walk_all(stmts)):
            if not isinstance(node, JsFunctionExpression):
                continue
            node_id = id(node)
            if node_id in activations:
                continue
            wrapper_info = _detect_wrapper_function(node, gen_name, num_vars)
            if wrapper_info is None:
                continue
            if _reenters(node, wrapper_info.initial_state, entries):
                return None
            creator = _creating_activation(node, activations, main)
            activation = _wrapper_activation(node, wrapper_info.scope_arg, creator, match)
            if activation is None:
                return None
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
                return None
            activation.props |= synthetic.scope_prop_names
            activations[node_id] = activation
            entries[node_id] = wrapper_info.initial_state
            recovered, _ = result
            target = _wrapper_arg_param_name(match, wrapper_info, recovered)
            if match.arg_var_name and target and match.arg_var_name != target:
                recovered = _rebind_free_arg_var(recovered, match.arg_var_name, target)
            recovered = keeping_directives(node.body, recovered)
            set_child(node, 'body', JsBlockStatement(body=recovered))
            if target is not None and target != wrapper_info.rest_param_name:
                set_child_list(node, 'params', _rebind_wrapper_param(node.params, target))
            if activation is not creator:
                _unpack_argument_stores(node, activation)
            resolved_any = True
        if not resolved_any:
            break

    resolved = list({id(activation): activation for activation in activations.values()}.values())
    inherited = frozenset(name for activation in resolved for name in activation.inherited)
    if inherited and _stores_to_any(stmts, inherited):
        return None
    return resolved


def _reenters(
    node: JsFunctionExpression,
    initial_state: list[int | float],
    entries: dict[int, list[int | float]],
) -> bool:
    """
    Whether a resolved wrapper whose recovered body holds the wrapper *node* enters the machine at
    the same *initial_state*, as recorded in *entries* by the node ids of the resolved wrappers.
    """
    cursor = node.parent
    while cursor is not None:
        if entries.get(id(cursor)) == initial_state:
            return True
        cursor = cursor.parent
    return False


def _stores_to_any(stmts: list[Statement], names: frozenset[str]) -> bool:
    """
    Whether *stmts* store to one of *names* where nothing between the statement and the store binds
    the name anew.
    """
    return any(
        isinstance(node, JsIdentifier)
        and node.name in names
        and node.name not in shadowed
        and is_reference(node)
        and is_member_write_target(node)
        for stmt in stmts
        for node, shadowed in _walk_scoped(stmt, names)
    )


def _is_activation_slot(target: Node | None, activation: _Activation) -> bool:
    """
    Whether *target* stores to what the scope object of *activation* holds for its own run: a
    member of a namespace the object is created with, or a variable the run keeps on the object.
    """
    if isinstance(target, JsIdentifier):
        return target.name in activation.props and target.name not in activation.inherited
    return (
        isinstance(target, JsMemberExpression)
        and isinstance(target.object, JsIdentifier)
        and target.object.name in activation.namespaces
        and access_key(target) is not None
    )


def _argument_slots(
    pattern: JsArrayExpression | JsArrayPattern,
    activation: _Activation,
) -> tuple[list[Expression], Expression | None] | None:
    """
    The slots an argument store `[s1, …, sn] = rest` or `[s1, …, ...r] = rest` fills, in order,
    and the slot taking the remaining arguments where the pattern ends in a rest element. `None`
    where one of them is not a slot of *activation*'s own scope object (`_is_activation_slot`), or
    the pattern skips an element or gives one a default.
    """
    elements = list(pattern.elements)
    remainder: Expression | None = None
    if elements and isinstance(last := elements[-1], (JsRestElement, JsSpreadElement)):
        remainder = last.argument
        elements.pop()
        if not _is_activation_slot(remainder, activation):
            return None
    slots: list[Expression] = []
    for element in elements:
        if element is None or not _is_activation_slot(element, activation):
            return None
        slots.append(element)
    return slots, remainder


def _unpack_argument_stores(function: JsFunctionExpression, activation: _Activation) -> None:
    """
    Give a wrapper whose run owns its scope object the parameters its run stores its arguments
    into. A run starts by destructuring the argument holder into slots of its own scope object, as
    in `[NS.a, NS.b] = rest` for the wrapper `function (...rest)`, and a function whose own
    parameters ended in a rest parameter is stored as `[NS.a, ...NS.r] = rest`. Where the rest
    parameter is read by such stores and nothing else, the wrapper takes the parameters `(a, ...r)`
    and the store becomes `NS.a = a, NS.r = r`: every slot receives what it received, the remainder
    being an array of the same arguments. Every store has to be a statement of the body itself,
    which runs once per call: the destructuring makes a new array each time it runs, and the rest
    parameter is one array per call. The wrapper's `length` counts the new parameters, as the
    function the obfuscator flattened counted them, and the destructuring's array iterator is
    trusted the way the recovery trusts the rest of the obfuscator's scaffolding. A body that reads
    its own `arguments`, whose elements a simple parameter list aliases, is left alone.
    """
    params = function.params
    if (
        function.body is None
        or len(params) != 1
        or not isinstance(rest := params[0], JsRestElement)
        or not isinstance(rest.argument, JsIdentifier)
        or references_own_arguments(function)
    ):
        return
    stores: list[tuple[JsAssignmentExpression, list[Expression], Expression | None]] = []
    for read in _references_to(function.body.body, frozenset({rest.argument.name})):
        store = read.parent
        if not (
            isinstance(store, JsAssignmentExpression)
            and store.operator == '='
            and store.right is read
            and isinstance(statement := store.parent, JsExpressionStatement)
            and statement.parent is function.body
            and isinstance(pattern := store.left, (JsArrayExpression, JsArrayPattern))
            and (slots := _argument_slots(pattern, activation)) is not None
        ):
            return
        stores.append((store, *slots))
    if not stores or len(stores) > 1 and any(remainder is not None for _, _, remainder in stores):
        return
    taken = {node.name for node in function.walk() if isinstance(node, JsIdentifier)}

    def fresh(slot: Expression) -> str:
        base = _deepest_property_name(slot)
        name = _fresh_arg_name(base if base and is_valid_identifier(base) else 'p', taken)
        taken.add(name)
        return name

    names: list[str] = []
    for index in range(max(len(elements) for _, elements, _ in stores)):
        slot = next(elements[index] for _, elements, _ in stores if index < len(elements))
        names.append(fresh(slot))
    remainder_name: str | None = None
    for store, elements, remainder in stores:
        assignments: list[Expression] = [
            JsAssignmentExpression(operator='=', left=element, right=JsIdentifier(name=name))
            for element, name in zip(elements, names)
        ]
        if remainder is not None:
            remainder_name = fresh(remainder)
            assignments.append(JsAssignmentExpression(
                operator='=', left=remainder, right=JsIdentifier(name=remainder_name)))
        if not assignments:
            statement = store.parent
            assert statement is not None
            _remove_from_parent(statement)
        elif len(assignments) == 1:
            _replace_in_parent(store, assignments[0])
        else:
            _replace_in_parent(store, JsSequenceExpression(expressions=assignments))
    new_params: list[Expression] = [JsIdentifier(name=name) for name in names]
    if remainder_name is not None:
        new_params.append(JsRestElement(argument=JsIdentifier(name=remainder_name)))
    set_child_list(function, 'params', new_params)


def _walk_all(stmts: list[Statement]):
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
    name. A construct that binds either name anew (`_scoped_children`) owns that identifier and is
    left untouched; a function binding neither is descended into, so a genuine closure over the
    wrapper arguments is still rebound. Member-property and object-key
    positions are skipped because a name there is not a variable reference; an object shorthand
    `{arg}` is expanded to `{arg: param}` so the value read is rebound without renaming the key.
    """
    for stmt in stmts:
        _rebind_arg_var_in_scope(stmt, arg_var_name, param_name)
    return stmts


def _rebind_arg_var_in_scope(node: Node, arg_var_name: str, param_name: str) -> None:
    for child, bound in _scoped_children(node):
        if arg_var_name in bound or param_name in bound:
            continue
        if isinstance(child, JsIdentifier) and child.name == arg_var_name:
            substitute_use_position(
                child, JsIdentifier(name=param_name, offset=child.offset))
            continue
        _rebind_arg_var_in_scope(child, arg_var_name, param_name)


def _emit_scope_namespace_declarations(
    namespaces: dict[str, Expression],
    recovered: list[Statement],
) -> list[Statement]:
    """
    Emit `var X = …` for each namespace a scope object is created with, but only for namespaces
    still referenced in the recovered body. Once free names are left bare, a namespace whose every
    member turned out free has no surviving reference, so its declaration would be dead; a surviving
    `X.member` keeps it.
    """
    referenced = {node.name for node in _walk_all(recovered) if isinstance(node, JsIdentifier)}
    declarations: list[Statement] = []
    for name, init in namespaces.items():
        if name not in referenced:
            continue
        decl = JsVariableDeclaration(
            declarations=[JsVariableDeclarator(
                id=JsIdentifier(name=name),
                init=_clone_node(init),
            )],
            kind=JsVarKind.VAR,
        )
        declarations.append(decl)
    return declarations


def _collect_scope_props(stmts: list[Statement], match: _GeneratorCFFMatch) -> None:
    """
    Record the property names of depth-1 scope-member accesses (`scope.X` / `scope["X"]`) in
    *stmts* in `scope_prop_names`. The names identify which bare identifiers in the recovered code
    originated as variables stored on the scope object, so the recovery can declare the live ones
    and drop write-only routing slots.
    """
    if match.scope_param_name is None:
        return
    for stmt in stmts:
        for member in _scope_members(stmt, match.scope_param_name):
            name = _deepest_property_name(member)
            assert name is not None
            match.scope_prop_names.add(name)


def _collect_read_names(node: Node | None, out: set[str]) -> None:
    """
    Collect names of identifiers that are read (appear in a value position) within *node*.
    Assignment targets, declaration ids, and non-computed member property names do not count as
    reads.
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


def _is_pure_rhs(node: Node, known: set[str]) -> bool:
    """
    Conservative purity check for dead-store removal: the expression contains no call, `new`,
    tagged template, assignment, update, `delete`, `yield` or `await`, and reads no name but those
    in *known*, which the recovered code declares itself; any other name may be unbound, and reading
    it throws. Dropping the statement then cannot discard an observable side effect.
    """
    for n in node.walk():
        if isinstance(n, (
            JsCallExpression,
            JsNewExpression,
            JsTaggedTemplateExpression,
            JsAssignmentExpression,
            JsUpdateExpression,
            JsYieldExpression,
            JsAwaitExpression,
        )):
            return False
        if isinstance(n, JsUnaryExpression) and n.operator == 'delete':
            return False
        if isinstance(n, JsIdentifier) and n.name not in known and is_reference(n):
            return False
    return True


def _remove_dead_scope_writes(
    stmts: list[Statement],
    dead: set[str],
    known: set[str],
) -> list[Statement]:
    """
    Remove pure `name = value` writes (and such sub-expressions of sequences) where *name* is a
    write-only scope slot, i.e. routing bookkeeping that is never read. Writes with side-effecting
    right-hand sides are preserved (`_is_pure_rhs`, with the names *known* to be declared).
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
            and _is_pure_rhs(e.right, known)
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
    The names the statement list *stmts* declares for the body it becomes: its own `let`, `const`,
    class and function declarations and every `var` outside nested functions and classes
    (`_hoisted_names`). A declaration inside a nested function, or a lexical one inside a nested
    block, binds nothing for that body.
    """
    return _block_bound_names(stmts) | _hoisted_names(stmts, None)


def _declare_recovered_scope_vars(
    recovered: list[Statement],
    activation: _Activation,
) -> list[Statement]:
    """
    Declare what the scope object of *activation* holds at the head of the body *recovered*
    recovers for it. Hoisted scope variables survive recovery as bare identifiers: the ones that are
    read are declared as locals, and the writes of slots that are pure routing bookkeeping (written
    but never read) are dropped. Slots already declared and the namespaces the object is created
    with or hands on are left to their own declarations; an in-body namespace (created by a
    `scope.X = {}` write) is a slot like any other, so it is declared here.
    """
    props = activation.props
    if props:
        reads: set[str] = set()
        for stmt in recovered:
            _collect_read_names(stmt, reads)
        dead = {p for p in props if p not in reads}
        known = (
            props
            | activation.inherited
            | set(activation.namespaces)
            | _declared_names_in_stmts(recovered)
        )
        recovered = _remove_dead_scope_writes(recovered, dead, known)
    present: set[str] = set()
    for stmt in recovered:
        for node in stmt.walk():
            if isinstance(node, JsIdentifier):
                present.add(node.name)
    exclude = _declared_names_in_stmts(recovered)
    exclude |= set(activation.namespaces)
    exclude |= activation.inherited
    to_declare = sorted(p for p in props if p in present and p not in exclude)
    declarations = _emit_scope_namespace_declarations(activation.namespaces, recovered)
    if to_declare:
        declarations.append(JsVariableDeclaration(
            declarations=[
                JsVariableDeclarator(id=JsIdentifier(name=name), init=None) for name in to_declare
            ],
            kind=JsVarKind.VAR,
        ))
    return declarations + recovered


def _declare_wrapper_scope_vars(activation: _Activation) -> None:
    """
    Declare what the scope object of a wrapper's run holds at the head of the wrapper's recovered
    body, behind its directives.
    """
    function = activation.function
    assert function is not None and function.body is not None
    body = function.body.body
    split = len(directive_prologue(function.body))
    recovered = _declare_recovered_scope_vars(body[split:], activation)
    set_child_list(function.body, 'body', body[:split] + recovered)


def _bind_main_arguments(recovered: list[Statement], match: _GeneratorCFFMatch) -> bool:
    """
    The main call hands the generator nothing beyond its state, so its run reads the argument
    variable as `undefined`: every read of it that the recovered code keeps becomes `void 0`. A
    store to it, or a `delete` of it, cannot be expressed that way and gives `False`.
    """
    if match.arg_var_name is None:
        return True
    reads = list(_references_to(recovered, frozenset({match.arg_var_name})))
    if any(is_member_write_target(read) for read in reads):
        return False
    for read in reads:
        substitute_use_position(read, make_undefined_expression())
    return True


def _settle_returns(
    recovered: list[Statement],
    match: _GeneratorCFFMatch,
    trailing: list[Statement],
    wrapped: bool,
) -> list[Statement] | None:
    """
    The recovered code with every `return` of the generator doing what it did, or `None` where
    that cannot be written. The code replaces the call in the body of a function or a script, so
    running off its end runs into the statements behind the call (*trailing*) and nothing else. A
    return of the generator only ends the generator, and its value is the result of the call. A
    returned call makes every such return a return of the function, and has the function return
    `undefined` where the generator ends without one, which the recovered code running on into
    *trailing* would not. The guard `if (didReturn) { return result; }` makes a return that raises
    the flag a return of the function and lets any other one fall through to what follows, which
    only a return at the end of the recovered code could be written as. A wrapper's run raises the
    same flag when it returns, so where the call has *wrapped* one and *trailing* is not empty, a
    wrapper called during the call would make the guard return where the recovered code runs on.
    Without either, every return falls through, and `sanitize_inlined_body` writes the one at the
    end as the expression it returns.
    """
    plain = False
    for node in walk_scope(match.switch_stmt):
        if not isinstance(node, JsReturnStatement):
            continue
        argument = node.argument
        if not (
            isinstance(argument, JsSequenceExpression)
            and argument.expressions
            and _is_did_return_assignment(argument.expressions[0], match.did_return_var)
        ):
            plain = True
    if match.returns_value:
        return None if trailing else recovered
    if match.guarded:
        return None if plain or (wrapped and trailing) else recovered
    return sanitize_inlined_body(recovered)


def _scaffolding_is_private(
    model: SemanticModel,
    body: list[Statement],
    match: _GeneratorCFFMatch,
) -> bool:
    """
    Whether nothing but the scaffolding the recovery removes can reach a binding it removes: the
    generator, and the flag and the result of its call (`_reached_only_from`).
    """
    removed = body[match.gen_decl_index:match.scaffolding_end + 1]
    inside = {id(node) for statement in removed for node in statement.walk()}
    generator = removed[0]
    assert isinstance(generator, JsFunctionDeclaration) and generator.id is not None
    names = {match.did_return_var, match.result_var}
    anchors = [generator.id]
    for statement in removed[1:]:
        anchors.extend(
            node for node in statement.walk()
            if isinstance(node, JsIdentifier) and node.name in names
        )
    for anchor in anchors:
        binding = model.binding_of(anchor) or model.resolve(anchor)
        if binding is None or not _reached_only_from(model, binding, inside):
            return False
    return True


def _reached_only_from(model: SemanticModel, binding: Binding, inside: set[int]) -> bool:
    """
    Whether every way the program can reach *binding* stands among the nodes whose ids are
    *inside*: its references, those a `with` body resolves, the opaque reflective surfaces that
    could name it (`refinery.lib.scripts.js.analysis.model.SemanticModel.reflection_surface_sites`),
    and every declaration that stores a value in it (`_declaration_stores`).
    """
    return (
        all(id(node) in inside for node in model.references(binding))
        and all(id(node) in inside for node in binding.dynamic_refs)
        and all(id(node) in inside for node in model.reflection_surface_sites(binding))
        and all(
            id(node) in inside or not _declaration_stores(node) for node in binding.declarations
        )
    )


def _declaration_stores(identifier: Node) -> bool:
    """
    Whether the declaration that *identifier* names puts a value in its binding, which all but a
    declarator without an initializer do.
    """
    declarator = identifier.parent
    return not (
        isinstance(declarator, JsVariableDeclarator)
        and declarator.id is identifier
        and declarator.init is None
    )


def _declares_only_its_own_names(
    model: SemanticModel,
    body: list[Statement],
    match: _GeneratorCFFMatch,
    recovered: list[Statement],
) -> bool:
    """
    Whether no code of the function around the call means anything else by a name the recovered
    code declares for that function (`_declared_names_in_stmts`). The recovery makes the
    generator's locals and the slots of its scope object locals of that function, where they would
    otherwise capture a name the function reads from outside, merge with one it declares, or clash
    with a lexical declaration of the same name. Every occurrence of such a name in the parameters
    and the body of that function, outside the removed statements, has to resolve to a binding
    declared below the function's own scope, and the function may not declare the name lexically.
    The name a function declaration gives itself stands in the scope around it and is not read.
    """
    names = _declared_names_in_stmts(recovered)
    if not names:
        return True
    removed = body[match.gen_decl_index:match.scaffolding_end + 1]
    inside = {id(node) for statement in removed for node in statement.walk()}
    home = model.scope_of(body[match.scaffolding_end])
    if home is None:
        return False
    for name in names:
        binding = model.lookup(name, home)
        if binding is not None and binding.scope is home and binding.is_lexical:
            return False
    owner = home.node
    roots: list[Node] = list(body)
    if isinstance(owner, FUNCTION_NODES):
        roots.extend(owner.params)
    for root in roots:
        for node in root.walk():
            if (
                id(node) in inside
                or not isinstance(node, JsIdentifier)
                or node.name not in names
                or not is_use_position(node)
            ):
                continue
            binding = model.binding_of(node) or model.resolve(node)
            if binding is None or not home.contains(binding.scope, strict=True):
                return False
    return True


def _leaves_the_generator(recovered: list[Statement], match: _GeneratorCFFMatch) -> bool:
    """
    Whether *recovered* still refers to a binding the recovery removes: the generator, its
    parameters, or the scaffolding variables of its call. Such a reference would be left to resolve
    to whatever the code around it binds under that name, or to nothing.
    """
    names = {
        match.generator_name,
        match.scope_param_name,
        match.arg_var_name,
        match.did_return_var,
        match.result_var,
        *match.state_var_names,
    }
    names.discard(None)
    return any(True for _ in _references_to(recovered, frozenset(names)))


def _is_a_function_body(node: Node) -> bool:
    """
    Whether *node* holds the statements a script or a function runs rather than a block inside
    them. Only there does running off the end of the recovered code mean what the end of the
    generator meant, and only there do the slots it declares live as long as one call does.
    """
    if isinstance(node, JsScript):
        return True
    function = node.parent
    return (
        isinstance(node, JsBlockStatement)
        and isinstance(function, FUNCTION_NODES)
        and function.body is node
    )


class JsGeneratorCFFUnflattening(BodyProcessingTransformer):
    """
    Recover original code from generator-based state-machine CFF dispatchers. Handles the pattern
    where a function body is replaced with a generator function containing a while/switch state
    machine driven by multiple state variables.
    """

    def __init__(self):
        super().__init__()
        self._root: JsScript | None = None

    def visit_JsScript(self, node: JsScript):
        self._root = node
        return super().visit_JsScript(node)

    def _process_body(self, parent: Node, body: list[Statement]) -> None:
        if not _is_a_function_body(parent):
            return
        i = 0
        while i < len(body):
            match = _match_generator_cff(body, i)
            if match is None:
                i += 1
                continue
            assert self._root is not None
            model = model_cache(self, self._root).model
            if not _scaffolding_is_private(model, body, match):
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
            main = _Activation(None, match.scope_default_inits, props=match.scope_prop_names)
            wrappers = _resolve_shared_wrappers(recovered, machine, match, outer_state, main)
            if wrappers is None or not _bind_main_arguments(recovered, match):
                i += 1
                continue
            for activation in wrappers:
                if activation.function is not None:
                    _declare_wrapper_scope_vars(activation)
            recovered = _declare_recovered_scope_vars(recovered, main)
            if (
                _leaves_the_generator(recovered, match)
                or not _declares_only_its_own_names(model, body, match, recovered)
            ):
                i += 1
                continue
            settled = _settle_returns(
                recovered,
                match,
                body[match.scaffolding_end + 1:],
                bool(wrappers),
            )
            if settled is None:
                i += 1
                continue
            recovered = settled
            for s in recovered:
                s.parent = parent
            start = match.gen_decl_index
            end = match.scaffolding_end
            replacement = body[:start] + recovered + body[end + 1:]
            self._replace_body(parent, replacement)
            i = start + len(recovered)
