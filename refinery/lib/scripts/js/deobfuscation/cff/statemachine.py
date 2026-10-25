"""
Recover original code from functions flattened into a state machine: the body of a function is
replaced by a call of a machine function, a `while`/`switch` loop whose discriminant is the sum of
its state, and each case changes the state by relative stores. The machine is a generator function
whose state is several variables.
"""
from __future__ import annotations

import enum
import math

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Iterator, NamedTuple, Sequence, TypeVar

from refinery.lib.scripts import (
    Expression,
    Node,
    Statement,
    _clone_node,
    _replace_in_parent,
    set_child,
    set_child_list,
    tree_root,
)
from refinery.lib.scripts.analysis.cfg import ControlFlowModel
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.js.analysis.cfg import build_cfg
from refinery.lib.scripts.js.analysis.environment import FileKind
from refinery.lib.scripts.js.analysis.evaluation import Evaluation, evaluation_of
from refinery.lib.scripts.js.analysis.intrinsics import denoting_leaves
from refinery.lib.scripts.js.analysis.model import (
    annex_b_function_home,
    is_direct_eval_call,
    is_invocation_target,
    is_member_write_target,
    is_simple_assignment_target,
    is_use_position,
    lexically_declared_names,
    pattern_identifiers,
    references_own_arguments,
    walk_receiver_scope,
)
from refinery.lib.scripts.js.deobfuscation.admission import CallAdmission
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BodyProcessingTransformer,
    PinnedTransformer,
    access_key,
    declares_a_watched_name,
    denoted_value,
    eval_binary_op,
    fresh_name,
    is_literal,
    is_reference,
    is_valid_identifier,
    make_numeric_literal,
    make_string_literal,
    make_undefined_expression,
    property_absent_from_written_chain,
    property_key,
    sanitize_inlined_body,
    substitute_use_position,
)
from refinery.lib.scripts.js.deobfuscation.interpreter import (
    InterpreterError,
    IrreducibleExpression,
    _ThrowSignal,
)
from refinery.lib.scripts.js.deobfuscation.namespaces import namespace_accesses
from refinery.lib.scripts.js.deobfuscation.parameters import parameter_list
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    LOOP_NODES,
    JsArrayExpression,
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsAwaitExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsBreakStatement,
    JsCallExpression,
    JsCatchClause,
    JsClassBody,
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
    JsTryStatement,
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
    object_member_access_runs_accessor,
    static_string,
    strip_parens,
)
from refinery.lib.scripts.js.numbers import is_negative_zero
from refinery.lib.scripts.js.strict import (
    directive_prologue,
    keeping_directives,
    strict_mode_at,
)


class _Undefined(enum.Enum):
    """
    The value `undefined`, which a case test reads from a routing slot no store has filled yet.
    """
    VALUE = 'undefined'


_UNDEFINED = _Undefined.VALUE


if TYPE_CHECKING:
    from refinery.lib.scripts.js.analysis.cache import ModelCache
    from refinery.lib.scripts.js.analysis.intrinsics import IntrinsicWrites
    from refinery.lib.scripts.js.analysis.model import Binding, Scope, SemanticModel
    from refinery.lib.scripts.js.deobfuscation.helpers import Value

    _StateValue = float | tuple[float, ...]
    _StateEnv = dict[str, _StateValue]
    _SlotPath = tuple[str, ...]
    _Value = float | bool | str | tuple[float, ...] | _Undefined
    _Slots = dict[_SlotPath, _Value]

_MAX_BLOCKS = 2000
"""
The most blocks the recovery reads for one run of a machine; it leaves a larger machine as it is.
"""


class _FlagVariable(NamedTuple):
    """
    The flag the call of a machine resets and its guard reads, held by a variable of the function
    that holds the call.
    """
    name: str

    @property
    def base(self) -> str:
        return self.name

    def spelled_by(self, node: Node | None) -> bool:
        return isinstance(node, JsIdentifier) and node.name == self.name


class _FlagProperty(NamedTuple):
    """
    The flag held by the property *key* of the object a variable *holder* of that function holds,
    as the recovery of a machine around this one writes a variable of the function it recovers that
    code from (`_Activation`).
    """
    holder: str
    key: str

    @property
    def base(self) -> str:
        return self.holder

    def spelled_by(self, node: Node | None) -> bool:
        return isinstance(node, JsMemberExpression) and _slot_path(node) == (self.holder, self.key)


_Flag = _FlagVariable | _FlagProperty


class _CallSiteInfo(NamedTuple):
    initial_state: list[_StateValue]
    flag: _Flag | None
    result_var: str | None
    scaffolding_end: int
    returns_value: bool
    guarded: bool
    undefined_reads: list[Expression]
    initial_args: list[Expression]
    call_index: int


class _WrapperFunctionInfo(NamedTuple):
    initial_state: list[_StateValue]
    rest_param_name: str | None
    scope_arg: Expression
    machine_reads: tuple[JsIdentifier, ...]
    """
    The names the call of the wrapper reads the machine through: its callee, and the `runtime` it
    hands on where the design has one.
    """


@dataclass
class _SMRawAssignment:
    """
    A single unevaluated state variable assignment: `name op= rhs`, and the node that makes it.
    """
    name: str
    operator: str
    rhs: Expression
    node: JsAssignmentExpression
    index: Expression | None = None


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
class _SMGuardedTransition:
    """
    A transition behind jumps ahead of it, `if (c) { stores; break; }`, each in *guards* with its
    condition and its stores: at each arrival the first jump whose condition holds takes its
    stores, and with none, the block takes *assignments*. A condition is evaluated on the state
    alone, and one that does not evaluate refuses the machine.
    """
    guards: list[tuple[Expression, list[_SMRawAssignment]]]
    assignments: list[_SMRawAssignment]


@dataclass
class _SMExitTransition:
    """
    The state machine reaches the end state after this block.
    """
    pass


if TYPE_CHECKING:
    _SMTransition = (
        _SMLinearTransition | _SMConditionalTransition | _SMExitTransition | _SMGuardedTransition
    )


@dataclass
class _SMBlock:
    """
    A single state in the machine: payload statements plus a transition, and the constants the
    payload stores in routing slots before anything else runs (`_routing_stores`).
    """
    payload: list[Statement]
    transition: _SMTransition
    routing_stores: list[tuple[_SlotPath, _Value]] = field(default_factory=list)


@dataclass
class _MachineMatch:
    machine: JsFunctionNode
    machine_names: frozenset[str]
    design: _Design
    state_var_names: list[str]
    initial_state: list[_StateValue]
    end_state: int | float
    loop_sum: Expression
    switch_stmt: JsSwitchStatement
    switch_label: str | None
    scope_param_name: str | None
    arg_var_name: str | None
    flag: _Flag | None
    result_var: str | None
    machine_index: int
    scaffolding_end: int
    with_redirect_var: str | None = None
    routed: bool = False
    returns_value: bool = False
    guarded: bool = False
    scope_default_props: list[str] = field(default_factory=list)
    scope_default_inits: dict[str, Expression] = field(default_factory=dict)
    scope_prop_names: set[str] = field(default_factory=set)
    namespaces: set[str] = field(default_factory=set)
    namespace_homes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    undefined_reads: list[Expression] = field(default_factory=list)
    runtime_name: str | None = None
    initial_args: list[Expression] = field(default_factory=list)
    calls: _Calls | None = None
    call_index: int = -1

    @property
    def call_start(self) -> int:
        """
        The index of the first statement of the call site: the statement behind the machine, or
        one further down the same body where the machine is a declared function.
        """
        return self.machine_index + 1 if self.call_index < 0 else self.call_index

    def removed(self, body: list[Statement]) -> list[Statement]:
        """
        The statements of *body* the recovery removes: the machine and its call site.
        """
        return [body[self.machine_index], *body[self.call_start:self.scaffolding_end + 1]]

    @property
    def qualifies_namespaces(self) -> bool:
        """
        Whether this generator uses the with-redirect namespace-qualification path: a single scope
        default namespace together with a redirect variable. When false, bare identifiers inside the
        `with` are left unqualified.
        """
        return self.with_redirect_var is not None and len(self.scope_default_props) == 1


@dataclass
class _Env:
    """
    What a run of the machine reads when it picks the next case: the value of every state variable,
    that of each routing slot (`_routing_paths`) whose value is known, and the calls of the
    program's own functions the run may make (`_Calls`), where its design computes with them.
    """
    states: _StateEnv
    slots: _Slots = field(default_factory=dict)
    calls: _Calls | None = None

    def same_as(self, other: _Env) -> bool:
        """
        Whether *other* holds the same values under the same names (`_same_value`).
        """
        return (
            self.states.keys() == other.states.keys()
            and self.slots.keys() == other.slots.keys()
            and all(_same_value(value, other.states[name]) for name, value in self.states.items())
            and all(_same_value(value, other.slots[path]) for path, value in self.slots.items())
        )


def _to_number(value: _Value) -> float | None:
    """
    The number JavaScript converts *value* to, or `None` for a string or an array, whose conversion
    this does not model.
    """
    if isinstance(value, _Undefined):
        return math.nan
    if isinstance(value, (str, tuple)):
        return None
    return float(value)


def _is_truthy(value: _Value) -> bool:
    if isinstance(value, _Undefined):
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, tuple):
        return True
    if isinstance(value, str):
        return bool(value)
    return not (value == 0 or math.isnan(value))


def _strictly_equal(a: _Value, b: _Value) -> bool | None:
    """
    JavaScript's `===` on the values a case test can make: a boolean is never a number, and an array
    is never a primitive. Two arrays are equal only where they are one object, which the values do
    not say: `None`.
    """
    if isinstance(a, tuple) and isinstance(b, tuple):
        return None
    if isinstance(a, (bool, _Undefined, tuple)) or isinstance(b, (bool, _Undefined, tuple)):
        return a is b
    if isinstance(a, str) or isinstance(b, str):
        return type(a) is type(b) and a == b
    return a == b


def _value_key(value: _Value) -> tuple[object, ...]:
    """
    A key under which two values the machine reads are one exactly where JavaScript's SameValue
    holds of them: `===`, except that it tells `-0` from `0`, which a block reading the value would
    print or divide by differently, and that `NaN` is itself. Two arrays of the state are one where
    their elements are, since the machine's state is what they hold and not which object holds it.
    """
    if isinstance(value, tuple):
        return ('array', *map(_value_key, value))
    if isinstance(value, _Undefined):
        return ('undefined',)
    if isinstance(value, bool):
        return ('boolean', value)
    if isinstance(value, str):
        return ('string', value)
    if math.isnan(value):
        return ('number', 'NaN')
    return ('number', value, is_negative_zero(value))


def _same_value(a: _Value, b: _Value) -> bool:
    """
    Whether *a* and *b* are one value of the machine (`_value_key`).
    """
    return _value_key(a) == _value_key(b)


def _finite_number(value: _Value | None) -> float | None:
    """
    The value where it is a finite number, the only value a state variable holds, or `None`.
    """
    if isinstance(value, (bool, _Undefined, str, tuple)) or value is None:
        return None
    if not math.isfinite(value):
        return None
    return value


def _loosely_equal(a: _Value, b: _Value) -> bool | None:
    """
    JavaScript's `==` on the values a case test can make: `undefined` equals only itself here, and a
    boolean compares as the number it converts to.
    """
    if isinstance(a, _Undefined) or isinstance(b, _Undefined):
        return a is b
    if (x := _to_number(a)) is None or (y := _to_number(b)) is None:
        return None
    return x == y


def _element(array: tuple[float, ...], key: _Value | None) -> _Value | None:
    """
    The element of a state array under *key*, where the key is the index of one.
    """
    if (index := _finite_number(key)) is None or not index.is_integer():
        return None
    if not 0 <= index < len(array):
        return None
    return array[int(index)]


def _eval_expr(node: Node | None, env: _Env) -> _Value | None:
    """
    Evaluate an expression of numbers, state variables and routing slots the way JavaScript does,
    or give `None` where it reads anything else or applies an operator this does not know. A
    comparison makes a boolean, which stays one, and arithmetic on `undefined` makes `NaN`.

    A state variable may hold an array of numbers. An element of one is read at an index that
    evaluates and lies in range, and an array literal is built of numbers and of spreads of arrays
    where arrays iterate as built at the spread (`_Calls.iterates_arrays`). A call with an argument
    that reads the state is run by the shared admission (`_Calls`), which may give a string or an
    array as well; a call that reads no state is the function evaluator's to fold.
    """
    node = strip_parens(node)
    if isinstance(node, JsNumericLiteral):
        return node.value
    if isinstance(node, JsIdentifier):
        return env.states.get(node.name)
    if isinstance(node, JsMemberExpression):
        holder = node.object
        if isinstance(holder, JsIdentifier) and isinstance(array := env.states.get(holder.name), tuple):
            if not node.computed or node.property is None:
                return None
            return _element(array, _eval_expr(node.property, env))
        path = _slot_path(node)
        return None if path is None else env.slots.get(path)
    if isinstance(node, JsArrayExpression):
        items: list[float] = []
        for element in node.elements:
            if element is None:
                return None
            if isinstance(element, JsSpreadElement):
                if element.argument is None or env.calls is None:
                    return None
                spread = _eval_expr(element.argument, env)
                if not isinstance(spread, tuple) or not env.calls.iterates_arrays(element):
                    return None
                items.extend(spread)
            elif (number := _finite_number(_eval_expr(element, env))) is None:
                return None
            else:
                items.append(number)
        return tuple(items)
    if (
        isinstance(node, JsCallExpression)
        and env.calls is not None
        and any(_reads_the_state(argument, env) for argument in node.arguments)
    ):
        arguments: list[_Value] = []
        for argument in node.arguments:
            if isinstance(argument, JsSpreadElement):
                return None
            if (value := _eval_expr(argument, env)) is None:
                return None
            arguments.append(value)
        return env.calls(node, arguments)
    if isinstance(node, JsUnaryExpression) and node.prefix and node.operand is not None:
        if node.operator in ('-', '+', '!'):
            operand = _eval_expr(node.operand, env)
            if operand is None:
                return None
            if node.operator == '!':
                return not _is_truthy(operand)
            if (number := _to_number(operand)) is None:
                return None
            return -number if node.operator == '-' else number
    if isinstance(node, JsLogicalExpression) and node.left is not None and node.right is not None:
        if node.operator in ('&&', '||'):
            lhs = _eval_expr(node.left, env)
            if lhs is None:
                return None
            if _is_truthy(lhs) == (node.operator == '||'):
                return lhs
            return _eval_expr(node.right, env)
    if isinstance(node, JsBinaryExpression) and node.left is not None and node.right is not None:
        lhs = _eval_expr(node.left, env)
        rhs = _eval_expr(node.right, env)
        if lhs is None or rhs is None:
            return None
        if node.operator in ('===', '!=='):
            if (equal := _strictly_equal(lhs, rhs)) is None:
                return None
            return equal == (node.operator == '===')
        if node.operator in ('==', '!='):
            if (equal := _loosely_equal(lhs, rhs)) is None:
                return None
            return equal == (node.operator == '==')
        if (x := _to_number(lhs)) is None or (y := _to_number(rhs)) is None:
            return None
        return eval_binary_op(node.operator, x, y)
    return None


def _reads_the_state(node: Node, env: _Env) -> bool:
    """
    Whether *node* reads a state variable of *env* outside a nested function.
    """
    if isinstance(node, FUNCTION_NODES):
        return False
    if isinstance(node, JsIdentifier):
        return node.name in env.states and is_reference(node)
    return any(_reads_the_state(child, env) for child in node.children())


def _eval_number(node: Expression) -> float | None:
    """
    The finite number *node* spells without reading anything, or `None`.
    """
    return _finite_number(_eval_expr(node, _Env({})))


def _slot_path(node: Expression) -> _SlotPath | None:
    """
    The names along a chain of property accesses under static keys, starting with the variable it
    starts from: `scope.M["p"]` gives `('scope', 'M', 'p')`. Any other expression gives `None`.
    """
    parts: list[str] = []
    cursor: Expression | None = node
    while isinstance(cursor, JsMemberExpression):
        if (key := access_key(cursor)) is None:
            return None
        parts.append(key)
        cursor = cursor.object
    if not parts or not isinstance(cursor, JsIdentifier):
        return None
    parts.append(cursor.name)
    parts.reverse()
    return tuple(parts)


def _is_discriminant_sum(node: Expression, var_names: list[str]) -> bool:
    """
    Check whether an expression is the sum of the given state variable identifiers.
    """
    collected: list[str] = []
    return _collect_sum_idents(node, collected) and sorted(collected) == sorted(var_names)


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
    Whether evaluating *node* does nothing but make its value, and the value holds nothing but data:
    a literal, a function, or an object or array literal of such values. The recovery declares a
    namespace only where the recovered code still refers to it, which drops the evaluation of an
    initializer nothing refers to, and it reads a store to a member of a namespace as a store of
    data: a getter or setter would run code on a later access instead, and a `__proto__` key gives
    the object a prototype rather than a property.
    """
    if isinstance(node, JsObjectExpression):
        return not object_member_access_runs_accessor(node) and all(
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
    machine_names: frozenset[str],
    num_state_vars: int,
) -> JsObjectExpression | None:
    """
    If *node* is a call of the generator under one of *machine_names*,

        generator(states…, scopeObj, …)

    whose argument at the scope position (index *num_state_vars*) is an object literal, return that
    object literal. This is the structural scope argument threaded through the shared generator by
    its wrapper functions.
    """
    if not isinstance(node, JsCallExpression):
        return None
    if not isinstance(node.callee, JsIdentifier) or node.callee.name not in machine_names:
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
    machine_names: frozenset[str],
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
        scope_arg = _scope_arg_object(node, machine_names, num_state_vars)
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


def _match_generator_cff(body: list[Statement], idx: int, design: _Design) -> _MachineMatch | None:
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
    if (held := _held_generator(body[idx])) is None:
        return None
    stmt, holder = held
    if not is_generator_function(stmt) or is_async_function(stmt):
        return None
    gen_name = holder.name
    gen_names = frozenset({gen_name, *_own_name(stmt)})
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
    loop_sum: Expression = lhs
    if _is_discriminant_sum(lhs, state_var_names):
        end_state = _eval_number(rhs)
    elif _is_discriminant_sum(rhs, state_var_names):
        end_state = _eval_number(lhs)
        loop_sum = rhs
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
    call_info = _find_generator_call_site(body, idx, gen_name)
    if call_info is None:
        return None
    if len(call_info.initial_state) != len(state_var_names):
        return None
    flag = call_info.flag
    if not routed or flag is not None:
        slots = _scope_slots(switch_stmt, scope_param_name, scope_default_props)
        if not routed and _spells_a_slot_bare(switch_stmt, slots):
            return None
        if flag is not None and flag.base in slots:
            return None
    namespaces: set[str] = set()
    namespace_homes: dict[str, tuple[str, ...]] = {}
    if with_redirect_var is not None and len(scope_default_props) == 1:
        collected = _collect_namespaces(
            switch_stmt,
            scope_param_name,
            scope_default_props,
            with_redirect_var,
            gen_names,
            len(state_var_names),
        )
        if collected is None:
            return None
        namespaces = collected
        homes = _collect_namespace_homes(switch_stmt, scope_param_name, namespaces)
        if homes is None:
            return None
        namespace_homes = homes
    if flag is not None and (flag.base in namespaces or flag.base in namespace_homes):
        return None
    return _MachineMatch(
        machine=stmt,
        machine_names=gen_names,
        design=design,
        state_var_names=state_var_names,
        initial_state=call_info.initial_state,
        end_state=end_state,
        loop_sum=loop_sum,
        switch_stmt=switch_stmt,
        switch_label=switch_label,
        scope_param_name=scope_param_name,
        arg_var_name=arg_var_name,
        flag=call_info.flag,
        result_var=call_info.result_var,
        undefined_reads=call_info.undefined_reads,
        machine_index=idx,
        scaffolding_end=call_info.scaffolding_end,
        with_redirect_var=with_redirect_var,
        routed=routed,
        returns_value=call_info.returns_value,
        guarded=call_info.guarded,
        scope_default_props=scope_default_props,
        scope_default_inits=scope_default_inits,
        namespaces=namespaces,
        namespace_homes=namespace_homes,
    )


def _state_sum_call(node: Expression | None, states: str) -> JsCallExpression | None:
    """
    The call `f(states)` of a function under a name with the state array as its one argument.
    """
    if (
        isinstance(node, JsCallExpression)
        and isinstance(node.callee, JsIdentifier)
        and len(node.arguments) == 1
        and isinstance(argument := node.arguments[0], JsIdentifier)
        and argument.name == states
    ):
        return node
    return None


def _match_array_machine(body: list[Statement], idx: int, design: _Design) -> _MachineMatch | None:
    """
    Starting at index *idx* in *body*, test whether the statement is the machine of the design
    whose state is one array of numbers, summed by a function of the program, with its call site
    following:

        function M(states, scope = {…}, runtime, arg) {
          while (sum(states) !== END) { L: switch (sum(states)) { … } }
        }
        M([…]);

    The machine is a plain function, declared or stored to a variable, and a `return` of
    `undefined` may stand behind its loop. A declared machine may be called further down the same
    body, as the recovery of an outer machine writes it; the statements between stay where they
    are. Its call hands it one array, which the design reads
    once the match is decided on (`_ArrayDesign.read_start`). Whether the code of the machine reads
    what its invocation binds, and whether it holds a function declared in a block of strict code,
    are asked of the whole function, and only once its shape matched.
    """
    if (held := _held_generator(body[idx])) is None:
        return None
    stmt, holder = held
    if is_generator_function(stmt) or is_async_function(stmt) or stmt.body is None:
        return None
    name = holder.name
    names = frozenset({name, *_own_name(stmt)})
    params = stmt.params
    if not 3 <= len(params) <= 4:
        return None
    states, scope, runtime, *rest = params
    if not isinstance(states, JsIdentifier) or not isinstance(runtime, JsIdentifier):
        return None
    if not isinstance(scope, JsAssignmentPattern) or not isinstance(scope.left, JsIdentifier):
        return None
    arg_var_name: str | None = None
    if rest:
        if not isinstance(rest[0], JsIdentifier):
            return None
        arg_var_name = rest[0].name
    scope_param_name = scope.left.name
    code = stmt.body.body
    implicit_reads: list[Expression] = []
    if len(code) == 2 and (implicit := _is_implicit_return(code[1])) is not None:
        implicit_reads = implicit
        code = code[:1]
    if len(code) != 1 or not isinstance(while_stmt := code[0], JsWhileStatement):
        return None
    test = while_stmt.test
    if not isinstance(test, JsBinaryExpression) or test.operator != '!==':
        return None
    if (loop_sum := _state_sum_call(test.left, states.name)) is None:
        return None
    if test.right is None or (end_state := _eval_number(test.right)) is None:
        return None
    inner: Statement | None = while_stmt.body
    if isinstance(inner, JsBlockStatement) and len(inner.body) == 1:
        inner = inner.body[0]
    switch_label: str | None = None
    if isinstance(inner, JsLabeledStatement):
        if inner.label is not None:
            switch_label = inner.label.name
        inner = inner.body
    if not isinstance(inner, JsSwitchStatement):
        return None
    discriminant = _state_sum_call(inner.discriminant, states.name)
    if discriminant is None or not isinstance(discriminant.callee, JsIdentifier):
        return None
    assert isinstance(loop_sum.callee, JsIdentifier)
    if discriminant.callee.name != loop_sum.callee.name:
        return None
    if (scope_defaults := _extract_scope_default_props(params, scope.left.name)) is None:
        return None
    if _reads_its_own_invocation(stmt):
        return None
    if strict_mode_at(stmt) and _holds_a_block_function(stmt.body):
        return None
    scope_default_props, scope_default_inits = scope_defaults
    call_info = _find_generator_call_site(body, idx, name, plain=True)
    if call_info is None and isinstance(stmt, JsFunctionDeclaration):
        for start in range(idx + 2, len(body)):
            if (call_info := _find_generator_call_site(body, idx, name, True, start)) is not None:
                break
    if call_info is None or len(call_info.initial_args) != 1:
        return None
    slots = _scope_slots(inner, scope_param_name, scope_default_props)
    if _spells_a_slot_bare(inner, slots):
        return None
    flag = call_info.flag
    if flag is not None and flag.base in slots:
        return None
    return _MachineMatch(
        machine=stmt,
        machine_names=names,
        design=design,
        state_var_names=[states.name],
        initial_state=[],
        end_state=end_state,
        loop_sum=loop_sum,
        switch_stmt=inner,
        switch_label=switch_label,
        scope_param_name=scope_param_name,
        arg_var_name=arg_var_name,
        flag=flag,
        result_var=call_info.result_var,
        undefined_reads=call_info.undefined_reads + implicit_reads,
        machine_index=idx,
        scaffolding_end=call_info.scaffolding_end,
        returns_value=call_info.returns_value,
        guarded=call_info.guarded,
        scope_default_props=scope_default_props,
        scope_default_inits=scope_default_inits,
        runtime_name=runtime.name,
        initial_args=call_info.initial_args,
        call_index=call_info.call_index,
    )


def _held_generator(
    stmt: Statement,
) -> tuple[JsFunctionDeclaration | JsFunctionExpression, JsIdentifier] | None:
    """
    The function *stmt* binds to a name, with that name: a function declaration, or the store of
    a function expression to a variable, as the recovery of a machine around this one writes the
    declaration of a generator in the function it recovers.
    """
    if isinstance(stmt, JsFunctionDeclaration):
        return None if stmt.id is None else (stmt, stmt.id)
    if not isinstance(stmt, JsExpressionStatement):
        return None
    store = stmt.expression
    if (
        isinstance(store, JsAssignmentExpression)
        and store.operator == '='
        and isinstance(store.left, JsIdentifier)
        and isinstance(store.right, JsFunctionExpression)
    ):
        return store.right, store.left
    return None


def _own_name(generator: JsFunctionNode) -> tuple[str, ...]:
    """
    The name a function expression binds for its own code, which the wrappers of a generator held
    by a variable call it by, or nothing.
    """
    if isinstance(generator, JsFunctionExpression) and generator.id is not None:
        return (generator.id.name,)
    return ()


def _reads_its_own_invocation(generator: JsFunctionNode) -> bool:
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


def _scope_slots(
    switch_stmt: JsSwitchStatement,
    scope_param_name: str | None,
    defaults: list[str],
) -> set[str]:
    """
    The names of the slots of a generator's scope object: its defaults and every key its code reads
    or writes on it.
    """
    slots = set(defaults)
    if scope_param_name is not None:
        for member in _scope_members(switch_stmt, scope_param_name):
            if (name := _deepest_property_name(member)) is not None:
                slots.add(name)
    return slots


def _spells_a_slot_bare(switch_stmt: JsSwitchStatement, slots: set[str]) -> bool:
    """
    Whether the code of a generator that reads its scope object through no `with` body spells the
    name of one of its *slots* bare (`_scope_slots`). There the bare name means some other binding,
    and once the strip turns `scope.K` into `K` it would name the slot instead.
    """
    return any(
        isinstance(node, JsIdentifier) and node.name in slots and is_use_position(node)
        for node in switch_stmt.walk()
    )


def _spells_an_inherited_name_bare(
    switch_stmt: JsSwitchStatement,
    absent: Callable[[str], bool],
) -> bool:
    """
    Whether the code of a generator that reads its scope object through a `with` body spells bare a
    name that *absent* cannot prove missing from a plain object, such as `toString`, which every
    object inherits. The `with` statement finds that name on its object before the binding of the
    code around it, and the recovery removes the `with` statement.
    """
    names = {
        node.name for node in switch_stmt.walk()
        if isinstance(node, JsIdentifier) and is_use_position(node)
    }
    inherited = frozenset(name for name in names if not absent(name))
    return bool(inherited) and any(
        isinstance(node, JsIdentifier)
        and node.name in inherited
        and node.name not in shadowed
        and is_use_position(node)
        for node, shadowed in _walk_scoped(switch_stmt, inherited)
    )


def _slots_may_become_variables(
    match: _MachineMatch,
    activations: list[_Activation],
    absent: Callable[[str], bool],
) -> bool:
    """
    Whether every slot the runs of *match* keep on a scope object may become a variable of its own
    name, as the strip makes it (`_strip_scope_param_prefix`): the slots of its main run
    (`scope_prop_names`) and of the runs of its wrappers (*activations*). No prototype of a plain
    object may supply the name (*absent*), as one supplies `constructor`, where a read of a slot no
    run stored finds it; and where the code reads its scope object through no `with` body, it may
    spell none of them bare (`_spells_a_slot_bare`). A key a run decodes from its state
    (`_fold_scope_keys`) names a slot only the run shows.
    """
    names = set(match.scope_prop_names).union(*(activation.props for activation in activations))
    if not all(absent(name) for name in names):
        return False
    return match.routed or not _spells_a_slot_bare(match.switch_stmt, names)


def _block_functions(root: Node) -> Iterator[JsFunctionDeclaration]:
    """
    Every function declared inside a block anywhere below *root*, where sloppy code would copy its
    name into the function around the block.
    """
    for node in root.walk():
        if not isinstance(node, JsFunctionDeclaration):
            continue
        holder = node.parent
        if isinstance(holder, JsScript):
            continue
        if isinstance(holder, JsBlockStatement) and isinstance(holder.parent, FUNCTION_NODES):
            continue
        yield node


def _holds_a_block_function(root: Node) -> bool:
    """
    Whether a function is declared inside a block anywhere below *root* (`_block_functions`).
    """
    return next(_block_functions(root), None) is not None


def _an_observed_copy_may_not_be_made(model: SemanticModel, generator: Node) -> bool:
    """
    Whether *generator* may run as strict code, which makes no Annex B copy, and declares a function
    in a block whose copy something observes. The recovered code is read apart from the tree and
    gives such a function the copy (`_hoisted_names`), which the file may then never have made.

    An ES module makes no copy in any reading, so the model holds none to ask about, and any
    function declared in a block of the generator counts, as it does for code the text makes strict
    (`_match_generator_cff`).
    """
    if not model.may_run_as_strict(generator):
        return False
    if model.file_kind is FileKind.es_module:
        return _holds_a_block_function(generator)
    return any(model.annex_b_copy_observed(function) for function in _block_functions(generator))


def _flag_spelled(node: Expression | None) -> _Flag | None:
    """
    The flag *node* spells: a name, or a property of a variable under a static key
    (`_FlagProperty`).
    """
    if node is None:
        return None
    if isinstance(node, JsIdentifier):
        return _FlagVariable(node.name)
    if (path := _slot_path(node)) is not None and len(path) == 2:
        return _FlagProperty(*path)
    return None


def _spells_undefined(node: Expression | None) -> list[Expression] | None:
    """
    The names the recovery has to find unbound for *node* to spell `undefined`, or `None` where it
    does not: none for `void` of a number, which means it wherever it stands, and the name itself
    for `undefined`.
    """
    if (
        isinstance(node, JsUnaryExpression)
        and node.operator == 'void'
        and isinstance(node.operand, JsNumericLiteral)
    ):
        return []
    if isinstance(node, JsIdentifier) and node.name == 'undefined':
        return [node]
    return None


def _did_return_reset(stmt: Statement) -> tuple[_Flag, list[Expression]] | None:
    """
    The flag *stmt* resets ahead of the generator's call, as `var didReturn;` or as a store of
    `undefined` to it (`_spells_undefined`), with the names that store relies on, or `None`.
    """
    if isinstance(stmt, JsVariableDeclaration):
        decls = stmt.declarations
        if (
            len(decls) == 1
            and isinstance(decls[0], JsVariableDeclarator)
            and isinstance(decls[0].id, JsIdentifier)
            and decls[0].init is None
        ):
            return _FlagVariable(decls[0].id.name), []
    if isinstance(stmt, JsExpressionStatement):
        expr = stmt.expression
        if (
            isinstance(expr, JsAssignmentExpression)
            and expr.operator == '='
            and (flag := _flag_spelled(expr.left)) is not None
            and (reads := _spells_undefined(expr.right)) is not None
        ):
            return flag, reads
    return None


def _is_result_guard(
    stmt: Statement,
    flag: _Flag,
    result_var: str,
    ends: bool,
) -> list[Expression] | None:
    """
    The names spelling `undefined` that *stmt* relies on where it is the guard

        if (didReturn) { return result; }

    and nothing more, or `None` where it is not. Where it *ends* the body of a function, its `else`
    may hold the return of `undefined` that ends that body (`_is_implicit_return`).
    """
    if not isinstance(stmt, JsIfStatement) or not flag.spelled_by(stmt.test):
        return None
    reads: list[Expression] = []
    if (otherwise := stmt.alternate) is not None:
        if isinstance(otherwise, JsBlockStatement) and len(otherwise.body) == 1:
            otherwise = otherwise.body[0]
        if not ends or (implicit := _is_implicit_return(otherwise)) is None:
            return None
        reads = implicit
    consequent = stmt.consequent
    if isinstance(consequent, JsBlockStatement) and len(consequent.body) == 1:
        consequent = consequent.body[0]
    if not (
        isinstance(consequent, JsReturnStatement)
        and isinstance(consequent.argument, JsIdentifier)
        and consequent.argument.name == result_var
    ):
        return None
    return reads


def _is_implicit_return(stmt: Statement | None) -> list[Expression] | None:
    """
    The names spelling `undefined` that *stmt* relies on where it returns `undefined`, as the
    obfuscator ends the body of every function whose code it puts into the machine of the function
    around it, or `None`: that body ends in the call of its own machine, and the recovery of the
    machine around it writes the return behind the guard or as its `else`.
    """
    if not isinstance(stmt, JsReturnStatement):
        return None
    if stmt.argument is None:
        return []
    return _spells_undefined(stmt.argument)


def _find_generator_call_site(
    body: list[Statement],
    gen_idx: int,
    gen_name: str,
    plain: bool = False,
    start: int | None = None,
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
    keeps the recovery from going ahead (`_scaffolding_is_private`). Where *plain*, the call is the
    plain call `M(array)` of a machine that is no generator, and *start* is the index the call site
    begins at where it does not stand right behind the machine. Returns a `_CallSiteInfo` or
    `None`.
    """
    pos = gen_idx + 1 if start is None else start
    call_index = pos
    undefined_reads: list[Expression] = []
    flag: _Flag | None = None
    if pos < len(body) and (reset := _did_return_reset(body[pos])) is not None:
        flag, undefined_reads = reset
        pos += 1
    if pos >= len(body):
        return None
    call_expr = _extract_generator_call(body[pos], gen_name, plain)
    if call_expr is None:
        return None
    call_node, result_var = call_expr
    initial_state: list[_StateValue] = []
    if not plain:
        for arg in call_node.arguments:
            val = _eval_number(arg)
            if val is None:
                return None
            initial_state.append(val)
    scaffolding_end = pos
    ends_a_function = (owner := body[gen_idx].parent) is not None and _is_a_function_body(owner)
    guard_reads = None
    if flag is not None and result_var is not None and scaffolding_end + 1 < len(body):
        guard_reads = _is_result_guard(
            body[scaffolding_end + 1],
            flag,
            result_var,
            ends_a_function and scaffolding_end + 2 == len(body),
        )
    guarded = guard_reads is not None
    if guard_reads is not None:
        undefined_reads.extend(guard_reads)
        scaffolding_end += 1
        if (
            ends_a_function
            and scaffolding_end + 2 == len(body)
            and (implicit := _is_implicit_return(body[-1])) is not None
        ):
            undefined_reads.extend(implicit)
            scaffolding_end += 1
    return _CallSiteInfo(
        initial_state,
        flag,
        result_var,
        scaffolding_end,
        isinstance(body[pos], JsReturnStatement),
        guarded,
        undefined_reads,
        list(call_node.arguments),
        call_index,
    )


class _GeneratorCallInfo(NamedTuple):
    call_node: JsCallExpression
    result_var: str | None


def _extract_generator_call(
    stmt: Statement,
    gen_name: str,
    plain: bool = False,
) -> _GeneratorCallInfo | None:
    """
    Extract a generator call from a statement. Handles:
    - var X = gen(...)["next"]()["value"];
    - X = gen(...)["next"]()["value"];
    - gen(...)["next"]()["value"];
    - return gen(...)["next"]()["value"];

    Where *plain*, the call is `gen(...)` itself. Returns a `(call, name)` pair (the inner call to
    gen and the result variable name) or `None`. A result stored anywhere but in a plain name is
    refused: the recovery would drop the store.
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
    gen_call = (expr if isinstance(expr, JsCallExpression) else None) if plain else _unwrap_next_value(expr)
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
    gen_names: frozenset[str],
    num_state_vars: int,
) -> _WrapperFunctionInfo | None:
    """
    Test whether *node* is a wrapper function expression of the form:

        function(...rest) { return gen(states..., scope, rest)["next"]()["value"]; }

    where `gen` is one of the names the generator is called by, *gen_names*.

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
    if gen_call.callee.name not in gen_names:
        return None
    args = gen_call.arguments
    if len(args) < num_state_vars + 1:
        return None
    initial_state: list[_StateValue] = []
    for arg in args[:num_state_vars]:
        val = _eval_number(arg)
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
    return _WrapperFunctionInfo(
        initial_state, rest_param_name, args[num_state_vars], (gen_call.callee,)
    )


def _plain_wrapper_call(node: JsFunctionExpression, match: _MachineMatch) -> JsCallExpression | None:
    """
    The call `M(states, scope, runtime, rest)` a wrapper of the machine of *match* returns where
    that is its whole body and it hands on the machine's own `runtime`, the design whose state is
    one array.
    """
    if node.body is None:
        return None
    body = node.body.body
    if len(body) != 1 or not isinstance(stmt := body[0], JsReturnStatement):
        return None
    call = stmt.argument
    if (
        not isinstance(call, JsCallExpression)
        or not isinstance(call.callee, JsIdentifier)
        or call.callee.name not in match.machine_names
        or len(call.arguments) != 4
    ):
        return None
    runtime = call.arguments[2]
    if not isinstance(runtime, JsIdentifier) or runtime.name != match.runtime_name:
        return None
    return call


def _detect_plain_wrapper(
    node: Expression,
    match: _MachineMatch,
) -> _WrapperFunctionInfo | None:
    """
    The wrapper `function (...rest) { return M(states, scope, runtime, rest); }` of the machine of
    *match*, the design whose state is one array. Its start state is read from numbers alone: a
    start state the run computes was put in its place as an array literal by the run that made the
    wrapper (`_fold_scope_keys`).
    """
    if not isinstance(node, JsFunctionExpression) or (call := _plain_wrapper_call(node, match)) is None:
        return None
    states, scope_arg, runtime, handed = call.arguments
    entry = _eval_expr(states, _Env({}))
    if not isinstance(entry, tuple):
        return None
    params = node.params
    if len(params) != 1 or not isinstance(rest := params[0], JsRestElement):
        return None
    if not isinstance(rest.argument, JsIdentifier):
        return None
    if not isinstance(handed, JsIdentifier) or handed.name != rest.argument.name:
        return None
    assert isinstance(call.callee, JsIdentifier) and isinstance(runtime, JsIdentifier)
    return _WrapperFunctionInfo([entry], rest.argument.name, scope_arg, (call.callee, runtime))


@dataclass
class _SMCase:
    """
    A label of the switch: its test, or `None` for `default`, and the block a match runs, which is
    that of the first body at or behind the label. The block is `None` where that body is not one
    the recovery reads, or where no body follows and a match would leave the switch unchanged.
    """
    test: Expression | None
    block: _SMBlock | None


@dataclass
class _StateMachine:
    """
    The labels of the switch in source order, the routing slots their tests read, the switch
    discriminant, the sum of the state variables the loop compares with the *end_state*, and the
    blocks of the bodies that declare a name, `None` for one the recovery cannot read. The labels
    whose test reads nothing are indexed by the value that test makes (`_dispatch`).
    """
    cases: list[_SMCase]
    routing: frozenset[_SlotPath]
    discriminant: Expression
    loop_sum: Expression
    end_state: float
    declaring: list[_SMBlock | None]
    constants: dict[float, int] = field(init=False, default_factory=dict)
    variables: list[int] = field(init=False, default_factory=list)

    def __post_init__(self):
        for index, case in enumerate(self.cases):
            if case.test is None:
                continue
            if (value := _eval_expr(case.test, _Env({}))) is None:
                self.variables.append(index)
            elif (number := _finite_number(value)) is not None:
                self.constants.setdefault(number, index)

    @property
    def default(self) -> _SMBlock | None:
        """
        The block the `default` label runs, or `None` where there is none or it runs no block the
        recovery reads.
        """
        for case in self.cases:
            if case.test is None:
                return case.block
        return None


def _extract_state_blocks(
    match: _MachineMatch,
    absent: Callable[[str], bool],
) -> _StateMachine | None:
    """
    Read the labels of the switch in source order, each with the block it runs (`_read_block`)
    from the statements of its body that can run on the graph of the generator. A case body that
    declares a state variable's name for the block of the switch gives `None`: that declaration
    takes the name in every case, test and transition alike.
    """
    cases: list[JsSwitchCase] = []
    for case in match.switch_stmt.cases:
        if not isinstance(case, JsSwitchCase):
            return None
        cases.append(case)
    declared = _block_bound_names([stmt for case in cases for stmt in case.body])
    if not declared.isdisjoint(match.state_var_names):
        return None
    routing = _routing_paths(cases, frozenset(match.state_var_names))
    flow = DominatorModel(ControlFlowModel({id(match.machine): build_cfg(match.machine)}))
    last_body = max((i for i, case in enumerate(cases) if case.body), default=-1)
    labels: list[_SMCase] = []
    pending: list[Expression | None] = []
    declaring: list[_SMBlock | None] = []
    for index, case in enumerate(cases):
        pending.append(case.test)
        if not case.body:
            continue
        block = _read_block(case.body, flow, match, routing, index == last_body, absent)
        labels.extend(_SMCase(test, block) for test in pending)
        pending.clear()
        if _declared_names_in_stmts(case.body):
            declaring.append(block)
    labels.extend(_SMCase(test, None) for test in pending)
    discriminant = match.switch_stmt.discriminant
    assert discriminant is not None
    return _StateMachine(
        labels, routing, discriminant, match.loop_sum, match.end_state, declaring
    )


def _routing_paths(cases: list[JsSwitchCase], states: frozenset[str] = frozenset()) -> frozenset[_SlotPath]:
    """
    The routing slots of a switch: every property a case test reads along a chain of static keys
    (`_slot_path`).
    """
    paths: set[_SlotPath] = set()
    for case in cases:
        if case.test is None:
            continue
        for node in case.test.walk():
            if not isinstance(node, JsMemberExpression):
                continue
            if isinstance(node.parent, JsMemberExpression) and node.parent.object is node:
                continue
            if (path := _slot_path(node)) is not None and path[0] not in states:
                paths.add(path)
    return frozenset(paths)


class _RunningBody(NamedTuple):
    """
    The statements of a case body that can run, and whether control never runs off the end of the
    last of them (`closed`).
    """
    statements: list[Statement]
    closed: bool


def _running_statements(stmts: list[Statement], flow: DominatorModel) -> _RunningBody | None:
    """
    The statements of a case body that can run, as the shared control-flow model of the generator
    answers it (`refinery.lib.scripts.analysis.dominance.DominatorModel.never_runs`): the
    obfuscator leaves the transition of a block behind a `return` and puts jumps it never takes
    behind a transition. A statement that never runs declares its names all the same, so a body
    where one declares a name gives `None`. Whether control runs off the end of the body is the same
    model's answer (`refinery.lib.scripts.analysis.dominance.DominatorModel.completes`).
    """
    runs: list[Statement] = []
    dead: list[Statement] = []
    for stmt in stmts:
        (dead if flow.never_runs(stmt) else runs).append(stmt)
    if dead and _declared_names_in_stmts(dead):
        return None
    return _RunningBody(runs, bool(runs) and not flow.completes(runs[-1]))


def _read_block(
    stmts: list[Statement],
    flow: DominatorModel,
    match: _MachineMatch,
    routing: frozenset[_SlotPath],
    last: bool,
    absent: Callable[[str], bool],
) -> _SMBlock | None:
    """
    The block the statements of a case body that can run make (`_running_statements`, asked of
    *flow*; `_parse_case_body`) with the stores they make to routing slots (`_routing_stores`), or
    `None` where the recovery cannot read either.
    """
    if (body := _running_statements(stmts, flow)) is None:
        return None
    runs = body.statements
    parsed = _parse_case_body(runs, match.state_var_names, match.switch_label, last, body.closed)
    if parsed is None:
        return None
    stores = _routing_stores(runs, match.scope_param_name, routing, absent)
    if stores is None:
        return None
    payload, transition = parsed
    return _SMBlock(payload, transition, stores)


def _store_pairs(expr: Expression) -> list[tuple[Expression, Expression]] | None:
    """
    The pairs of target and value the plain assignment *expr* stores: the one pair of `t = v`, or
    one pair for each element where it destructures an array literal of as many values into names
    and members, as in `[t1, t2] = [v1, v2]`. A rest element, a default, a hole or a spread gives
    `None`, and so does any other expression. The destructuring runs the array iterator, which is
    trusted the way `_unpack_argument_stores` trusts it.
    """
    if (
        not isinstance(expr, JsAssignmentExpression)
        or expr.operator != '='
        or expr.left is None
        or expr.right is None
    ):
        return None
    if not isinstance(expr.left, JsArrayPattern):
        return [(expr.left, expr.right)]
    if (
        not isinstance(expr.right, JsArrayExpression)
        or len(expr.left.elements) != len(expr.right.elements)
    ):
        return None
    pairs: list[tuple[Expression, Expression]] = []
    for target, value in zip(expr.left.elements, expr.right.elements):
        if (
            not isinstance(target, (JsIdentifier, JsMemberExpression))
            or value is None
            or isinstance(value, JsSpreadElement)
        ):
            return None
        pairs.append((target, value))
    return pairs


def _data_stores(
    stmt: Statement,
    scope_param_name: str | None,
) -> list[tuple[JsMemberExpression, _SlotPath, Expression]] | None:
    """
    The stores where *stmt* does nothing but store values that hold data (`_is_inert`) under static
    keys of the scope object (`_store_pairs`), as in

        scope.M = {}, [scope.M.p, scope.M.q] = [85, -3];

    each with its target, the path of that target (`_slot_path`), and the value. Any other
    statement gives `None`.
    """
    if not isinstance(stmt, JsExpressionStatement) or stmt.expression is None:
        return None
    expr = stmt.expression
    stores: list[tuple[JsMemberExpression, _SlotPath, Expression]] = []
    for part in expr.expressions if isinstance(expr, JsSequenceExpression) else [expr]:
        if (pairs := _store_pairs(part)) is None:
            return None
        for target, value in pairs:
            if (
                not isinstance(target, JsMemberExpression)
                or (path := _slot_path(target)) is None
                or path[0] != scope_param_name
                or not _is_inert(value)
            ):
                return None
            stores.append((target, path, value))
    return stores


def _routing_stores(
    stmts: list[Statement],
    scope_param_name: str | None,
    routing: frozenset[_SlotPath],
    absent: Callable[[str], bool],
) -> list[tuple[_SlotPath, _Value]] | None:
    """
    The constants a case body stores in routing slots, in the order it stores them, or `None`
    where it stores them in a way the obfuscator does not. The obfuscator puts one store of all
    routing slots in front of the block the machine starts in,

        [scope.M.p, scope.M.q] = [85, -3];

    so every store to a routing slot has to stand among the statements that open the body and do
    nothing but store data (`_data_stores`), has to store a number, and has to store it under a key
    no prototype supplies (*absent*), where it makes a property of data. One of these statements
    may also store a new object where a routing slot's object was, as long as the ones behind it
    store every routing slot of that object again. Any other write of a routing slot or of an
    object that holds one gives `None` (`_writes_a_routing_slot`), including one in the code of a
    function these statements store.
    """
    if not routing:
        return []
    stores: list[tuple[_SlotPath, _Value]] = []
    handled: set[int] = set()
    replaced: set[_SlotPath] = set()
    for stmt in stmts:
        if (pairs := _data_stores(stmt, scope_param_name)) is None:
            break
        for target, path, value in pairs:
            if path in routing:
                if (number := _eval_number(value)) is None or not absent(path[-1]):
                    return None
                stores.append((path, number))
                replaced.discard(path)
            elif held := {slot for slot in routing if slot[:len(path)] == path}:
                replaced |= held
            else:
                continue
            handled.add(id(target))
    if replaced or _writes_a_routing_slot(stmts, routing, handled):
        return None
    return stores


def _writes_a_routing_slot(
    stmts: list[Statement],
    routing: frozenset[_SlotPath],
    handled: set[int],
) -> bool:
    """
    Whether *stmts* write a routing slot or an object along its path anywhere but at the targets
    whose ids *handled* holds: they store a property under any key along that path, a variable of
    such a name, which the `with` statement may resolve to the slot or its object, or a property
    under a key only known at runtime or under `__proto__` on an object of such a name. They may
    also declare such a variable.
    """
    names = {name for path in routing for name in path[1:]}
    holders = {name for path in routing for name in path[:-1]}
    for stmt in stmts:
        for node in stmt.walk():
            if isinstance(node, JsMemberExpression):
                if id(node) in handled or not is_member_write_target(node):
                    continue
                if (key := access_key(node)) in names:
                    return True
                if (key is None or key == '__proto__') and _holder_name(node.object) in holders:
                    return True
            elif isinstance(node, JsVariableDeclarator):
                declared: set[str] = set()
                _collect_binding_names(node.id, declared)
                if not names.isdisjoint(declared):
                    return True
            elif isinstance(node, JsIdentifier) and node.name in names and is_use_position(node):
                if is_member_write_target(node):
                    return True
                if (
                    isinstance(parent := node.parent, (JsFunctionDeclaration, JsClassDeclaration))
                    and parent.id is node
                ):
                    return True
    return False


def _holder_name(node: Expression | None) -> str | None:
    """
    The name an object is reached by: the key of the last access for a property, or the name of a
    variable.
    """
    if isinstance(node, JsMemberExpression):
        return access_key(node)
    if isinstance(node, JsIdentifier):
        return node.name
    return None


def _parse_case_body(
    stmts: list[Statement],
    var_names: list[str],
    switch_label: str | None,
    last: bool,
    closed: bool,
) -> tuple[list[Statement], _SMTransition] | None:
    """
    Separate the statements of a case body that run into payload statements and the state
    transition the obfuscator ends them with (`_split_case_body`). A body that stores a state
    variable anywhere but in its transition (`_writes_a_state_variable`), or whose payload leaves
    the switch or the loop of the machine (`_leaves_the_block`), gives `None`.
    """
    parsed = _split_case_body(stmts, var_names, switch_label, last, closed)
    if parsed is None:
        return None
    payload, transition = parsed
    if _writes_a_state_variable(stmts, var_names, _transition_assignments(transition)):
        return None
    if isinstance(transition, _SMConditionalTransition):
        payload = [*payload, *transition.true_prefix, *transition.false_prefix]
    if _leaves_the_block(payload):
        return None
    return parsed


def _split_case_body(
    stmts: list[Statement],
    var_names: list[str],
    switch_label: str | None,
    last: bool,
    closed: bool,
) -> tuple[list[Statement], _SMTransition] | None:
    """
    Separate the statements of a case body that run into payload statements and a state
    transition. A body that ends in a `return` or `throw` leaves the machine, and so does a *closed*
    one whose end control never reaches, such as one ending in a `switch` every case of which
    returns: nothing of it stores the next state. Any other body ends in the assignments of its
    transition, directly or in both branches of a final `if` statement, and then in a `break` of
    the switch, which only the *last* body may leave out: every other body runs on into the next
    one without it. A body with no transition, which would dispatch the same state again forever,
    gives `None`.
    """
    if stmts and isinstance(stmts[-1], (JsReturnStatement, JsThrowStatement)):
        return (stmts, _SMExitTransition())
    if (split := _split_transition_at_the_end(stmts, var_names, switch_label, last)) is not None:
        return split
    return (stmts, _SMExitTransition()) if closed else None


def _split_transition_at_the_end(
    stmts: list[Statement],
    var_names: list[str],
    switch_label: str | None,
    last: bool,
) -> tuple[list[Statement], _SMTransition] | None:
    """
    The payload of a case body and the transition it ends in (`_split_case_body`), or `None`.
    """
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
        guards: list[tuple[Expression, list[_SMRawAssignment]]] = []
        while payload and (guard := _state_guard(payload[-1], var_names, switch_label)) is not None:
            guards.insert(0, guard)
            payload = payload[:-1]
        if guards:
            transition = _SMGuardedTransition(guards, assignments)
        else:
            transition = _SMLinearTransition(assignments=assignments)
    else:
        return None
    if not terminated and not last:
        return None
    return (payload, transition)


def _state_guard(
    stmt: Statement,
    var_names: list[str],
    switch_label: str | None,
) -> tuple[Expression, list[_SMRawAssignment]] | None:
    """
    The condition and the stores of a jump `if (c) { stores; break; }` ahead of a transition, which
    leaves the block with its own stores where its condition holds. A jump without stores enters
    the same block again.
    """
    if (
        not isinstance(stmt, JsIfStatement)
        or stmt.alternate is not None
        or stmt.test is None
        or stmt.consequent is None
    ):
        return None
    inner, terminated = _strip_trailing_break(_block_stmts(stmt.consequent), switch_label)
    if not terminated:
        return None
    if not inner:
        return stmt.test, []
    if (split := _split_transition(inner, var_names)) is None:
        return None
    rest, assignments = split
    if rest:
        return None
    return stmt.test, assignments


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
        not isinstance(expr, JsAssignmentExpression)
        or expr.operator not in ('=', '+=')
        or expr.right is None
    ):
        return None
    target = expr.left
    if isinstance(target, JsIdentifier) and target.name in var_names:
        return _SMRawAssignment(target.name, expr.operator, expr.right, expr)
    if (
        isinstance(target, JsMemberExpression)
        and target.computed
        and isinstance(target.object, JsIdentifier)
        and target.object.name in var_names
        and target.property is not None
    ):
        return _SMRawAssignment(target.object.name, expr.operator, expr.right, expr, target.property)
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

    whose leading expressions stay behind, cloned into a statement of their own so that the tree
    the machine is read from keeps them. Returns `None` where the statements do not end in such an
    assignment.
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
            head = [_clone_node(part) for part in parts[:split]]
            leading = head[0] if split == 1 else JsSequenceExpression(expressions=head)
            return [*stmts[:index], JsExpressionStatement(expression=leading)], assignments
    if not assignments:
        return None
    return stmts[:index], assignments


def _transition_assignments(transition: _SMTransition) -> list[_SMRawAssignment]:
    """
    The assignments of a transition, of both branches where it has two.
    """
    if isinstance(transition, _SMLinearTransition):
        return transition.assignments
    if isinstance(transition, _SMConditionalTransition):
        return transition.true_assignments + transition.false_assignments
    if isinstance(transition, _SMGuardedTransition):
        return [a for _, guard in transition.guards for a in guard] + transition.assignments
    return []


def _writes_a_state_variable(
    stmts: list[Statement],
    var_names: list[str],
    transition: list[_SMRawAssignment],
) -> bool:
    """
    Whether *stmts* store to a state variable anywhere but in the assignments of the *transition*,
    or declare one, where nothing between them and the store binds its name anew. The recovery
    reads the state only from the transition that ends a block, and puts each state variable's
    value at entry in place of its every read.
    """
    watched = frozenset(var_names)
    allowed = {id(assignment.node) for assignment in transition}
    for stmt in stmts:
        for node, shadowed in _walk_scoped(stmt, watched):
            names = watched - shadowed
            if isinstance(node, JsVariableDeclarator):
                declared: set[str] = set()
                _collect_binding_names(node.id, declared)
                if not names.isdisjoint(declared):
                    return True
            elif isinstance(node, (JsFunctionDeclaration, JsClassDeclaration)):
                if node.id is not None and node.id.name in names:
                    return True
            elif (
                isinstance(node, JsIdentifier)
                and node.name in names
                and is_member_write_target(node)
                and id(node.parent) not in allowed
            ):
                return True
            elif (
                isinstance(node, JsMemberExpression)
                and isinstance(node.object, JsIdentifier)
                and node.object.name in names
                and is_member_write_target(node)
                and id(node.parent) not in allowed
            ):
                return True
    return False


def _leaves_the_block(stmts: list[Statement]) -> bool:
    """
    Whether *stmts* hold a `break` or `continue` that leaves them: one naming a label they do not
    declare, or one that no loop or `switch` among them takes. In a case body, it would leave the
    switch or the loop of the machine, neither of which the recovered code has.
    """
    stack: list[tuple[Node, frozenset[str], bool, bool]] = [
        (stmt, frozenset(), False, False) for stmt in stmts
    ]
    while stack:
        node, labels, breaks, continues = stack.pop()
        if isinstance(node, (JsBreakStatement, JsContinueStatement)):
            if node.label is not None:
                if node.label.name not in labels:
                    return True
            elif not (breaks if isinstance(node, JsBreakStatement) else continues):
                return True
            continue
        if isinstance(node, JsLabeledStatement) and node.label is not None:
            labels = labels | {node.label.name}
        if isinstance(node, LOOP_NODES):
            breaks = continues = True
        elif isinstance(node, JsSwitchStatement):
            breaks = True
        stack.extend(
            (child, labels, breaks, continues) for child in node.children()
            if isinstance(child, (Statement, JsSwitchCase, JsCatchClause))
            and not isinstance(child, (*FUNCTION_NODES, JsClassDeclaration))
        )
    return False


def _apply_raw_transition(assignments: list[_SMRawAssignment], current: _Env) -> _Env | None:
    """
    Evaluate the assignments of a transition in order, each seeing the results of those before it,
    and give what the machine reads after them, or `None` where a state variable would not hold a
    finite number.
    """
    states = dict(current.states)
    for assign in assignments:
        env = _Env(states, current.slots, current.calls)
        held = states.get(assign.name)
        index: int | None = None
        if assign.index is not None:
            if not isinstance(held, tuple):
                return None
            key = _finite_number(_eval_expr(assign.index, env))
            if key is None or not key.is_integer() or not 0 <= key < len(held):
                return None
            index = int(key)
            old = held[index]
        elif isinstance(held, tuple) or held is None:
            return None
        else:
            old = held
        value = _eval_expr(assign.rhs, env)
        if value is not None and assign.operator == '+=':
            if (addend := _to_number(value)) is None:
                return None
            value = eval_binary_op('+', old, addend)
        if (number := _finite_number(value)) is None:
            return None
        if index is None:
            states[assign.name] = number
        else:
            assert isinstance(held, tuple)
            states[assign.name] = (*held[:index], number, *held[index + 1:])
    return _Env(states, current.slots, current.calls)


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
    both branches then leave the switch with a `break`.
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
    transition = _SMConditionalTransition(
        condition=if_stmt.test,
        true_assignments=true_assigns,
        false_assignments=false_assigns,
        true_prefix=true_prefix,
        false_prefix=false_prefix,
    )
    return transition, true_terminated and false_terminated


def _dispatch(machine: _StateMachine, env: _Env) -> _SMBlock | None:
    """
    The block the switch runs for what the machine reads: it compares the discriminant with the
    case tests in source order and with `===`, and runs the `default` label where none matches.
    Only the tests that read something are evaluated here, and only those ahead of the first label
    whose constant test matches. Where a test ahead of the match cannot be evaluated, or the
    matched label runs no block the recovery reads (`_SMCase`), this gives `None`.
    """
    if (discriminant := _finite_number(_eval_expr(machine.discriminant, env))) is None:
        return None
    first = machine.constants.get(discriminant)
    for index in machine.variables:
        if first is not None and index > first:
            break
        test = machine.cases[index].test
        assert test is not None
        if (value := _eval_expr(test, env)) is None:
            return None
        if (equal := _strictly_equal(value, discriminant)) is None:
            return None
        if equal:
            return machine.cases[index].block
    if first is not None:
        return machine.cases[first].block
    return machine.default


def _ends(machine: _StateMachine, env: _Env) -> bool | None:
    """
    Whether the loop of the machine stops for what the run reads, or `None` where the sum it
    compares cannot be evaluated.
    """
    if (total := _finite_number(_eval_expr(machine.loop_sum, env))) is None:
        return None
    return total == machine.end_state


def _apply_initial_state(var_names: list[str], values: list[_StateValue]) -> _StateEnv:
    return dict(zip(var_names, values))


def _initial_slots(
    routing: frozenset[_SlotPath],
    scope_param_name: str | None,
    created: dict[str, Expression],
    handed_on: set[str],
    creator: _Slots,
    absent: Callable[[str], bool],
) -> _Slots:
    """
    The values the routing slots hold when a run starts on a scope object that an object literal
    makes: *created* maps the keys of its own properties to their values, and *handed_on* names the
    keys under which it holds the objects of the run that calls it, whose routing slots hold
    *creator*. A slot of a namespace the literal makes holds what that namespace's own literal gives
    it (`_scope_object_properties`), and a slot neither literal holds reads `undefined` where
    *absent* proves that no prototype supplies its key. Every other slot is left unknown.
    """
    slots: _Slots = {}
    for path in routing:
        value: _Value | None = None
        if path[0] != scope_param_name:
            continue
        if len(path) == 2 and (key := path[1]) not in handed_on:
            if key in created:
                value = _eval_number(created[key])
            elif absent(key):
                value = _UNDEFINED
        elif len(path) == 3:
            home, key = path[1:]
            if home in handed_on:
                value = creator.get(path)
            elif (
                isinstance(namespace := created.get(home), JsObjectExpression)
                and (properties := _scope_object_properties(namespace)) is not None
            ):
                if key in properties:
                    value = _eval_number(properties[key])
                elif absent(key):
                    value = _UNDEFINED
        if value is not None:
            slots[path] = value
    return slots


def _process_payload(
    stmts: list[Statement],
    state: _StateEnv,
    match: _MachineMatch,
) -> list[Statement] | None:
    """
    Process statements a block runs, its payload or a branch prefix of its transition, through the
    standard pipeline: substitute the state, record the scope slots they use, strip the scope
    prefix, qualify, and filter the redirect bookkeeping. Returns the processed statements ready
    for emission, or `None` where a key of an access to the scope object does not decode
    (`_fold_scope_keys`).
    """
    if not stmts:
        return []
    result = [_clone_node(stmt) for stmt in stmts]
    if not _fold_scope_keys(stmts, result, state, match):
        return None
    for clone in result:
        _substitute_in_scope(clone, state)
    _collect_scope_props(result, match)
    result = _strip_scope_param_prefix(result, match.scope_param_name)
    result = _qualify_with_identifiers(result, match)
    return _filter_redirect_var_assignments(result, match)


_VIRTUAL_EXIT: int = -1

_N = TypeVar('_N', bound=Node)


@dataclass
class _CFGNode:
    """
    A node in the control flow graph derived from the state machine: one block, keyed by its
    identity (`id(block)`), with the one state every arrival at it finds. A block reached again is
    the same node, which is how a loop shows as a back-edge.
    """
    node_id: int
    payload: list[Statement]
    condition: Expression | None
    successors: list[int] = field(default_factory=list)
    leaves: bool = False
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
    entry: _Env,
    match: _MachineMatch,
    main: bool,
) -> tuple[_CFG, _Slots] | None:
    """
    Build a control flow graph by BFS from the block a run enters, where the machine reads *entry*.
    Nodes are keyed by the identity of the `_SMBlock` they correspond to, so a block reached twice
    is one node and a loop is a back-edge. The obfuscator gives every block one state, so every
    arrival at a block has to find what the machine reads there as the first one did
    (`_Env.same_as`); where it does not, where the loop would not run at all or the next block
    cannot be told (`_dispatch`), or where the run reaches more than `_MAX_BLOCKS` blocks, this
    gives `None`. Only the *main* run may store routing slots, and only in the block it enters
    (`_routing_stores`), so they hold what that block leaves in them from before any wrapper
    exists. The recovery leaves out every block the main run does not reach, and a name one of them
    declares would go with it, so the main run has to reach each of them. Returns the CFG and those
    values.
    """
    if _ends(machine, entry) is not False:
        return None
    entry_block = _dispatch(machine, entry)
    if entry_block is None:
        return None
    entry_id = id(entry_block)
    nodes: dict[int, _CFGNode] = {}
    arrivals: dict[int, _Env] = {entry_id: entry}
    queue: deque[_SMBlock] = deque([entry_block])
    settled = entry.slots

    def arrive(env: _Env | None) -> int | None:
        if env is None or (ended := _ends(machine, env)) is None:
            return None
        if ended:
            return _VIRTUAL_EXIT
        if (block := _dispatch(machine, env)) is None:
            return None
        node_id = id(block)
        if node_id not in arrivals:
            if len(arrivals) >= _MAX_BLOCKS:
                return None
            arrivals[node_id] = env
            queue.append(block)
        elif not arrivals[node_id].same_as(env):
            return None
        return node_id

    while queue:
        block = queue.popleft()
        node_id = id(block)
        env = arrivals[node_id]
        if block.routing_stores:
            if not main or node_id != entry_id:
                return None
            settled = {**env.slots, **dict(block.routing_stores)}
            env = _Env(env.states, settled, env.calls)

        payload = _process_payload(block.payload, env.states, match)
        if payload is None:
            return None

        condition: Expression | None = None
        successors: list[int] = []
        true_prefix_payload: list[Statement] = []
        false_prefix_payload: list[Statement] = []
        transition = block.transition

        if isinstance(transition, _SMExitTransition):
            successors = [_VIRTUAL_EXIT]
        elif isinstance(transition, _SMLinearTransition):
            if (target := arrive(_apply_raw_transition(transition.assignments, env))) is None:
                return None
            successors = [target]
        elif isinstance(transition, _SMGuardedTransition):
            chosen = transition.assignments
            for condition_of_jump, assignments in transition.guards:
                if (holds := _eval_expr(condition_of_jump, env)) is None:
                    return None
                if _is_truthy(holds):
                    chosen = assignments
                    break
            if (target := arrive(_apply_raw_transition(chosen, env))) is None:
                return None
            successors = [target]
        elif isinstance(transition, _SMConditionalTransition):
            true_id = arrive(_apply_raw_transition(transition.true_assignments, env))
            false_id = arrive(_apply_raw_transition(transition.false_assignments, env))
            if true_id is None or false_id is None:
                return None
            successors = [true_id, false_id]
            true_prefix = _process_payload(transition.true_prefix, env.states, match)
            false_prefix = _process_payload(transition.false_prefix, env.states, match)
            if true_prefix is None or false_prefix is None:
                return None
            true_prefix_payload = true_prefix
            false_prefix_payload = false_prefix
            condition = _qualify_condition(transition.condition, env.states, match)

        node = _CFGNode(
            node_id=node_id,
            payload=payload,
            condition=condition,
            successors=successors,
            true_prefix_payload=true_prefix_payload,
            false_prefix_payload=false_prefix_payload,
            leaves=isinstance(transition, _SMExitTransition),
        )
        nodes[node_id] = node

    if main and any(block is None or id(block) not in arrivals for block in machine.declaring):
        return None

    exit_node = _CFGNode(node_id=_VIRTUAL_EXIT, payload=[], condition=None)
    nodes[_VIRTUAL_EXIT] = exit_node

    for n in nodes.values():
        for succ_id in n.successors:
            nodes[succ_id].predecessors.append(n.node_id)

    return (_CFG(nodes=nodes, entry=entry_id, exit=_VIRTUAL_EXIT), settled)


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


def _post_dominators(successors: dict[int, list[int]], exit_id: int) -> dict[int, int]:
    """
    The immediate post-dominator of every block of the graph *successors* describes that has a way
    to *exit_id*: the nearest block every way from it to *exit_id* passes, computed as dominators
    of the reversed graph (Cooper, Harvey and Kennedy). Neither *exit_id* nor a block without such
    a way has one.
    """
    predecessors: dict[int, list[int]] = {exit_id: []}
    for disc, succs in successors.items():
        predecessors.setdefault(disc, [])
        for succ in succs:
            predecessors.setdefault(succ, []).append(disc)

    visited: set[int] = set()
    rpo: list[int] = []
    stack: list[tuple[int, int]] = [(exit_id, 0)]
    while stack:
        current, idx = stack.pop()
        if idx == 0:
            if current in visited:
                continue
            visited.add(current)
        preds = predecessors.get(current, [])
        if idx < len(preds):
            stack.append((current, idx + 1))
            if (pred := preds[idx]) not in visited:
                stack.append((pred, 0))
        else:
            rpo.append(current)

    rpo.reverse()
    position = {disc: index for index, disc in enumerate(rpo)}
    ipdom: dict[int, int] = {exit_id: exit_id}

    def intersect(a: int, b: int) -> int:
        while a != b:
            while position[a] > position[b]:
                a = ipdom[a]
            while position[b] > position[a]:
                b = ipdom[b]
        return a

    changed = True
    while changed:
        changed = False
        for disc in rpo:
            if disc == exit_id:
                continue
            succs = [succ for succ in successors.get(disc, []) if succ in ipdom]
            if not succs:
                continue
            new_ipdom = succs[0]
            for succ in succs[1:]:
                new_ipdom = intersect(new_ipdom, succ)
            if ipdom.get(disc) != new_ipdom:
                ipdom[disc] = new_ipdom
                changed = True

    del ipdom[exit_id]
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


def _block_code(node: _CFGNode) -> list[Node]:
    """
    The code the structuring writes for the block *node*: its payload, the condition of its
    transition, and what each branch of it runs first.
    """
    code: list[Node] = [*node.payload, *node.true_prefix_payload, *node.false_prefix_payload]
    if node.condition is not None:
        code.append(node.condition)
    return code


class _NodeParts(NamedTuple):
    """
    What the structuring writes for one block: its payload, the condition of its transition, and
    the statements each branch of that transition runs first.
    """
    payload: list[Statement]
    condition: Expression | None
    true_prefix: list[Statement]
    false_prefix: list[Statement]


class _Region:
    """
    The blocks one walk of the structuring places, up to its *exit*: the end of the machine for the
    walk over the run, the header of the loop for a walk over that loop's body (*members*, `None`
    for the run). A block that has a way to the exit not passing a block that leaves the machine is
    steady, and the join of a steady conditional is its post-dominator over those ways (`ipdom`). A
    block without such a way (`tails`) only leaves the machine or the loop, and the structuring
    writes it wherever control reaches it. `reach` holds the blocks each block reaches and
    `dominated` the blocks each block dominates, as bits by their position in the order the graph
    runs (`order`); `leaving_ipdom` holds post-dominators over every way, each way out of the
    region ending at the exit.
    """

    def __init__(
        self,
        cfg: _CFG,
        order: dict[int, int],
        dominated: dict[int, int],
        exit_disc: int,
        members: set[int] | None,
    ):
        nodes = {disc for disc in (cfg.nodes if members is None else members) if disc != exit_disc}
        steady = {disc for disc in nodes if not cfg.nodes[disc].leaves}
        self.exit = exit_disc
        self.members = members
        self.dominated = dominated
        steady_ways = {
            disc: [
                succ for succ in cfg.nodes[disc].successors if succ in steady or succ == exit_disc
            ] for disc in steady
        }
        every_way = {
            disc: [
                succ if succ in nodes else exit_disc for succ in cfg.nodes[disc].successors
            ] for disc in nodes
        }
        self.ipdom = _post_dominators(steady_ways, exit_disc)
        self.tails = {disc for disc in nodes if disc not in self.ipdom}
        self.leaving_ipdom = _post_dominators(every_way, exit_disc)
        self.at_position = {order[disc]: disc for disc in nodes}
        self.reach = {disc: 1 << order[disc] for disc in nodes}
        ordered = sorted(nodes, key=order.__getitem__, reverse=True)
        changed = True
        while changed:
            changed = False
            for disc in ordered:
                reached = self.reach[disc]
                for succ in cfg.nodes[disc].successors:
                    reached |= self.reach.get(succ, 0)
                if reached != self.reach[disc]:
                    self.reach[disc] = reached
                    changed = True

    def holds(self, disc: int) -> bool:
        """
        Whether the block *disc* lies in the region rather than where the loop it is the body of
        is left to.
        """
        return self.members is None or disc in self.members

    def join(self, cfg: _CFG, disc: int) -> int:
        """
        Where the branches of the conditional *disc* meet again. For a steady conditional, the
        nearest block that every way on from it not leaving the machine passes: a branch that always
        leaves stands in the conditional, and the code after the conditional is the other branch's.
        For one that only leaves: the block both branches reach that dominates every block both
        reach, so that both run into the code after the conditional through it; else the nearest
        block every way on from it passes; else, where the branches leave the region apart, the
        false successor: the true branch then runs on into it or leaves.
        """
        if disc == self.exit:
            return self.exit
        if (found := self.ipdom.get(disc)) is not None:
            return found
        true_succ, false_succ = cfg.nodes[disc].successors
        if common := self.reach.get(true_succ, 0) & self.reach.get(false_succ, 0):
            first = self.at_position[(common & -common).bit_length() - 1]
            if not common & ~self.dominated[first]:
                return first
        if (found := self.leaving_ipdom.get(disc)) is not None and found != self.exit:
            return found
        return false_succ


class _CopiesOutgrowTheRun(Exception):
    """
    Raised where the copies the structuring writes would hold more code than the blocks of the run
    (`_Structuring.allowance`), or would make a wrapper: a copy of a wrapper is a function of its
    own, which the recovery resolves as a run of its own, and the allowance does not count that run.
    """


def _code_size(code: Sequence[Node]) -> int:
    """
    The number of syntax nodes in *code*.
    """
    return sum(1 for part in code for _ in part.walk())


def _refers_to_one_of(code: Sequence[Node], names: frozenset[str]) -> bool:
    """
    Whether *code* refers to one of *names* anywhere below it.
    """
    return any(
        isinstance(node, JsIdentifier) and node.name in names and is_reference(node)
        for part in code
        for node in part.walk()
    )


class _Structuring:
    """
    The recovery of structured code from the graph of one run: loops innermost first, each written
    once and then standing for its header (`collapsed`), then the run itself, by walks over regions
    (`_Region`) that place blocks in the order the graph runs them. A block that only leaves is
    placed wherever control reaches it; where a block is placed a second time, the walk writes a
    copy of its code (`_parts`, `_collapsed`), since a tree holds a node in one place. Blocks whose
    ways part and share blocks without meeting again make every level of them double what the
    levels below write, so the copies may hold at most as much code as the blocks of the run
    (`allowance`), and none of them may call the generator under one of its *machine_names*;
    beyond that, the run is not written.

    A loop is written only where every way out of it goes to one block. A `break` goes to where the
    code after the loop continues, and nothing else can be said with one.
    """

    def __init__(
        self,
        cfg: _CFG,
        idom: dict[int, int | None],
        machine_names: frozenset[str],
    ):
        self.cfg = cfg
        self.machine_names = machine_names
        self.collapsed: dict[int, list[Statement]] = {}
        self.placed: set[int] = set()
        self.placed_loops: set[int] = set()
        self.homes: dict[Node, tuple[int, int]] = {}
        self.allowance = sum(_code_size(_block_code(node)) for node in cfg.nodes.values())
        self.order = {disc: index for index, disc in enumerate(_reverse_postorder(cfg))}
        self.dominated = {disc: 1 << index for disc, index in self.order.items()}
        for disc in sorted(self.order, key=self.order.__getitem__, reverse=True):
            if (parent := idom.get(disc)) is not None:
                self.dominated[parent] |= self.dominated[disc]

    def run(self, loops: list[_NaturalLoop]) -> list[Statement] | None:
        try:
            for loop in sorted(loops, key=lambda lp: len(lp.body)):
                if (body := self._loop(loop)) is None:
                    return None
                self.collapsed[loop.header] = body
                for body_node in loop.body:
                    if body_node != loop.header:
                        self.collapsed[body_node] = []
            region = _Region(self.cfg, self.order, self.dominated, self.cfg.exit, None)
            return self._acyclic(region, self.cfg.entry, self.cfg.exit, set())
        except _CopiesOutgrowTheRun:
            return None

    def _copy(self, code: Sequence[_N]) -> list[_N]:
        """
        A copy of *code*, charged to what the copies may hold in all (`allowance`). Code that calls
        the generator, as the code making a wrapper does, is not copied (`_CopiesOutgrowTheRun`).
        """
        self.allowance -= _code_size(code)
        if self.allowance < 0 or _refers_to_one_of(code, self.machine_names):
            raise _CopiesOutgrowTheRun
        return [_clone_node(part) for part in code]

    def _parts(self, disc: int) -> _NodeParts:
        """
        The code of the block *disc* as a walk places it: the block's own the first time, a copy
        every other time. Each statement of its payload is recorded with the block and its position
        there (`homes`).
        """
        node = self.cfg.nodes[disc]
        if disc not in self.placed:
            self.placed.add(disc)
            parts = _NodeParts(
                list(node.payload),
                node.condition,
                list(node.true_prefix_payload),
                list(node.false_prefix_payload),
            )
        else:
            parts = _NodeParts(
                self._copy(node.payload),
                self._copy([node.condition])[0] if node.condition is not None else None,
                self._copy(node.true_prefix_payload),
                self._copy(node.false_prefix_payload),
            )
        for index, stmt in enumerate(parts.payload):
            self.homes[stmt] = (disc, index)
        return parts

    def _collapsed(self, disc: int) -> list[Statement]:
        """
        The code the loop whose header is *disc* was written as, or a copy of it where it was placed
        before; nothing for another block of a loop, whose code the loop's holds.
        """
        code = self.collapsed[disc]
        if disc in self.placed_loops:
            return self._copy(code)
        self.placed_loops.add(disc)
        return list(code)

    def _loop(self, loop: _NaturalLoop) -> list[Statement] | None:
        """
        One natural loop as a `while` statement: tested at its header where it is left from there
        alone, else `while (true)` left with a `break`. `None` where the loop is left to more than
        one block.
        """
        nodes = self.cfg.nodes
        targets = {
            succ for disc in loop.body for succ in nodes[disc].successors if succ not in loop.body
        }
        if len(targets) > 1:
            return None
        region = _Region(self.cfg, self.order, self.dominated, loop.header, loop.body)
        header = nodes[loop.header]
        if (
            header.condition is not None
            and len(header.successors) == 2
            and not header.payload
            and not any(
                succ not in loop.body
                for disc in loop.body if disc != loop.header
                for succ in nodes[disc].successors
            )
        ):
            true_succ, false_succ = header.successors
            if true_succ not in loop.body and true_succ in nodes:
                parts = self._parts(loop.header)
                assert parts.condition is not None
                body_entry = false_succ
                condition: Expression = JsUnaryExpression(
                    operator='!',
                    operand=parts.condition,
                    prefix=True,
                )
                body_prefix, exit_prefix = parts.false_prefix, parts.true_prefix
            elif false_succ not in loop.body and false_succ in nodes:
                parts = self._parts(loop.header)
                assert parts.condition is not None
                body_entry = true_succ
                condition = parts.condition
                body_prefix, exit_prefix = parts.true_prefix, parts.false_prefix
            else:
                return self._infinite_loop(loop, region)
            body = self._acyclic(region, body_entry, loop.header, set())
            return [
                JsWhileStatement(
                    test=condition,
                    body=JsBlockStatement(body=[*body_prefix, *body]),
                ),
                *exit_prefix,
            ]
        return self._infinite_loop(loop, region)

    def _infinite_loop(self, loop: _NaturalLoop, region: _Region) -> list[Statement]:
        """
        A loop without a simple test at its header as `while (true)`, left with `break`.
        """
        return [JsWhileStatement(
            test=JsBooleanLiteral(value=True),
            body=JsBlockStatement(body=self._loop_body(loop.header, region)),
        )]

    def _branches(
        self,
        region: _Region,
        disc: int,
        parts: _NodeParts,
        join: int,
        visited: set[int],
    ) -> Statement:
        """
        The `if` statement of the conditional *disc*, each branch running from its successor up to
        *join*. A block either branch places counts as placed for what follows.
        """
        true_succ, false_succ = self.cfg.nodes[disc].successors
        true_visited = set(visited)
        true_stmts = list(parts.true_prefix)
        if true_succ != join:
            true_stmts.extend(self._acyclic(region, true_succ, join, true_visited))
        false_visited = set(visited)
        false_stmts = list(parts.false_prefix)
        if false_succ != join:
            false_stmts.extend(self._acyclic(region, false_succ, join, false_visited))
        visited.update(true_visited)
        visited.update(false_visited)
        assert parts.condition is not None
        return _build_js_if(parts.condition, true_stmts, false_stmts)

    def _acyclic(
        self,
        region: _Region,
        entry: int,
        exit_disc: int,
        visited: set[int],
    ) -> list[Statement]:
        """
        The blocks of *region* from *entry* up to *exit_disc* as a statement sequence, with an `if`
        for each conditional whose branches run up to its join (`_Region.join`). A block another
        walk placed is placed again only where it only leaves (`_Region.tails`); a block outside the
        loop the region is the body of is where the loop is left, a `break`.
        """
        result: list[Statement] = []
        here: set[int] = set()
        worklist: deque[int] = deque([entry])
        while worklist:
            disc = worklist.popleft()
            if disc == exit_disc or disc in here:
                continue
            here.add(disc)
            if not region.holds(disc):
                result.append(JsBreakStatement())
                continue
            if disc in visited and disc not in region.tails:
                continue
            visited.add(disc)
            node = self.cfg.nodes[disc]
            if disc in self.collapsed:
                result.extend(self._collapsed(disc))
                worklist.extend(node.successors)
                continue
            parts = self._parts(disc)
            result.extend(parts.payload)
            if node.condition is not None and len(node.successors) == 2:
                join = region.join(self.cfg, disc)
                result.append(self._branches(region, disc, parts, join, visited))
                worklist.appendleft(join)
            else:
                worklist.extend(node.successors)
        return result

    def _loop_body(self, header: int, region: _Region) -> list[Statement]:
        """
        The body of the loop whose header is *header*, for `while (true)`: a branch back to the
        header is a `continue`, and one out of the loop a `break`.
        """
        result: list[Statement] = []
        visited: set[int] = set()
        here: set[int] = set()
        worklist: deque[int] = deque([header])
        while worklist:
            disc = worklist.popleft()
            if disc in here:
                continue
            here.add(disc)
            if not region.holds(disc):
                result.append(JsBreakStatement())
                continue
            if disc in visited and disc not in region.tails:
                continue
            visited.add(disc)
            node = self.cfg.nodes[disc]
            if disc in self.collapsed:
                result.extend(self._collapsed(disc))
                worklist.extend(succ for succ in node.successors if succ != header)
                continue
            parts = self._parts(disc)
            result.extend(parts.payload)
            if node.condition is None or len(node.successors) != 2:
                for succ in node.successors:
                    if succ != header:
                        worklist.append(succ)
                continue
            assert parts.condition is not None
            true_succ, false_succ = node.successors
            true_in_loop = region.holds(true_succ)
            false_in_loop = region.holds(false_succ)
            condition = parts.condition

            def negated() -> Expression:
                return JsUnaryExpression(operator='!', operand=condition, prefix=True)

            if true_succ == header or false_succ == header:
                back_on_true = true_succ == header
                other = false_succ if back_on_true else true_succ
                back_prefix = parts.true_prefix if back_on_true else parts.false_prefix
                other_prefix = parts.false_prefix if back_on_true else parts.true_prefix
                if not region.holds(other):
                    result.append(JsIfStatement(
                        test=negated() if back_on_true else condition,
                        consequent=JsBlockStatement(body=[*other_prefix, JsBreakStatement()]),
                    ))
                    result.extend(back_prefix)
                else:
                    result.append(JsIfStatement(
                        test=condition if back_on_true else negated(),
                        consequent=JsBlockStatement(body=[*back_prefix, JsContinueStatement()]),
                    ))
                    result.extend(other_prefix)
                    worklist.append(other)
                continue
            if not true_in_loop and not false_in_loop:
                if parts.true_prefix or parts.false_prefix:
                    result.append(_build_js_if(
                        parts.condition,
                        [*parts.true_prefix, JsBreakStatement()],
                        [*parts.false_prefix, JsBreakStatement()],
                    ))
                else:
                    result.append(_build_js_if(parts.condition, [], []))
                    result.append(JsBreakStatement())
                continue
            if not true_in_loop:
                result.append(JsIfStatement(
                    test=parts.condition,
                    consequent=JsBlockStatement(body=[*parts.true_prefix, JsBreakStatement()]),
                ))
                result.extend(parts.false_prefix)
                worklist.append(false_succ)
                continue
            if not false_in_loop:
                result.append(JsIfStatement(
                    test=negated(),
                    consequent=JsBlockStatement(body=[*parts.false_prefix, JsBreakStatement()]),
                ))
                result.extend(parts.true_prefix)
                worklist.append(true_succ)
                continue
            join = region.join(self.cfg, disc)
            result.append(self._branches(region, disc, parts, join, visited))
            if join != header:
                worklist.appendleft(join)
        return result


def _fold_scope_keys(
    originals: Sequence[Node],
    clones: Sequence[Node],
    state: _StateEnv,
    match: _MachineMatch,
) -> bool:
    """
    Put what the run computes from *state* into *clones*, the copies of *originals*: the string
    each computed key of an access to the scope object, or to a member of it, evaluates to in place
    of the key, and the array a wrapper's call starts the machine in as an array literal. Each is
    evaluated on the original node, which anchors the calls that make it, and only where it runs
    at the state: none in code that runs at a time of its own
    (`refinery.lib.scripts.js.analysis.evaluation.Evaluation.LATER`), such as a nested function,
    which reads the state when it is called, or the initializer of a class field, which reads it
    when an instance is made, and none whose scope object or state variables something between the
    block and the key binds anew (`_scoped_children`). `False` where a key of the block does not
    decode.
    """
    if match.calls is None or match.scope_param_name is None:
        return True
    scope = match.scope_param_name
    watched = frozenset({scope, *state})
    keys: dict[Node, str] = {}

    def decode(node: Node, hidden: frozenset[str]) -> bool:
        if isinstance(node, FUNCTION_NODES):
            return True
        if (
            isinstance(node, JsMemberExpression)
            and node.computed
            and (key := node.property) is not None
            and not isinstance(key, JsStringLiteral)
            and isinstance(holder := _scope_holder(node), JsIdentifier)
            and holder.name == scope
            and scope not in hidden
        ):
            visible = {name: value for name, value in state.items() if name not in hidden}
            if not isinstance(value := _eval_expr(key, _Env(visible, calls=match.calls)), str):
                return False
            keys[node] = value
        for child, bound in _scoped_children(node):
            if evaluation_of(node, child) is Evaluation.LATER:
                continue
            if not decode(child, hidden | (watched & bound) if bound else hidden):
                return False
        return True

    for original, clone in zip(originals, clones):
        keys.clear()
        if not decode(original, frozenset()):
            return False
        starts: dict[Node, Expression] = {}
        for node in original.walk():
            if (
                isinstance(node, JsFunctionExpression)
                and (call := _plain_wrapper_call(node, match)) is not None
                and isinstance(entry := _eval_expr(call.arguments[0], _Env({}, calls=match.calls)), tuple)
                and (literal := _array_literal(entry)) is not None
            ):
                starts[call.arguments[0]] = literal
        for node, copy in list(zip(original.walk(), clone.walk())):
            if (value := keys.get(node)) is not None:
                assert isinstance(copy, JsMemberExpression) and copy.property is not None
                _replace_in_parent(copy.property, make_string_literal(value))
            elif (literal := starts.get(node)) is not None:
                _replace_in_parent(copy, literal)
    return True


def _array_literal(values: tuple[float, ...]) -> JsArrayExpression | None:
    """
    An array literal of the numbers *values*, or `None` where one of them has no literal.
    """
    elements: list[Expression | None] = []
    for value in values:
        if (literal := make_numeric_literal(value)) is None:
            return None
        elements.append(literal)
    return JsArrayExpression(elements=elements)


def _scope_holder(member: JsMemberExpression) -> Expression | None:
    """
    The object an access `scope[k]` or `scope.P[k]` reads the scope object as.
    """
    holder = member.object
    if isinstance(holder, JsMemberExpression):
        holder = holder.object
    return holder


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
    a nested block whose name Annex B copies into the function *home* (`annex_b_function_home`).
    A list of statements not yet standing in the function it becomes the body of is given no such
    copy.
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
                and annex_b_function_home(node) is home
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
        while isinstance(statement, JsLabeledStatement):
            statement = statement.body
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
    Replace state variable identifiers with numeric literals. Code that runs at a time of its own
    (`refinery.lib.scripts.js.analysis.evaluation.Evaluation.LATER`) is not entered, a nested
    function at the root as well: a function reads the state variable when it is called, and the
    initializer of a class field when an instance is made, not at the state being recovered.
    """
    if isinstance(node, FUNCTION_NODES):
        return
    for child, bound in _scoped_children(node):
        if isinstance(child, FUNCTION_NODES) or evaluation_of(node, child) is Evaluation.LATER:
            continue
        if (
            isinstance(child, JsMemberExpression)
            and isinstance(holder := child.object, JsIdentifier)
            and isinstance(env.get(holder.name), tuple)
            and holder.name not in bound
            and not is_member_write_target(child)
            and (value := _finite_number(_eval_expr(child, _Env(env)))) is not None
        ):
            literal = make_numeric_literal(value)
            if literal is not None:
                _replace_in_parent(child, literal)
                continue
        if (
            isinstance(child, JsIdentifier)
            and child.name not in bound
            and (held := env.get(child.name)) is not None
            and not isinstance(held, tuple)
        ):
            literal = make_numeric_literal(held)
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


def _qualify_exempt(match: _MachineMatch) -> set[str]:
    """
    The set of names that home-driven qualification must leave bare: the state variables, the
    JavaScript built-in globals, every namespace object, and the compiler-introduced scaffolding
    identifiers (generator, scope parameter, argument holder, return flag, redirect variable).
    """
    exempt: set[str] = set(match.state_var_names) | _JS_BUILTIN_GLOBALS | set(match.namespaces)
    exempt |= match.machine_names
    for name in (
        match.scope_param_name,
        match.arg_var_name,
        match.with_redirect_var,
    ):
        if name is not None:
            exempt.add(name)
    if isinstance(match.flag, _FlagVariable):
        exempt.add(match.flag.name)
    return exempt


def _qualify_condition(
    condition: Expression,
    state: _StateEnv,
    match: _MachineMatch,
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
    assert wrapper.expression is not None
    _fold_scope_keys([condition], [wrapper.expression], state, match)
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
    match: _MachineMatch,
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


class _RunReturns(NamedTuple):
    """
    What the returns of the code of one run say: whether one returns without raising the flag
    (`plain`), and whether one that raises it stands in a `try` statement (`intercepted`). The flag
    is raised before the value of such a return is computed: the value may throw into a `catch`, and
    a `finally` may end the run another way, so the run may go on with the flag raised.
    """
    plain: bool
    intercepted: bool


def _raises_the_flag(expr: Expression | None, flag: _Flag | None) -> bool:
    """
    Whether *expr* is the store `didReturn = true` the obfuscator writes ahead of the value of a
    return.
    """
    return (
        flag is not None
        and isinstance(expr, JsAssignmentExpression)
        and expr.operator == '='
        and flag.spelled_by(expr.left)
        and isinstance(expr.right, JsBooleanLiteral)
        and expr.right.value is True
    )


def _own_returns(
    stmt: Statement,
    name: str,
    hidden: bool,
) -> Iterator[tuple[JsReturnStatement, bool, bool]]:
    """
    Each `return` of the code *stmt* belongs to, not of a function inside it, with whether *name*
    may mean another binding there than the one it means around *stmt*, and whether the return
    stands in a `try` statement. It may where it does at *stmt* already (*hidden*), where something
    between *stmt* and the return binds it anew (`_scoped_children`), and in the body of a `with`
    statement, whose object may hold a property of that name.
    """
    stack: list[tuple[Node, bool, bool]] = [(stmt, hidden, False)]
    while stack:
        node, hidden, guarded = stack.pop()
        if isinstance(node, JsReturnStatement):
            yield node, hidden, guarded
        if isinstance(node, FUNCTION_NODES):
            continue
        guarded = guarded or isinstance(node, JsTryStatement)
        scoped = node.body if isinstance(node, JsWithStatement) else None
        stack.extend(
            (child, hidden or name in bound or child is scoped, guarded)
            for child, bound in reversed(list(_scoped_children(node)))
        )


def _recover_returns(stmts: list[Statement], match: _MachineMatch) -> _RunReturns:
    """
    Rewrite each return of the code of a run of the machine of *match* that raises the flag,

        return didReturn = true, value;

    to the return of its value, wherever in that code it stands; a function inside keeps its own
    returns. A store under the flag's spelling where the generator binds its name for the code of
    the switch (`_names_bound_for_the_switch`), or where something between binds it anew, stores to
    that binding, and the return does not raise the flag.
    """
    flag = match.flag
    name = flag.base if flag is not None else ''
    hidden = flag is not None and name in _names_bound_for_the_switch(match)
    plain = intercepted = False
    for stmt in stmts:
        for node, hidden_here, guarded in list(_own_returns(stmt, name, hidden)):
            argument = node.argument
            if (
                hidden_here
                or not isinstance(argument, JsSequenceExpression)
                or len(argument.expressions) < 2
                or not _raises_the_flag(argument.expressions[0], flag)
            ):
                plain = True
                continue
            intercepted = intercepted or guarded
            value = (
                argument.expressions[1] if len(argument.expressions) == 2
                else JsSequenceExpression(expressions=argument.expressions[1:])
            )
            set_child(node, 'argument', value)
    return _RunReturns(plain, intercepted)


def _names_bound_for_the_switch(match: _MachineMatch) -> set[str]:
    """
    The names the generator of *match* binds for the code of the cases of its switch: its parameters
    and its own name, what its body declares (`_function_bound_names`), and what the cases declare
    for the block of the switch.
    """
    statements = [
        statement for case in match.switch_stmt.cases if isinstance(case, JsSwitchCase)
        for statement in case.body
    ]
    return _function_bound_names(match.machine) | _block_bound_names(statements)


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
    match: _MachineMatch,
) -> list[Statement]:
    if not match.qualifies_namespaces:
        return stmts
    redirect_var = match.with_redirect_var
    assert redirect_var is not None
    return _rewrite_comma_parts(
        stmts, lambda part: None if _is_bare_redirect_assignment(part, redirect_var) else part
    )


def _rewrite_comma_parts(
    stmts: list[Statement],
    rewrite: Callable[[Expression], Expression | None],
) -> list[Statement]:
    """
    Pass the expression of each expression statement among *stmts*, or each expression of the
    comma sequence it holds, through *rewrite*, which gives it back, gives an expression to take
    its place, or gives `None` to drop it. A statement none of whose expressions remain goes.
    """
    result: list[Statement] = []
    for stmt in stmts:
        if not isinstance(stmt, JsExpressionStatement) or stmt.expression is None:
            result.append(stmt)
            continue
        expr = stmt.expression
        parts = expr.expressions if isinstance(expr, JsSequenceExpression) else [expr]
        remaining = [kept for part in parts if (kept := rewrite(part)) is not None]
        if remaining == parts:
            result.append(stmt)
        elif len(remaining) == 1:
            result.append(JsExpressionStatement(expression=remaining[0]))
        elif remaining:
            result.append(JsExpressionStatement(
                expression=JsSequenceExpression(expressions=remaining),
            ))
    return result


class _RunOrder:
    """
    When the statements of the code recovered for one run run, read off the graph of the run: the
    block whose payload each statement is and its position there (`homes`), the dominators of the
    blocks, and the blocks each block reaches.
    """

    def __init__(self, cfg: _CFG, idom: dict[int, int | None], homes: dict[Node, tuple[int, int]]):
        self.cfg = cfg
        self.idom = idom
        self.homes = homes
        self._reached: dict[int, set[int]] = {}

    def _reaches(self, disc: int) -> set[int]:
        """
        The blocks a way of at least one step from the block *disc* reaches.
        """
        if (found := self._reached.get(disc)) is None:
            found = set()
            stack = list(self.cfg.nodes[disc].successors)
            while stack:
                if (succ := stack.pop()) in found or succ not in self.cfg.nodes:
                    continue
                found.add(succ)
                stack.extend(self.cfg.nodes[succ].successors)
            self._reached[disc] = found
        return found

    def _home(self, node: Node) -> tuple[int, int] | None:
        cursor: Node | None = node
        while cursor is not None:
            if (home := self.homes.get(cursor)) is not None:
                return home
            cursor = cursor.parent
        return None

    def replace(self, statement: Node, replacement: Sequence[Node]) -> None:
        """
        Record that the statements of *replacement* stand where *statement* stood, and run when it
        ran.
        """
        if (home := self.homes.pop(statement, None)) is not None:
            for stmt in replacement:
                self.homes[stmt] = home

    def runs_only_before(self, first: Node, then: Node) -> bool:
        """
        Whether *first* runs before *then* on every way to it and never again once *then* has run,
        both standing in the code of this run: the payload statement holding *first* comes earlier
        in a block that holds both and that no loop holds, or its block dominates the block of
        *then*, which does not reach it.
        """
        if (early := self._home(first)) is None or (late := self._home(then)) is None:
            return False
        if early[0] == late[0]:
            return early[1] < late[1] and early[0] not in self._reaches(early[0])
        return _dominates(self.idom, early[0], late[0]) and early[0] not in self._reaches(late[0])


class _Run(NamedTuple):
    """
    The code recovered for one run of the machine, what its routing slots hold once it has entered
    the machine (`_build_cfg`), what its returns say (`_RunReturns`), and when its statements run
    (`_RunOrder`).
    """
    statements: list[Statement]
    settled: _Slots
    returns: _RunReturns
    order: _RunOrder


def _execute_machine(
    machine: _StateMachine,
    match: _MachineMatch,
    slots: _Slots,
    main: bool,
) -> _Run | None:
    """
    Recover structured code for a run of the machine whose routing slots start out holding *slots*,
    using CFG-based structural analysis: builds a control flow graph, identifies loops via dominator
    analysis, and emits structured control flow (while, if/else, break). Returns the run (`_Run`),
    the *main* run or a wrapper's.
    """
    entry = _Env(_apply_initial_state(match.state_var_names, match.initial_state), slots, match.calls)
    cfg_result = _build_cfg(machine, entry, match, main)
    if cfg_result is None:
        return None

    cfg, settled = cfg_result
    idom = _compute_idom(cfg)
    structuring = _Structuring(cfg, idom, match.machine_names)
    if (stmts := structuring.run(_find_loops(cfg, idom))) is None:
        return None
    return _Run(
        stmts,
        settled,
        _recover_returns(stmts, match),
        _RunOrder(cfg, idom, structuring.homes),
    )


def _build_js_if(
    condition: Expression,
    true_body: list[Statement],
    false_body: list[Statement],
) -> Statement:
    """
    Build a JsIfStatement, omitting empty branches. Where both are empty, the condition is still
    evaluated, as a statement of its own: it may do something, as a call does.
    """
    if not true_body and not false_body:
        return JsExpressionStatement(expression=condition)
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
    routing: _Slots = field(default_factory=dict)

    def holds(self, name: str) -> bool:
        return name in self.namespaces or name in self.inherited or name in self.props


def _creating_activation(
    node: Node,
    activations: dict[int, _Activation],
    main: _Activation,
) -> _Activation:
    """
    The activation of the run that creates the wrapper *node*: that of the innermost resolved
    wrapper whose recovered body holds it, or the main one. A node in the parameters of a resolved
    wrapper is evaluated when that wrapper is called, in the scope of the run that created it.
    """
    cursor: Node = node
    while (parent := cursor.parent) is not None:
        if (
            isinstance(parent, JsFunctionExpression)
            and cursor is parent.body
            and (activation := activations.get(id(parent))) is not None
        ):
            return activation
        cursor = parent
    return main


def _wrapper_activation(
    node: JsFunctionExpression,
    scope_arg: Expression,
    creator: _Activation,
    match: _MachineMatch,
) -> _Activation | None:
    """
    The activation of the run a wrapper's call starts, read off the scope argument it hands the
    generator, in the recovered code the creating run's payload became. The scope parameter itself
    shares *creator*'s scope object. An object literal is a fresh scope object per call: each
    property holding an inert object literal (`_is_inert`) that reads no name is a namespace created
    with it, and a property `scope.K` under its own key `K`, which the strip of the creating run's
    payload left as a bare `K`, hands on the creating run's `K`, which that run has to hold and
    nothing between its code and the literal may bind anew. A namespace is declared in the
    wrapper's body only once the recovery has renamed the wrapper's parameters, so a name its value
    read could no longer mean what it meant. Where something between the generator and the scope
    argument binds the scope parameter's name anew, the argument is not the creator's scope object.
    Any other scope argument gives `None`.
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
        elif (
            isinstance(value, JsIdentifier)
            and value.name == key
            and creator.holds(key)
            and not _bound_on_the_way_to(value, key)
        ):
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
    match: _MachineMatch,
    main: _Activation,
    main_order: _RunOrder,
    absent: Callable[[str], bool],
) -> list[_Activation] | None:
    """
    Walk recovered statements looking for function expressions that are wrappers around the same
    shared generator. For each wrapper found, execute the state machine from its entry point and
    replace the wrapper with a proper function containing the recovered body. The run of a wrapper
    reads the routing slots of the scope object it hands the generator (`_initial_slots`, with
    *absent* for keys no literal holds): where it hands on the scope object or namespaces of the
    run that creates it, they hold what that run filled them with before any wrapper existed.
    Iterates until no more wrappers are resolved (handles nesting). A function that calls a name of
    the machine, or hands on a `runtime`, which something in the recovered code binds anew, as a
    machine nested in it under the same names does, calls that binding (`_references_to`) and is
    no wrapper of this machine.

    Returns the activations of the resolved wrappers, each one once and *main* among them where a
    wrapper shares its scope object, or `None` where a wrapper cannot be resolved: it would be left
    calling the generator the recovery removes. So is a wrapper nested in the recovered body of one
    that enters the machine at the same state, whose resolution would recover the same wrapper again
    without end, and a key a wrapper hands on from its creator (`_wrapper_activation`) whose stores
    could leave the copy the wrapper's scope object holds apart from the creator's value, which the
    recovered code can only share (`_stores_precede_the_wrappers`).
    """
    gen_names = match.machine_names
    named = gen_names if match.runtime_name is None else gen_names | {match.runtime_name}
    activations: dict[int, _Activation] = {}
    orders: dict[int, _RunOrder] = {}
    entries: dict[int, list[_StateValue]] = {}

    while True:
        resolved_any = False
        reads_of_the_machine = {id(read) for read in _references_to(stmts, named)}
        for node in list(_walk_all(stmts)):
            if not isinstance(node, JsFunctionExpression):
                continue
            node_id = id(node)
            if node_id in activations:
                continue
            wrapper_info = match.design.wrapper(node, match)
            if wrapper_info is None or node.body is None:
                continue
            if not all(id(read) in reads_of_the_machine for read in wrapper_info.machine_reads):
                continue
            if _reenters(node, wrapper_info.initial_state, entries):
                return None
            creator = _creating_activation(node, activations, main)
            activation = _wrapper_activation(node, wrapper_info.scope_arg, creator, match)
            if activation is None:
                return None
            if activation is not creator:
                activation.routing = _initial_slots(
                    machine.routing,
                    match.scope_param_name,
                    activation.namespaces,
                    activation.inherited,
                    creator.routing,
                    absent,
                )
            synthetic = _MachineMatch(
                machine=match.machine,
                machine_names=gen_names,
                design=match.design,
                state_var_names=match.state_var_names,
                initial_state=wrapper_info.initial_state,
                end_state=match.end_state,
                loop_sum=match.loop_sum,
                switch_stmt=match.switch_stmt,
                switch_label=match.switch_label,
                scope_param_name=match.scope_param_name,
                arg_var_name=match.arg_var_name,
                flag=match.flag,
                result_var=None,
                machine_index=0,
                scaffolding_end=0,
                with_redirect_var=match.with_redirect_var,
                scope_default_props=match.scope_default_props,
                namespaces=match.namespaces,
                namespace_homes=match.namespace_homes,
                runtime_name=match.runtime_name,
                calls=match.calls,
            )
            result = _execute_machine(machine, synthetic, activation.routing, main=False)
            if result is None:
                return None
            activation.props |= synthetic.scope_prop_names
            activations[node_id] = activation
            orders[node_id] = result.order
            entries[node_id] = wrapper_info.initial_state
            recovered = result.statements
            target = _wrapper_arg_param_name(match, wrapper_info, recovered)
            if match.arg_var_name and target and match.arg_var_name != target:
                recovered = _rebind_free_arg_var(recovered, match.arg_var_name, target)
            recovered = keeping_directives(node.body, recovered)
            set_child(node, 'body', JsBlockStatement(body=recovered))
            if target is not None and target != wrapper_info.rest_param_name:
                set_child_list(node, 'params', _rebind_wrapper_param(node.params, target))
            if activation is not creator:
                _unpack_argument_stores(node, activation, result.order)
            resolved_any = True
        if not resolved_any:
            break

    resolved = list({id(activation): activation for activation in activations.values()}.values())
    if not _stores_precede_the_wrappers(stmts, activations, orders, main, main_order):
        return None
    return resolved


def _stores_precede_the_wrappers(
    stmts: list[Statement],
    activations: dict[int, _Activation],
    orders: dict[int, _RunOrder],
    main: _Activation,
    main_order: _RunOrder,
) -> bool:
    """
    Whether every store in *stmts* to a key a resolved wrapper hands on from the run that creates it
    (`_Activation.inherited`) leaves what the wrapper's runs read as it was. A wrapper's scope
    object holds a copy of the creator's value, made when the wrapper is called, which the recovered
    code shares with the creator. They read the same as long as the run that holds the key as its
    own stores to it only before it makes the wrapper that hands it on, directly or through
    wrappers that hand it on again: the store and the statement making that wrapper both stand in
    the own code of that run (`_own_run`), and the store runs before it on every way to it and never
    again afterwards (`_RunOrder.runs_only_before`). The obfuscator stores the scope object of a
    block that way, once, where the block starts, before the functions the block declares. A direct
    `eval` can store to the key where no store is written, so none may stand in the code.
    """
    wrappers = [
        activation for activation in activations.values()
        if activation.function is not None and activation.inherited
    ]
    names = frozenset(name for activation in wrappers for name in activation.inherited)
    if not names:
        return True
    if any(is_direct_eval_call(node) for stmt in stmts for node in stmt.walk()):
        return False
    for stmt in stmts:
        for node, shadowed in _walk_scoped(stmt, names):
            if not (
                isinstance(node, JsIdentifier)
                and node.name in names
                and node.name not in shadowed
                and is_reference(node)
                and is_member_write_target(node)
            ):
                continue
            if (owner := _own_run(node, activations)) is None:
                return False
            for activation in wrappers:
                if node.name not in activation.inherited:
                    continue
                wrapper = activation.function
                assert wrapper is not None
                creator = _creating_activation(wrapper, activations, main)
                while creator.function is not None and node.name in creator.inherited:
                    wrapper = creator.function
                    creator = _creating_activation(wrapper, activations, main)
                if _own_run(wrapper, activations) != owner:
                    return False
                order = main_order if owner == _MAIN_RUN else orders[owner]
                if creator is not (main if owner == _MAIN_RUN else activations[owner]):
                    return False
                if not order.runs_only_before(node, wrapper):
                    return False
    return True


_MAIN_RUN = 0
"""
The key `_own_run` gives the code of the main run, which no wrapper's `id` can be.
"""


def _own_run(node: Node, activations: dict[int, _Activation]) -> int | None:
    """
    The run whose own code holds *node*: the `id` of the innermost resolved wrapper whose body holds
    it, or `_MAIN_RUN`; `None` where another function or a class body holds it first, whose code
    runs whenever it is called or constructed.
    """
    cursor: Node | None = node.parent
    while cursor is not None:
        if isinstance(cursor, FUNCTION_NODES):
            return id(cursor) if id(cursor) in activations else None
        if isinstance(cursor, JsClassBody):
            return None
        cursor = cursor.parent
    return _MAIN_RUN


def _reenters(
    node: JsFunctionExpression,
    initial_state: list[_StateValue],
    entries: dict[int, list[_StateValue]],
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


class _ArgumentSlot(NamedTuple):
    """
    A slot an argument store fills, and the default an element `slot = default` gives it.
    """
    target: Expression
    default: Expression | None


def _argument_slots(
    pattern: JsArrayExpression | JsArrayPattern,
    activation: _Activation,
) -> tuple[list[_ArgumentSlot], Expression | None] | None:
    """
    The slots an argument store `[s1, …, sn] = rest` or `[s1, …, ...r] = rest` fills, in order,
    and the slot taking the remaining arguments where the pattern ends in a rest element. `None`
    where one of them is not a slot of *activation*'s own scope object (`_is_activation_slot`), or
    the pattern skips an element. An element may carry a default, `s = d`.
    """
    elements = list(pattern.elements)
    remainder: Expression | None = None
    if elements and isinstance(last := elements[-1], (JsRestElement, JsSpreadElement)):
        remainder = last.argument
        elements.pop()
        if not _is_activation_slot(remainder, activation):
            return None
    slots: list[_ArgumentSlot] = []
    for element in elements:
        target, default = element, None
        if isinstance(element, JsAssignmentPattern):
            target, default = element.left, element.right
        if target is None or not _is_activation_slot(target, activation):
            return None
        slots.append(_ArgumentSlot(target, default))
    return slots, remainder


def _activation_slot_identity(node: Node, activation: _Activation) -> tuple[str, ...] | None:
    """
    What *node* names of the scope object of *activation*: `(namespace, key)` for a member of a
    namespace the object is created with, `(name,)` for a variable the run keeps on the object, `()`
    for a namespace itself, and `None` for anything else.
    """
    if isinstance(node, JsIdentifier):
        if node.name in activation.namespaces:
            return ()
        if node.name in activation.props and node.name not in activation.inherited:
            return (node.name,)
        return None
    if (
        isinstance(node, JsMemberExpression)
        and isinstance(node.object, JsIdentifier)
        and node.object.name in activation.namespaces
        and (key := access_key(node)) is not None
    ):
        return (node.object.name, key)
    return None


def _is_anonymous_definition(node: Node | None) -> bool:
    """
    Whether *node* defines a function or a class without a name of its own, which a binding of a
    plain name gives the name it binds: an arrow, or a function or class expression with no name.
    """
    node = strip_parens(node)
    if isinstance(node, JsArrowFunctionExpression):
        return True
    return isinstance(node, (JsFunctionExpression, JsClassExpression)) and node.id is None


def _default_reads(
    default: Expression,
    earlier: list[Expression],
    function: JsFunctionExpression,
    activation: _Activation,
) -> dict[Node, int] | None:
    """
    Whether the default *default* of an element of the argument store can become the default of its
    parameter, and the reads in it that become reads of an earlier parameter. A default reads the
    elements before it, stored before it is evaluated, and where it reads one of them plainly, the
    read becomes that parameter (`_unpack_argument_stores`). `None` where the default reads `this`,
    a name the body binds, or any other part of what the run keeps on its scope object: its own
    element or a later one, which the parameter list has not stored, a namespace as a whole, a
    store to one, a call through one, which hands the namespace on as `this`, and a read under a
    function, which reads it when called. `None` as well where the default holds a direct `eval`,
    which the parameter list runs where no name of the body exists, and where it is a function or a
    class without a name of its own, which a parameter names after itself and an element of the
    store, a member, leaves unnamed (`_is_anonymous_definition`).
    """
    if _is_anonymous_definition(default):
        return None
    bound = _function_bound_names(function)
    slots = {
        identity: index for index, target in enumerate(earlier)
        if (identity := _activation_slot_identity(target, activation))
    }
    reads: dict[Node, int] = {}

    def visit(node: Node, nested: bool) -> bool:
        if isinstance(node, JsThisExpression) or is_direct_eval_call(node):
            return False
        if isinstance(node, JsIdentifier) and not is_reference(node):
            return True
        if isinstance(node, JsIdentifier) and node.name in bound:
            return False
        if (identity := _activation_slot_identity(node, activation)) is not None:
            if (
                nested
                or not identity
                or (index := slots.get(identity)) is None
                or is_member_write_target(node)
                or is_invocation_target(node)
            ):
                return False
            reads[node] = index
            return True
        inner = nested or isinstance(node, FUNCTION_NODES)
        return all(visit(child, inner) for child in node.children())

    return reads if visit(default, False) else None


def _unpack_argument_stores(
    function: JsFunctionExpression,
    activation: _Activation,
    order: _RunOrder,
) -> None:
    """
    Give a wrapper whose run owns its scope object the parameters its run stores its arguments into.
    A run starts by destructuring the argument holder into slots of its own scope object, as in
    `[NS.a, NS.b] = rest` for the wrapper `function (...rest)`, and a function whose own parameters
    ended in a rest parameter is stored as `[NS.a, ...NS.r] = rest`. Where the rest parameter is
    read by such stores and nothing else, the wrapper takes the parameters `(a, ...r)` and the store
    becomes the statements `NS.a = a; NS.r = r;`: every slot receives what it received, the
    remainder being an array of the same arguments. Each store is a statement of its own, where the
    passes that drop a dead store or fold a read copy into its parameter reach it, and runs when the
    store it replaces ran in the run of the wrapper (*order*, `_RunOrder.replace`). Every store has
    to be a statement of the body itself, which runs once per call: the destructuring makes a new
    array each time it runs, and the rest parameter is one array per call. The wrapper's `length`
    counts the new parameters, as the function the obfuscator flattened counted them, and the
    destructuring's array iterator is trusted the way the recovery trusts the rest of the
    obfuscator's scaffolding. A body that reads its own `arguments`, whose elements a simple
    parameter list aliases, is left alone, and the list is the one
    `refinery.lib.scripts.js.deobfuscation.parameters.parameter_list` writes. A parameter takes a
    name no identifier and no static key of the function spells.

    An element with a default, `[NS.a, NS.b = d] = rest`, gives its parameter that default where the
    destructuring is the first statement of the body and `_default_reads` admits it: the default
    reads no `this`, no name the body binds, and of the scope object only a plain read of an element
    before it, which becomes a read of that element's parameter. The store

        [NS.a, NS.b = NS.a] = rest;

    gives the wrapper the parameters `(a, b = a)`.
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
    stores: list[tuple[JsAssignmentExpression, list[_ArgumentSlot], Expression | None]] = []
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
    taken.update(
        key for node in function.walk()
        if isinstance(node, JsMemberExpression) and (key := access_key(node)) is not None
    )

    def fresh(slot: Expression) -> str:
        base = _deepest_property_name(slot)
        name = fresh_name(base if base and is_valid_identifier(base) else 'p', taken.__contains__)
        taken.add(name)
        return name

    defaults: dict[int, tuple[Expression, dict[Node, int]]] = {}
    for store, slots, _ in stores:
        for index, (_, default) in enumerate(slots):
            if default is None:
                continue
            if len(stores) > 1 or store.parent is not function.body.body[0]:
                return
            earlier = [slot.target for slot in slots[:index]]
            if (reads := _default_reads(default, earlier, function, activation)) is None:
                return
            defaults[index] = default, reads
    names: list[str] = []
    for index in range(max(len(slots) for _, slots, _ in stores)):
        target = next(slots[index].target for _, slots, _ in stores if index < len(slots))
        names.append(fresh(target))
    remainders = [remainder for _, _, remainder in stores if remainder is not None]
    remainder_name = fresh(remainders[0]) if remainders else None

    def parameter(index: int, name: str) -> Expression:
        if index not in defaults:
            return JsIdentifier(name=name)
        default, reads = defaults[index]
        value = _clone_node(default)
        for node, copy in list(zip(default.walk(), value.walk())):
            if (slot := reads.get(node)) is None:
                continue
            if copy is value:
                value = JsIdentifier(name=names[slot])
            else:
                _replace_in_parent(copy, JsIdentifier(name=names[slot]))
        return JsAssignmentPattern(left=JsIdentifier(name=name), right=value)

    new_params: list[Expression] = [parameter(index, name) for index, name in enumerate(names)]
    if remainder_name is not None:
        new_params.append(JsRestElement(argument=JsIdentifier(name=remainder_name)))
    parameters = parameter_list(new_params, function, None)
    if parameters is None:
        return
    for store, slots, remainder in stores:
        assignments: list[Expression] = [
            JsAssignmentExpression(operator='=', left=slot.target, right=JsIdentifier(name=name))
            for slot, name in zip(slots, names)
        ]
        if remainder is not None and remainder_name is not None:
            assignments.append(JsAssignmentExpression(
                operator='=', left=remainder, right=JsIdentifier(name=remainder_name)))
        statement = store.parent
        assert statement is not None and function.body is not None
        body = function.body.body
        at = next(index for index, kept in enumerate(body) if kept is statement)
        separate: list[Statement] = [
            JsExpressionStatement(expression=assignment) for assignment in assignments
        ]
        set_child_list(function.body, 'body', [*body[:at], *separate, *body[at + 1:]])
        order.replace(statement, separate)
    set_child_list(function, 'params', parameters.build())


def _walk_all(stmts: list[Statement]):
    for stmt in stmts:
        yield from stmt.walk()


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
    match: _MachineMatch,
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
    return fresh_name(match.arg_var_name, taken.__contains__)


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


def _collect_scope_props(stmts: list[Statement], match: _MachineMatch) -> None:
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


def _namespace_keys_read(
    stmts: list[Statement],
    namespaces: set[str],
    names: set[str],
) -> dict[str, set[str] | None]:
    """
    For each namespace in *namespaces*, the keys *stmts* read from it where nothing between the
    statement and the read binds the namespace's name anew, or `None` where they may read any key:
    under a key only known at runtime, or through the namespace itself, which any use but as the
    object of an access under a static key hands on whole, as `JSON.stringify(NS)` and `k in NS`
    do. Everything but the target of a plain `=` reads the key. The names *stmts* read bare count
    as keys read from every namespace, since a `with` statement may have resolved one to a member.
    A read through a reference to the namespace that *stmts* do not spell with its name, the
    receiver of a method called on it, is not seen: the recovery trusts that the obfuscator never
    calls a method of a namespace on the namespace.
    """
    if not namespaces:
        return {}
    watched = frozenset(namespaces)
    keys: dict[str, set[str] | None] = {name: set(names) for name in namespaces}
    for stmt in stmts:
        for node, shadowed in _walk_scoped(stmt, watched):
            if (
                not isinstance(node, JsIdentifier)
                or (name := node.name) not in watched
                or name in shadowed
                or not is_reference(node)
                or (read := keys[name]) is None
            ):
                continue
            member = node.parent
            if not isinstance(member, JsMemberExpression) or member.object is not node:
                keys[name] = None
            elif is_simple_assignment_target(member):
                continue
            elif (key := access_key(member)) is None:
                keys[name] = None
            else:
                read.add(key)
    return keys


def _remove_dead_scope_writes(
    stmts: list[Statement],
    dead: set[str],
    keys_read: dict[str, set[str] | None],
    known: set[str],
) -> list[Statement]:
    """
    Remove the stores the statements *stmts* of a body make at their top level to scope slots
    nothing reads: a write-only scope variable in *dead* where the value has no effect
    (`_is_pure_rhs`, with the names *known* to be declared), and a number stored in a member of a
    namespace under a key *keys_read* does not list for it (`_namespace_keys_read`), as the
    obfuscator stores its routing values, whose only readers were the case tests the recovery
    removes. A store goes as a whole statement, as one expression of a comma sequence, or as one
    pair of target and value in a destructuring of an array literal (`_store_pairs`).
    """
    def is_dead(target: Expression, value: Expression) -> bool:
        if isinstance(target, JsIdentifier):
            return target.name in dead and _is_pure_rhs(value, known)
        return (
            isinstance(target, JsMemberExpression)
            and isinstance(target.object, JsIdentifier)
            and (read := keys_read.get(target.object.name)) is not None
            and (key := access_key(target)) is not None
            and key not in read
            and _eval_number(value) is not None
        )

    def live_part(expr: Expression) -> Expression | None:
        if (pairs := _store_pairs(expr)) is None:
            return expr
        live = [(target, value) for target, value in pairs if not is_dead(target, value)]
        if len(live) == len(pairs):
            return expr
        if not live:
            return None
        if len(live) == 1 and _is_pure_rhs(live[0][1], known):
            target, value = live[0]
            return JsAssignmentExpression(operator='=', left=target, right=value)
        return JsAssignmentExpression(
            operator='=',
            left=JsArrayPattern(elements=[target for target, _ in live]),
            right=JsArrayExpression(elements=[value for _, value in live]),
        )

    return _rewrite_comma_parts(stmts, live_part)


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
    but never read), members of the namespaces the object is created with among them, are dropped
    (`_remove_dead_scope_writes`). Slots already declared and the namespaces the object is created
    with or hands on are left to their own declarations; an in-body namespace (created by a
    `scope.X = {}` write) is a slot like any other, so it is declared here.
    """
    props = activation.props
    reads: set[str] = set()
    for stmt in recovered:
        _collect_read_names(stmt, reads)
    dead = {p for p in props if p not in reads}
    keys_read = _namespace_keys_read(recovered, set(activation.namespaces), reads)
    declared = _declared_names_in_stmts(recovered)
    known = props | activation.inherited | set(activation.namespaces) | declared
    recovered = _remove_dead_scope_writes(recovered, dead, keys_read, known)
    present: set[str] = set()
    for stmt in recovered:
        for node in stmt.walk():
            if isinstance(node, JsIdentifier):
                present.add(node.name)
    exclude = declared | set(activation.namespaces) | activation.inherited
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


def _bind_main_arguments(recovered: list[Statement], match: _MachineMatch) -> bool:
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
    match: _MachineMatch,
    trailing: list[Statement],
    wrapped: bool,
    returns: _RunReturns,
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
    wrapper called during the call would make the guard return where the recovered code runs on,
    and so does a return that raises the flag where the run may go on (`_RunReturns.intercepted`).
    Without either, every return falls through, and `sanitize_inlined_body` writes the one at the
    end as the expression it returns.
    """
    if match.returns_value:
        return None if trailing else recovered
    if match.guarded:
        if returns.plain or (trailing and (wrapped or returns.intercepted)):
            return None
        return recovered
    return sanitize_inlined_body(recovered)


def _scaffolding_is_private(
    model: SemanticModel,
    body: list[Statement],
    match: _MachineMatch,
    absent: Callable[[str], bool],
) -> bool:
    """
    Whether nothing but the scaffolding the recovery removes can reach a binding it removes: the
    generator, and the flag and the result of its call (`_reached_only_from`), each a `var` of the
    function holding the call, as the obfuscator writes them, or a function declaration. The flag
    lives as long as one call of that function does: a variable it declares, or a property of an
    object it makes for each call (`_property_flag_is_private`). A flag every call shares could be
    raised by a call the recovered code makes before the guard reads it. Every name that spells
    `undefined` in the scaffolding has to denote it. No opaque reflective surface, such as a direct
    `eval` in the code of the generator, may name one of its parameters: the recovery moves that
    code out of the generator, where the name no longer exists
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.reflection_surface_sites`).
    """
    if any(
        (binding := model.binding_of(name)) is None or model.reflection_surface_sites(binding)
        for param in match.machine.params
        for name in pattern_identifiers(param)
    ):
        return False
    removed = match.removed(body)
    inside = {id(node) for statement in removed for node in statement.walk()}
    home = model.scope_of(body[match.scaffolding_end])
    if (holder := _held_generator(removed[0])) is None or home is None:
        return False
    flag = match.flag
    names = {match.result_var}
    if isinstance(flag, _FlagVariable):
        names.add(flag.name)
    named = [
        node for statement in removed[1:] for node in statement.walk()
        if isinstance(node, JsIdentifier) and node.name in names
    ]
    anchors: dict[str, Binding] = {}
    for anchor in [holder[1], *named]:
        binding = model.binding_of(anchor) or model.resolve(anchor)
        if binding is None or binding.is_lexical:
            return False
        anchors.setdefault(anchor.name, binding)
    if isinstance(flag, _FlagVariable):
        if (binding := anchors.get(flag.name)) is None or not binding.declared_within(home.node):
            return False
    elif isinstance(flag, _FlagProperty):
        if not _property_flag_is_private(model, body, match, flag, home, inside, absent):
            return False
    if not all(_reached_only_from(model, binding, inside) for binding in anchors.values()):
        return False
    return all(denoted_value(read, model) == (True, None) for read in match.undefined_reads)


def _property_flag_is_private(
    model: SemanticModel,
    body: list[Statement],
    match: _MachineMatch,
    flag: _FlagProperty,
    home: Scope,
    inside: set[int],
    absent: Callable[[str], bool],
) -> bool:
    """
    Whether the property *flag* is a variable of one call of the function whose scope is *home*,
    which only the nodes whose ids are *inside* reach. Its holder is a `var` of that function,
    declared once, with an empty object literal, by a statement of *body* ahead of the generator,
    so it holds an object of its own whenever the call runs. Every reference to the holder reaches
    that object as a namespace
    (`refinery.lib.scripts.js.deobfuscation.namespaces.namespace_accesses`) under keys *absent*
    proves no prototype supplies, so each of them is a property of data. What reaches the flag's
    key, and every reflective surface that could name the holder, stands inside.
    """
    references = (
        node for statement in match.removed(body)[1:]
        for node in statement.walk()
        if isinstance(node, JsIdentifier) and node.name == flag.holder and is_reference(node)
    )
    anchor = next(references, None)
    if anchor is None or (binding := model.binding_of(anchor) or model.resolve(anchor)) is None:
        return False
    if binding.scope is not home or binding.is_lexical:
        return False
    declarations = list(binding.declarations)
    if len(declarations) != 1:
        return False
    declarator = declarations[0].parent
    if not (
        isinstance(declarator, JsVariableDeclarator)
        and declarator.id is declarations[0]
        and isinstance(declarator.init, JsObjectExpression)
        and not declarator.init.properties
        and any(
            declarator.parent is statement
            for statement in body[:match.call_start] if statement is not body[match.machine_index]
        )
    ):
        return False
    accesses = namespace_accesses([*model.references(binding), *binding.dynamic_refs])
    if accesses is None or not all(absent(key) for key in accesses):
        return False
    if not all(id(access) in inside for access in accesses.get(flag.key, ())):
        return False
    return all(id(node) in inside for node in model.reflection_surface_sites(binding))


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
    match: _MachineMatch,
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
    removed = match.removed(body)
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
            if any(not home.contains(copy.var.scope, strict=True) for copy in binding.copies_made):
                return False
    return True


def _leaves_the_generator(recovered: list[Statement], match: _MachineMatch) -> bool:
    """
    Whether *recovered* still refers to a binding the recovery removes: the generator under any of
    its names, its parameters, or the scaffolding variables of its call. Such a reference would be
    left to resolve to whatever the code around it binds under that name, or to nothing. A flag
    that is a property of a variable is still referred to where the code reads or writes that
    property.
    """
    flag = match.flag
    names = {
        match.scope_param_name,
        match.arg_var_name,
        match.result_var,
        match.runtime_name,
        *match.state_var_names,
        *match.machine_names,
    }
    if isinstance(flag, _FlagVariable):
        names.add(flag.name)
    names.discard(None)
    if any(True for _ in _references_to(recovered, frozenset(names))):
        return True
    if not isinstance(flag, _FlagProperty):
        return False
    return any(
        isinstance(access := node.parent, JsMemberExpression)
        and access.object is node
        and access_key(access) == flag.key
        for node in _references_to(recovered, frozenset({flag.holder}))
    )


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


def _values_the_recovery_binds(
    model: SemanticModel,
    roots: Sequence[Node],
    match: _MachineMatch,
) -> Iterator[Node]:
    """
    The values under *roots* that the recovery of *match* hands to bindings where the scaffolding
    kept them in properties: what the scope object receives — from the parameter's default, from a
    literal a call of the generator passes, and from a store to one of its slots — and what a store
    to a name a `with` statement resolves stores. A pattern storing into one of these yields every
    node of its right side that may denote a value, since which of them reaches the slot is not
    read here.

    A store to a member of a namespace the scope object holds is not one of them: the recovery
    declares the namespace, not its keys, so the value stays where no binding holds it. A store
    the model does not know was made by an earlier recovery of the invocation, which judged it.
    """
    for root in roots:
        for node in root.walk():
            if isinstance(node, JsAssignmentPattern):
                target = node.left
                if isinstance(target, JsIdentifier) and target.name == match.scope_param_name:
                    yield from _literal_values(node.right)
            elif isinstance(node, JsCallExpression):
                if any(
                    isinstance(leaf, JsIdentifier) and leaf.name in match.machine_names
                    for leaf in denoting_leaves(node.callee)
                ):
                    for argument in node.arguments:
                        yield from _literal_values(argument)
            elif isinstance(node, JsAssignmentExpression) and node.right is not None:
                target = strip_parens(node.left)
                if isinstance(target, (JsIdentifier, JsMemberExpression)):
                    if _stores_into_the_scope(model, target, match):
                        yield node.right
                elif _stores_into_the_scope_through(model, target, match):
                    yield from (
                        value for value in node.right.walk()
                        if isinstance(value, (JsIdentifier, JsThisExpression, JsMemberExpression))
                    )


def _literal_values(node: Node | None) -> Iterator[Node]:
    """
    The values of the properties of *node* where it is an object literal.
    """
    if isinstance(node, JsObjectExpression):
        for prop in node.properties:
            if isinstance(prop, JsProperty) and prop.value is not None:
                yield prop.value


def _stores_into_the_scope(model: SemanticModel, target: Node, match: _MachineMatch) -> bool:
    """
    Whether a store to *target* stores into a slot of the scope object of *match*: through its
    parameter, or through a name a `with` statement resolves, which no binding below the statement
    holds and the model knows to cross it.
    """
    if isinstance(target, JsMemberExpression):
        holder = strip_parens(target.object)
        return isinstance(holder, JsIdentifier) and holder.name == match.scope_param_name
    return (
        isinstance(target, JsIdentifier)
        and model.knows(target)
        and model.resolve(target) is None
        and model.read_has_dynamic_effect(target)
    )


def _stores_into_the_scope_through(
    model: SemanticModel,
    pattern: Node | None,
    match: _MachineMatch,
) -> bool:
    """
    Whether the pattern *pattern* stores into a slot of the scope object of *match* at one of its
    positions (`_stores_into_the_scope`).
    """
    if pattern is None:
        return False
    return any(_stores_into_the_scope(model, position, match) for position in pattern.walk())


def _bindings_past_the_with(model: SemanticModel, roots: Sequence[Node]) -> Iterator[Binding]:
    """
    The bindings outside a `with` statement under *roots* that a name the statement may resolve
    reaches past it (`refinery.lib.scripts.js.analysis.model.SemanticModel.lookup` across it).
    While the statement stands, a write through such a name is attributed to the name alone; the
    recovery removes the statement, after which the name resolves to the binding and a write
    through it is attributed to what the binding holds. A name the model does not know stands in
    code an earlier recovery of the invocation made, which judged it.
    """
    for root in roots:
        for node in root.walk():
            if isinstance(node, JsIdentifier) and model.read_has_dynamic_effect(node):
                binding = model.lookup(node.name, model.scope_of(node), cross_dynamic=True)
                if binding is not None:
                    yield binding


def _recovery_reveals(
    model: SemanticModel,
    scan: IntrinsicWrites,
    removed: list[Statement],
    recovered: list[Statement],
    match: _MachineMatch,
) -> bool:
    """
    Whether replacing the scaffolding *removed* of *match* with *recovered* shows the models a
    write the held ones do not record: a store the recovery turns into a binding store hands the
    binding a value the scan follows only through bindings (`_values_the_recovery_binds`), the
    removed `with` statement stood between a name and a binding whose values denote a root the scan
    watches (`_bindings_past_the_with`), or the recovered code declares or assigns a name the scan
    watches (`refinery.lib.scripts.js.deobfuscation.helpers.declares_a_watched_name`).
    """
    return (
        any(
            scan.follows_only_through_bindings(value)
            for value in _values_the_recovery_binds(model, removed, match)
        )
        or any(
            scan.denotes_a_watched_root(binding)
            for binding in _bindings_past_the_with(model, removed)
        )
        or declares_a_watched_name(recovered)
    )


class _Calls:
    """
    The calls of the program's own functions a run of the machine makes, run by the shared
    admission (`refinery.lib.scripts.js.deobfuscation.admission.CallAdmission`) on the values the
    run computes. It is asked only about a call of the machine being decided, a node of the tree
    it holds, and answers each call once for each value of its arguments (`_value_key`). The
    admission is built on the first question, over the models the cache holds then, and again
    wherever the cache holds another effect model: what it derived from one tree is no answer about
    another.
    """

    def __init__(self, models: ModelCache, script: JsScript):
        self._models = models
        self._script = script
        self._admission: CallAdmission | None = None
        self._admitted: dict[Node, JsFunctionNode | None] = {}
        self._memo: dict[tuple[object, ...], _Value | None] = {}

    def _current(self) -> CallAdmission:
        admission = self._admission
        if admission is None or admission.effects is not self._models.effects:
            self._admission = admission = CallAdmission(self._models, self._script)
            self._admitted.clear()
            self._memo.clear()
        return admission

    def iterates_arrays(self, node: Node) -> bool:
        """
        Whether a spread of an array at *node* yields its elements: the prototype chain of an array
        is intact there, the question a `for-of` walk of the interpreter asks.
        """
        trust = self._current().trust_at(node)
        return trust is not None and trust.chain(list)

    def __call__(self, node: JsCallExpression, arguments: list[_Value]) -> _Value | None:
        """
        The value the call *node* gives with *arguments*, or `None` where the admission does not
        run it, an argument is `undefined`, the run is refused or throws, or its result is no value
        a run of the machine holds: a number, a boolean, a string, or an array of numbers, which a
        Buffer is not. An array argument is the state of the machine or an array made from it, and
        the helper is handed a copy: two array arguments may be one object, which two copies are
        not, so such a call is not run, and a helper that changes the array it is handed changes
        the state, which the run does not follow (`_left_as_handed`), so its value is not taken.
        """
        admission = self._current()
        if not admission.holds(node):
            return None
        if sum(isinstance(argument, tuple) for argument in arguments) > 1:
            return None
        values: list[Value] = []
        for argument in arguments:
            if isinstance(argument, _Undefined):
                return None
            values.append(list(argument) if isinstance(argument, tuple) else argument)
        if node not in self._admitted:
            self._admitted[node] = admission.callee(node)
        if (function := self._admitted[node]) is None:
            return None
        key = (node, *map(_value_key, arguments))
        if key in self._memo:
            return self._memo[key]
        try:
            result = admission.interpreter_at(node).execute(function, values)
        except (InterpreterError, IrreducibleExpression, _ThrowSignal):
            result = None
        value: _Value | None
        if not all(map(_left_as_handed, values, arguments)):
            value = None
        elif isinstance(result, (bool, str)):
            value = result
        elif isinstance(result, (int, float)):
            value = float(result)
        elif (
            type(result) is list
            and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in result)
        ):
            value = tuple(float(x) for x in result)
        else:
            value = None
        self._memo[key] = value
        return value


def _left_as_handed(handed: Value, argument: _Value) -> bool:
    """
    Whether a run of a helper left *handed*, what it was given for *argument*, as it was given: an
    array still holds the same numbers.
    """
    if not isinstance(argument, tuple):
        return True
    return (
        isinstance(handed, list)
        and len(handed) == len(argument)
        and all(
            isinstance(x, (int, float)) and not isinstance(x, bool) and _same_value(float(x), y)
            for x, y in zip(handed, argument)
        )
    )


class _Design:
    """
    What one design of the flattening spells its own way: the machine and the call that runs it
    (`match`), the state that call starts in (`read_start`), and the call a wrapper of the machine
    makes (`wrapper`). Blocks, transitions, structuring, returns, wrappers and the checks that the
    scaffolding is private are shared.
    """

    runs_helpers: bool = False
    """
    Whether the values of a run are made by calls of the program's own functions, which the shared
    admission runs (`_Calls`).
    """

    def match(self, body: list[Statement], idx: int) -> _MachineMatch | None:
        """
        The machine of this design declared at index *idx* of *body*, with its call site.
        """
        raise NotImplementedError

    def read_start(self, match: _MachineMatch) -> bool:
        """
        Read the state the call of the machine starts in into *match*; `False` where it is not
        known.
        """
        return True

    def wrapper(self, node: JsFunctionExpression, match: _MachineMatch) -> _WrapperFunctionInfo | None:
        """
        The call of the machine *node* makes where it is a wrapper of the machine of *match*.
        """
        raise NotImplementedError


class _GeneratorDesign(_Design):
    """
    A generator whose state is several variables, run by `M(…).next().value`; the matcher reads
    the state it starts in from the numbers of its call.
    """

    def match(self, body: list[Statement], idx: int) -> _MachineMatch | None:
        return _match_generator_cff(body, idx, self)

    def wrapper(self, node: JsFunctionExpression, match: _MachineMatch) -> _WrapperFunctionInfo | None:
        return _detect_wrapper_function(node, match.machine_names, len(match.state_var_names))


class _ArrayDesign(_Design):
    """
    A plain function whose state is one array of numbers, summed by a function of the program, run
    by `M(array)`. The array of the call is evaluated with the call as the anchor of every question
    the run asks, and only once the match is decided on: what it calls is run by the shared
    admission, which the pass builds for the tree its held models were built over.
    """

    runs_helpers = True

    def match(self, body: list[Statement], idx: int) -> _MachineMatch | None:
        return _match_array_machine(body, idx, self)

    def read_start(self, match: _MachineMatch) -> bool:
        entry = _eval_expr(match.initial_args[0], _Env({}, calls=match.calls))
        if not isinstance(entry, tuple):
            return False
        match.initial_state = [entry]
        return True

    def wrapper(self, node: JsFunctionExpression, match: _MachineMatch) -> _WrapperFunctionInfo | None:
        return _detect_plain_wrapper(node, match)


_DESIGNS: tuple[_Design, ...] = (_GeneratorDesign(), _ArrayDesign())


class JsStateMachineUnflattening(PinnedTransformer, BodyProcessingTransformer):
    """
    Recover original code from functions flattened into a state machine: the body of a function is
    replaced by a call of a machine function, a `while`/`switch` loop whose discriminant is the sum
    of its state. Two designs write the machine (`_Design`): a generator function whose state is
    several variables, and a plain function whose state is one array of numbers, summed by a
    function of the program, whose values the program's own functions compute (`_Calls`).

    The pass holds the models it reads for an invocation
    (`refinery.lib.scripts.js.deobfuscation.helpers.PinnedTransformer`): the semantic model, the
    intrinsic-write scan, and the effect, dominance and tampering models the shared admission of
    calls is built over. A recovery replaces the scaffolding of a machine with code made from
    copies of its states, and leaves the answers about the next machine no more permissive than
    rebuilt ones:

    - Whether the scaffolding is private (`_scaffolding_is_private`) is asked of the bindings the
      recovery of that machine removes, which are its own: no other recovery declares or reaches
      them.
    - Whether the recovered code declares only its own names (`_declares_only_its_own_names`) is
      asked of the function around the machine outside its scaffolding. Before deciding a machine
      whose body, or whose function outside the scaffolding, holds a body the invocation edited
      since the last renewal, the pass renews.
    - Whether a plain object inherits a routing key (`_provably_absent`) is read off the scan, which
      a recovery changes only where it turns a store of a value the scan follows only through
      bindings into a binding store, where it removes the `with` statement between a name and a
      binding whose values denote a root the scan watches, or where its code declares or assigns a
      name the scan watches (`_recovery_reveals`). After such a recovery, the pass renews.
    - Whether a call the machine makes may be run, and what it gives (`_Calls`), is asked only
      about a call of the machine being decided, on a node of the tree the held models were built
      over: before it builds the admission, the pass renews where it edited since the last
      renewal. A recovery puts copies of the machine's own blocks where its call stood, so a call
      or a store of a built-in the held models know of runs where it ran.
    """

    reads = ('_model', '_intrinsic_writes', '_effects', '_dominance', '_tampering')

    def __init__(self):
        super().__init__()
        self._edited: dict[Node, list[Node]] = {}
        self._calls: _Calls | None = None

    def visit_JsScript(self, node: JsScript):
        with self.holding_models(node):
            return super().visit_JsScript(node)

    def _forget_edits(self) -> None:
        self._edited = {}
        self._calls = None

    def _note_edit(self, body: Node) -> None:
        """
        Record that the invocation edited *body*, under the script and every function that holds it,
        which are the places `_edited_around` asks about.
        """
        cursor: Node | None = body
        while cursor is not None:
            if isinstance(cursor, (JsScript, *FUNCTION_NODES)):
                self._edited.setdefault(cursor, []).append(body)
            cursor = cursor.parent

    def _edited_around(self, parent: Node, removed: list[Statement]) -> bool:
        """
        Whether a body the invocation edited since the last renewal is *parent*, the body holding a
        machine, or lies in the function holding it outside the scaffolding *removed*.
        """
        function = parent if isinstance(parent, JsScript) else parent.parent
        if function is None:
            return False
        return any(
            body is parent or not any(body.is_descendant_of(statement) for statement in removed)
            for body in self._edited.get(function, ())
        )

    def _provably_absent(self, key: str) -> bool:
        """
        Whether a plain object that does not own *key* reads `undefined` under it, and a store there
        makes a property of data: no prototype the language installs holds the key, and the program
        writes no prototype of a plain object
        (`refinery.lib.scripts.js.analysis.intrinsics.IntrinsicWrites.chain_roots_unwritten`), or
        at least not this key
        (`refinery.lib.scripts.js.analysis.intrinsics.IntrinsicWrites.key_written`), as a file
        patching another key of `Object`, such as a polyfill, does not.
        """
        scan = self.held_models().intrinsic_writes
        return property_absent_from_written_chain(None, dict, key) and (
            scan.chain_roots_unwritten(dict) or not scan.key_written('Object', key)
        )

    def _process_body(self, parent: Node, body: list[Statement]) -> None:
        if not _is_a_function_body(parent):
            return
        i = 0
        while i < len(body):
            match = next((m for design in _DESIGNS if (m := design.match(body, i))), None)
            if match is None:
                i += 1
                continue
            design = match.design
            models = self.held_models()
            removed = match.removed(body)
            if (
                self._edited_around(parent, removed)
                or design.runs_helpers and self._calls is None and self._edited
            ):
                self.renew_models()
            if design.runs_helpers:
                if self._calls is None:
                    root = tree_root(parent)
                    assert isinstance(root, JsScript)
                    self._calls = _Calls(self.held_models(), root)
                match.calls = self._calls
            if not design.read_start(match):
                i += 1
                continue
            model = models.model
            if _an_observed_copy_may_not_be_made(model, match.machine):
                i += 1
                continue
            if not _scaffolding_is_private(model, body, match, self._provably_absent):
                i += 1
                continue
            if (
                match.routed
                and _spells_an_inherited_name_bare(match.switch_stmt, self._provably_absent)
            ):
                i += 1
                continue
            machine = _extract_state_blocks(match, self._provably_absent)
            if machine is None:
                i += 1
                continue
            slots = _initial_slots(
                machine.routing,
                match.scope_param_name,
                match.scope_default_inits,
                set(),
                {},
                self._provably_absent,
            )
            result = _execute_machine(machine, match, slots, main=True)
            if result is None:
                i += 1
                continue
            recovered = result.statements
            main = _Activation(
                None,
                match.scope_default_inits,
                props=match.scope_prop_names,
                routing=result.settled,
            )
            wrappers = _resolve_shared_wrappers(
                recovered, machine, match, main, result.order, self._provably_absent
            )
            if (
                wrappers is None
                or not _bind_main_arguments(recovered, match)
                or not _slots_may_become_variables(match, wrappers, self._provably_absent)
            ):
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
                result.returns,
            )
            if settled is None:
                i += 1
                continue
            recovered = settled
            for s in recovered:
                s.parent = parent
            start = match.machine_index
            end = match.scaffolding_end
            reveals = _recovery_reveals(model, models.intrinsic_writes, removed, recovered, match)
            between = body[start + 1:match.call_start]
            replacement = body[:start] + between + recovered + body[end + 1:]
            self._replace_body(parent, replacement)
            self._note_edit(parent)
            if reveals:
                self.renew_models()
            i = start + len(between) + len(recovered)
