"""
Per-function effect summaries for JavaScript, computed over the
`refinery.lib.scripts.js.analysis.model.SemanticModel`'s resolved bindings and call graph. A summary
records, conservatively, what observable effects *one call* of a function may have — writing a
global, mutating a binding captured from an enclosing scope, throwing, or invoking code the analysis
cannot account for — from which a single `is_pure` verdict follows.

This is the second layer of the analysis substrate. Like the model it sits on, it is *flow-insensitive*
and conservative by construction: every effect is an over-approximation (when in doubt, an effect is
reported), so a function judged pure is pure on every path, and callers may treat a pure call whose
result is unused as removable. The summary deliberately does not model termination; purity here means
freedom from observable effects, not a guarantee that the call returns. The one ordering question it
does answer is the temporal dead zone of a binding the function itself owns, where the read and its
declaration both run inside the call and no call site can order them: the summary consults the
`refinery.lib.scripts.js.analysis.dominance.DominanceModel` — the one `build_effects` accepts, or a
private one built on demand — for that alone, so deleting a call never drops the `ReferenceError`
such a read raises.

Purity of a call to a built-in (for example `String.fromCharCode`) is asserted only under a verified
*pristine-intrinsics precondition*: the whole program must not reassign or monkeypatch any intrinsic the
registry trusts, nor contain a reflection surface through which one could be replaced at runtime. When
that precondition fails the registry is disregarded and such calls are treated as unknown. A read of a
trusted intrinsic-named property off the global object (for example `globalThis.Uint8Array`) is treated
likewise, under a parallel *pristine-global precondition*: no reflective surface and no accessor installed
on the global object, so the read cannot run a user getter.

Symmetrically, an assignment is not counted as a write when nothing can observe it: the assigned binding
is read nowhere, or every reference to it is confined to the assigning function so it never escapes. Both
rest on the same pristine-global precondition, since a reflective surface or an installed setter could
otherwise observe the assignment. This is what lets a function whose only effect is an obfuscator's
write-only scratch global be judged pure. A scratch name the function also *reads* is a separate
question, answered by `SemanticModel.read_may_throw` rather than here: where the name's only
binding is an implicit global, the read may run before the assignment that creates it, which this
flow-insensitive summary cannot rule out, so the function throws even though the write itself is
unobservable.

The public surface — `EffectSummary`, `EffectModel.summary_of`, `EffectModel.is_pure_call`,
`build_effects` — is representation-agnostic and keyed to AST node identity, matching the model's
contract so a later control-flow layer can sharpen the same answers without changing callers.
"""
from __future__ import annotations

import enum

from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Iterator, Sequence

from refinery.lib.scripts import Expression, Node, tree_root, tree_version
from refinery.lib.scripts.js.analysis.conversions import (
    RECEIVER_INSTALL_METHODS,
    ConversionInstalls,
    ConversionSettlement,
)
from refinery.lib.scripts.js.analysis.dominance import DominanceModel, build_dominance
from refinery.lib.scripts.js.analysis.intrinsics import (
    GLOBAL_OBJECT,
    INHERITED_CHAIN_ROOTS,
    PROTOTYPE_OWNERS,
    PURE_GLOBAL_FUNCTIONS,
    PURE_INTRINSIC_METHODS,
    PURE_INTRINSIC_ROOTS,
    SPECIES_KEYS,
    IntrinsicWrites,
    _GlobalObject,
    build_intrinsic_writes,
    unambiguous_callee,
    unambiguous_function,
)
from refinery.lib.scripts.js.analysis.environment import typeof_of_global
from refinery.lib.scripts.js.analysis.model import (
    _TESTED_FORMS,
    FUNCTION_NODES,
    GLOBAL_OBJECT_ALIASES,
    Binding,
    BindingKind,
    ContainerRole,
    Role,
    SemanticModel,
    _property_key_name,
    arguments_name_their_function,
    arguments_reads_only_elements,
    container_reference_role,
    element_positions,
    enclosing_function,
    enclosing_operator,
    is_invocation_target,
    is_member_write_target,
    is_plain_store_target,
    own_arguments_binding,
    reference_role,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAwaitExpression,
    JsBinaryExpression,
    JsBooleanLiteral,
    JsCallExpression,
    JsConditionalExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsImportExpression,
    JsLogicalExpression,
    JsMemberExpression,
    JsNewExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsProperty,
    JsPropertyKind,
    JsRestElement,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsStringLiteral,
    JsTaggedTemplateExpression,
    JsTemplateLiteral,
    JsThrowStatement,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclarator,
    JsYieldExpression,
    accessor_install_method,
    is_generator_function,
    object_member_access_runs_accessor,
    static_property_key,
    strip_parens,
    value_is_discarded,
    wraps_return,
)

_FRESH_ARRAY_RESULT_METHODS = frozenset({
    'slice',
    'concat',
    'map',
    'filter',
    'flat',
    'flatMap',
})
"""
`Array.prototype` methods the specification requires to return a *newly created* array, so a write through the
result cannot be observed through the receiver. Membership turns on that guarantee alone and not on any other
property a method may have: `join` returns a string, `reverse` and `sort` return the receiver itself, and
`splice` returns a fresh array but also mutates the receiver — none of them belong here.

Each of these routes through ArraySpeciesCreate, which reads `constructor[Symbol.species]` off the receiver, so
the guarantee holds only for a receiver whose prototype and `constructor` the program has left alone.
`EffectModel.trusted_prototype` answers the prototype half and `EffectModel._species_written` the per-receiver
half; the interpreter additionally refuses to model a named property write on an array at all.
"""

_ARRAY_READING_METHODS = frozenset({
    'at',
    'includes',
    'indexOf',
    'join',
    'lastIndexOf',
    'slice',
})
"""
`Array.prototype` methods a call of which leaves its receiver as it was: the method neither writes
the receiver nor hands it to code of the program, as `map` hands it to its callback. Code of the
program may still run during the call, converting an argument (`valueOf`, `toString`), an element
`join` converts, or the constructor `slice` creates its result with, but none of it is handed the
receiver: it reaches the array only through a reference of its own, which the container question
judges like every other. That holds for an array that owns every position below its length: at a
hole, the method reads the position from the prototypes, where an accessor is handed the receiver.
Unlike `_FRESH_ARRAY_RESULT_METHODS`, membership says nothing about the result.
"""

_PURE_CONSTRUCTOR_ROOTS = frozenset({'Array'})
"""
Intrinsic roots whose `new`-construction has no observable effect when its arguments are safe. Only
`Array` here: it is already guarded against reassignment/shadowing by `_intrinsics_pristine` (it is
a `refinery.lib.scripts.js.analysis.intrinsics.PURE_INTRINSIC_ROOTS` member via `Array.isArray`),
and its sole throw is a bad single numeric length. Adding a root not already in
`refinery.lib.scripts.js.analysis.intrinsics.PURE_INTRINSIC_ROOTS` (e.g. `Object`) requires first
extending the `_intrinsics_pristine` guard to it, or trusting `new Object()` while `Object` was
monkeypatched would be unsound.
"""

_SPEC_GLOBAL_INTRINSICS = frozenset({
    'Object',
    'Boolean',
    'Symbol',
    'BigInt',
    'Number',
    'Math',
    'Date',
    'String',
    'RegExp',
    'Array',
    'JSON',
    'Promise',
    'Reflect',
    'Proxy',
    'Map',
    'Set',
    'WeakMap',
    'WeakSet',
    'ArrayBuffer',
    'SharedArrayBuffer',
    'DataView',
    'Int8Array',
    'Uint8Array',
    'Uint8ClampedArray',
    'Int16Array',
    'Uint16Array',
    'Int32Array',
    'Uint32Array',
    'Float32Array',
    'Float64Array',
    'BigInt64Array',
    'BigUint64Array',
    'Error',
    'EvalError',
    'RangeError',
    'ReferenceError',
    'SyntaxError',
    'TypeError',
    'URIError',
})
"""
Global properties the ECMAScript specification mandates as writable, configurable *data* properties of
the global object. A read of one runs no user getter and so carries no observable effect, soundly and
without any host assumption.
"""

_HOST_GLOBAL_INTRINSICS = frozenset({
    'TextDecoder',
    'TextEncoder',
    'Buffer',
})
"""
Global intrinsics a standard, non-adversarial host (Node, browsers) exposes as data properties. Trusted
like `_SPEC_GLOBAL_INTRINSICS`, but resting on that host assumption rather than the language standard.
"""

_GLOBAL_DATA_PROPERTIES = _SPEC_GLOBAL_INTRINSICS | _HOST_GLOBAL_INTRINSICS

_POISON_PILL_PROPERTIES = frozenset({'caller', 'arguments', '__proto__'})
"""
Property names whose read is never treated as getter-free even off an otherwise trusted base. `caller`
and `arguments` are the poison-pill accessors on strict and built-in functions — reading one may throw a
`TypeError` — and `__proto__` is an `Object.prototype` accessor rather than an own data slot. A read of
one carries a possible throw or accessor call, so it is not the plain field read the getter-safe base
rule would otherwise clear.
"""


def _is_poison_pill_property(member: JsMemberExpression) -> bool:
    """
    Whether *member* reads a poison-pill property (`.caller`, `.arguments`, `.__proto__`) by name, in
    either the dotted (`f.caller`) or the string-computed (`f['caller']`) form. A computed access whose
    key is not a string literal (`f[k]`) names no fixed property and does not count.
    """
    prop = member.property
    if member.computed:
        return isinstance(prop, JsStringLiteral) and prop.value in _POISON_PILL_PROPERTIES
    return isinstance(prop, JsIdentifier) and prop.name in _POISON_PILL_PROPERTIES


_FUNCTION_KEYS_READ_IN_PLACE = frozenset({'call', 'apply', 'toString', 'name', 'length'})
"""
The keys `EffectModel.function_object_untouched` lets a read of a function take: `call` and `apply`
run it, and `toString`, `name` and `length` answer what it was created with. `bind` is not one of
them, because `new` on the bound copy builds an object whose `constructor` is the function.
"""

_FUNCTION_FOLLOW_LIMIT = 4
"""
How many names and parameters `EffectModel.function_object_untouched` follows a function object
through before it refuses. The limit bounds a function handed around a cycle of calls.
"""

_UNARY_OPERATORS_READING_A_FUNCTION = frozenset({'typeof', '!', 'void', '+', '-', '~'})


class FunctionUse(enum.IntEnum):
    """
    What a use of a function object may do to the function, from least to most: `IN_PLACE` leaves
    it where it is, in the sense of `EffectModel.function_object_untouched`; `TOUCHED` may hand it
    to code that could give it a property of its own, or gives it one under a key other than a
    conversion key; `CONVERSION` may give it a `toString`, `valueOf` or `Symbol.toPrimitive` of its
    own, or a new prototype: a write under a conversion key or under a key known only at runtime,
    an installer call with the function as its target whose key may name a conversion, or a call
    through a key known only at runtime that receives the function.
    """
    IN_PLACE = 0
    TOUCHED = 1
    CONVERSION = 2


_INTRINSIC_CHAIN_ROOTS = frozenset({'Object', 'Function'})
"""
The prototypes an intrinsic root's own chain can contain. `Math` is a plain object and inherits from
`Object.prototype` alone, while a constructor such as `Array` is a function and inherits from
`Function.prototype` first, so a plain read on either walks one of these two.
"""

_LITERAL_RECEIVER_TYPES: dict[type, type] = {
    JsArrayExpression: list,
    JsStringLiteral: str,
    JsNumericLiteral: float,
    JsBooleanLiteral: bool,
    JsObjectExpression: dict,
}
"""
The runtime type of a receiver whose literal syntax fixes it, mapping an AST node type to the value
type `refinery.lib.scripts.js.analysis.intrinsics.PROTOTYPE_OWNERS` is keyed on. A literal is the
one receiver form whose prototype is knowable from the expression alone: `[1, 2].join('-')` has an
array receiver whatever the surrounding program does, whereas `a.join('-')` depends on what `a`
holds and on whether anything mutated it in between.

Deciding this here rather than at each caller is what lets a fold ask about a whole chain without walking
it: the recursive case above resolves an inner link, and this resolves the literal the chain starts from.
The `receiver_type` parameter remains for callers that hold an evaluated receiver — a value whose type is
known but whose syntax is not a literal — and is consulted only when the syntax settles nothing.

A function literal is deliberately absent, so `(function () {}).call(x)` is not a trusted callee. The
interpreter's `.call`/`.apply` dispatch carries no prototype guard, unlike its `list` and `str` neighbours,
so admitting one here would fold a dispatch a patched `Function.prototype` had redirected. Reading a
property of a function literal is a different question and has its own table below.
"""

_LITERAL_READ_TYPES: dict[type, type] = dict(_LITERAL_RECEIVER_TYPES)
_LITERAL_READ_TYPES[JsFunctionExpression] = JsFunctionExpression
_LITERAL_READ_TYPES[JsArrowFunctionExpression] = JsArrowFunctionExpression
"""
The value type of a literal whose *property read* must consult a prototype, extending
`_LITERAL_RECEIVER_TYPES` with the two function forms. Reading `f.name` walks `Function.prototype`,
which a program can patch, so the read needs an answer where the method call above must refuse
outright: the call is unsound to fold because the interpreter cannot guard its dispatch, while the
read is merely a question about one named intrinsic. A function node maps to itself, since the
interpreter represents a function value as its own AST node and
`refinery.lib.scripts.js.analysis.intrinsics.PROTOTYPE_OWNERS` is keyed on that type's name.
"""


class _PureCall:
    """
    Sentinel marking a callee resolved to a known-pure intrinsic, distinct from an unresolved callee.
    """


_PURE = _PureCall()


@dataclass
class EffectSummary:
    """
    The observable effects one call of a function may have, each field a conservative over-estimate.
    `writes_global` covers assignment to a global or to a property of an object reached through one;
    `writes_captured` covers assignment to a binding owned by an enclosing function (a closure mutation
    visible after the call returns); `throws` covers a `throw`, an operation that may throw on a
    value the analysis cannot prove safe, or a read of a name that is not certain to denote a binding
    (`SemanticModel.read_may_throw`); `calls_unknown` covers invoking a callee that cannot be
    resolved and summarized. A summary with none of these set is `is_pure`. `mutates_returned_local` is
    held apart from those four: it records a write to a fresh local the function owns whose sole route to
    the caller is the value the call returns. Such a write is a real mutation baked into the returned
    value, so it blocks `is_pure` and `is_expression_replaceable`, but not
    `is_effect_free_when_discarded` — a call whose result is thrown away can never expose it — and not
    `is_literal_replaceable`, whose replacement is a fresh object at every site. `wraps_return` is separate:
    it does not bear on purity but records that a call to the function yields a wrapper (a promise from
    an `async` function, an iterator from a generator) rather than the value of its return expression,
    so the call cannot be replaced by that expression. `written_bindings` names, by identity, the outer
    bindings — captured locals and globals — a call may write where the write resolves to one, so a
    caller can ask which binding a call mutates rather than only whether it mutates some. It is decided
    independently of purity: a write the purity analysis deems unobservable because the binding never
    escapes the function is still recorded here, since a consumer reasoning about a read *inside* that
    function must still see the mutation. A binding written but never read anywhere adds nothing, as no
    read can observe the change; likewise a coarse write with no resolvable binding (a dynamic-scope or
    `globalThis.x =` member write) sets `writes_global` but adds nothing here.

    `dead_zone_reads` mirrors `written_bindings` for a read that throws only at some call sites: it
    names, by identity, the outer `let`/`const`/`class` bindings a call to this function may read
    (directly or through a transitive callee) before that binding is initialized, which is a
    `ReferenceError` the function raises iff the call lands in the binding's temporal dead zone.
    The flow-insensitive summary cannot collapse this to `throws` — that flag fires at *every*
    call, but this read throws only inside the dead zone and is safe after the declaration — so it
    is deferred per binding to the call site, which owns the ordering judgment. A binding the
    function itself owns is decided at the summary instead (see `_scan`): the call site cannot
    order it, since the read and its declaration both run inside the call, so the summary asks the
    dominance model whether every read of it runs past its declaration and a read that may land in
    the zone sets `throws`, the same ReferenceError the call would raise itself.

    Four properties read these flags, and they are not a scale from strict to permissive — each answers a
    different question about a *different rewrite*, so a consumer picks by naming the rewrite it is about to
    perform rather than by how many flags a property excludes:

    - `is_pure` — may the call be deleted outright, result and all? Nothing may be lost, so every flag blocks.
    - `is_effect_free_when_discarded` — may the call be deleted when its result is already unused? A mutation
      confined to the returned value is then unreachable, so only that flag is forgiven.
    - `is_literal_replaceable` — may the call become a literal denoting its value? Throwing and unknown reads
      are reproduced by actually evaluating it, and `mutates_returned_local` is forgiven because a literal is a
      fresh object at every site. A rewrite that yields something other than a literal may not use this.
    - `is_expression_replaceable` — may the call become one expression lifted out of its body, with the rest of
      the body discarded? Everything the literal case needs, plus a refusal of `mutates_returned_local`, since
      a lifted expression yields no fresh object.
    """
    writes_global: bool = False
    writes_captured: bool = False
    throws: bool = False
    calls_unknown: bool = False
    mutates_returned_local: bool = False
    wraps_return: bool = False
    written_bindings: set[Binding] = field(default_factory=set)
    dead_zone_reads: set[Binding] = field(default_factory=set)

    @property
    def is_pure(self) -> bool:
        """
        Whether a call to the summarized function produces no observable effect, so it carries no
        consequence the program can detect (termination aside) whether or not its result is used. A
        mutation the function confines to its returned value (`mutates_returned_local`) disqualifies it
        here, since a caller that uses the result observes that mutation; `is_effect_free_when_discarded`
        is the companion test for a call whose result is thrown away, which tolerates it.

        A `dead_zone_reads` throw is NOT reflected here: it fires only inside a binding's dead
        zone, not at every call, so it cannot set `throws`. A consumer that EVALUATES the call (a
        value fold, a HOF fold) needs no extra guard — the dead-zone read manifests as the
        evaluation throwing, which aborts the rewrite exactly as reading the binding would. A
        consumer that DELETES the call without evaluating it (the dead-store and orphan sweeps, via
        `call_clearable`) must gate on the call-site establishment of every `dead_zone_reads`
        binding; reading `is_pure` alone would drop the throw. A binding the function itself owns
        is the exception the summary decides itself: its dead zone runs inside the call, so a read
        that may land in it sets `throws` and blocks every property alike.
        """
        return not (
            self.writes_global
            or self.writes_captured
            or self.throws
            or self.calls_unknown
            or self.mutates_returned_local
        )

    @property
    def is_effect_free_when_discarded(self) -> bool:
        """
        Whether a call to the summarized function, its result discarded, produces no observable effect.
        Identical to `is_pure` except it tolerates `mutates_returned_local`: a write to a fresh local the
        function owns is observable only through the value the call returns, so once that value is thrown
        away the write can never be seen and the call is free to drop. Every other way such a local — or a
        closure over it — reaches the caller is a distinct effect that independently sets a blocking flag
        (a store to a global, a store to an enclosing capture, a leak into an unknown callee, a throw), so
        excluding only `mutates_returned_local` here stays sound.

        As with `is_pure`, a `dead_zone_reads` throw is not reflected here — the read raises
        regardless of whether the result is used — so a consumer that deletes the call on the
        strength of this property must additionally gate on call-site establishment of every
        `dead_zone_reads` binding.
        """
        return not (self.writes_global or self.writes_captured or self.throws or self.calls_unknown)

    @property
    def is_literal_replaceable(self) -> bool:
        """
        Whether a call to the summarized function may be replaced by a *literal* denoting its computed return
        value. This holds when the call writes no state visible after it returns — neither a global nor a
        captured binding — and returns its value directly rather than wrapped: an `async` function's call is a
        promise and a generator's is an iterator, neither equal to the return expression, so `wraps_return`
        disqualifies it. Unlike `is_pure`, a call that may throw or read unknown state still qualifies: an
        evaluator that actually executes the call to a value reproduces those, and only a *write* would be
        silently lost.

        `mutates_returned_local` is tolerated, and the name of this property is what licenses that. Such a
        mutation is baked into a container the call returns, so the substituted value must be a distinct
        object per call — which a literal is, because `value_to_node` builds a new array or object literal at
        every site it fills. A replacement that is *not* a literal has no such guarantee and must not consult
        this property; see the family note on `EffectSummary`.
        """
        return not (
            self.writes_global
            or self.writes_captured
            or self.wraps_return
        )

    @property
    def is_expression_replaceable(self) -> bool:
        """
        Whether a call to the summarized function may be replaced by a single expression lifted out of its
        body, with everything else the body would have done discarded.

        Everything `is_literal_replaceable` requires is required here, for the same reasons: a write to a
        global or a capture would be lost, and a wrapped return is not the return expression. Throwing and
        unknown reads are tolerated identically — the lifted expression sits at the call site and still
        performs them, so they are reproduced rather than dropped, which is why the discard question is *not*
        the right one to ask even though statements are being discarded.

        What this additionally forbids is `mutates_returned_local`. The literal case tolerates it because
        `value_to_node` builds a new array or object at every site it fills, so the distinct container the
        mutation is baked into survives. A lifted expression is spliced from the body and names whatever the
        body named, guaranteeing nothing about identity, so a mutated container must not travel this way.
        """
        return self.is_literal_replaceable and not self.mutates_returned_local

    def absorb(self, other: EffectSummary):
        """
        Union *other*'s effects into this summary, used to fold a callee's effects into its caller.
        """
        self.writes_global = self.writes_global or other.writes_global
        self.writes_captured = self.writes_captured or other.writes_captured
        self.throws = self.throws or other.throws
        self.calls_unknown = self.calls_unknown or other.calls_unknown
        self.mutates_returned_local = self.mutates_returned_local or other.mutates_returned_local
        self.written_bindings |= other.written_bindings
        self.dead_zone_reads |= other.dead_zone_reads


def _literal_number(node: Node) -> int | float | None:
    """
    The numeric value *node* denotes as a literal, folding a leading `-`/`+` on a numeric literal, or
    `None` when it is not a numeric literal. `void` and any non-literal are not numbers here; `NaN` and
    `Infinity` are identifiers, not literals, so they too return `None`.
    """
    if isinstance(node, JsNumericLiteral):
        return node.value
    if (
        isinstance(node, JsUnaryExpression)
        and node.operator in ('-', '+')
        and isinstance(node.operand, JsNumericLiteral)
    ):
        return -node.operand.value if node.operator == '-' else node.operand.value
    return None


def _array_construct_is_pure(arguments: Sequence[Node]) -> bool:
    """
    Whether `new Array(*arguments)` is a pure allocation — it runs no user code and cannot throw. `Array`
    throws a `RangeError` only for a single numeric argument that is not a valid length
    (`ToUint32(v) != v`, i.e. not an integer in `[0, 2**32)`); a single argument provably not a number
    builds a one-element array; two or more arguments build a list. A spread argument runs the iterable's
    iterator (arbitrary user code) and its element count may be an invalid length, so it is never pure,
    and a single non-literal argument has an unknown value that could be an out-of-range length.
    """
    if any(isinstance(arg, JsSpreadElement) for arg in arguments):
        return False
    if len(arguments) != 1:
        return True
    arg = arguments[0]
    number = _literal_number(arg)
    if number is not None:
        return 0 <= number < 2 ** 32 and number == int(number)
    return isinstance(arg, (
        JsStringLiteral,
        JsBooleanLiteral,
        JsNullLiteral,
        JsArrayExpression,
        JsObjectExpression,
        JsFunctionExpression,
        JsArrowFunctionExpression,
    ))


def container_literal_access_is_plain(node: Node | None) -> bool:
    """
    Whether *node* is a container literal on which a plain member access touches a data slot and nothing
    else: an array or function expression, or an object literal that declares no accessor and installs no
    custom prototype. This is the one shared atom behind every predicate that has to decide what a member
    access on a freshly built value does — `EffectModel._base_is_safe` and `EffectModel._base_getter_safe`
    here, and `strict_divergence._fresh_writable_base`.

    Each of those asks a further question this deliberately does not answer, which is why they remain
    distinct predicates rather than aliases of this one: whether the base can be nullish, whether a
    primitive or a pristine intrinsic also qualifies, whether every slot is *writable* as opposed to
    merely accessor-free. What they must not disagree about is this atom.

    It answers only what the *literal* declares, so it is never sufficient on its own for a getter-freeness
    question: `[1, 2]` declares no accessor and still inherits everything on `Array.prototype` and
    `Object.prototype`. A caller asking about a read must pair this with `EffectModel.read_chain_intact`.
    """
    node = strip_parens(node)
    if isinstance(node, JsObjectExpression):
        return not object_member_access_runs_accessor(node)
    return isinstance(node, (JsArrayExpression, JsFunctionExpression, JsArrowFunctionExpression))


def _is_safe_property_base(node: Node, defunct: set[str] | None = None) -> bool:
    """
    Whether a property access on *node* cannot run a custom getter without consulting any model: only an
    identifier in *defunct*, which names a binding being removed, so whatever getters it carries are
    irrelevant to the code that remains.

    No literal qualifies here, though the syntax of one fixes its type. Every property read walks a
    prototype chain the program can patch — `Object.defineProperty(Array.prototype, 'k', { get: … })` makes
    `[1, 2].k` run user code, and `Object.prototype` roots the chain of even a primitive — so the question
    cannot be answered from syntax at all. It needs `_globals_written`, which only a model has, and
    `EffectModel._base_getter_safe` asks it there. `_SideEffectScan` consults that through *member_safe*
    for everything this refuses, so a caller with a model loses nothing; a caller without one keeps the
    read, which is the sound direction.
    """
    return isinstance(node, JsIdentifier) and bool(defunct) and node.name in defunct


_CallPredicate = Callable[[JsCallExpression | JsNewExpression], bool]


_NUMBER_TAKING_UNARY_OPERATORS = frozenset({'+', '-', '~'})
"""
The unary operators that take their operand to a number. `ToNumber` enters the object protocol —
`valueOf` or `Symbol.toPrimitive` answers for an object, and either is code the operand carries —
so the operand of one of these is held to a value that cannot be an object at all where the caller
drops the evaluation (`coercions_may_write`). `!` and `typeof` are not here: they take the operand
to a truth value or a type name without asking it anything.
"""

_COERCING_BINARY_OPERATORS = frozenset({
    '+',
    '-',
    '*',
    '/',
    '%',
    '**',
    '&',
    '|',
    '^',
    '<<',
    '>>',
    '>>>',
    '==',
    '!=',
    '<',
    '>',
    '<=',
    '>=',
})
"""
The binary operators that apply `ToPrimitive` — or `ToNumber`, which begins with it — to an
operand. The same reasoning as `_NUMBER_TAKING_UNARY_OPERATORS` applies: the coercion is an effect
of the operator itself, of no sub-expression, so an operand whose value may be an object keeps the
whole expression where the caller drops the evaluation. Strict equality is not here because it
compares values as they are; `in` and `instanceof` are held to the stronger
`_OBJECT_TESTING_BINARY_OPERATORS` rule instead. The loose equality operators are held to the same
rule except beside `null`, which the language answers without asking either operand anything.
"""

_OBJECT_TESTING_BINARY_OPERATORS = frozenset({'in', 'instanceof'})
"""
The binary operators the language decides from the *kind* of the right operand rather than from
coercing an operand, so no operand value settles whether they run cleanly. `in` throws a `TypeError`
unless its right operand is an object, coerces its left operand to a property key, and fires a
proxy's `has` trap where the right operand carries one; `instanceof` throws unless its right operand
is callable and otherwise runs the `Symbol.hasInstance` method or reads the `prototype` getter it
finds there. Where the caller drops the evaluation (`coercions_may_write`) neither may go: the throw
and the code it runs are effects of the operator that dropping the operands cannot excuse.
"""


def _comparison_with_null(node: JsBinaryExpression) -> bool:
    """
    Whether *node* is a loose equality beside the `null` literal, which the language answers from
    the two values alone: `x == null` is true where *x* is `null` or `undefined` and false
    everywhere else, so no operand is coerced and neither needs a value that cannot be an object.
    """
    if node.operator not in ('==', '!='):
        return False
    return isinstance(node.left, JsNullLiteral) or isinstance(node.right, JsNullLiteral)


def _value_cannot_be_an_object(node: Node | None) -> bool:
    """
    Whether the value *node* evaluates to is beyond doubt one of the primitives, so a coercion
    applied to it runs no code and asks no `valueOf` for anything. Every unary, binary, update and
    template expression answers a primitive by its own operation, whatever its operands were, and
    the remaining cases are decided by the value they hand on: a parenthesis and a sequence by the
    expression they group or end with, a logical operator and a conditional by the operand that
    supplies their answer. A name, a member read, a call, an allocation — anything whose value a
    program may make an object — is not decided here.
    """
    if isinstance(node, (JsStringLiteral, JsNumericLiteral, JsBooleanLiteral, JsNullLiteral)):
        return True
    if isinstance(node, (
        JsUnaryExpression,
        JsBinaryExpression,
        JsUpdateExpression,
        JsTemplateLiteral,
    )):
        return True
    if isinstance(node, JsParenthesizedExpression):
        return _value_cannot_be_an_object(node.expression)
    if isinstance(node, JsSequenceExpression):
        return bool(node.expressions) and _value_cannot_be_an_object(node.expressions[-1])
    if isinstance(node, JsLogicalExpression):
        return (
            _value_cannot_be_an_object(node.left)
            and _value_cannot_be_an_object(node.right)
        )
    if isinstance(node, JsConditionalExpression):
        return (
            _value_cannot_be_an_object(node.consequent)
            and _value_cannot_be_an_object(node.alternate)
        )
    return False


class _SideEffectScan:
    """
    The recursive engine behind `side_effect_free`. It holds the fixed policy — the callables and the
    *defunct* set — so that only the per-node `discarded` flag threads down the recursion, and every
    consumed sub-expression is scanned with `discarded` reset to false by default.

    `discarded` is true where the value being scanned is thrown away by the enclosing context, which
    lets a top-level call be cleared by the more permissive *call_pure_discarded* — one that tolerates a
    write the call confines to its own returned value (`EffectSummary.mutates_returned_local`), since a
    discarded result can never expose it. It is propagated only into positions that are themselves
    discarded whenever the whole is: the expression a parenthesis groups, and every element of a
    sequence (each but the last is always discarded; the last inherits the sequence's own fate). It is
    reset for every operand whose value is consumed — a call argument, a unary/binary operand, a member
    base, a conditional branch — because a call nested there does have its result used, so a mutation it
    confines to that result must still count.
    """

    def __init__(
        self,
        defunct: set[str] | None,
        call_pure: _CallPredicate | None,
        read_effect: Callable[[Node], bool] | None,
        member_safe: Callable[[JsMemberExpression], bool] | None,
        call_established: _CallPredicate | None,
        call_pure_discarded: _CallPredicate | None,
        coercions_may_write: bool = False,
        store_unobserved: Callable[[JsMemberExpression], bool] | None = None,
    ):
        self.defunct = defunct
        self.call_pure = call_pure
        self.read_effect = read_effect
        self.member_safe = member_safe
        self.call_established = call_established
        self.call_pure_discarded = call_pure_discarded
        self.coercions_may_write = coercions_may_write
        self.store_unobserved = store_unobserved

    def free(self, node: Node, discarded: bool = False) -> bool:
        if isinstance(node, (JsStringLiteral, JsNumericLiteral, JsBooleanLiteral, JsNullLiteral)):
            return True
        if isinstance(node, JsIdentifier):
            return self.read_effect is None or not self.read_effect(node)
        if isinstance(node, (JsFunctionExpression, JsArrowFunctionExpression)):
            return True
        if isinstance(node, JsParenthesizedExpression):
            return node.expression is not None and self.free(node.expression, discarded)
        if isinstance(node, JsUnaryExpression):
            if node.operator == 'delete':
                return False
            if (
                self.coercions_may_write
                and node.operator in _NUMBER_TAKING_UNARY_OPERATORS
                and not _value_cannot_be_an_object(node.operand)
            ):
                return False
            return node.operand is not None and self.free(node.operand)
        if isinstance(node, JsMemberExpression):
            if node.object is None:
                return False
            if not self.free(node.object):
                return False
            if node.property is not None and not self.free(node.property):
                return False
            if _is_poison_pill_property(node):
                return self.member_safe is not None and self.member_safe(node)
            if _is_safe_property_base(node.object, self.defunct):
                return True
            return self.member_safe is not None and self.member_safe(node)
        if isinstance(node, (JsBinaryExpression, JsLogicalExpression)):
            if self.coercions_may_write and isinstance(node, JsBinaryExpression):
                if node.operator in _OBJECT_TESTING_BINARY_OPERATORS:
                    return False
                if (
                    node.operator in _COERCING_BINARY_OPERATORS
                    and not _comparison_with_null(node)
                    and not (
                        _value_cannot_be_an_object(node.left)
                        and _value_cannot_be_an_object(node.right)
                    )
                ):
                    return False
            return (
                node.left is not None
                and self.free(node.left)
                and node.right is not None
                and self.free(node.right)
            )
        if isinstance(node, JsConditionalExpression):
            return (
                node.test is not None
                and self.free(node.test)
                and node.consequent is not None
                and self.free(node.consequent)
                and node.alternate is not None
                and self.free(node.alternate)
            )
        if isinstance(node, JsObjectExpression):
            for prop in node.properties:
                if not isinstance(prop, JsProperty):
                    return False
                if prop.computed and (prop.key is None or not self.free(prop.key)):
                    return False
                if prop.value is not None and not self.free(prop.value):
                    return False
            return True
        if isinstance(node, JsArrayExpression):
            return all(elem is None or self.free(elem) for elem in node.elements)
        if isinstance(node, JsSequenceExpression):
            return all(self.free(e, discarded) for e in node.expressions)
        if isinstance(node, JsAssignmentExpression):
            target = strip_parens(node.left)
            return (
                isinstance(target, JsMemberExpression)
                and self.store_unobserved is not None
                and self.store_unobserved(target)
                and target.object is not None
                and self.free(target.object)
                and node.right is not None
                and self.free(node.right)
            )
        if isinstance(node, JsCallExpression):
            if self.defunct and isinstance(node.callee, JsIdentifier) and node.callee.name in self.defunct:
                # The callee is read before it is called, and a name being removed is one a read of
                # may not resolve, so the read leaf decides it exactly as any other operand's does.
                return self.free(node.callee) and all(self.free(arg) for arg in node.arguments)
        if (
            isinstance(node, (JsCallExpression, JsNewExpression))
            and self._call_is_pure(node, discarded)
            and self.call_established is not None
            and self.call_established(node)
        ):
            return all(self.free(arg) for arg in node.arguments)
        return False

    def _call_is_pure(self, node: JsCallExpression | JsNewExpression, discarded: bool) -> bool:
        """
        Whether the call leaf itself carries no effect, choosing the discard-aware predicate only where
        the call's result is thrown away and one was supplied; otherwise the ordinary purity predicate.
        """
        if discarded and self.call_pure_discarded is not None:
            return self.call_pure_discarded(node)
        return self.call_pure is not None and self.call_pure(node)


def side_effect_free(
    node: Node,
    defunct: set[str] | None = None,
    call_pure: _CallPredicate | None = None,
    read_effect: Callable[[Node], bool] | None = None,
    member_safe: Callable[[JsMemberExpression], bool] | None = None,
    call_established: _CallPredicate | None = None,
    discarded: bool = False,
    call_pure_discarded: _CallPredicate | None = None,
    coercions_may_write: bool = False,
    store_unobserved: Callable[[JsMemberExpression], bool] | None = None,
) -> bool:
    """
    Conservative check for whether evaluating an expression can be dropped or reordered with no
    observable side effect. Compositional: an expression is free when every sub-expression is. Three
    leaves can bear an effect. The store — free only where *store_unobserved* certifies that no code
    observes it, with its base and its value free. The call — free only when its callee is a
    *defunct* identifier, or, when both *call_pure* and *call_established* are supplied, when
    *call_pure* certifies the call (or `new`) pure, *call_established* certifies its callee is in
    place before the call runs, and its arguments are free. An inline function-expression callee is
    not special-cased: it is resolved like any other callee through *call_pure*, which inspects its
    body, so a called IIFE with an effectful body is not cleared. The identifier read — free unless
    *read_effect* rejects it, which `EffectModel.is_side_effect_free` supplies as
    `SemanticModel.read_has_dynamic_effect` to reject a bare name that resolves through a `with`
    body's dynamic scope (reading it may fire the `with` object's getter or throw). A function
    expression is free without descending into its body — defining it runs nothing — so a
    dynamic-scope read inside an un-called function does not make the value effectful. A
    parenthesized expression is transparent, bearing exactly the effects of the expression it
    groups. A member read is free when its base is a safe value or *member_safe* certifies it;
    `EffectModel.is_side_effect_free` supplies `EffectModel._is_trusted_global_read` to clear a
    getter-free read of a trusted global data property. It passes `EffectModel.is_pure_call`,
    `read_has_dynamic_effect` and `EffectModel.store_unobserved` too. A caller without a model gets
    the conservative behaviour. When *defunct* is given its identifiers name bindings being removed,
    so calls to them and property reads through them are treated as free.

    When *discarded* is set the expression's own value is thrown away by the caller, so a top-level call
    (or `new`) leaf is cleared through *call_pure_discarded* instead of *call_pure* — admitting a call
    whose only residual effect is a write it confines to its returned value, unobservable once that value
    is dropped. The flag reaches only positions that stay discarded — a parenthesized group and every
    element of a sequence — and is reset into any consumed operand, so a nested call whose result is used
    is still held to *call_pure*.

    When *coercions_may_write* is set the caller drops the evaluation, and an operator that converts an
    operand is then held to a value that cannot be an object: unary `+`, `-` and `~` take their operand
    to a number, the arithmetic, bitwise, shift, loose-equality and relational operators and `in` take
    theirs to a primitive or a property key, and a conversion asks the operand's `valueOf` or
    `Symbol.toPrimitive`, which is code the operand carries. The conversion is an effect of the operator
    itself, of no sub-expression, so the composition alone cannot see it and the caller must say it is
    dropping the evaluation for it to matter. A caller that relocates the evaluation — the object fold
    moving a property value to its use — keeps the conversion where it runs and answers for it with its
    own gates, which is why the flag is opt-in rather than the rule.
    """
    return _SideEffectScan(
        defunct, call_pure, read_effect, member_safe, call_established, call_pure_discarded,
        coercions_may_write, store_unobserved,
    ).free(node, discarded)


def _method_call_is_inert(reference: Node, methods: frozenset[str] | None) -> bool:
    """
    Whether the method call *reference* begins leaves the container it holds unchanged, by the
    promise of a caller that names its inert own *methods*: a call on the container itself,
    `reference.m(...)` or the tag `` reference.m`...` ``, for an `m` among them, and a call on a
    value the container holds, `reference.k.m(...)`, which the caller vouches for. No call is inert
    where *methods* is `None`.
    """
    if methods is None:
        return False
    member = enclosing_operator(reference)
    if not isinstance(member, JsMemberExpression) or strip_parens(member.object) is not reference:
        return False
    if not is_invocation_target(member):
        return True
    return static_property_key(member) in methods


def _method_call_reads_an_array(reference: Node) -> bool:
    """
    Whether *reference* is the receiver of a call of one of `_ARRAY_READING_METHODS`,
    `reference.slice(...)` or the tag `` reference.join`...` ``.
    """
    member = enclosing_operator(reference)
    if not isinstance(member, JsMemberExpression) or strip_parens(member.object) is not reference:
        return False
    if not is_invocation_target(member):
        return False
    return static_property_key(member) in _ARRAY_READING_METHODS


def _result_goes_nowhere(node: Node) -> bool:
    """
    Whether the value of *node* is thrown away: it is the value of a statement, an operand of a
    sequence but its last, or a branch of a conditional, an operand of a logical operator or the
    last operand of a sequence whose own value is thrown away. A logical operator tests its left
    operand for truth, which reads nothing of an object.
    """
    while True:
        parent = enclosing_operator(node)
        if isinstance(parent, JsConditionalExpression) and node is not strip_parens(parent.test):
            node = parent
        elif isinstance(parent, JsLogicalExpression):
            node = parent
        elif (
            isinstance(parent, JsSequenceExpression)
            and parent.expressions
            and strip_parens(parent.expressions[-1]) is node
        ):
            node = parent
        else:
            return value_is_discarded(node)


class _WriteClass(enum.Enum):
    """
    How far a member write through a container base can be observed by code outside the writing
    function. `UNOBSERVABLE`: the container is a fresh value the function owns and never lets escape, so
    no other code can ever reach it and the write is invisible. `VIA_RESULT`: the container is a fresh
    local the function owns, but it — or a closure over it — leaves the function only through the value
    the call returns, so the write is seen only if that value is used, and a call whose result is
    discarded may still be dropped. `OBSERVABLE`: the base may alias state the caller already holds — a
    global, a plain parameter, a binding captured from an enclosing scope, or a write hidden behind a
    dynamic scope — so the write is a plain side effect that any caller can observe.
    """
    UNOBSERVABLE = 0
    VIA_RESULT = 1
    OBSERVABLE = 2


class _FreshKind(enum.Enum):
    """
    What an expression is known to evaluate to, for the purpose of deciding whether a write through it can be
    observed. `NOT_FRESH`: nothing is known, so the value may alias state the caller already holds.
    `CONTAINER`: a container no other code can reach, built where the expression sits. `ARRAY`: the same, and
    additionally known to be an array.

    Array-ness is tracked apart from freshness because the two are independent and both are needed: an
    allocating `Array.prototype` method returns a new array only when the receiver really is an array, and an
    object literal carrying its own `slice` is a fresh container whose `slice` may hand back a shared one. A
    boolean would force that second question to be asked separately at the one site that needs it, which is
    how a predicate acquires a divergent copy.
    """
    NOT_FRESH = 0
    CONTAINER = 1
    ARRAY = 2

    @property
    def is_fresh(self) -> bool:
        return self is not _FreshKind.NOT_FRESH


class _CallEdges:
    """
    The reverse call-edge index the worklist in `EffectModel._compute` schedules from: for every
    function, the set of functions that call it. One instance per compute; `caller` names the
    function whose scan is in progress, and `record` is the edge sink handed to `_scan`.
    """

    def __init__(self):
        self.callers: dict[int, set[int]] = {}
        self.caller: int | None = None

    def record(self, callee: Node):
        if self.caller is None:
            raise RuntimeError('an edge was recorded outside a scan')
        callers = self.callers.get(id(callee))
        if callers is None:
            self.callers[id(callee)] = {self.caller}
        else:
            callers.add(self.caller)


class EffectModel:
    """
    Per-function effect summaries for one script, built over a
    `refinery.lib.scripts.js.analysis.model.SemanticModel`. Query a function's summary with
    `summary_of` and a call expression's purity with `is_pure_call`. Build through `build_effects`.
    """

    def __init__(
        self,
        model: SemanticModel,
        dominance: DominanceModel | None = None,
        intrinsic_writes: IntrinsicWrites | None = None,
        settlement: ConversionSettlement | None = None,
    ):
        self.model = model
        self._dominance = dominance
        self._dead_zone_safe_cache: dict[int, bool] = {}
        self.intrinsics_pristine = _intrinsics_pristine(model)
        self.global_pristine = _global_pristine(model)
        if intrinsic_writes is None:
            intrinsic_writes = build_intrinsic_writes(model)
        self.intrinsic_writes = intrinsic_writes
        self._globals_written = intrinsic_writes.names
        self._summaries: dict[int, EffectSummary] = {}
        self._confine_cache: dict[int, Node | None] = {}
        self._immutable_cache: dict[tuple[int, frozenset[str] | None, bool], bool] = {}
        self._member_write_cache: dict[int, _WriteClass] = {}
        self._uses_arguments_cache: dict[int, bool] = {}
        self._mutators_escape_cache: dict[int, bool] = {}
        self._some_mutator_cache: dict[int, bool] = {}
        self._settlement = settlement
        self._function_use_cache: dict[tuple[Node, frozenset[Node]], FunctionUse] = {}
        self._name_use_cache: dict[tuple[Binding, int, frozenset[Node]], FunctionUse] = {}
        self._functions: list[Node] = self._collect_functions()
        self._compute()
        self.conversion_installs = ConversionInstalls(self)

    def summary_of(self, func: Node) -> EffectSummary:
        """
        The effect summary of a function node (or the script). An unknown node is reported as impure.
        """
        return self._summaries.get(id(func), EffectSummary(calls_unknown=True))

    def mutated_bindings(self, func: Node) -> frozenset[Binding]:
        """
        The outer bindings (captured locals and globals) a call to *func* may write, directly or through
        any function it transitively calls, each identified by its `Binding` rather than its name so a
        caller can ask whether one specific binding is mutated. Empty for a function with no such writes
        and for an unknown node alike — use `summary_of(func).calls_unknown` to tell those apart.
        """
        return frozenset(self.summary_of(func).written_bindings)

    def function_can_mutate(self, func: Node, binding: Binding) -> bool:
        """
        Whether a call to *func* may write *binding*, itself or through a transitive callee.
        """
        return binding in self.summary_of(func).written_bindings

    def function_escapes(self, func: Node) -> bool:
        """
        Whether *func* may be invoked at a point the surrounding scope cannot enumerate as a resolvable
        `name(...)` call site: an anonymous function (an IIFE, a callback, stored and called later), or a
        named function whose binding is reassigned, redeclared, or referenced anywhere other than as the
        callee of a direct call (aliased, passed as an argument, `f.call(...)`). A reference inside a
        dynamic scope — a name a `with` body resolves at runtime — counts too: the model cannot order or
        resolve it, so the function may be invoked or aliased there with no static call site. A call to
        such a function can land at a point no call site pins down; a function only ever called directly
        by name has all its invocations enumerated by those call sites.
        """
        names = self.model.function_names(func)
        if names is None:
            return True
        for binding in names.bindings:
            if binding.writes or binding.dynamic_refs or len(binding.declarations) != 1:
                return True
            if not self.model.binding_pinned_to(binding, func):
                return True
            for ref in names.references_of(binding):
                parent = ref.parent
                if isinstance(parent, JsCallExpression) and parent.callee is ref:
                    continue
                return True
        return False

    def mutators_escape(self, binding: Binding) -> bool:
        """
        Whether some function that may write *binding* — itself or through a transitive callee — escapes
        (`function_escapes`), so a write to *binding* may occur at a point no call site enumerates. When
        true, the places *binding* changes cannot be pinned down, and a caller reasoning about where its
        value survives must treat it as volatile everywhere. Memoized per binding.
        """
        cached = self._mutators_escape_cache.get(id(binding))
        if cached is None:
            cached = any(
                func is not self.model.root
                and binding in self.summary_of(func).written_bindings
                and self.function_escapes(func)
                for func in self._functions
            )
            self._mutators_escape_cache[id(binding)] = cached
        return cached

    def some_function_can_mutate(self, binding: Binding) -> bool:
        """
        Whether any function this file writes may write *binding*, itself or through a transitive
        callee. The answer a caller needs where a call runs a function it cannot name: not knowing
        which one runs, it has to reckon with every one that could. Memoized per binding.
        """
        cached = self._some_mutator_cache.get(id(binding))
        if cached is None:
            cached = any(
                func is not self.model.root and self.function_can_mutate(func, binding)
                for func in self._functions
            )
            self._some_mutator_cache[id(binding)] = cached
        return cached

    def is_pure_call(self, call: JsCallExpression | JsNewExpression) -> bool:
        """
        Whether evaluating *call* has no observable effect: it invokes a trusted pure intrinsic (under
        the pristine-intrinsics precondition) or a local function whose summary is pure.
        """
        callee = self._resolve_callee(call)
        if callee is _PURE:
            return True
        if isinstance(callee, Node):
            return self.summary_of(callee).is_pure
        return False

    def is_pure_call_discarded(self, call: JsCallExpression | JsNewExpression) -> bool:
        """
        Whether evaluating *call* and discarding its result has no observable effect. Like `is_pure_call`
        but resolved through `EffectSummary.is_effect_free_when_discarded`, so a callee whose only residual
        effect is a write it confines to its returned value qualifies — that write is unobservable once the
        result is thrown away. A caller may use this only in a position it has proven discards the value.
        """
        callee = self._resolve_callee(call)
        if callee is _PURE:
            return True
        if isinstance(callee, Node):
            return self.summary_of(callee).is_effect_free_when_discarded
        return False

    def call_clearable(
        self,
        call: JsCallExpression | JsNewExpression,
        callee_established: Callable[[Binding], bool],
        binding_established: Callable[[Binding], bool],
    ) -> bool:
        """
        Whether *call* may be cleared with respect to ordering — its callee in place before the
        call runs, and every outer lexical binding its body may read past that binding's
        temporal dead zone. Two ordering judgments the caller supplies, since only its layer can
        make them: *callee_established* tests the name a named local callee is read through, which
        holds the function from a point of its own, and
        *binding_established* tests a `dead_zone_reads` binding (whether the call sits after the
        binding's declaration). A trusted pure intrinsic qualifies unconditionally. Otherwise
        the callee resolves to a function, and the call is refused unless every binding the
        callee's summary defers here is `binding_established` — a dead-zone read would throw a
        `ReferenceError` the deletion of the call would silently drop, which no establishment of
        the callee itself excuses. Past that gate, an inline function-expression callee (defined
        at the call site, hence always in place) qualifies, and a call resolving to a single
        named local function qualifies when *callee_established* accepts it; an unresolved or
        ambiguous callee does not.

        The resolution, the intrinsic case, the dead-zone gate, and the inline-callee case live
        here so callers supply only the ordering judgments their layer can make. An ordering-free
        caller passes `binding_established = lambda binding: False`, which refuses any callee that
        reads an outer lexical binding. This certifies establishment ONLY, not purity — a caller
        deciding whether a call may be dropped must conjoin it with `is_pure_call`, as
        `side_effect_free` does, since an established callee may still run an effectful body.
        """
        resolved = self._resolve_callee(call)
        if resolved is _PURE:
            return True
        if isinstance(resolved, Node):
            deferred = self.summary_of(resolved).dead_zone_reads
            if deferred and not all(binding_established(binding) for binding in deferred):
                return False
            callee = call.callee
            if isinstance(strip_parens(callee), (JsFunctionExpression, JsArrowFunctionExpression)):
                return True
            name = self.model.resolve(callee) if isinstance(callee, JsIdentifier) else None
            return name is not None and callee_established(name)
        return False

    def _established_call_default(self, call: JsCallExpression | JsNewExpression) -> bool:
        """
        The ordering-free floor for `is_side_effect_free`: clears a trusted pure intrinsic, an
        inline function-expression callee (established at its call site), or a call through a name a
        function declaration hoists (empty
        `refinery.lib.scripts.js.analysis.model.SemanticModel.binding_establishment_sites`), whose
        value is in place before any statement runs. A non-hoisted named local callee — a
        `const`/`let`/`var` initializer, a bare assignment, or the copy Annex B makes — is
        refused, since this model cannot order the definition against the call; a caller that can
        supplies its own `call_established`. Being ordering-free, it passes `lambda binding: False`
        for the dead-zone gate, so a callee reading any outer lexical binding is refused here — the
        fail-closed floor a caller with a dominance model lifts by supplying its own
        `binding_established`.
        """
        return self.call_clearable(
            call,
            lambda binding: self.model.binding_establishment_sites(binding) == [],
            lambda binding: False,
        )

    def is_side_effect_free(
        self,
        node: Node,
        defunct: set[str] | None = None,
        member_safe: Callable[[JsMemberExpression], bool] | None = None,
        call_established: Callable[[JsCallExpression | JsNewExpression], bool] | None = None,
        discarded: bool = False,
        reads_may_throw: bool = False,
        read_established: Callable[[JsIdentifier], bool] | None = None,
        coercions_may_write: bool = False,
    ) -> bool:
        """
        Whether evaluating *node* can be dropped or reordered without an observable side effect, with
        the call leaf resolved through this model's `is_pure_call`: a call to a proven-pure function or
        trusted intrinsic is free, recursing into its arguments. *defunct* names bindings being removed,
        whose calls and property reads are treated as free. This is the model-aware form of the
        model-free `side_effect_free` in this module, which clears only calls to a defunct name; unlike
        it, an identifier read that resolves through a `with` body's dynamic
        scope is rejected here — reading the bare name may fire the `with` object's getter or throw (see
        `refinery.lib.scripts.js.analysis.model.SemanticModel.read_has_dynamic_effect`) — while a
        function value whose body performs such a read stays free, since defining it runs nothing. A
        caller with control-flow context passes *member_safe* to also clear a getter-free read through a
        local global-object alias it can prove established before the read; the default clears only the
        syntactic global case (`_is_trusted_global_read`).

        With *discarded* the caller asserts *node*'s own value is thrown away, so a top-level call leaf is
        cleared through `is_pure_call_discarded` and a callee that only mutates a local it returns is
        droppable — the removal contexts of `JsUnusedCodeRemoval` supply it.

        With *reads_may_throw* the read leaf is rejected not only when it fires a `with` object's getter
        but also when it may throw a `ReferenceError`, which is the throw half of the *read_effect*
        contract that `read_has_dynamic_effect` supplies only the getter half of. A caller asks for
        it of an expression whose value it drops with nothing left evaluating the read — an
        allocation discarded to answer its type or truthiness, the store-removal sweep, the
        discarded-test and dead-branch folds, the string-array dispatcher's dropped trailing
        arguments, and the reflective inliner's dropped comma-sequence prefix — so the throw that
        reading it would have raised is not muted. A pass that relocates the read into a position
        still evaluated — the object fold moving a property value to its use, an inliner
        substituting an argument into a body — keeps the throw at that position and asks this only
        of the sub-expression it truly drops (an unaccessed property, an unused parameter, a
        `typeof` operand). With *read_established* a caller passes its establishment proof — in
        every consumer the query of
        one shared `refinery.lib.scripts.js.analysis.assignment.DefiniteAssignmentModel` — and a
        may-throw read the proof vouches a completed creating write for is free again, which is what
        lets a sweep still drop `X = 5; y = X;` whole rather than keep the read of `X` a kept store
        establishes. A proof is only ever offered against the throw it excuses, so supplying one
        asks for that half of the contract as much as *reads_may_throw* does, and neither is quietly
        ignored for want of the other.

        With *coercions_may_write* the caller drops the evaluation, so an operator that converts
        its operand is held to a value that cannot be an object — the conversion asks the operand's
        `valueOf` or `Symbol.toPrimitive`, which is code the operand carries, and the composition
        alone cannot see it. The same drop-versus-relocation divide as *reads_may_throw* applies:
        a pass that relocates the evaluation keeps the conversion where it runs and answers for it
        with its own gates.
        """
        read_effect = self.model.read_has_dynamic_effect
        if reads_may_throw or read_established is not None:
            read_effect = self.throwing_read_effect(read_established)
        return side_effect_free(
            node,
            defunct,
            self.is_pure_call,
            read_effect,
            member_safe or self._getter_free_read,
            call_established or self._established_call_default,
            discarded,
            self.is_pure_call_discarded,
            coercions_may_write,
            self.store_unobserved,
        )

    def throwing_read_effect(
        self, read_established: Callable[[JsIdentifier], bool] | None,
    ) -> Callable[[Node], bool]:
        """
        The read leaf for a caller that keeps the throw half of the contract: rejects a read that
        fires a `with` object's getter or may throw a `ReferenceError`, except one *read_established*
        vouches a creating write has certainly completed for. `is_side_effect_free` composes it for
        its own callers; a pass that reaches the module-level `side_effect_free` directly passes it
        as that function's *read_effect*, so every discarding context asks one read contract.
        """
        if read_established is None:
            return self._read_effectful_or_throwing
        return lambda node: self.read_throws(node, read_established)

    def read_throws(
        self, node: Node, read_established: Callable[[JsIdentifier], bool],
    ) -> bool:
        """
        Whether reading *node* fires a `with` object's getter or may throw a `ReferenceError`
        *read_established* does not vouch the read is past — a creating write that has completed, or
        a lexical binding whose declaration has run, ending its temporal dead zone. A read of a
        `let`/`const`/`class` binding is a candidate here even though the name resolves, since it
        throws all the same while the declaration has not run; the establishment proof clears it
        once the declaration is ordered before the read. The predicate `throwing_read_effect`
        composes, exposed directly so a caller that queries one node at a time (the reflective
        inliner) allocates no closure per read.
        """
        if self.model.read_has_dynamic_effect(node):
            return True
        if not isinstance(node, JsIdentifier):
            return False
        if not self.model.read_may_raise_reference_error(node):
            return False
        return not read_established(node)

    def _read_effectful_or_throwing(self, node: Node) -> bool:
        """
        Whether reading *node* fires a `with` object's getter or may throw a `ReferenceError` — the
        whole of the *read_effect* contract `side_effect_free` states, of which
        `read_has_dynamic_effect` alone answers the getter half. `read_may_raise_reference_error`
        asks whether the read may not resolve (a name the program neither declares nor is certain the
        host defines) or resolves to a lexical binding that may be in its temporal dead zone; with no
        establishment proof to clear the dead-zone case it fails closed, so an allocation discarded to
        answer its shape keeps the throw that reading it would have raised.
        """
        return self.model.read_has_dynamic_effect(node) or (
            isinstance(node, JsIdentifier) and self.model.read_may_raise_reference_error(node)
        )

    def binding_is_immutable_container(
        self,
        binding: Binding,
        *,
        inert_methods: frozenset[str] | None = None,
        exclude: Node | None = None,
        direct_eval_ordered: bool = False,
    ) -> bool:
        """
        Whether *binding* holds a container — an object or array — whose element and property values
        are stable after construction, so that an access into it may be soundly inlined at its read
        sites. Every reference must read through the container (`obj.k`, `obj[i]`) or plainly rebind
        the name (`obj = ...`, whose value the caller resolves by domination); a write through the
        container (`obj.k = v`, `obj[i]++`, `delete obj[i]`, a `for-of` or destructuring target)
        makes it mutable. A method invoked on the container (`obj.m(...)`) may mutate it — an
        array's `sort`/`push`/`splice` and so on — so by default it too counts as mutable, except
        a method of `Array.prototype` that only reads its receiver (`_ARRAY_READING_METHODS`)
        called on an array literal without holes while the program leaves that prototype trusted;
        a caller that knows some of the container's own methods cannot mutate it (an object literal
        with no `this`-bound property) names their keys in *inert_methods*: a call of one of those
        on the container is permitted, and so is a call on a value it holds (`obj.k.split(...)`),
        which such a caller vouches for. A method the container inherits is never one of them:
        `obj.valueOf()` hands the container back and `obj.__defineGetter__(k, g)` replaces a
        property. A reference that escapes is safe in three cases: it aliases another binding that
        is itself an immutable container (alias-following the textual predicates this replaces could
        not do, and the reason a reassigned-and-aliased lookup array stays inlinable), it is passed
        to a statically known function as an argument whose parameter is itself an immutable
        container (so the callee neither mutates nor further-escapes it), or it is the value of a
        store no code observes (`store_unobserved`). Any other escape — returned, stored as a
        property, passed to a call that cannot be resolved — is treated conservatively as mutable,
        and so is an exported binding or an alias of one: an importer holds the container and may
        change it after the module has run, which no reference in this file records. A mutation
        through a dynamic scope is modelled: a `with` body that names the container — a member
        write, method call, reassignment, or escape — is attributed to it as a dynamic reference and
        judged by the same role logic, so a `with` that never names it keeps it foldable, and a
        direct `eval` in a local container's own function makes it mutable. The one residual is a
        script-scope container reached by an opaque global surface — a direct `eval`, `Function`,
        timer, or dynamic global write whose code cannot be read — which cannot be frozen without
        also freezing the lookup arrays real samples fold, so it is left to the caller's reflection
        reasoning, the trust an unresolved external call already receives.

        The query is over a *resolved binding*, so it is shadowing-correct, and it descends through
        alias chains, callee parameters, and nested functions, so a capturing closure that mutates
        the container is caught. The answer is fixed for the model's lifetime — a binding's
        reference set does not change — so it is memoized per
        `(binding, inert_methods, direct_eval_ordered)`. A caller may pass *exclude* to
        disregard references within that subtree — asking whether the container is stable across
        the rest of the program, ignoring a read site about to be relocated into it; such a query is
        not memoized, since the answer depends on the excluded region.

        *direct_eval_ordered* is the caller's promise that it has ordered every direct-`eval` site
        of the container's owning function against the read it is folding — the definition-to-read
        span `ReachingModel.value_preserved` proves, whose kills hold those sites — so the eval
        leg does not refuse here. A caller that cannot order its reads against the sites keeps the
        default and the refusal; the promise covers the binding asked about and not the aliases
        its escapes are judged through, which keep the strict answer.
        """
        if exclude is not None:
            return self._immutable_container(
                binding, set(), inert_methods, exclude, direct_eval_ordered)
        key = (id(binding), inert_methods, direct_eval_ordered)
        cached = self._immutable_cache.get(key)
        if cached is None:
            cached = self._immutable_container(
                binding, set(), inert_methods, None, direct_eval_ordered)
            self._immutable_cache[key] = cached
        return cached

    def _immutable_container(
        self,
        binding: Binding,
        visiting: set[int],
        inert_methods: frozenset[str] | None,
        exclude: Node | None = None,
        direct_eval_ordered: bool = False,
    ) -> bool:
        key = id(binding)
        if key in visiting:
            return True
        if binding.exported:
            return False
        visiting = visiting | {key}
        if self._dynamic_scope_mutates(binding, inert_methods, exclude, direct_eval_ordered):
            return False
        for ref in self.model.references(binding, exclude=exclude):
            role = container_reference_role(ref)
            if role is ContainerRole.MEMBER_WRITE:
                return False
            if role is ContainerRole.MEMBER_CALL and not self._call_keeps_container(binding, ref, inert_methods):
                return False
            if role is ContainerRole.ESCAPE:
                if not isinstance(ref, JsIdentifier):
                    return False
                if not self._escape_keeps_container(ref, visiting, inert_methods):
                    return False
        return True

    def _call_keeps_container(
        self,
        binding: Binding,
        reference: Node,
        inert_methods: frozenset[str] | None,
    ) -> bool:
        """
        Whether the method call *reference* begins leaves the container *binding* holds as it was:
        a call its caller vouches for (`_method_call_is_inert`), or a call of one of
        `_ARRAY_READING_METHODS` where the one value of the binding is an array literal without
        holes and the program leaves `Array.prototype` trusted, so that the method called is the
        built-in and every position it reads is one the array owns.
        """
        if _method_call_is_inert(reference, inert_methods):
            return True
        if not _method_call_reads_an_array(reference):
            return False
        literal = self.model.singular_value(binding)
        return (
            isinstance(literal, JsArrayExpression)
            and all(element is not None for element in literal.elements)
            and self.trusted_prototype(list)
        )

    def _dynamic_scope_mutates(
        self,
        binding: Binding,
        inert_methods: frozenset[str] | None,
        exclude: Node | None,
        direct_eval_ordered: bool = False,
    ) -> bool:
        """
        Whether a dynamic scope may change the container *binding* holds. A direct `eval` in a
        local container's own function can rewrite it opaquely — a global is left to the caller's
        reflection reasoning, since freezing every global on any surface over-blocks — unless the
        caller has ordered the eval sites against its read (*direct_eval_ordered*), which carries
        the promise the public query documents. A `with` body's accesses are attributed by name: a
        member write, a reassignment, or an escape mutates it or may alias it out, and a method
        call may mutate it unless the caller vouches that its methods cannot; only a plain member
        read leaves it intact, so a `with` that never names the container is no threat. A dynamic
        escape or reassignment cannot be alias-followed or ordered the way a resolved one can, so
        either is treated as mutating.
        """
        if not direct_eval_ordered and self.model.local_reachable_by_direct_eval(binding):
            return True
        for ref in self.model.dynamic_references(binding, exclude=exclude):
            role = container_reference_role(ref)
            if role is ContainerRole.MEMBER_READ:
                continue
            if role is ContainerRole.MEMBER_CALL and _method_call_is_inert(ref, inert_methods):
                continue
            return True
        return False

    def _escape_keeps_container(
        self,
        ref: JsIdentifier,
        visiting: set[int],
        inert_methods: frozenset[str] | None,
    ) -> bool:
        """
        Whether an escaping reference leaves the container unmutated. Two escapes are precise: an
        alias (`var x = ref` or `x = ref`) keeps it when the aliased binding is itself an immutable
        container, and an argument passed to a statically known function (`f(ref)`) keeps it when
        the parameter it binds is itself an immutable container — interprocedural Case B, the
        parameter's own references decide whether the callee mutates or further-escapes it. A store
        no code observes (`store_unobserved`) hands the container to nobody, as long as the value of
        the assignment goes nowhere either. Every other escape is conservatively unsafe, an
        assignment that is no statement of its own among them: `var x = (y = ref)` stores the
        container in `x` as well as in `y`.
        """
        alias = self.model.name_holding(ref)
        if alias is not None:
            return self._immutable_container(alias, visiting, inert_methods)
        store = enclosing_operator(ref)
        if (
            isinstance(store, JsAssignmentExpression)
            and strip_parens(store.right) is ref
            and isinstance(target := strip_parens(store.left), JsMemberExpression)
            and self.store_unobserved(target)
        ):
            return _result_goes_nowhere(store)
        return self._argument_keeps_container(ref, visiting)

    def _argument_keeps_container(self, ref: JsIdentifier, visiting: set[int]) -> bool:
        """
        Case B: whether an argument *ref* passed to a statically known function leaves the container
        it holds unmutated — true when the parameter it binds is itself an immutable container,
        judged recursively from that parameter's own references, so the callee neither member-writes
        the argument nor lets it escape mutably. The parameter is judged with no inert method: the
        caller's *inert_methods* is its promise that the container's own methods cannot mutate it at
        the original site, and does not carry to a method the callee invokes on the argument or on
        one of its nested containers (`x.a.push(...)`), which may mutate it. False, conservatively,
        when the call cannot be analysed: the callee is not a single known function, it can reach
        the argument through its own `arguments` object, the argument is spread, a spread precedes
        it (so its runtime position shifts past the textual index and the parameter it binds cannot
        be pinned down), the slot it lands in is a rest or destructuring parameter, or the parameter
        is reachable through a `with` or direct `eval` in the callee that resolves a name at runtime
        (an unrecorded write the parameter's reference set cannot rule out). An argument with no
        parameter to bind — passed beyond the declared parameters of a function with no rest
        collector and no `arguments` reach, textual or reflective — is safe, since the callee cannot
        name it.
        """
        parent = ref.parent
        if not isinstance(parent, JsCallExpression) or ref not in parent.arguments:
            return False
        func = self.unambiguous_callee(parent)
        if func is None:
            return False
        if self._callee_uses_arguments(func):
            return False
        params = func.params
        if any(isinstance(param, JsRestElement) for param in params):
            return False
        index = parent.arguments.index(ref)
        if any(isinstance(arg, JsSpreadElement) for arg in parent.arguments[:index]):
            return False
        if index >= len(params):
            return True
        param = params[index]
        if not isinstance(param, JsIdentifier):
            return False
        binding = self.model.binding_of(param)
        if binding is None:
            return False
        if self.model.reflection_can_reach(binding):
            return False
        return self._immutable_container(binding, visiting, None)

    def _callee_uses_arguments(self, func: Node) -> bool:
        """
        Whether a non-arrow callee can reach its call's arguments through its own `arguments` object,
        which aliases the positional arguments — including any passed beyond the declared parameters — so
        that `arguments[i][...] = v` mutates a container the by-position parameter reasoning in
        `_argument_keeps_container` would otherwise miss. It is reached either by naming `arguments`
        directly, or reflectively: a `with` or a direct `eval` in the callee — or in a closure nested
        inside it, which inherits the callee's `arguments` — can read that object with no textual
        reference, so a reflectively reachable `arguments` counts too. An arrow has no `arguments` of its
        own (a reference inside it binds the enclosing function's, unrelated to the arrow's parameters),
        so it is exempt. When the callee can reach `arguments`, the escape is treated as mutable. The
        answer is a structural property of the callee, so it is memoized per function.
        """
        cached = self._uses_arguments_cache.get(id(func))
        if cached is None:
            cached = self._compute_callee_uses_arguments(func)
            self._uses_arguments_cache[id(func)] = cached
        return cached

    def _compute_callee_uses_arguments(self, func: Node) -> bool:
        if isinstance(func, JsArrowFunctionExpression):
            return False
        func_scope = self.model.parameter_scope(func)
        if func_scope is None:
            return False
        binding = func_scope.bindings.get('arguments')
        if binding is None:
            return False
        if self.model.references(binding):
            return True
        return self.model.reflection_can_reach(binding)

    def static_callee(
        self, call: JsCallExpression
    ) -> JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression | None:
        """
        The function a call invokes, resolved permissively through `function_of`: a direct function or
        arrow expression callee, or an identifier bound to a single function — a declaration, a
        `var`/`let`/`const` initializer, or the value a name is assigned exactly once. For a name that
        held a value and was then reassigned this returns the post-reassignment value, which is the
        running target only where that reassignment is established before the call; a consumer that
        cannot order the reassignment against the call must use `unambiguous_callee` instead. `None` for
        a method call, a parameter, a redeclared or dynamically-rebindable binding, or an unresolved name.
        """
        callee = call.callee
        if isinstance(callee, (JsFunctionExpression, JsArrowFunctionExpression)):
            return callee
        if not isinstance(callee, JsIdentifier):
            return None
        return self.function_of(self.model.resolve(callee))

    def a_name_this_file_binds_holds_the_callee(self, call: JsCallExpression) -> bool:
        """
        Whether *call* names its callee with an identifier this file binds, while `static_callee`
        declines to say which function that binding holds.

        A caller reasoning about what a call may have done reads `static_callee` answering `None` in
        two ways, and this tells them apart. Where the callee is a method, a host function, a name
        nothing here declares, or one holding what the host passed
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.supplied_from_outside`), `None` means
        the call runs something outside this file's reckoning, which is a standing condition every
        such caller was written under. Where it is a name this file binds, `None` means the model
        saw the binding and would not state its value - one Annex B copies into a block's enclosing
        scope is such a function - and what it runs may be any of the ones written here, one that
        writes the very binding being reasoned about included.
        """
        callee = strip_parens(call.callee)
        if not isinstance(callee, JsIdentifier):
            return False
        if self.model.supplied_from_outside(self.model.resolve(callee)):
            return False
        return self.static_callee(call) is None

    def unambiguous_callee(
        self, call: JsCallExpression
    ) -> JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression | None:
        """
        The ordering-free twin of `static_callee`, for a consumer that reasons about a call without
        knowing where it sits in execution order. Identical except an identifier callee resolves through
        `unambiguous_function`, so a name that held a value and was then reassigned — whose running target
        depends on the call's position relative to the reassignment — yields `None` rather than the
        post-reassignment value.
        """
        return unambiguous_callee(self.model, call)

    def _collect_functions(self) -> list[Node]:
        functions: list[Node] = [self.model.root]
        for node in self.model.root.walk():
            if isinstance(node, FUNCTION_NODES):
                functions.append(node)
        return functions

    def _compute(self):
        """
        The least fixpoint of the function summaries, by worklist: every function is scanned once, and a
        scan that changes a summary re-queues only the functions that call the changed one. An edge is
        recorded on every scan, including one that changes no summary, so the edge exists by the time its
        callee first changes even when the caller was scanned before it.
        """
        functions: dict[int, Node] = {}
        for func in self._functions:
            fid = id(func)
            functions[fid] = func
            self._summaries[fid] = EffectSummary()
        edges = _CallEdges()
        queue = deque(functions.values())
        queued = set(functions)
        while queue:
            func = queue.popleft()
            queued.discard(id(func))
            edges.caller = id(func)
            summary = self._scan(func, edges.record)
            if summary == self._summaries[id(func)]:
                continue
            self._summaries[id(func)] = summary
            for caller in edges.callers.get(id(func), ()):
                if caller not in queued:
                    queued.add(caller)
                    queue.append(functions[caller])

    def _scan(
        self,
        func: Node,
        record_call: Callable[[Node], None] | None = None,
    ) -> EffectSummary:
        summary = EffectSummary()
        if isinstance(func, FUNCTION_NODES) and wraps_return(func):
            summary.wraps_return = True
        for node in _body_nodes(func):
            if isinstance(node, JsThrowStatement):
                summary.throws = True
            elif isinstance(node, JsIdentifier):
                if not summary.throws and self.model.read_may_throw(node):
                    summary.throws = True
                lexical_read = self.model.lexical_binding_read(node)
                if lexical_read is not None:
                    summary.dead_zone_reads.add(lexical_read)
                if reference_role(node) is not Role.READ:
                    self._account_write(summary, node, func)
            elif isinstance(node, JsMemberExpression):
                base = node.object
                if base is not None and not self._base_is_safe(base):
                    summary.throws = True
                if is_member_write_target(node):
                    write_class = self._member_write_class(node, func)
                    if write_class is _WriteClass.OBSERVABLE:
                        summary.writes_global = True
                    elif write_class is _WriteClass.VIA_RESULT:
                        summary.mutates_returned_local = True
                elif base is not None and not self._getter_free_read(node):
                    summary.calls_unknown = True
            elif isinstance(node, (JsCallExpression, JsNewExpression)):
                self._account_call(summary, node, record_call)
            elif isinstance(node, JsImportExpression):
                summary.calls_unknown = True
        if isinstance(func, FUNCTION_NODES) and not is_generator_function(func):
            for binding in summary.dead_zone_reads:
                if (
                    self._owns_binding(binding, func)
                    and not self._binding_reads_past_dead_zone(binding)
                ):
                    summary.throws = True
            summary.dead_zone_reads = {
                binding
                for binding in summary.dead_zone_reads
                if not self._owns_binding(binding, func)
            }
        else:
            summary.dead_zone_reads = set()
        return summary

    def _binding_reads_past_dead_zone(self, binding: Binding) -> bool:
        """
        Whether every read of *binding* is guaranteed to run past its temporal dead zone, so no call
        that reaches one raises the `ReferenceError` a read before the declaration would. The reads
        are enumerated from the binding itself rather than the scan that reached it: a function that
        owns the binding may read it directly or only through a nested function whose summary the
        scan absorbed, and the question — does some read run before every declaration of it — is the
        one `DominanceModel.past_dead_zone` answers per read, ordering the read against its
        declaration across the nested call the same way the call-site gate orders an outer binding
        against the call. Answered once per binding: it is a pure function of the binding and the
        model, both fixed for this model's lifetime.

        A function's generator is the one shape that never asks: its body runs at an iteration
        rather than the call, so a dead-zone read inside it is not an effect the call carries.
        """
        cached = self._dead_zone_safe_cache.get(id(binding))
        if cached is not None:
            return cached
        if self._dominance is None:
            self._dominance = build_dominance(self.model, intrinsic_writes=self.intrinsic_writes)
        cached = all(
            self._dominance.past_dead_zone(binding, read)
            for read in binding.reads
        )
        self._dead_zone_safe_cache[id(binding)] = cached
        return cached

    def _account_write(self, summary: EffectSummary, target: JsIdentifier, func: Node):
        binding = self.model.resolve(target)
        if binding is None:
            summary.writes_global = True
            return
        if self._owns_binding(binding, func):
            return
        if binding.is_read:
            summary.written_bindings.add(binding)
        if self._write_unobservable(binding, func):
            return
        if binding.kind is BindingKind.IMPLICIT_GLOBAL or binding.scope is self.model.root_scope:
            summary.writes_global = True
        else:
            summary.writes_captured = True

    def _write_unobservable(self, binding: Binding, func: Node) -> bool:
        """
        Whether assigning *binding* within *func* has no observable consumer, so the assignment
        is not counted as a write. The program must be `global_pristine`: it exposes no reflection
        surface through which the name could be read and installs no accessor that an assignment to
        a global property could trigger as a setter. An exported binding is always observed, since
        an importer reads it across the module boundary. Otherwise the write is unobservable when
        either the value is read nowhere (`Binding.is_read` is false), or every reference to it is
        `_confined_to` *func* so no outside code can see it. This ports the evaluator's sound
        permissiveness for an obfuscator's scratch binding — whether a write-only global or an
        accumulator local to a single function.

        Not counting the write is not the same as answering that the function is pure. A confined
        accumulator whose name is an implicit global is also *read*, and
        `SemanticModel.read_may_throw` answers that such a read may throw, since nothing here orders
        the creating assignment in front of it; the summary then carries `throws` with
        `writes_global` clear.
        """
        if not self.global_pristine or binding.exported:
            return False
        return not binding.is_read or self._confined_to(binding, func)

    def _confined_to(self, binding: Binding, func: Node) -> bool:
        """
        Whether every reference to *binding* lies within *func*, which must be a function rather than the
        script, so the binding does not escape: no code outside *func* can read it, and a write to it is
        unobservable past the single call.
        """
        if not isinstance(func, FUNCTION_NODES):
            return False
        return self._confining_function(binding) is func

    def _member_write_class(self, member: JsMemberExpression, func: Node) -> _WriteClass:
        """
        How observable the container written by *member* (`base.k = v`, `base[i]++`, `delete base[i]`) is
        to code outside *func* — the distinction that lets a mutation of an obfuscator's scratch container
        be tolerated without weakening purity. The base must be a fresh value: written directly on an
        object/array/function literal, or resolving to a binding *func* owns whose value is always freshly
        built — a rest parameter, which the language guarantees is a new array, or a local initialized
        only to an object/array/function literal. An object literal with an own setter — or one that
        installs a custom prototype through `__proto__:`, which may carry an inherited setter — does NOT
        qualify, since the write then runs an accessor a caller can observe. A plain parameter does NOT
        qualify either: it aliases the caller's object, so `function modify(a){ a[0] = 9; }` mutates the
        argument observably — the soundness boundary this rests on. Ownership is the exact test
        `_account_write` uses for a plain-identifier write (`func_scope.contains(binding.scope)` and not
        global), so a binding captured *from an enclosing scope* is not owned and its mutation stays
        `OBSERVABLE`, matching that a call mutating an outer local is a visible effect.

        For an owned fresh container the outcome splits on how it escapes. When no reference lets it out
        (`_container_non_escaping`) and no nested function captures it, the write is `UNOBSERVABLE` — the
        container dies with the call and no caller can ever reach it, so a function whose only effect is
        the mutation is pure. Otherwise the container — or a closure over it — leaves *func*, but every
        escape route other than the return value independently sets a blocking flag on the summary (a
        store to a global or captured binding, a leak into an unknown callee, a throw), so the only
        unflagged escape is `return`, whose value the caller may discard: the write is then `VIA_RESULT`,
        seen only if that value is used.

        A write hidden behind a dynamic scope — through a name a `with` body or direct `eval` resolves at
        runtime — is `OBSERVABLE`: the base resolves to no binding, so the write is conservatively kept,
        which is sound. The residual is the opaque-surface one `binding_is_immutable_container` documents:
        a reflective surface whose code cannot be read could install a prototype accessor that observes a
        write this deems unobservable, and freezing on it would refuse the obfuscator idioms this is meant
        to see through, so it is left to that boundary.

        The judgment is structural — fixed by the binding's declarations and reference set — so it is
        invariant across the fixpoint passes that recompute the summaries, and is memoized per member.
        """
        cached = self._member_write_cache.get(id(member))
        if cached is None:
            cached = self._classify_member_write(member, func)
            self._member_write_cache[id(member)] = cached
        return cached

    def _classify_member_write(self, member: JsMemberExpression, func: Node) -> _WriteClass:
        if self.store_unobserved(member):
            return _WriteClass.UNOBSERVABLE
        base = member.object
        if isinstance(base, (JsArrayExpression, JsFunctionExpression)):
            return _WriteClass.UNOBSERVABLE
        if isinstance(base, JsObjectExpression):
            if object_member_access_runs_accessor(base):
                return _WriteClass.OBSERVABLE
            return _WriteClass.UNOBSERVABLE
        if not isinstance(base, JsIdentifier):
            return _WriteClass.OBSERVABLE
        binding = self.model.resolve(base)
        if binding is None or not self._owns_binding(binding, func):
            return _WriteClass.OBSERVABLE
        if not self._fresh_container_origin(binding, func):
            return _WriteClass.OBSERVABLE
        if not binding.captured and self._container_non_escaping(binding):
            return _WriteClass.UNOBSERVABLE
        return _WriteClass.VIA_RESULT

    def store_unobserved(self, member: JsMemberExpression) -> bool:
        """
        Whether the store whose target is *member* is observed by no code: it is the store
        `module.exports = v` through the `module` the host passed, and nothing reads what the file
        stores there (`SemanticModel.module_exports_unread`). The host made `exports` a data
        property of its own on that object, so the store runs no setter and cannot fail; under the
        reading as an ES module, where the name may be absent, the read of `module` keeps its own
        throw.
        """
        if static_property_key(member) != 'exports' or not is_plain_store_target(member):
            return False
        base = strip_parens(member.object)
        if not isinstance(base, JsIdentifier) or base.name != 'module':
            return False
        binding = self.model.resolve(base)
        if binding is None or binding is not self.model.root_scope.bindings.get('module'):
            return False
        return self.model.module_exports_unread()

    def _owns_binding(self, binding: Binding, func: Node) -> bool:
        """
        Whether *binding* is declared within *func* rather than reaching in from an enclosing scope or the
        global object — the exact ownership test `_account_write` applies to a plain-identifier write, so a
        mutation of an owned local and a mutation of its name agree on observability. A binding *func* owns
        has all its references inside *func*'s subtree, so the summary scan sees every one of its escapes.

        A function whose parameter list holds an expression introduces its parameters and its own
        name in scopes standing *outside* its body's, so containment alone would read a write to its
        own parameter as a write reaching in from elsewhere. `Scope.closure_home` says those scopes
        are the same call as the body, and answers for all three shapes a function is built in.
        """
        if binding.kind is BindingKind.IMPLICIT_GLOBAL or binding.scope is self.model.root_scope:
            return False
        func_scope = self.model.function_scope(func)
        if func_scope is None:
            return False
        return func_scope.contains(binding.scope) or binding.scope.closure_home is func_scope

    def _fresh_container_origin(self, binding: Binding, func: Node) -> bool:
        """
        Whether *binding* only ever holds a container freshly built inside *func*, so a member write through
        it cannot be observed anywhere else. The binding-level face of `_fresh_kind`; see that method.
        """
        return self._binding_fresh_kind(binding, func, frozenset()).is_fresh

    def _binding_fresh_kind(
        self, binding: Binding, func: Node, visiting: frozenset[int]
    ) -> _FreshKind:
        """
        The kind of container *binding* is known to hold on every path, judged from inside *func*. A rest
        parameter is a fresh array by language guarantee. Otherwise the binding must be one *func* owns — a
        name reaching in from an enclosing scope or the global object denotes a container other code can
        already reach, however freshly its initializer built it — and *every* value it can take must be
        fresh: each declaration's initializer and each later write, because a name that holds an outer
        container even once makes a write through it observable there. A binding written through a pattern
        rather than a plain assignment target has no single value expression to judge, so it fails.

        A binding whose `constructor` or `__proto__` is written anywhere is never an `ARRAY`, however it was
        built. Those two properties decide what an allocating `Array.prototype` method actually returns:
        `slice` and its neighbours route through ArraySpeciesCreate, which reads
        `constructor[Symbol.species]` off the receiver, so a program that writes either one can make the
        "new" array be a shared object — or make the call throw, by leaving a primitive there. The container
        is still fresh, so a write *into* it stays unobservable; it is only the array guarantee that is lost.

        The kind is the weakest of the values, since a consumer may only rely on what holds for all of them.
        """
        if self._is_rest_param(binding):
            return _FreshKind.ARRAY
        if binding.kind not in (BindingKind.VAR, BindingKind.LET, BindingKind.CONST):
            return _FreshKind.NOT_FRESH
        if not self._owns_binding(binding, func):
            return _FreshKind.NOT_FRESH
        if not binding.declarations or id(binding) in visiting:
            return _FreshKind.NOT_FRESH
        visiting = visiting | {id(binding)}
        kind = _FreshKind.ARRAY
        if self._species_written(binding):
            kind = _FreshKind.CONTAINER
        for decl in binding.declarations:
            declarator = decl.parent
            if not isinstance(declarator, JsVariableDeclarator):
                return _FreshKind.NOT_FRESH
            kind = _weakest(kind, self._fresh_kind(declarator.init, func, visiting))
            if not kind.is_fresh:
                return _FreshKind.NOT_FRESH
        for ref in self.model.references(binding):
            if reference_role(ref) is Role.READ:
                continue
            parent = ref.parent
            if not isinstance(parent, JsAssignmentExpression) or parent.left is not ref:
                return _FreshKind.NOT_FRESH
            if parent.operator != '=':
                return _FreshKind.NOT_FRESH
            kind = _weakest(kind, self._fresh_kind(parent.right, func, visiting))
            if not kind.is_fresh:
                return _FreshKind.NOT_FRESH
        return kind

    def _species_written(self, binding: Binding) -> bool:
        """
        Whether any reference to *binding* writes a property that decides what an allocating
        `Array.prototype` method returns. Only `constructor` and `__proto__` do: ArraySpeciesCreate reads
        `constructor[Symbol.species]` off the receiver, and `__proto__` replaces the prototype the
        `constructor` lookup walks.

        A key that is not a literal counts, because it may name either one. That conservatism is affordable
        here and would not be in a whole-program rule: the question is asked about the handful of references
        to one binding, so an ordinary `s[i] = v` element write on a *different* binding is untouched. It is
        also the direction that survives constant folding — a fold turns `a['const' + 'ructor']` into
        `a.constructor`, moving the answer from unsafe to unsafe rather than from safe to unsafe.
        """
        for ref in self.model.references(binding):
            parent = ref.parent
            if not isinstance(parent, JsMemberExpression) or parent.object is not ref:
                continue
            if not is_member_write_target(parent):
                continue
            prop = parent.property
            if not parent.computed:
                if isinstance(prop, JsIdentifier) and prop.name in SPECIES_KEYS:
                    return True
            elif isinstance(prop, JsStringLiteral):
                if prop.value in SPECIES_KEYS:
                    return True
            elif not isinstance(prop, JsNumericLiteral):
                return True
        return False

    def _fresh_kind(self, node: Node | None, func: Node, visiting: frozenset[int]) -> _FreshKind:
        """
        The kind of container the expression *node* is known to build when evaluated inside *func*, or
        `NOT_FRESH` when it may evaluate to something other code can already reach. This is a *must* analysis:
        it answers only for expressions whose result is provably a new object, which is what lets a member
        write through the result be classified as unobservable.

        Five forms qualify. A container literal builds its value on the spot — unless its member access runs an
        accessor, the shared `container_literal_access_is_plain` test. An identifier resolves through its
        binding, which *func* must own. An allocating `Array.prototype` method
        (`_FRESH_ARRAY_RESULT_METHODS`) returns a new array, but only when the prototype is undisturbed and
        the receiver is itself known to be an array: a fresh object literal carrying its own `slice` is not,
        and neither is a value of unknown type such as a plain parameter. A call the model resolves to one
        function qualifies when every `return` in that function yields a fresh container — and a function with
        a path that returns no value does not, since that path yields `undefined`. `new Array(...)` is
        deferred to `_pure_construct`, which owns the argument rule for that root.

        Deliberately *not* a may-allocate analysis. `JsObjectFold._value_allocates` asks the opposite
        question — whether an expression might mint an object whose identity a fold would duplicate — and
        answers `True` for any nested call, where this answers `NOT_FRESH` for nearly all of them. The two are
        not monotone in one another and must not be merged.
        """
        node = strip_parens(node)
        if node is None:
            return _FreshKind.NOT_FRESH
        if isinstance(node, JsArrayExpression):
            return _FreshKind.ARRAY
        if isinstance(node, (JsObjectExpression, JsFunctionExpression, JsArrowFunctionExpression)):
            return _FreshKind.CONTAINER if container_literal_access_is_plain(node) else _FreshKind.NOT_FRESH
        if isinstance(node, JsIdentifier):
            binding = self.model.resolve(node)
            if binding is None:
                return _FreshKind.NOT_FRESH
            return self._binding_fresh_kind(binding, func, visiting)
        if isinstance(node, JsNewExpression):
            return _FreshKind.ARRAY if self._pure_construct(node) else _FreshKind.NOT_FRESH
        if isinstance(node, JsCallExpression):
            return self._call_fresh_kind(node, func, visiting)
        return _FreshKind.NOT_FRESH

    def _call_fresh_kind(
        self, call: JsCallExpression, func: Node, visiting: frozenset[int]
    ) -> _FreshKind:
        callee = strip_parens(call.callee)
        if isinstance(callee, JsMemberExpression) and not callee.computed:
            prop = callee.property
            if not isinstance(prop, JsIdentifier) or prop.name not in _FRESH_ARRAY_RESULT_METHODS:
                return _FreshKind.NOT_FRESH
            if not self.trusted_prototype(list):
                return _FreshKind.NOT_FRESH
            if self._fresh_kind(callee.object, func, visiting) is not _FreshKind.ARRAY:
                return _FreshKind.NOT_FRESH
            return _FreshKind.ARRAY
        if isinstance(callee, JsIdentifier):
            callee_func = self.unambiguous_function(self.model.resolve(callee))
            if callee_func is None or id(callee_func) in visiting:
                return _FreshKind.NOT_FRESH
            visiting = visiting | {id(callee_func)}
            returns = [n for n in _body_nodes(callee_func) if isinstance(n, JsReturnStatement)]
            if not returns or not _returns_on_every_path(callee_func):
                return _FreshKind.NOT_FRESH
            kind = _FreshKind.ARRAY
            for statement in returns:
                kind = _weakest(kind, self._fresh_kind(statement.argument, callee_func, visiting))
                if not kind.is_fresh:
                    return _FreshKind.NOT_FRESH
            return kind

        return _FreshKind.NOT_FRESH

    @staticmethod
    def _is_rest_param(binding: Binding) -> bool:
        """
        Whether *binding* is a function's rest parameter (`function f(...xs)`), whose value the language
        guarantees is a fresh array on every call.
        """
        return binding.kind is BindingKind.PARAM and any(
            isinstance(decl.parent, JsRestElement) for decl in binding.declarations
        )

    def _container_non_escaping(self, binding: Binding) -> bool:
        """
        Whether every reference to *binding* keeps its container contained: each is a member read or
        write (`obj.k`, `obj[i] = v`), a verdict read (`!obj`, `if (obj)`) that consumes the value
        whole and forwards nothing, or — failing those — an escape, rebinding, or method call
        through which the container could be aliased out, mutated by other code, or replaced. The
        tightest form of the escape check, since a mutation only stays unobservable while no other
        code can reach the object.

        Orthogonal to freshness, and deliberately not merged with `_binding_fresh_kind`: this asks where a
        container *goes*, that asks where it *came from*. Both are needed and neither implies the other — a
        fresh literal can escape, and a parameter that never escapes was still not built here.
        `_classify_member_write` is where the two compose.
        """
        for ref in self.model.references(binding):
            if container_reference_role(ref) not in (
                ContainerRole.MEMBER_READ, ContainerRole.MEMBER_WRITE, ContainerRole.VERDICT_READ,
            ):
                return False
        return True

    def _confining_function(self, binding: Binding) -> Node | None:
        """
        The single function that lexically encloses every reference to *binding*, or `None` when the
        references do not share one — they span sibling functions or reach the top level. Cached per
        binding, since the binding's reference set is fixed for the lifetime of the model.
        """
        key = id(binding)
        if key not in self._confine_cache:
            self._confine_cache[key] = self._scan_confining_function(binding)
        return self._confine_cache[key]

    def _scan_confining_function(self, binding: Binding) -> Node | None:
        refs = self.model.references(binding)
        if not refs:
            return None
        enclosing = enclosing_function(refs[0])
        if enclosing is None:
            return None
        for ref in refs[1:]:
            if enclosing_function(ref) is not enclosing:
                return None
        return enclosing

    def _account_call(
        self,
        summary: EffectSummary,
        call: JsCallExpression | JsNewExpression,
        record_call: Callable[[Node], None] | None = None,
    ):
        callee = self._resolve_callee(call)
        if callee is _PURE:
            return
        if isinstance(callee, Node):
            if record_call is not None:
                record_call(callee)
            summary.absorb(self.summary_of(callee))
        else:
            summary.calls_unknown = True

    def _resolve_callee(self, call: JsCallExpression | JsNewExpression) -> Node | _PureCall | None:
        callee = call.callee
        if isinstance(call, JsNewExpression) and self._pure_construct(call):
            return _PURE
        if isinstance(callee, (JsFunctionExpression, JsArrowFunctionExpression)):
            return callee
        if isinstance(callee, JsMemberExpression) and not callee.computed:
            base, prop = callee.object, callee.property
            if isinstance(base, JsIdentifier) and isinstance(prop, JsIdentifier):
                if F'{base.name}.{prop.name}' in PURE_INTRINSIC_METHODS and self._is_global_intrinsic(base):
                    return _PURE
            return None
        if isinstance(callee, JsIdentifier):
            if callee.name in PURE_GLOBAL_FUNCTIONS and self._is_global_intrinsic(callee):
                return _PURE
            return self.unambiguous_function(self.model.resolve(callee))
        return None

    def _pure_construct(self, call: JsNewExpression) -> bool:
        """
        Whether `new <callee>(...)` is a pure allocation: the callee denotes a pristine constructor root in
        `_PURE_CONSTRUCTOR_ROOTS` and its arguments are safe for that root. `Array` — the only such root
        today — throws only on a bad single numeric length, decided by `_array_construct_is_pure`; a root
        added to the set needs its own argument rule wired in here rather than reusing Array's.

        Purity of the construction, not freshness of its result: those are separate questions, and this stays
        separate from `_fresh_kind` even though that predicate's `new Array(n)` form calls it. A construction
        can be impure and still yield a fresh object, so a caller wanting freshness must ask `_fresh_kind`.
        """
        root = self.intrinsic_of(call.callee)
        if not (isinstance(root, str) and root in _PURE_CONSTRUCTOR_ROOTS):
            return False
        return _array_construct_is_pure(call.arguments)

    def function_of(
        self, binding: Binding | None
    ) -> JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression | None:
        """
        The single function a *binding* stably resolves to — a sole declaration's function declaration or
        function/arrow initializer, or a name assigned a function exactly once (`f = function(){}`, the
        form namespace flattening leaves) — or `None` when the binding is absent, redeclared, reassigned
        to more than one value, dynamically rebindable, or not bound to a function. A lone assignment
        counts because the name denotes that one function wherever it is not in the value's temporal dead
        zone; a caller that also needs the value established before a use orders it separately. The
        binding-level twin of `static_callee`, and the function-typed specialization of
        `SemanticModel.singular_value`: it filters that value-resolution to a function node.
        """
        value = self.model.singular_value(binding)
        if isinstance(value, FUNCTION_NODES):
            return value
        return None

    def unambiguous_function(
        self, binding: Binding | None
    ) -> JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression | None:
        """
        The single function *binding* names for a consumer that resolves calls without execution ordering
        — the interpreter — or `None`. A name that carried a value from its declaration and is then
        reassigned holds two values across its life and is refused; since `SemanticModel.singular_value`
        took the complete-singleton contract, that refusal is the query's own, and this answer equals
        `function_of`. The name survives for the intent it documents at its call sites — the ordering-free
        view the evaluator's visible-functions map applied before interpretation routed resolution
        through the model.
        """
        return unambiguous_function(self.model, binding)

    def _is_global_intrinsic(self, name: JsIdentifier) -> bool:
        """
        Whether *name* denotes a trusted intrinsic root that the program leaves pristine and does not
        shadow with a local binding at this use site.
        """
        if not self.intrinsics_pristine:
            return False
        return self.model.lookup(name.name, self.model.scope_of(name)) is None

    def intrinsic_of(self, node: Node | None) -> str | _GlobalObject | None:
        """
        The pristine intrinsic value *node* provably denotes: `GLOBAL_OBJECT` for the global object,
        an intrinsic root name (`'Array'`, `'String'`, …) for a named intrinsic, or `None`. A name
        is returned only under `intrinsics_pristine` and where the identifier is unshadowed at this
        use site, so the result may be *value-trusted* — used to construct, to clear a getter-free
        static read, or to fold `A || B`. Every value it can return — `globalThis` and every
        `refinery.lib.scripts.js.analysis.intrinsics.PURE_INTRINSIC_ROOTS` member — is truthy, so
        `A || B` evaluates to `A` whenever `intrinsic_of(A)` is not `None`; a contributor extending
        this must preserve that truthiness invariant and never return a falsy name such as
        `NaN`/`undefined`.

        It deliberately does NOT follow a local alias through its value — `intrinsic_of` of an identifier
        bound to `var x = Array` is `None` — because a local's value holds only where it is established, a
        control-flow fact this flow-insensitive query cannot certify; a consumer that owns dominance
        resolves the alias itself against `singular_value`. It likewise does not treat `<global-object>.Name`
        as a value: that read's getter-freeness rests on `global_pristine`, a weaker premise than value
        trust, so it stays the concern of `_is_trusted_global_read`.
        """
        node = strip_parens(node)
        if isinstance(node, JsIdentifier):
            if node.name == 'globalThis' and self.model.lookup(node.name, self.model.scope_of(node)) is None:
                return GLOBAL_OBJECT
            if node.name in PURE_INTRINSIC_ROOTS and self._is_global_intrinsic(node):
                return node.name
            return None
        if isinstance(node, JsLogicalExpression) and node.operator == '||':
            return self.intrinsic_of(node.left)
        return None

    def trusted_intrinsic(self, node: Node | None) -> str | None:
        """
        The global name *node* denotes, when that one name is provably still the built-in, or `None`. A
        name qualifies when the program never binds it, never assigns to it, never writes or updates a
        property anywhere on it, and neither exposes a reflection surface through which it could be
        replaced at runtime nor stores a property on the global object under a runtime key
        (`SemanticModel.has_opaque_global_write`), which may replace that name's value the same way.

        This differs from `intrinsic_of` in *scope of the question*, not in strictness. `intrinsic_of`
        rests on `intrinsics_pristine`, one program-wide flag over a fixed root set, so a single
        `Object.prototype.x = 1` withdraws trust from every intrinsic in the file — including `Math`,
        which that line cannot affect. This query answers per name, so the same program still folds
        `Math.floor` while declining `Object.keys`. Its callers are the constant folds, which need to know
        whether *this* built-in is intact; `intrinsic_of` answers the stronger question of whether a value
        may be trusted for construction or `A || B` folding, and keeps its own callers and vocabulary.

        The name is not checked against a list of blessed intrinsics: whether a fold *knows how* to
        evaluate the call is the caller's question, answered by its own registry lookup. Conflating the two
        is what let a registry entry exist with no matching trust rule.

        Shadowing needs no per-site scope resolution, because a name bound *anywhere* in the program is
        already disqualified: `_globals_written` collects every binding in every scope. That is stricter
        than JavaScript requires — a shadow inside an unrelated function does not affect this use site —
        and deliberately so. A name the program binds at all is one an obfuscator may be routing values
        through, and the price of refusing is an unfolded call rather than a wrong value.
        """
        node = strip_parens(node)
        if not isinstance(node, JsIdentifier):
            return None
        if not self.trusted_intrinsic_name(node.name):
            return None
        return node.name

    def program_trust(self) -> AnchoredTrust:
        """
        The trust questions of a fold no point is given for, each answered for the whole program:
        the oracle vouches for no anchor, and a load of code anywhere may precede the fold.
        """
        model = self.model
        return AnchoredTrust(self, lambda: False, lambda: model.imports_code() or bool(model.code_load_sites()))

    def trusted_intrinsic_name(self, name: str) -> bool:
        """
        `EffectModel.trusted_intrinsic` for a caller that holds a global name rather than a node
        spelling it: a regular-expression literal builds its object from `RegExp` without naming it,
        so a fold deciding what `/a/g` matches has no identifier to ask about.
        """
        if self.model.has_reflection_surface() or self.model.has_opaque_global_write():
            return False
        return name not in self._globals_written

    def intrinsic_name_unwritten(self, node: Node | None) -> str | None:
        """
        The per-name arm of `trusted_intrinsic`: the global name *node* denotes when the program
        never binds it, never assigns to it, and never writes or updates a property anywhere on it.
        The question a consumer that holds an oracle clearance composes with it — the oracle
        answered the reflection terms at the anchor, so the name question is what remains. A
        consumer without one takes `trusted_intrinsic`, which is this plus those terms.
        """
        node = strip_parens(node)
        if not isinstance(node, JsIdentifier):
            return None
        if node.name in self._globals_written:
            return None
        return node.name

    def prototype_name_unwritten(self, value_type: type) -> bool:
        """
        The per-name arm of `trusted_prototype`: whether the intrinsic owning *value_type*'s
        prototype was never written. The question a consumer that holds an oracle clearance
        composes with it; a consumer without one takes `trusted_prototype`, which is this plus its
        reflection term.
        """
        owner = PROTOTYPE_OWNERS.get(value_type.__name__)
        return owner is not None and owner not in self._globals_written

    def trusted_prototype(self, value_type: type) -> bool:
        """
        Whether the prototype supplying *value_type*'s methods is provably unmodified, so a method call on
        a receiver of that type still means what the language says. A method call on a literal receiver
        names no global, which is exactly why it needs its own question: `trusted_intrinsic` can only
        judge names the expression mentions, and `'ab'.toUpperCase()` mentions none.

        The owning intrinsic is looked up rather than assumed, and then asked the same per-name question a
        named callee gets — `String.prototype.toUpperCase = f` and
        `Object.defineProperty(Array.prototype, ...)` are both already recorded as writes to `String` and
        `Array` by `refinery.lib.scripts.js.analysis.intrinsics.build_intrinsic_writes`. A type with
        no known owner is never trusted.
        """
        owner = PROTOTYPE_OWNERS.get(value_type.__name__)
        if owner is None:
            return False
        if self.model.has_reflection_surface():
            return False
        return self.prototype_name_unwritten(value_type)

    def global_key_written(self, name: str, key: str) -> bool:
        """
        Whether the program writes the property *key* on a chain rooted at the global *name*:
        `Object.prototype.constructor = C`, `delete Object.getPrototypeOf`, or a descriptor
        installed for that key. The per-name question `_globals_written` answers is too coarse for a
        caller that cares which property was replaced — a file patching `Object.prototype.z` has
        written `Object`, and refusing everything about `Object` on that basis refuses the very
        files the question is asked about.

        The write is attributed to a *name* rather than to a receiver, which is what makes it
        answerable at all: the receiver of `Object.prototype.constructor = C` is a value no static
        analysis names, while the chain it is written through is rooted in one that is. A name whose
        written keys cannot be bounded — one the program binds, hands to code this analysis cannot
        read, writes a computed key on, or installs a descriptor on from a value it cannot read —
        answers `True` for every key, and so does a name outside
        `refinery.lib.scripts.js.analysis.intrinsics.KEYED_WRITE_ROOTS`, which the scan records
        nothing about at all.
        """
        return self.intrinsic_writes.key_written(name, key)

    def _prototypes_intact(self, owner: str, roots: frozenset[str], region: list[Node] | None = None) -> bool:
        """
        `refinery.lib.scripts.js.analysis.intrinsics.IntrinsicWrites.roots_unwritten` with the
        reflection term, which is what separates the two questions `read_chain_intact` and
        `chain_roots_unwritten` ask. Neither is spelled out twice, so a term added to one chain
        question reaches both arms rather than only the one it was written into.

        With *region*, the reflection term is asked of the opaque surfaces the nodes of *region*
        leave standing rather than of the whole program — the tree an edit that deletes them
        leaves, which is the tree a fold deciding what that same edit may drop has to judge on.
        """
        if region is None:
            if self.model.has_reflection_surface():
                return False
        elif any(
            not any(site is root or site.is_descendant_of(root) for root in region)
            for site in self.model.opaque_reflection_sites()
        ):
            return False
        return self.intrinsic_writes.roots_unwritten(owner, roots)

    def read_chain_intact(self, value_type: type, region: list[Node] | None = None) -> bool:
        """
        Whether every prototype a plain property read on a value of *value_type* consults is unmodified, so
        the read touches a data slot and runs nothing. Strictly stronger than `trusted_prototype`, which
        answers the neighbouring question for a method *call*, and the two must not be merged: a method
        resolves on the prototype that owns it, so `Array.prototype.join` shadows anything installed on
        `Object.prototype` and a patch there cannot change what `[1, 2].join('-')` means. A read of an
        arbitrary name has no such shadow — `Object.prototype` roots every chain, so a getter installed
        there is reached by a read on an array literal, on a primitive, and on `Math` alike.

        Confirmed against Node in both directions rather than reasoned from the specification: patching
        `Object.prototype.join` leaves `[1, 2].join('-')` intact, while patching `Object.prototype.zz`
        makes `[1, 2].zz` run a getter.

        Two separate facts have to hold and this is their conjunction: no chain root was written,
        which is `chain_roots_unwritten`, and no reflective surface could have written one without
        saying so. A caller for which the second costs more than it buys takes the first alone — see
        the note there for what that trade is and where it is made.
        """
        owner = PROTOTYPE_OWNERS.get(value_type.__name__)
        if owner is None:
            return False
        return self._prototypes_intact(owner, INHERITED_CHAIN_ROOTS, region)

    def chain_roots_unwritten(self, value_type: type) -> bool:
        """
        Whether the program writes no prototype a plain property read on a value of *value_type*
        consults. This is `read_chain_intact` without its reflection term, and the difference is not
        a weakening of the same question but a different one: `read_chain_intact` also refuses
        wherever `SemanticModel.has_reflection_surface` holds, and that predicate answers whether
        code could reference a global *by name* — true of `new Function('return this')`, which
        writes no prototype at all.

        The distinction is what the answer costs where it is wrong, and it decides who may ask this
        rather than being a judgement each caller makes for itself. A caller folding one expression
        pays an unfolded expression for refusing, so it may as well refuse under a surface, and
        every one of them asks `read_chain_intact`. A caller deciding whether a whole *pass* may run
        pays the pass, and a reflective surface is exactly what real obfuscated files carry: the
        surface is present in the input and gone from the finished output, so a pass gated on it
        never runs and never clears the surface that was gating it. Only those callers ask this —
        today namespace flattening and the dispatcher unwrapper — and they accept that an
        unresolvable `eval` could in principle have written a prototype, which is no worse than the
        nothing they asked before.
        """
        return self.intrinsic_writes.chain_roots_unwritten(value_type)

    def function_object_untouched(self, function: Node, exempt: Sequence[Node] = ()) -> bool:
        """
        Whether no code but the reads in *exempt* can give the function object *function* a
        property of its own, or hand it to code that could: whether every use of it is
        `FunctionUse.IN_PLACE`. A fold deciding whether the object may carry a property it reads
        asks this; a conversion asks `function_conversion_untouched`.

        The object is reached only through the names holding it — its declaring name, the one name
        a declarator or an assignment statement stores it into, a named expression's own name — or
        as the value of a property of an object literal that one name holds as a read-only
        container, and a literal no name holds is reached only where it is written. An assignment
        that is not a statement of its own hands its value on as well, as `f(W = function () {})`
        does, so a function written there is not left in place. Every read of those names, and the
        position of a literal no name holds, has to leave the object where it is: call it, run
        `call` or `apply` on it, read its `toString`, `name` or `length`, convert, compare or test
        it, or hand it to `String` while `String` is the built-in. A read may also copy it into
        another name, or hand it to a parameter of a function the call certainly runs, when the
        reads of that name or parameter answer the same question in turn, up to
        `_FUNCTION_FOLLOW_LIMIT` steps. The left of
        `instanceof` is handed to a method of the right operand, a tagged template hands its holes
        to the tag, and `new` hands the function to its own body as `new.target` and to the object
        it builds as its `constructor`, so none of these leave it in place. Its body may use its own
        `arguments` only by index, length, spread or as the second argument of `apply`, since
        `arguments.callee` is the function. A program that spells `caller` anywhere is refused:
        `g.caller` is whichever function called `g`.
        """
        return self._function_use(function, frozenset(exempt)) is FunctionUse.IN_PLACE

    def function_conversion_untouched(self, function: Node, exempt: Sequence[Node] = ()) -> bool:
        """
        Whether no code but the reads in *exempt* can give the function object *function* a
        `toString`, `valueOf` or `Symbol.toPrimitive` of its own, or a new prototype, so that
        converting it answers the text it was written with as far as the function itself goes. A
        function `function_object_untouched` accepts converts so, and a use that may install a
        conversion (`FunctionUse.CONVERSION`) refuses.

        A function that is only handed on converts so when no install the program makes can reach
        it (`refinery.lib.scripts.js.analysis.conversions.ConversionInstalls`), but this is asked
        only of the tree the run has settled, since a key the run decodes later may yet spell an
        install. On any other tree the question is refused and the run record notes the tree
        (`refinery.lib.scripts.js.analysis.conversions.ConversionSettlement`); a model built without
        a record refuses it and notes nothing. The tree is read as it stands, not as this model saw
        it, so a model a pass holds across its own changes refuses as soon as the tree has moved. A
        function of another tree, such as one in the body of a `new Function` the interpreter
        parsed, is judged by its own position alone: this model holds none of its names, and the
        scan never read that tree.

        The run record and the tree are read on every question; only the grade and the scan are
        remembered.
        """
        use = self._function_use(function, frozenset(exempt))
        if use is FunctionUse.IN_PLACE:
            return True
        if use is FunctionUse.CONVERSION:
            return False
        if tree_root(function) is not self.model.root:
            return False
        if self.conversion_installs.may_reach(function):
            return False
        settlement = self._settlement
        if settlement is None:
            return False
        version = tree_version(self.model.root)
        if settlement.settled(version):
            return True
        settlement.defer(version)
        return False

    def _function_use(self, function: Node, spared: frozenset[Node]) -> FunctionUse:
        """
        The most a use of the function object *function* may do to it, the reads in *spared*
        aside. The answer is fixed for the model's lifetime, so it is memoized per function and set
        of spared reads: every conversion of a function the interpreter folds asks it again.
        """
        key = (function, spared)
        use = self._function_use_cache.get(key)
        if use is None:
            use = self._function_use_cache[key] = self._compute_function_use(function, spared)
        return use

    def _compute_function_use(self, function: Node, spared: frozenset[Node]) -> FunctionUse:
        use = FunctionUse.IN_PLACE
        if self.model.spells_caller() or arguments_name_their_function(function):
            use = FunctionUse.TOUCHED
        if isinstance(function, JsFunctionExpression) and isinstance(function.id, JsIdentifier):
            own = self.model.binding_of(function.id)
            if own is None:
                use = max(use, FunctionUse.TOUCHED)
            else:
                use = max(use, self._name_use(own, spared, 0))
        if isinstance(function, JsFunctionDeclaration):
            names = self.model.function_names(function)
            if names is None:
                return max(use, FunctionUse.TOUCHED)
            for binding in names.bindings:
                use = max(use, self._name_use(binding, spared | {function}, 0))
            return use
        method = self._method_use(function)
        if method is not None:
            return max(use, method)
        name = self.model.name_holding(function)
        if name is not None:
            return max(use, self._name_use(name, spared, 0))
        return max(use, self._function_read_use(function, 0))

    def _name_use(self, name: Binding, spared: frozenset[Node], depth: int) -> FunctionUse:
        """
        The most a read of the name *name*, which may hold a function object, may do to that object,
        the reads in *spared* aside; a name code can reach without a read is `FunctionUse.TOUCHED`
        at least. Memoized: a parameter is asked once for every read that hands a function to it.
        """
        key = (name, depth, spared)
        use = self._name_use_cache.get(key)
        if use is None:
            use = FunctionUse.IN_PLACE
            if (
                name.exported
                or name.written_at_entry
                or name.reachable_through_a_handed_object
                or self.model.reflection_can_reach(name)
            ):
                use = FunctionUse.TOUCHED
            for read in name.reads:
                if read in spared:
                    continue
                use = max(use, self._function_read_use(read, depth))
                if use is FunctionUse.CONVERSION:
                    break
            self._name_use_cache[key] = use
        return use

    def _method_use(self, function: Node) -> FunctionUse | None:
        """
        `_function_use` for a function written as the value of a property of an object literal, or
        `None` for a function written anywhere else. The literal has to be the one value of a name
        that holds it as a read-only container, and every read of that name has to take a key off
        it; a read that may take the function's key is a read of the function.
        """
        parent = enclosing_operator(function)
        if not isinstance(parent, JsProperty) or strip_parens(parent.value) is not function:
            return None
        key = _property_key_name(parent)
        holder = parent.parent
        if parent.kind is not JsPropertyKind.INIT or key is None or not isinstance(holder, JsObjectExpression):
            return FunctionUse.TOUCHED
        declarator = enclosing_operator(holder)
        if (
            not isinstance(declarator, JsVariableDeclarator)
            or strip_parens(declarator.init) is not holder
            or not isinstance(declarator.id, JsIdentifier)
        ):
            return FunctionUse.TOUCHED
        binding = self.model.binding_of(declarator.id)
        if binding is None or strip_parens(self.model.singular_value(binding)) is not holder:
            return FunctionUse.TOUCHED
        if not self.binding_is_immutable_container(binding) or self.model.reflection_can_reach(binding):
            return FunctionUse.TOUCHED
        use = FunctionUse.IN_PLACE
        for read in binding.reads:
            member = enclosing_operator(read)
            if not isinstance(member, JsMemberExpression) or strip_parens(member.object) is not read:
                use = max(use, FunctionUse.TOUCHED)
                continue
            taken = static_property_key(member)
            if taken is None or taken == key:
                use = max(use, self._function_read_use(member, 0))
        return use

    def _function_read_use(self, read: Node, depth: int) -> FunctionUse:
        """
        The most the read *read* of a function object may do to the object, in the sense of
        `function_object_untouched`; *depth* counts the names and parameters followed to reach it.
        """
        parent = enclosing_operator(read)
        if isinstance(parent, JsCallExpression):
            return self._call_use(parent, read, depth)
        if isinstance(parent, (JsVariableDeclarator, JsAssignmentExpression)):
            if depth >= _FUNCTION_FOLLOW_LIMIT:
                return FunctionUse.TOUCHED
            alias = self.model.name_holding(read)
            if alias is None:
                return FunctionUse.TOUCHED
            return self._name_use(alias, frozenset(), depth + 1)
        if isinstance(parent, JsMemberExpression):
            return self._member_use(parent, read)
        if isinstance(parent, JsTaggedTemplateExpression):
            in_place = strip_parens(parent.tag) is read
        elif isinstance(parent, JsBinaryExpression):
            in_place = parent.operator != 'instanceof' or strip_parens(parent.right) is read
        elif isinstance(parent, JsUnaryExpression):
            in_place = parent.operator in _UNARY_OPERATORS_READING_A_FUNCTION
        elif isinstance(parent, JsTemplateLiteral):
            in_place = not isinstance(parent.parent, JsTaggedTemplateExpression)
        elif isinstance(parent, _TESTED_FORMS):
            in_place = strip_parens(parent.test) is read
        else:
            in_place = False
        return FunctionUse.IN_PLACE if in_place else FunctionUse.TOUCHED

    def _call_use(self, call: JsCallExpression, read: Node, depth: int) -> FunctionUse:
        """
        `_function_read_use` for a function read as the callee or an argument of *call*. A call
        through a key known only at runtime may run an installer, and so is a `CONVERSION`.
        """
        callee = strip_parens(call.callee)
        if callee is read:
            return FunctionUse.IN_PLACE
        if isinstance(callee, JsMemberExpression) and callee.computed and static_property_key(callee) is None:
            return FunctionUse.CONVERSION
        installer = self.conversion_installs.installer_of_call(call)
        if installer is not None:
            for target, argument in enumerate(call.arguments):
                argument = strip_parens(argument)
                if isinstance(argument, JsSpreadElement):
                    break
                if argument is read:
                    return self._install_use(call, installer, target)
            return FunctionUse.CONVERSION
        if self.trusted_intrinsic(call.callee) == 'String':
            return FunctionUse.IN_PLACE
        return self._parameter_use(call, read, depth)

    def _member_use(self, member: JsMemberExpression, read: Node) -> FunctionUse:
        """
        `_function_read_use` for a function read as the object or the key of *member*. A write
        under a key that may be a conversion key, and a call of a method under a key known only at
        runtime, are a `CONVERSION`; reading `call`, `apply`, `toString`, `name` or `length` leaves
        the function in place.
        """
        if strip_parens(member.object) is not read:
            return FunctionUse.TOUCHED
        if is_member_write_target(member):
            governor = enclosing_operator(member)
            if isinstance(governor, JsUnaryExpression) and governor.operator == 'delete':
                return FunctionUse.TOUCHED
            if self.conversion_installs.spells_member_key(member.property, member.computed) is False:
                return FunctionUse.TOUCHED
            return FunctionUse.CONVERSION
        key = static_property_key(member)
        call = enclosing_operator(member)
        if isinstance(call, JsCallExpression) and strip_parens(call.callee) is member:
            if key is None:
                return FunctionUse.CONVERSION
            if key in RECEIVER_INSTALL_METHODS:
                return self._install_use(call, key, -1)
        if key in _FUNCTION_KEYS_READ_IN_PLACE:
            return FunctionUse.IN_PLACE
        return FunctionUse.TOUCHED

    def _install_use(self, call: JsCallExpression, installer: str, target: int) -> FunctionUse:
        """
        The use the installer call *call* makes of the value at argument *target*, or of its
        receiver when *target* is -1: a `CONVERSION` unless it certainly installs no conversion.
        """
        if self.conversion_installs.install_spelled(call, installer, target) is False:
            return FunctionUse.TOUCHED
        return FunctionUse.CONVERSION

    def _parameter_use(self, call: JsCallExpression, read: Node, depth: int) -> FunctionUse:
        """
        The use handing the function read at *read* to *call* makes of it: the use the receiving
        parameter makes, when the call certainly runs one function whose parameters are plain
        names, together with the use its own `arguments` make of it (`_element_use`). A value past
        the last parameter is reached through `arguments` alone.
        """
        if depth >= _FUNCTION_FOLLOW_LIMIT:
            return FunctionUse.TOUCHED
        callee = self.unambiguous_callee(call)
        if callee is None or not all(isinstance(param, JsIdentifier) for param in callee.params):
            return FunctionUse.TOUCHED
        position = None
        for index, argument in enumerate(call.arguments):
            if isinstance(argument, JsSpreadElement):
                return FunctionUse.TOUCHED
            if strip_parens(argument) is read:
                position = index
                break
        if position is None:
            return FunctionUse.TOUCHED
        use = FunctionUse.IN_PLACE
        if self._callee_uses_arguments(callee):
            use = self._element_use(callee, position, depth)
        if position >= len(callee.params) or use is FunctionUse.CONVERSION:
            return use
        param = callee.params[position]
        binding = self.model.binding_of(param) if isinstance(param, JsIdentifier) else None
        if binding is None:
            return FunctionUse.TOUCHED
        return max(use, self._name_use(binding, frozenset(), depth + 1))

    def _element_use(self, callee: Node, position: int, depth: int) -> FunctionUse:
        """
        The use the function *callee*, which can reach its own `arguments`, makes through them of
        the value its call passes at *position*. It is `TOUCHED` at least, and where every
        reference reads the object element by element (`arguments_reads_only_elements`), the most
        any read of an element that may be that one does to the value.
        """
        own = own_arguments_binding(self.model, callee)
        if own is None or self.model.reflection_can_reach(own) or not arguments_reads_only_elements(own):
            return FunctionUse.TOUCHED
        use = FunctionUse.TOUCHED
        for reference in own.reads:
            element = enclosing_operator(reference)
            if not isinstance(element, JsMemberExpression):
                continue
            positions = element_positions(element)
            if positions is None or position in positions:
                use = max(use, self._function_read_use(element, depth + 1))
            if use is FunctionUse.CONVERSION:
                break
        return use

    def call_is_foldable(
        self,
        node: JsCallExpression,
        *,
        receiver_type: type | None = None,
        trust: AnchoredTrust | None = None,
    ) -> bool:
        """
        Whether the call *node* may be evaluated to a constant and have its result replace it. This is the
        one admission gate every fold shares, so that a rule proven necessary at one site cannot be missing
        at another — the fold surface acquired its divergent hand-rolled checks precisely because each
        transform owned its own.

        Three questions must all answer yes:

        - The callee is still the built-in it is spelled as. A named callee (`parseInt(...)`,
          `String.fromCharCode(...)`) is judged by `trusted_intrinsic` on its root name; a call on a
          literal receiver is judged by `trusted_prototype` on the type that literal's syntax fixes; and a
          call on another call — a chain link — is judged by asking this whole question of that inner call.
          `receiver_type` covers the remaining case, a caller holding an already-evaluated receiver whose
          type it knows and this model does not.
        - Every function-valued argument writes nothing outside itself. `is_effect_free_when_discarded` is
          the right predicate rather than `is_pure`: a callback that mutates a fresh local and returns it —
          the `reduce` accumulator idiom — is not pure, but that mutation is the value being computed and an
          evaluator that runs the call reproduces it. Purity is not sufficient on its own either, since a
          callback writing a script-scope `var` reports `writes_captured=False` — that binding is not
          captured from its perspective — so the write would be dropped while the value folds.
          `written_bindings` records it by identity and catches it.
        - Nothing in the argument list is itself a call this gate does not also clear, so admitting an outer
          call cannot smuggle in an inner one. A nested built-in (`Math.floor(Math.abs(-1.7))`) is fine
          precisely because the same questions are asked of it.
        - No part of the call stores anything the residual would go on to read. The fold deletes the
          whole expression, so a store is lost wherever in it the store was written — an argument, the
          receiver, or the computed key naming the method; see `_call_stores_nothing`.

        Trust is not evaluability, and this answers only the first. `trusted_intrinsic` says `unknownFn` is
        undisturbed — true, and no help, since no such built-in exists to fold. Whether a callee can
        actually be evaluated is the caller's question, answered by its own registry lookup before it asks
        this one; conflating the two is what let a registry entry exist with no matching trust rule.

        The first question is asked of the whole program, or at a point where *trust* is given: the
        `AnchoredTrust` of that point answers it, for the call and for every call nested in its
        arguments.
        """
        if trust is None:
            if not self._callee_is_trusted(node, receiver_type):
                return False
        elif not trust.callee(node, receiver_type):
            return False
        if not self._call_stores_nothing(node):
            return False
        return all(self._argument_is_admissible(arg, trust) for arg in node.arguments)

    def call_names_an_unwritten_builtin(
        self,
        node: JsCallExpression,
        *,
        receiver_type: type | None = None,
    ) -> bool:
        """
        `call_is_foldable`'s callee-trust question with the reflection terms lifted: whether the
        built-in *node* spells is still that built-in, judged by attributed writes alone. A named
        callee is asked `intrinsic_name_unwritten`; a literal receiver's or known receiver type's
        method is asked `prototype_name_unwritten`; and a chained call is asked this same question
        of its inner link. The composition a consumer that holds an oracle clearance makes — the
        oracle answered the reflection terms at the anchor, so the name questions are what remain.
        A consumer without one takes `call_is_foldable`, whose trust leg is this plus those terms.
        """
        callee = strip_parens(node.callee)
        if isinstance(callee, JsIdentifier):
            return self.intrinsic_name_unwritten(callee) is not None
        if not isinstance(callee, JsMemberExpression):
            return False
        base = strip_parens(callee.object)
        if isinstance(base, JsIdentifier):
            return self.intrinsic_name_unwritten(base) is not None
        if isinstance(base, JsCallExpression):
            return self.call_names_an_unwritten_builtin(base)
        literal_type = _LITERAL_RECEIVER_TYPES.get(type(base))
        if literal_type is not None:
            return self.prototype_name_unwritten(literal_type)
        if receiver_type is None:
            return False
        return self.prototype_name_unwritten(receiver_type)

    def _call_stores_nothing(self, node: JsCallExpression) -> bool:
        """
        Whether the parts of *node* that name what is being called store anything: the receiver it is
        called on, and the computed key that says which method. The fold deletes the whole call
        expression, so a store written into either is lost exactly as one written into an argument is,
        and `Math[v = 'floor'](1.9)` drops the write to `v` while answering `1`.

        A receiver that is itself a call is not asked here. It is a link in a chain, and
        `_callee_is_trusted` already puts it through this same gate in full, where its own receiver,
        key and arguments are each accounted for.
        """
        callee = strip_parens(node.callee)
        if not isinstance(callee, JsMemberExpression):
            return True
        base = strip_parens(callee.object)
        if not isinstance(base, JsCallExpression) and not self._stores_nothing(base):
            return False
        return not callee.computed or self._stores_nothing(callee.property)

    def _callee_is_trusted(self, node: JsCallExpression, receiver_type: type | None) -> bool:
        callee = strip_parens(node.callee)
        if isinstance(callee, JsIdentifier):
            return self.trusted_intrinsic(callee) is not None
        if not isinstance(callee, JsMemberExpression):
            return False
        base = strip_parens(callee.object)
        if isinstance(base, JsIdentifier):
            return self.trusted_intrinsic(base) is not None
        if isinstance(base, JsCallExpression):
            # A chained call (`Buffer.from(x).toString('hex')`, `[1, 2].map(f).join('')`) has no name at
            # this link. Its receiver is whatever the inner call returned, so it is trustworthy exactly
            # when that inner call is admissible in full — including its arguments, since an effectful
            # argument to the inner link is just as observable as one to the outer.
            return self.call_is_foldable(base)
        literal_type = _LITERAL_RECEIVER_TYPES.get(type(base))
        if literal_type is not None:
            return self.trusted_prototype(literal_type)
        if receiver_type is None:
            return False
        return self.trusted_prototype(receiver_type)

    def _argument_is_admissible(self, arg: Node | None, trust: AnchoredTrust | None = None) -> bool:
        """
        Whether *arg* may be evaluated as part of a fold that then replaces the whole call, deleting
        the argument's text along with it.

        A function-valued argument is judged by what calling it would do, because the call is what the
        fold performs. A call is judged by this same gate in full, so that admitting an outer call
        cannot smuggle in an inner one. Everything else is judged by whether evaluating it can be
        dropped at all, which is the question `is_side_effect_free` already answers over the whole
        subtree — and it is the argument's *subtree* that matters, because a store need not be the
        argument itself. `Math.floor(v = 4)` is only the plainest spelling of it; the same store hides
        in a summand, a comma operand, a template substitution, and a compound or logical assignment,
        each of which the fold would delete while the residual keeps reading the old value.
        """
        node = strip_parens(arg)
        if isinstance(node, FUNCTION_NODES):
            summary = self.summary_of(node)
            return summary.is_effect_free_when_discarded and not summary.written_bindings
        if isinstance(node, JsCallExpression):
            return self.call_is_foldable(node, trust=trust)
        return self._stores_nothing(node)

    def _stores_nothing(self, node: Node | None) -> bool:
        """
        Whether evaluating the expression *node* performs no store, so that a fold which replaces it
        with the value it computed loses nothing a later statement could read.

        A fold deletes the expression it replaces. Where that expression assigned, updated or deleted
        something, the store went with it and the residual program keeps reading the old value, which
        is what makes `Math.floor(v = 4)` answer `4` and leave `v` at `0`. The store is rarely the
        whole argument — it hides in a summand, a comma operand, a template substitution, a compound
        or a logical assignment — so the question is asked of the whole subtree and not of the shape
        at its root.

        A `yield` or an `await` is refused under the same heading: neither stores, but both hand
        control somewhere that can, and a fold that runs them decides when they resume.

        A function written down inside the expression stores nothing by being evaluated, since it is a
        value and only calling it could store; its body is therefore not walked.

        A call is refused when its callee can be named and that callee is known to write. It is
        admitted when the callee cannot be named, which is where this predicate stops being a proof:
        `s.charCodeAt(i)` on a parameter resolves to nothing this model can summarize and stores
        nothing, and refusing every unnameable call would decline the string decoders this tool exists
        to read. A `new` expression is admitted on the same terms. Admitting them is what the gate did
        for every call in this position before, so the rule only ever narrows what folds.
        """
        if node is None:
            return True
        pending: list[Node] = [node]
        while pending:
            current = pending.pop()
            if isinstance(current, FUNCTION_NODES):
                continue
            if isinstance(current, (JsAssignmentExpression, JsUpdateExpression)):
                return False
            if isinstance(current, JsUnaryExpression) and current.operator == 'delete':
                return False
            if isinstance(current, (JsYieldExpression, JsAwaitExpression)):
                return False
            if isinstance(current, JsCallExpression):
                callee = self.unambiguous_callee(current)
                if callee is not None and self.summary_of(callee).written_bindings:
                    return False
            pending.extend(current.children())
        return True

    def _is_trusted_global_read(self, member: JsMemberExpression) -> bool:
        """
        Whether reading *member* off the global object runs no user getter, so the read carries no
        observable effect: a non-computed access of a trusted intrinsic-named data property on the global
        object, sound only under the `global_pristine` precondition. This mirrors the intrinsic-call trust
        of `_resolve_callee`, lifted from methods to global data-property reads.
        """
        if not self.global_pristine or member.computed:
            return False
        prop = member.property
        if not isinstance(prop, JsIdentifier) or prop.name not in _GLOBAL_DATA_PROPERTIES:
            return False
        return member.object is not None and self._base_is_global_object(member.object)

    def _base_is_global_object(self, node: Node) -> bool:
        """
        Whether *node* denotes the global object through a base read that itself cannot throw: an
        unshadowed `globalThis`, the one global-object alias the language mandates in every host.
        Both callers remove code on the strength of this answer — `_base_is_safe` clears a property
        access and `_is_trusted_global_read` clears a getter — so a host-conditional alias
        (`window`, `self`, `top`, `frames`, `global`) is refused here: it denotes the global object
        where it resolves, but a host that lacks it throws a `ReferenceError` on the base read, and
        clearing that read would drop the throw (`SemanticModel.read_may_throw`). An analyst who
        pins the host recovers the alias as certain. A local that only holds the global from an
        establishing definition is resolved separately by `_trusted_global_alias_read`, whose caller
        orders that definition before the read.
        """
        if isinstance(node, JsIdentifier) and node.name == 'globalThis':
            return self.model.lookup(node.name, self.model.scope_of(node)) is None
        return False

    def member_read_getter_free(
        self,
        member: JsMemberExpression,
        established: Callable[[Binding, JsMemberExpression], bool] | None = None,
    ) -> bool:
        """
        Whether reading *member* runs no user getter, so it carries no observable effect: a
        getter-free read off a pristine value (a fresh literal or a pristine intrinsic root) or a
        trusted global data-property read off a syntactic global-object alias — always, since
        neither is nullish — or off a local single-assigned to the global object, which holds it
        only from its establishing definition onward, or off a local the model knows holds a
        function, of a key outside the accessor-poisoned set. The local cases qualify only when
        *established* confirms the single definition reaches the read, an ordering this effect
        model cannot decide on its own (see
        `refinery.lib.scripts.js.analysis.reaching.ReachingModel.value_preserved`).
        """
        if self._getter_free_read(member):
            return True
        if established is None:
            return False
        binding = self._trusted_global_alias_read(member)
        if binding is not None and established(binding, member):
            return True
        return self._typed_local_function_read(member, established)

    def _typed_local_function_read(
        self,
        member: JsMemberExpression,
        established: Callable[[Binding, JsMemberExpression], bool],
    ) -> bool:
        """
        Whether *member* is a non-computed read off a local the model knows holds a function, reading
        a key a function cannot answer with a trap: `caller` and `arguments` are accessors that
        throw off a strict-mode function, and `__proto__` is an accessor every prototype chain
        carries, so none of the three is provably throw-free or getter-free. Every other name on a
        function resolves through the prototype chain `read_chain_intact` vouches for — which only
        holds where no reflective surface stands, the term the trusting model clears — and an own
        property of the key can only be there through a write, so the container the binding holds
        must be immutable (`binding_is_immutable_container`, the alias-aware own-write check: a
        write through any alias of the binding refuses it). The value must be in place at the read
        (`established`), since a hoisted `var` reads `undefined` before its initializer runs and
        `undefined.constructor` throws.
        """
        if member.computed:
            return False
        prop = member.property
        if not isinstance(prop, JsIdentifier) or _is_poison_pill_property(member):
            return False
        base = member.object
        if not isinstance(base, JsIdentifier):
            return False
        binding = self.model.resolve(base)
        if binding is None or self.model.reflection_can_reach(binding):
            return False
        value = self.model.singular_value(binding)
        if not isinstance(value, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
            return False
        if not self.read_chain_intact(type(value)):
            return False
        if not self.binding_is_immutable_container(binding):
            return False
        return established(binding, member)

    def _trusted_global_alias_read(self, member: JsMemberExpression) -> Binding | None:
        """
        The local binding *member*'s base reads when *member* is a non-computed access of a trusted
        global data property through a local provably holding the global object — a `globalThis` alias
        or a `globalThis || ...` guard — under `global_pristine`; `None` otherwise. This answer drives
        a rewrite, so it takes the removing polarity over `SemanticModel.binding_values`: the value set
        must be complete, non-empty (a complete empty set answers the universal question vacuously),
        and EVERY value must be the object — the opposite reading from the recording
        `names_the_global_object`, which admits on ANY value. The binding is returned rather than a
        verdict because whether it already holds the global where it is read is an ordering question
        for a layer that sees control flow.
        """
        if not self.global_pristine or member.computed:
            return None
        prop = member.property
        if not isinstance(prop, JsIdentifier) or prop.name not in _GLOBAL_DATA_PROPERTIES:
            return None
        base = member.object
        if not isinstance(base, JsIdentifier) or base.name in GLOBAL_OBJECT_ALIASES:
            return None
        binding = self.model.resolve(base)
        if binding is None or self.model.reflection_can_reach(binding):
            return None
        values, complete = self.model.binding_values(binding)
        if not complete or not values:
            return None
        return binding if all(self._value_is_global_object(value) for value in values) else None

    def _value_is_global_object(self, node: Node | None) -> bool:
        """
        Whether *node*, one value a local holds, is provably the global object: the canonical
        `globalThis`, or a `globalThis || ...` existence guard whose truthy left is exactly it. A host
        alias that may be `undefined` is excluded, so a read through the local cannot throw on a
        nullish base.
        """
        return self.intrinsic_of(node) is GLOBAL_OBJECT

    def _base_is_safe(self, node: Node) -> bool:
        """
        Whether a property access on *node* cannot throw because *node* is known not to be nullish: a
        container literal whose access is plain, a primitive literal other than `null`, the global object, a
        pristine intrinsic root, a name holding what the CommonJS host passed where it passes it (none of
        which is nullish), or a never-rebound rest parameter. A rest parameter is bound to a fresh array
        at function entry, before any body statement runs — no temporal-dead-zone or hoisted-`undefined` window
        a flow-insensitive check could miss — so a member access on it is safe wherever it appears, provided the
        name is never reassigned to a value that could be nullish. A `var`/`let`/`const` local initialized to a
        literal is deliberately NOT admitted here: its initializer may not have run yet at the access
        (`function(){ a.x = 1; var a = []; }` throws), which this flow-insensitive predicate cannot rule out.
        The global object is recognized through `_base_is_global_object`, so an alias spelling a
        local declaration shadows names that local and is decided by the same rules as any other
        name: a shadowed `window` is the hoisted-`undefined` window this predicate refuses
        elsewhere.

        Non-nullishness is a *different* question from freshness and from getter-freeness, so this shares only
        the container-literal atom with its neighbours: a primitive qualifies here and is not fresh, while a
        fresh local qualifies as fresh and not here. It needs no prototype question either, unlike
        `_base_getter_safe`: no patch to any prototype can make `[1, 2]` nullish, and a throwing getter
        reached through a patched chain is that predicate's concern. There is no member-chain arm, because
        `root.a` may be `undefined` however safe *root* is, and the second read would then throw.
        """
        if container_literal_access_is_plain(node):
            return True
        if isinstance(node, (JsStringLiteral, JsNumericLiteral, JsBooleanLiteral)):
            return True
        if isinstance(node, JsIdentifier):
            if self._base_is_global_object(node):
                return True
            if isinstance(self.intrinsic_of(node), str):
                return True
            binding = self.model.resolve(node)
            if binding is None:
                return False
            if binding.supplied_by_host and not binding.may_be_absent:
                return self.model.holds_what_the_host_passed(binding)
            return self._is_rest_param(binding) and not binding.writes
        return False

    def _base_getter_safe(self, node: Node, region: list[Node] | None = None) -> bool:
        """
        Whether reading a property of *node* cannot run a user-defined getter, so the read carries no
        hidden effect: a literal, or a pristine intrinsic root, whose entire prototype chain the program
        leaves alone. Unlike `_base_is_safe`, the global object does not qualify — a global property such as
        `location` may be an accessor — so a read through it is treated as an unknown call. Unlike
        freshness, a primitive and an intrinsic root do qualify: neither is a newly built container, and
        neither runs user code on a read of a pristine chain.

        Syntax alone settles the *type* of a literal base but not its behaviour, which is why every arm ends
        in `read_chain_intact` rather than returning on the node kind: the prototype may carry a getter. A
        container literal must additionally declare no
        accessor of its own, the shared `container_literal_access_is_plain` question, since a getter written
        into the literal needs no prototype at all. There is no member-chain arm, for the reason given on
        `_base_is_safe`. With *region*, the chain question is asked of the tree an edit deleting the nodes
        of *region* leaves standing — see `getter_free_read_dropped_with`.
        """
        inner = strip_parens(node)
        value_type = _LITERAL_READ_TYPES.get(type(inner))
        if value_type is not None:
            if self._literal_declares_accessor(inner):
                return False
            return self.read_chain_intact(value_type, region)
        if isinstance(inner, JsIdentifier) and isinstance(self.intrinsic_of(inner), str):
            return self._prototypes_intact('Object', _INTRINSIC_CHAIN_ROOTS, region)
        return False

    def _literal_declares_accessor(self, node: Node) -> bool:
        """
        Whether *node* is a container literal that declares an accessor of its own, so a member access on it
        runs user code with no prototype involved. Separate from the chain question because it needs no
        model: the getter is written into the expression.
        """
        if not isinstance(node, (JsObjectExpression, JsArrayExpression)):
            return False
        return not container_literal_access_is_plain(node)

    def _getter_free_read(self, member: JsMemberExpression, region: list[Node] | None = None) -> bool:
        """
        Whether reading *member* runs no user getter and cannot fire a poison-pill accessor: the base is a
        getter-safe value (a fresh literal or a pristine intrinsic root) or a trusted global-object data
        property, and the property is not one of the poison-pill names whose read may throw or run an
        `Object.prototype` accessor. This is the single getter-freeness gate the summary scan and
        `is_side_effect_free` share. With *region*, the chain question on the base is asked of the tree an
        edit deleting the nodes of *region* leaves standing — see `getter_free_read_dropped_with`.
        """
        if _is_poison_pill_property(member):
            return False
        if member.object is not None and self._base_getter_safe(member.object, region):
            return True
        return self._is_trusted_global_read(member)

    def getter_free_read_dropped_with(self, member: JsMemberExpression, region: list[Node]) -> bool:
        """
        `member_read_getter_free` asked of the tree an edit deleting the nodes of *region* leaves
        standing: a read inside the region is dropped together with them, so the opaque surfaces
        that tree still carries — those outside the region — are the only ones that could have
        tampered the chain the read consults, and a surface the edit removes never gets to. A
        read outside the region survives the edit and keeps the stock answer, which the
        trusted-global arm keeps in full: it rests on `global_pristine`, a whole-program
        precondition this question does not re-ask per region.
        """
        if not any(member is root or member.is_descendant_of(root) for root in region):
            return self.member_read_getter_free(member)
        return self._getter_free_read(member, region)


def _weakest(left: _FreshKind, right: _FreshKind) -> _FreshKind:
    """
    The kind that holds for both operands — the weaker of the two, since a consumer may rely only on what is
    true of every value an expression or binding can take.
    """
    return left if left.value <= right.value else right


def _returns_on_every_path(func: Node) -> bool:
    """
    Whether *func* cannot complete without an explicit `return`, so its call never yields the implicit
    `undefined`. Deciding this exactly is a control-flow question, and this model has no graph, so the test is
    the conservative syntactic one: the body's last statement must itself be a `return` or a `throw`. That
    refuses `if (c) { return x; } else { return y; }`, which does return on every path — a missed opportunity,
    not an unsound answer, and the direction to err in when a caller is about to treat the result as a
    container it may write through.
    """
    body = getattr(func, 'body', None)
    statements = getattr(body, 'body', None)
    if isinstance(body, (JsReturnStatement, JsThrowStatement)):
        return True
    if not isinstance(statements, list) or not statements:
        return isinstance(body, Expression)
    return isinstance(statements[-1], (JsReturnStatement, JsThrowStatement))


def _body_nodes(func: Node) -> Iterator[Node]:
    """
    Yield the nodes a single execution of *func* evaluates — its parameter list and the statements
    of its body, with their descendants — without descending into nested function bodies, whose
    effects belong to *their* calls. Nested function nodes are still yielded so a call to one can be
    recognized. The parameter list is part of what a call evaluates because a default runs on every
    call that omits its argument (`function f(a = zzz){}` reads `zzz` before the body is entered),
    so a scan that started at the body alone could not see an effect the call really has.
    """
    if isinstance(func, JsScript):
        roots: list[Node] = list(func.body)
    else:
        roots = list(getattr(func, 'params', ()))
        body = getattr(func, 'body', None)
        if body is not None:
            roots.append(body)
    stack = list(reversed(roots))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, FUNCTION_NODES):
            continue
        stack.extend(reversed(node.children()))


def _intrinsics_pristine(model: SemanticModel) -> bool:
    """
    Whether the program leaves every trusted intrinsic untouched: it neither reassigns an intrinsic
    root nor writes a property on one, nor shadows one with a binding of its own, nor contains a
    reflection surface through which an intrinsic could be replaced at runtime, nor stores a
    property on the global object under a runtime key, which may replace an intrinsic the same
    way. Only then may a call to a registry intrinsic be trusted to behave as specified.
    """
    if model.has_reflection_surface() or model.has_opaque_global_write():
        return False
    if any(name in model.root_scope.bindings for name in PURE_INTRINSIC_ROOTS):
        return False
    for node in model.root.walk():
        if isinstance(node, JsIdentifier) and node.name in PURE_INTRINSIC_ROOTS:
            if reference_role(node) is not Role.READ:
                return False
        elif isinstance(node, JsAssignmentExpression):
            left = node.left
            if (
                isinstance(left, JsMemberExpression)
                and isinstance(left.object, JsIdentifier)
                and left.object.name in PURE_INTRINSIC_ROOTS
            ):
                return False
        elif isinstance(node, JsUpdateExpression):
            target = node.argument
            if (
                isinstance(target, JsMemberExpression)
                and isinstance(target.object, JsIdentifier)
                and target.object.name in PURE_INTRINSIC_ROOTS
            ):
                return False
    return True


def _writes_the_global_prototype(model: SemanticModel, member: JsMemberExpression) -> bool:
    """
    Whether *member* assigns to `__proto__` on a base that may be the global object
    (`globalThis.__proto__ = p`), replacing the global object's prototype with one that may carry
    an inherited setter. `accessor_install_method` catches a setter installed through
    `Object.defineProperty`; a prototype swapped in through the `__proto__` setter reaches the same
    result by a member write that names no method, so the pristine question must refuse it too. A
    runtime key names no property statically and reaches `has_opaque_global_write` instead.
    """
    return (
        is_member_write_target(member)
        and static_property_key(member) == '__proto__'
        and model.may_be_the_global_object(member.object)
    )


def _global_pristine(model: SemanticModel) -> bool:
    """
    Whether a property read on the global object is free of user getters: the program exposes no
    reflective surface through which an accessor could be installed at runtime, and installs none
    statically through `Object.defineProperty`, `defineProperties`, the legacy
    `__define[GS]etter__`, or a prototype swap onto the global object through `__proto__`. Only
    under this precondition may a read of a trusted global data property be treated as effect-free.

    A computed key counts as an install, since `Object['define' + 'Property']` reaches the same method as
    the dotted form; reading the property name alone would let a fold of the key withdraw this trust after
    a consumer had already relied on it.

    A key whose value is *not* statically known — `Object[k]` — is deliberately not treated as an install.
    It would deny this trust to nearly every dynamic call, and it buys nothing: a variable key is resolved
    by substitution in a different pass, never within the one that consumes this answer. The global
    object carrying one — `globalThis[k] = v` — is the one computed key that *is* an install for this
    question: it may give the read property a new value or setter, so `has_opaque_global_write`
    refuses here.
    """
    if model.has_reflection_surface() or model.has_opaque_global_write():
        return False
    for node in model.root.walk():
        if not isinstance(node, JsMemberExpression):
            continue
        if accessor_install_method(node) is not None:
            return False
        if _writes_the_global_prototype(model, node):
            return False
    return True


class AnchoredTrust:
    """
    The questions whether the built-ins are still the language's, asked at one point of the program,
    the anchor. Each is the program-wide question of the `EffectModel`, or, where the tampering
    oracle vouches that no built-in was replaced before the anchor runs (*oracle*), its per-name arm
    alone: the oracle has answered the reflection terms at the anchor, and the writes the text
    attributes to a name are what remains. This is the composition the oracle's consumers share, so
    no consumer asks a per-name arm without the oracle having cleared its point. The oracle is asked
    once, and only where a program-wide question refuses. *loads* says whether code the text does
    not hold may have been loaded before the anchor, which may have set up a global name. Built by
    `refinery.lib.scripts.js.analysis.tampering.TamperingModel.trust_at`, and for no point at all by
    `EffectModel.program_trust`.
    """

    def __init__(self, effects: EffectModel, oracle: Callable[[], bool], loads: Callable[[], bool]):
        self._effects = effects
        self._oracle = oracle
        self._loads = loads
        self._cleared: bool | None = None

    @property
    def cleared(self) -> bool:
        """
        Whether the oracle vouches for the anchor.
        """
        if (cleared := self._cleared) is None:
            self._cleared = cleared = self._oracle()
        return cleared

    def intrinsic(self, node: Node | None) -> str | None:
        """
        `EffectModel.trusted_intrinsic` at the anchor.
        """
        effects = self._effects
        if (name := effects.trusted_intrinsic(node)) is not None:
            return name
        return effects.intrinsic_name_unwritten(node) if self.cleared else None

    def intrinsic_name(self, name: str) -> bool:
        """
        `EffectModel.trusted_intrinsic_name` at the anchor.
        """
        effects = self._effects
        if effects.trusted_intrinsic_name(name):
            return True
        return self.cleared and name not in effects._globals_written

    def global_typeof(self, name: str) -> str | None:
        """
        What `typeof name` yields at the anchor, for a name that resolves to no binding there: the
        answer of the host (`typeof_of_global`), where the name is still the host's at the anchor
        (`intrinsic_name`) and no code the text does not hold may have been loaded before it.
        """
        folded = typeof_of_global(name, self._effects.model.environment)
        if folded is None or not self.intrinsic_name(name) or self._loads():
            return None
        return folded

    def prototype(self, value_type: type) -> bool:
        """
        `EffectModel.trusted_prototype` at the anchor.
        """
        effects = self._effects
        if effects.trusted_prototype(value_type):
            return True
        return self.cleared and effects.prototype_name_unwritten(value_type)

    def chain(self, value_type: type) -> bool:
        """
        `EffectModel.read_chain_intact` at the anchor.
        """
        effects = self._effects
        if effects.read_chain_intact(value_type):
            return True
        return self.cleared and effects.chain_roots_unwritten(value_type)

    def callee(self, node: JsCallExpression, receiver_type: type | None = None) -> bool:
        """
        Whether the built-in the call *node* spells is still that built-in at the anchor: the trust
        leg of `EffectModel.call_is_foldable` there.
        """
        effects = self._effects
        if effects._callee_is_trusted(node, receiver_type):
            return True
        return self.cleared and effects.call_names_an_unwritten_builtin(node, receiver_type=receiver_type)

    def call_is_foldable(self, node: JsCallExpression, receiver_type: type | None = None) -> bool:
        """
        `EffectModel.call_is_foldable` at the anchor.
        """
        return self._effects.call_is_foldable(node, receiver_type=receiver_type, trust=self)


def build_effects(
    model: SemanticModel,
    dominance: DominanceModel | None = None,
    intrinsic_writes: IntrinsicWrites | None = None,
    settlement: ConversionSettlement | None = None,
) -> EffectModel:
    """
    Build the `EffectModel` for a script's `refinery.lib.scripts.js.analysis.model.SemanticModel`,
    sharing *dominance* when the caller holds one so the two models order the same tree through one
    control-flow layer. A `None` is not a refusal: the model builds its own the first time a summary
    must order a binding's temporal dead zone. *intrinsic_writes* is shared the same way, so the
    effect and ordering layers read one scan of what the program writes on the intrinsics; a `None`
    builds it here. *settlement* is the record of the deobfuscation run the model serves, which
    `EffectModel.function_conversion_untouched` reads; without one that question refuses wherever
    it would wait for the run to settle.
    """
    return EffectModel(model, dominance, intrinsic_writes, settlement)
