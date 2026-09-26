"""
What a JavaScript program writes on the intrinsics, computed once per
`refinery.lib.scripts.js.analysis.model.SemanticModel`. `build_intrinsic_writes` scans the program
for every global name it binds, assigns, writes a property on, installs a descriptor on, or hands to
code this analysis cannot read, and for the property keys it writes on the names whose keys are
watched; `IntrinsicWrites` holds the answer and asks the prototype-chain questions of it.

The scan reads only the semantic model, so it sits beside it rather than above any layer that orders
or summarizes code: the `refinery.lib.scripts.js.analysis.effects.EffectModel` and the
`refinery.lib.scripts.js.analysis.dominance.DominanceModel` both read the one answer
`refinery.lib.scripts.js.analysis.cache.ModelCache` builds, and neither has to reach into the other
for it. The registry of intrinsics the scan watches lives here for the same reason.
"""
from __future__ import annotations

from typing import Iterator, NamedTuple

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    Binding,
    Role,
    SemanticModel,
    reference_role,
)
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsCallExpression,
    JsConditionalExpression,
    JsForInStatement,
    JsForOfStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsParenthesizedExpression,
    JsSequenceExpression,
    JsSpreadElement,
    JsTemplateLiteral,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclarator,
    accessor_install_method,
    static_property_key,
    static_string,
    strip_parens,
)

PURE_INTRINSIC_METHODS = frozenset({
    'String.fromCharCode',
    'Array.isArray',
    'Math.abs',
    'Math.ceil',
    'Math.floor',
    'Math.round',
    'Math.trunc',
    'Math.sign',
    'Math.max',
    'Math.min',
    'Math.pow',
    'Math.sqrt',
    'Math.cbrt',
    'Math.log',
    'Math.log2',
    'Math.log10',
    'Math.exp',
    'Number.isNaN',
    'Number.isFinite',
    'Number.isInteger',
    'Number.isSafeInteger',
    'Number.parseInt',
    'Number.parseFloat',
})

PURE_GLOBAL_FUNCTIONS = frozenset({
    'parseInt',
    'parseFloat',
    'isNaN',
    'isFinite',
})

SPECIES_KEYS = frozenset({'constructor', '__proto__'})
"""
The two property names that decide what an allocating `Array.prototype` method returns.
ArraySpeciesCreate reads `constructor[Symbol.species]` off the receiver, and `__proto__` replaces
the prototype that `constructor` lookup walks, so writing either can make the "newly created" array
be a shared object — or make the call throw, by leaving a primitive where a constructor is expected.
"""

_SURFACE_KEYS = SPECIES_KEYS | frozenset({'prototype'})
"""
The property names whose value shares the mutable surface of the intrinsic it was read from, so
handing that value to unanalysable code is as dangerous as handing over the intrinsic itself.
`SPECIES_KEYS` reach the prototype chain and `prototype` is the chain. Every other key yields
something whose properties nobody consults when the intrinsic is used: patching a property of the
number `Math.PI` or of the function `Math.floor` cannot change what `Math.floor(1.7)` returns, while
patching one of `Array.prototype` decides what `[1, 2].join()` means.

`refinery.lib.scripts.js.deobfuscation.helpers.PROTOTYPE_CHAIN_PROPERTIES` holds the same two
species keys for the same reason, but importing it here would invert the layering this module rests
on — the interpreter imports from the analysis layer, never the reverse, as `PROTOTYPE_OWNERS` also
records.
"""

PURE_INTRINSIC_ROOTS = (
    frozenset(name.split('.', 1)[0] for name in PURE_INTRINSIC_METHODS) | PURE_GLOBAL_FUNCTIONS
)

_DENOTED_ROOT_DEPTH_LIMIT = 16

_CALLEE_DEPTH_LIMIT = 4
"""
How far `_callee_is_write_free` follows an intrinsic through nested calls before refusing. A chain
longer than this is not proven safe, merely unproven, so exhausting the limit records the write.
Four was enough for every shape measured; the limit exists because the recursion is over call
*edges*, which a mutually-recursive pair makes unbounded.
"""

_VALUE_FORWARDING_NODES = (
    JsParenthesizedExpression,
    JsLogicalExpression,
    JsConditionalExpression,
    JsSequenceExpression,
    JsSpreadElement,
)
"""
The forms that hand an operand's value onward unchanged, so an intrinsic inside one escapes wherever
the form itself does. These are the outward counterpart of the arms `_denoted_roots` looks *into*,
and the pairing is not incidental: a fold that collapses `Math || 0` to `Math` must not change this
analysis's answer, which the pinning contract in `refinery.lib.scripts.js.analysis.cache.ModelCache`
requires.
"""

PROTOTYPE_OWNERS: dict[str, str] = {
    'str': 'String',
    'list': 'Array',
    'JsBuffer': 'Buffer',
    'dict': 'Object',
    'bool': 'Boolean',
    'int': 'Number',
    'float': 'Number',
    'JsFunctionDeclaration': 'Function',
    'JsFunctionExpression': 'Function',
    'JsArrowFunctionExpression': 'Function',
}
"""
The intrinsic whose prototype supplies the methods of each interpreter value type, keyed by type
name so this module needs no import from the interpreter that depends on it. A method call on a
literal receiver names no global at the call site, so trusting it means asking whether *this*
prototype is intact: `String.prototype.toUpperCase = f` is a write to `String`, and it changes what
`'ab'.toUpperCase()` means even though the expression mentions no identifier at all.

Every type in the interpreter's value domain is named here directly, including
`refinery.lib.scripts.js.deobfuscation.helpers.JsBuffer`, whose methods come from `Buffer.prototype`
rather than the `Array.prototype` its `list` base would suggest. A function value is represented as
its own AST node, so the two function node names appear here as value types rather than as syntax;
both inherit from `Function.prototype`. Lookup is exact rather than a walk up the Python MRO, which
would silently answer `Array` for any future `list` subclass instead of refusing. A type with no
entry is never trusted through this route.
"""

INHERITED_CHAIN_ROOTS = frozenset({'Object'})
"""
The prototypes every value inherits from beyond the one that owns its own methods.
`Object.prototype` roots every chain, so a getter installed there is reached by a plain read on an
array literal and on `Math` alike — which is why reading a property is a strictly stronger
requirement than calling a method.
"""

KEYED_WRITE_ROOTS = (
    PURE_INTRINSIC_ROOTS
    | INHERITED_CHAIN_ROOTS
    | frozenset(PROTOTYPE_OWNERS.values())
)
"""
The global names whose written property keys
`refinery.lib.scripts.js.analysis.effects.EffectModel.global_key_written` bounds. A name outside
this set is one the scan records no key for, so answering `False` about it would read an absence of
evidence as evidence of absence; that predicate answers `True` for every key of such a name instead.

The set is the union of the names this module already watches for a reason: the intrinsics whose
methods are trusted, the roots a plain property read walks through, and the owners of the prototypes
that supply each value type's members. A caller asking about a name outside it is asking a question
this scan was not built to answer, and is told so.
"""


class IntrinsicWrites(NamedTuple):
    """
    What one scan of a program says about the globals it writes: *names*, the set a caller asks
    about a whole name with, and *keys*, the properties each of the watched names was written at —
    or `None` for a name whose written keys this scan cannot bound.

    The two are produced together because they are read off the same nodes and must not disagree:
    a name recorded in one for a reason the other cannot express is a name one caller refuses and
    the other clears. Where a write cannot be pinned to a key, *keys* records the name unbounded
    rather than omitting it, so `keys` never reports less about a name than `names` does.
    """
    names: frozenset[str]
    keys: dict[str, frozenset[str] | None]

    def roots_unwritten(self, owner: str, roots: frozenset[str]) -> bool:
        """
        Whether the program writes neither *owner* nor any prototype in *roots*. A property read
        resolves against the whole prototype chain rather than one prototype, so each name the chain
        passes through has to answer the same question
        `refinery.lib.scripts.js.analysis.effects.EffectModel.trusted_prototype` asks of the owner
        alone.
        """
        return all(name not in self.names for name in (owner, *roots))

    def chain_roots_unwritten(self, value_type: type) -> bool:
        """
        Whether the program writes no prototype a plain property read on a value of *value_type*
        consults, so such a read can run no accessor the program installed there. See
        `refinery.lib.scripts.js.analysis.effects.EffectModel.chain_roots_unwritten` for what the
        answer leaves out and who may ask it.
        """
        owner = PROTOTYPE_OWNERS.get(value_type.__name__)
        if owner is None:
            return False
        return self.roots_unwritten(owner, INHERITED_CHAIN_ROOTS)


def build_intrinsic_writes(model: SemanticModel) -> IntrinsicWrites:
    """
    The set of global names the program does anything with beyond reading them, and the property
    keys it writes on each of the names whose keys are watched.

    A name belongs to the first for binding it in any scope, assigning to it, writing or updating or
    deleting a property anywhere along a chain rooted at it (`Object.prototype.x = 1`,
    `Math.PI++`), installing a descriptor on it with `Object.defineProperty`, or handing it to
    code whose writes this analysis cannot enumerate.

    This is the per-name counterpart of
    `refinery.lib.scripts.js.analysis.effects._intrinsics_pristine`, which answers the same question
    for a fixed root set but collapses it to one program-wide flag. Keeping the answer per name is
    what lets a program that patches `Object.prototype` still have its `Math.floor` calls folded;
    the flag cannot express that, because one disturbed root disables every other one.

    Bindings cover every *assignment* form too, so no separate scan of write-role identifiers is
    needed: a bare `Math = 1` introduces an implicit-global binding for `Math`, as do the
    destructuring and `for`-target forms. Only property writes, deletes, and descriptor installs —
    which leave the name itself a plain read — need the explicit branches below.

    A write target names the intrinsic it patches only when the program spells it out.
    `var m = Math; m.floor = f` patches `Math` while mentioning it nowhere in the assignment, so the
    chain root is resolved through the values its binding may hold rather than taken as the name it
    is spelled with.

    A write need not be *anywhere* in the program for a name to belong here. Handing an intrinsic to
    code whose writes this analysis cannot enumerate — `patch(Math)` for a `patch` it cannot resolve
    — leaves the name looking untouched while its properties are replaced, so an intrinsic that
    escapes is recorded as written. `_value_escapes` decides which uses hand the value over.

    The keyed answer is the same scan read for the property a write names rather than only for the
    name it is rooted at, and it exists because the per-name question is too coarse for a caller
    that cares which property was replaced — a file patching `Object.prototype.z` has written
    `Object`, and refusing everything about `Object` on that basis refuses the very files the
    question is asked about.

    Only the *final* key of a chain is recorded, which is the one a write replaces:
    `Object.prototype.z = 9` replaces `z` and leaves `prototype` and `constructor` alone, so
    recording the keys it passes through would report a file as having patched the mechanism a
    caller is asking about when it did nothing of the kind. Every other route by which a name's
    properties can change — a binding that shadows it, a value that escapes, a computed key, a
    descriptor read from a value this analysis cannot read — bounds no key at all and is recorded
    as unbounded.
    """
    names: set[str] = set()
    keys: dict[str, set[str] | None] = {}

    def record_keys(found: frozenset[str], key: str | None) -> None:
        for name in found & KEYED_WRITE_ROOTS:
            if key is None:
                keys[name] = None
                continue
            known = keys.setdefault(name, set())
            if known is not None:
                known.add(key)

    def record(found: frozenset[str], key: str | None) -> None:
        names.update(found)
        record_keys(found, key)

    pending = [model.root_scope]
    while pending:
        scope = pending.pop()
        record(frozenset(scope.bindings), None)
        pending.extend(scope.children)
    aliases = _IntrinsicAliases(model)
    for node in model.root.walk():
        if isinstance(node, JsIdentifier):
            if reference_role(node) is Role.READ:
                watched = aliases.names_denoted_by(node) & KEYED_WRITE_ROOTS
                if watched and _value_escapes(model, aliases, node, watched):
                    record_keys(watched, None)
                    names.update(watched & PURE_INTRINSIC_ROOTS)
            continue
        if isinstance(node, JsCallExpression):
            for base in _accessor_install_targets(node):
                record(aliases.names_denoted_by(base), _installed_key(node))
            install_key = _installed_key(node)
            if install_key is not None and _install_reaches_the_global_object(model, node):
                record(frozenset({install_key}), None)
            continue
        target = None
        if isinstance(node, JsAssignmentExpression):
            target = node.left
        elif isinstance(node, JsUpdateExpression):
            target = node.argument
        elif isinstance(node, JsUnaryExpression) and node.operator == 'delete':
            target = node.operand
        elif isinstance(node, (JsForInStatement, JsForOfStatement)):
            target = node.left
        for member in _written_members(target):
            base = _member_chain_root(member)
            if base is not None:
                record(aliases.names_denoted_by(base), static_property_key(member))
            written_global = model.may_name_a_global(member)
            if written_global is not None:
                record(frozenset({written_global}), None)
    return IntrinsicWrites(
        frozenset(names),
        {name: None if written is None else frozenset(written) for name, written in keys.items()},
    )


def _written_members(target: Node | None) -> Iterator[JsMemberExpression]:
    """
    Every member access a write to *target* may store through. A plain member target is that one
    access; a pattern holds one per position it assigns into, which `[Object.prototype.z] = [9]` and
    `({k: Object.prototype.z} = o)` both write a property through while naming no member target at
    the top. A pattern is read by walking it, so a member standing in a computed key inside one is
    yielded too — which over-reports a write and is the direction this whole scan fails in.
    """
    cursor = strip_parens(target)
    if isinstance(cursor, JsMemberExpression):
        yield cursor
    elif cursor is not None and not isinstance(cursor, JsIdentifier):
        for node in cursor.walk():
            if isinstance(node, JsMemberExpression):
                yield node


def _installed_key(call: JsCallExpression) -> str | None:
    """
    The property name the descriptor install *call* names, or `None` where it names more than one or
    none this analysis can read. `Object.defineProperty(o, 'k', d)` and `o.__defineGetter__('k', f)`
    both name it in the argument before the descriptor; `defineProperties` names a whole object of
    them, which is not one key and is reported as unbounded. The method is read through
    `refinery.lib.scripts.js.model.accessor_install_method`, so a computed key a fold will collapse
    — `Object['define' + 'Property']` — already names the install here, which keeps the answer from
    changing as the pipeline respells the call.
    """
    callee = strip_parens(call.callee)
    if not isinstance(callee, JsMemberExpression):
        return None
    method = accessor_install_method(callee)
    if method == 'defineProperty':
        return static_string(call.arguments[1]) if len(call.arguments) > 1 else None
    if method in ('__defineGetter__', '__defineSetter__'):
        return static_string(call.arguments[0]) if call.arguments else None
    return None


def _install_reaches_the_global_object(model: SemanticModel, call: JsCallExpression) -> bool:
    """
    Whether the descriptor install *call* installs on the global object: its receiver form
    (`globalThis.__defineGetter__`) or its argument form (`Object.defineProperty(globalThis, …)`)
    names the object the installed key then becomes a global under.
    `refinery.lib.scripts.js.analysis.model.SemanticModel.may_be_the_global_object` is the reading,
    so a local holding the object installs on it too; a receiver that is any other object installs
    on that object and records nothing here. The method is read through
    `refinery.lib.scripts.js.model.accessor_install_method` for the same reason `_installed_key`
    reads it there.
    """
    callee = strip_parens(call.callee)
    if not isinstance(callee, JsMemberExpression):
        return False
    method = accessor_install_method(callee)
    if method in ('__defineGetter__', '__defineSetter__'):
        return model.may_be_the_global_object(callee.object)
    if method == 'defineProperty' and call.arguments:
        return model.may_be_the_global_object(call.arguments[0])
    return False


def _value_escapes(
    model: SemanticModel,
    aliases: _IntrinsicAliases,
    node: JsIdentifier,
    names: frozenset[str],
    depth: int = 0,
) -> bool:
    """
    Whether the value read at *node* — which may denote the intrinsics *names* — reaches code that
    could write a property on it without this analysis seeing the write.

    The question is deliberately inverted. Tracking where an intrinsic *flows to* would need a
    binder from each argument to its parameter, and that binder reaches none of the routes an
    obfuscator actually uses: a callback that receives the value, a function that returns it,
    `arguments`, spread, rest, or a method on an object literal. Asking instead whether the value
    leaves a position whose effect is *known* covers all of them at once, and fails in the safe
    direction by construction — an unrecognized position counts as an escape, which costs an
    unfolded call rather than a wrong value.

    The positions that hand nothing over, and so must stay free or every fold collapses:

    - a member base, when the key cannot yield the intrinsic's own mutable surface
      (`Math.floor(1.7)`)
    - a callee, which the call consumes (`parseInt(x)`)
    - an operator operand, which reads a value without capturing the object (`typeof Math`)
    - a rebinding whose target the alias analysis still resolves to the same names (`var m = Math`)

    That last arm is what makes one predicate serve both this scan and the parameter-escape question
    inside `_callee_is_write_free`, rather than two walks differing by a flag. A rebinding is safe
    precisely when a later write through the new name is still attributed back, which is a question
    `_IntrinsicAliases` already answers: `var m = Math` is spared because `m` denotes `Math`, while
    `save = o` inside a callee is not, because a parameter denotes nothing and the attribution chain
    dies there. The *names* being non-empty is therefore load-bearing — an empty set is a subset of
    everything, and would spare the very case the arm exists to catch.
    """
    value = _forwarded_value(node)
    if value is None:
        return False
    parent = value.parent
    if isinstance(parent, JsCallExpression):
        if parent.callee is value:
            return False
        callee = unambiguous_callee(model, parent)
        return not _callee_is_write_free(model, aliases, callee, depth + 1)
    if isinstance(parent, (JsUnaryExpression, JsBinaryExpression, JsTemplateLiteral)):
        return False
    target = None
    if isinstance(parent, JsVariableDeclarator) and parent.init is value:
        target = parent.id
    elif isinstance(parent, JsAssignmentExpression) and parent.right is value:
        target = parent.left
    if target is not None:
        return not (names and names <= _names_bound_to(model, aliases, target))
    return True


def _forwarded_value(node: JsIdentifier) -> Node | None:
    """
    The outermost expression still carrying *node*'s value, or `None` when no enclosing form can
    hand that value on. The walk looks through the forms that forward a value unchanged —
    parentheses, the operands of `||`/`&&`/`??`, the branches of a conditional, the last expression
    of a sequence, and a spread — and through a member access only when its key reaches the
    intrinsic's own surface, since `p(Array.prototype)` hands over an object whose properties decide
    what `[1, 2].join()` means while `p(Math.PI)` hands over a number nobody consults.

    Strictly outward through `parent`, so unlike `_denoted_roots` — which recurses *into* an
    expression and needs `_DENOTED_ROOT_DEPTH_LIMIT` — this terminates on the finite path to the
    root without a limit.
    """
    cursor: Node = node
    while True:
        parent = cursor.parent
        if parent is None:
            return None
        if isinstance(parent, JsMemberExpression) and parent.object is cursor:
            if not _reaches_intrinsic_surface(parent):
                return None
            cursor = parent
            continue
        if isinstance(parent, _VALUE_FORWARDING_NODES):
            cursor = parent
            continue
        return cursor


def _reaches_intrinsic_surface(member: JsMemberExpression) -> bool:
    """
    Whether reading *member*'s key off an intrinsic can yield an object sharing that intrinsic's
    mutable surface. A computed key whose string value is not statically known may be any of them,
    so it counts.

    This is a *may* analysis, opposite in direction to the use
    `refinery.lib.scripts.js.model.accessor_install_method` makes of
    `refinery.lib.scripts.js.model.static_string`: there an unknown key names no method, because
    only a key a fold can collapse can reveal an install mid-pass; here an unknown key reaches
    everything, because a missed reach is a name that keeps its trust while the program patches it.
    """
    prop = member.property
    if member.computed:
        value = static_string(prop)
        return value is None or value in _SURFACE_KEYS
    return isinstance(prop, JsIdentifier) and prop.name in _SURFACE_KEYS


def _names_bound_to(
    model: SemanticModel, aliases: _IntrinsicAliases, target: Node | None
) -> frozenset[str]:
    """
    The intrinsic names a value stored into *target* may still be found under, so a rebinding that
    keeps the value reachable by name is not an escape. A destructuring or member target yields
    nothing, since neither leaves a name this analysis resolves writes through.

    Both binding lookups are needed. A declarator id is not a *reference*, so `resolve` finds
    nothing for it and only `refinery.lib.scripts.js.analysis.model.SemanticModel.binding_of`
    answers; an assignment target is a reference and only `resolve` does.
    """
    if not isinstance(target, JsIdentifier):
        return frozenset()
    binding = model.binding_of(target) or model.resolve(target)
    if binding is None:
        return frozenset({target.name})
    return aliases.names_of(binding)


def _callee_is_write_free(
    model: SemanticModel,
    aliases: _IntrinsicAliases,
    func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression | None,
    depth: int,
) -> bool:
    """
    Whether a call to *func* provably writes no property reachable from one of its parameters, and
    lets no parameter escape further. This is what keeps the escape rule from refusing every call:
    `log(Math)` for a `log` that only reads `o.PI` hands the intrinsic to code whose writes are
    fully enumerable, so `Math` keeps its trust.

    Fails closed on every way the enumeration could be incomplete — an unresolvable callee, a rest
    or destructured parameter whose contents no name tracks, a reachable `arguments` object, or
    recursion past `_CALLEE_DEPTH_LIMIT`. Each of those means a parameter's value could be written
    through somewhere this scan does not look.

    The parameter-escape question routes back through `_value_escapes` rather than scanning for
    identifiers, so a callee that merely *reads* through its parameter (`return o.PI`) stays
    write-free while one that passes it on (`g(o)`) does not. That reuse also subsumes the return
    case without a branch of its own: a parameter in a return position matches no sparing arm, so it
    escapes — and by the same rule so do `return [o]`, `return { m: o }`, and an arrow's concise
    body, which an explicit return check missed.
    """
    if func is None or depth > _CALLEE_DEPTH_LIMIT:
        return False
    scope = model.parameter_scope(func)
    if scope is None:
        return False
    if not isinstance(func, JsArrowFunctionExpression):
        binding = scope.bindings.get('arguments')
        if binding is not None and (model.references(binding) or model.reflection_can_reach(binding)):
            return False
    names = [param.name for param in func.params if isinstance(param, JsIdentifier)]
    if len(names) != len(func.params):
        return False
    params = frozenset(names)
    if not params:
        return True
    body = getattr(func, 'body', None)
    if body is None:
        return False
    for node in body.walk():
        target = None
        if isinstance(node, JsAssignmentExpression):
            target = node.left
        elif isinstance(node, JsUpdateExpression):
            target = node.argument
        elif isinstance(node, JsUnaryExpression) and node.operator == 'delete':
            target = node.operand
        base = _member_chain_root(target)
        if base is not None and base.name in params:
            return False
        if isinstance(node, JsIdentifier) and node.name in params:
            if reference_role(node) is Role.READ:
                names = aliases.names_denoted_by(node)
                if _value_escapes(model, aliases, node, names, depth):
                    return False
    return True


def unambiguous_callee(
    model: SemanticModel, call: JsCallExpression
) -> JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression | None:
    """
    The function *call* certainly invokes for a consumer that cannot order the call against a
    reassignment of the callee's name, or `None`. The module-scope form of
    `refinery.lib.scripts.js.analysis.effects.EffectModel.unambiguous_callee`, which delegates here:
    the answer needs only the model, so `build_intrinsic_writes`, which runs before any effect model
    exists, can still ask it.
    """
    callee = call.callee
    if isinstance(callee, (JsFunctionExpression, JsArrowFunctionExpression)):
        return callee
    if not isinstance(callee, JsIdentifier):
        return None
    return unambiguous_function(model, model.resolve(callee))


def unambiguous_function(
    model: SemanticModel, binding: Binding | None
) -> JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression | None:
    """
    The module-scope form of
    `refinery.lib.scripts.js.analysis.effects.EffectModel.unambiguous_function`, which delegates
    here. See that method for which bindings qualify.
    """
    value = model.singular_value(binding)
    return value if isinstance(value, FUNCTION_NODES) else None


class _IntrinsicAliases:
    """
    Resolves the identifier at the root of a write target to every name it may denote, so that a
    property write reaching an intrinsic through a local is attributed to the intrinsic rather than
    to the local. `var m = Math; m.floor = f` must record `Math`, or the write stays invisible to
    every consumer of `IntrinsicWrites.names` and `Math.floor(1.7)` goes on folding to the built-in.

    A *may* analysis on purpose: every value a binding can hold contributes, so one branch assigning
    an intrinsic is enough to poison the name. The direction is forced — missing an alias yields a
    wrong value, while an extra name yields an unfolded call — and it matches how the
    accessor-install targets are already over-approximated, `Object.defineProperty(0 || Math, …)`
    among them.

    The backward step is `_denoted_roots`, the same value-preserving walk the install-target scan
    uses, reused rather than reimplemented for two reasons. It already looks through exactly the
    forms a fold collapses (`||`, `&&`, `??`, conditional, sequence-last, assignment-RHS, parens),
    which is what keeps this answer stable while passes run — the pinning contract in
    `refinery.lib.scripts.js.analysis.cache.ModelCache` requires that this set never *grow* across a
    pass. And it stops at a call, so `var s = String.fromCharCode(x)` does not alias `String`: the
    local holds the *result*. Its member-chain arm over-approximates in the one remaining direction
    — `var n = Array.length` reports `Array` — which is sound and costs nothing.
    """

    def __init__(self, model: SemanticModel):
        self.model = model
        self._cache: dict[int, frozenset[str]] = {}

    def names_denoted_by(self, node: JsIdentifier) -> frozenset[str]:
        """
        Every intrinsic-root name *node* may denote, including its own when it names one directly. A
        name that resolves to no binding is a free global and denotes itself.
        """
        if node.name in PURE_INTRINSIC_ROOTS:
            return frozenset({node.name})
        binding = self.model.resolve(node)
        if binding is None:
            return frozenset({node.name})
        return self.names_of(binding)

    def names_of(self, binding: Binding) -> frozenset[str]:
        """
        Every name a value of *binding* may denote. The binding-level entry point, for a caller
        holding a binding rather than a reference to it — resolving a *write* target, whose
        declaration id is not a reference at all.
        """
        return self._names_of(binding, set())

    def _names_of(self, binding: Binding, visiting: set[int]) -> frozenset[str]:
        """
        Every name a value of *binding* may denote, memoized per binding. The *visiting* set breaks
        the cycle a mutually-assigning pair (`a = b; b = a`) would otherwise spin on; a binding
        still on the stack contributes nothing further, since whatever it reaches is already being
        collected.
        """
        key = id(binding)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        if key in visiting:
            return frozenset()
        visiting.add(key)
        found: set[str] = set()
        for root in _binding_value_roots(binding):
            if root.name in PURE_INTRINSIC_ROOTS:
                found.add(root.name)
                continue
            inner = self.model.resolve(root)
            if inner is None:
                found.add(root.name)
                continue
            found |= self._names_of(inner, visiting)
        visiting.discard(key)
        result = frozenset(found)
        self._cache[key] = result
        return result


def _binding_value_roots(binding: Binding) -> Iterator[JsIdentifier]:
    """
    Every name a value of *binding* may denote, over its declarations' initializers and the right
    side of every plain assignment to it. Both are needed: a binding declared empty and assigned
    later (`var m; m = Math`) holds the intrinsic just as one initialized with it does.

    A write the model cannot pin to a value
    (`refinery.lib.scripts.js.analysis.model.Binding.indefinite_writes`) contributes as well. This
    is a *may* analysis, and `arguments[k] = Math` stores the intrinsic under a parameter's name
    whether or not the text says which parameter or whether the call supplied it; leaving it out is
    exactly the missed alias the caller's docstring names as a wrong answer.

    The may-side sibling of `refinery.lib.scripts.js.analysis.model.SemanticModel.binding_values`,
    deliberately wider than its readable channels: a compound assignment's right side contributes
    here where the must-query refuses the whole binding, because `_value_escapes`'s rebinding arm
    spares a target only while the names it may denote are still attributed back, and narrowing this
    walk would turn those rebindings into escapes. A channel neither walk reads — an intrinsic
    stored through a pattern, a parameter fed at a call site — is covered at its source instead: the
    intrinsic *read* that fed it escapes, which withdraws the key trust there.
    """
    for declaration in binding.declarations:
        parent = getattr(declaration, 'parent', None)
        initializer = getattr(parent, 'init', None)
        if initializer is not None:
            yield from _denoted_roots(initializer)
    for reference in (*binding.writes, *binding.indefinite_writes):
        parent = getattr(reference, 'parent', None)
        if isinstance(parent, JsAssignmentExpression) and parent.left is reference:
            yield from _denoted_roots(parent.right)


def _accessor_install_targets(call: JsCallExpression) -> Iterator[JsIdentifier]:
    """
    The names whose properties *call* may install an accessor or data descriptor on. An
    `Object.defineProperty(Math, ...)` replaces a method without ever writing `Math` syntactically,
    so a scan for assignments alone would leave the name looking untouched. The receiver form
    (`o.__defineGetter__(...)`) attributes to the receiver instead of an argument.

    Every name the target *may* denote is yielded, because a caller collecting writes needs an
    over-approximation: a missed name is a name that keeps its trust while the program patches it.
    That is the opposite of `refinery.lib.scripts.js.analysis.effects.EffectModel.intrinsic_of`,
    which must certify what a node *does* denote and so takes only the left of `A || B`; here both
    operands are yielded, since either may survive.
    """
    callee = strip_parens(call.callee)
    if not isinstance(callee, JsMemberExpression):
        return
    method = accessor_install_method(callee)
    if method is None:
        return
    if method.startswith('__define'):
        yield from _denoted_roots(callee.object)
    elif call.arguments:
        yield from _denoted_roots(call.arguments[0])


def _denoted_roots(node: Node | None, depth: int = 0) -> Iterator[JsIdentifier]:
    """
    Every name *node* may denote, looking through the value-preserving forms a constant fold
    collapses: parentheses, the operands of `||`/`&&`/`??` and the branches of a conditional (either
    side may be the value), the last expression of a sequence, and the right side of an assignment.

    Resolving only the syntactic form would make this analysis change its answer as folds fire —
    `Math || 0` names nothing until it collapses to `Math` — which is precisely what a consumer
    holding the answer across a pass cannot tolerate.
    """
    if depth > _DENOTED_ROOT_DEPTH_LIMIT:
        return
    cursor = strip_parens(node)
    if isinstance(cursor, JsIdentifier):
        yield cursor
    elif isinstance(cursor, JsMemberExpression):
        root = _member_chain_root(cursor)
        if root is not None:
            yield root
    elif isinstance(cursor, JsLogicalExpression):
        yield from _denoted_roots(cursor.left, depth + 1)
        yield from _denoted_roots(cursor.right, depth + 1)
    elif isinstance(cursor, JsConditionalExpression):
        yield from _denoted_roots(cursor.consequent, depth + 1)
        yield from _denoted_roots(cursor.alternate, depth + 1)
    elif isinstance(cursor, JsSequenceExpression):
        if cursor.expressions:
            yield from _denoted_roots(cursor.expressions[-1], depth + 1)
    elif isinstance(cursor, JsAssignmentExpression):
        yield from _denoted_roots(cursor.right, depth + 1)


def _member_chain_root(node: Node | None) -> JsIdentifier | None:
    """
    The identifier at the foot of a member-access chain, or `None` when the chain does not start at
    a plain name. `Math.prototype.x` roots at `Math`, so a write anywhere along the chain is
    attributed to the name that owns it; testing only the immediate `.object` would miss every
    nested write.
    """
    cursor = strip_parens(node)
    if not isinstance(cursor, JsMemberExpression):
        return None
    while isinstance(cursor, JsMemberExpression):
        cursor = strip_parens(cursor.object)
    return cursor if isinstance(cursor, JsIdentifier) else None
