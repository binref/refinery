"""
Inline properties of locally-defined constant object literals.

When the obfuscator lifts string literals and operator wrappers into a local object, this
transformer detects the pattern and replaces all member-access reads with the inlined property
values. Function-valued properties that are trivial wrappers (single return statement whose body is
an expression using only parameters) are inlined at the call site.
"""
from __future__ import annotations

import enum

from typing import Callable, Iterator, NamedTuple

from refinery.lib.scripts import (
    Node,
    Statement,
    _clone_node,
    _replace_in_parent,
)
from refinery.lib.scripts.js.analysis.conversions import CONVERSION_KEYS
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.intrinsics import SPECIES_KEYS, IntrinsicWrites
from refinery.lib.scripts.js.analysis.model import (
    REFLECTIVE_INTRINSICS,
    STRING_EVAL_NAMES,
    Binding,
    Scope,
    SemanticModel,
    is_direct_eval_call,
    is_use_position,
    walk_receiver_scope,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    Landing,
    PinnedTransformer,
    ScopeProcessingTransformer,
    a_host_reaches_the_binding,
    access_key,
    expression_a_call_answers,
    make_undefined_expression,
    property_key,
    property_provably_absent,
    references_receiver_this,
    remove_declarator,
    spelled_for_the_callee_position,
    try_inline_trivial_function,
    value_landing,
    walk_scope,
)
from refinery.lib.scripts.js.model import (
    CONVERSION_INSTALL_METHODS,
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsCallExpression,
    JsClassExpression,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNewExpression,
    JsObjectExpression,
    JsProperty,
    JsPropertyKind,
    JsRegExpLiteral,
    JsScript,
    JsTaggedTemplateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    object_sets_prototype,
    static_string,
    strip_parens,
)


def _build_property_map(
    obj: JsObjectExpression,
) -> dict[str, Node] | None:
    """
    Build a map from string key to value node for every property in the object literal.
    Returns `None` if any property cannot be statically keyed (computed key, spread, etc.). Each value
    is stripped of enclosing parentheses so the fold guards inspect the expression itself: a
    parenthesized function value (`{ f: (function(){}) }`) must reach the identity guard as the function
    it wraps, or a bare `o.f` read would fold to a fresh clone and break `o.f === o.f`.
    """
    result: dict[str, Node] = {}
    for prop in obj.properties:
        if not isinstance(prop, JsProperty):
            return None
        if prop.kind is not JsPropertyKind.INIT:
            return None
        key = property_key(prop)
        value = strip_parens(prop.value)
        if key is None or value is None:
            return None
        result[key] = value
    return result


def _object_binds_this(prop_map: dict[str, Node]) -> bool:
    """
    Return whether any property value depends on `this` being supplied by the object, so that
    folding the object away (detaching the value from its receiver) would change its meaning.
    """
    return any(references_receiver_this(value) for value in prop_map.values())


def _function_observes_its_identity(func: JsFunctionExpression) -> bool:
    """
    Whether a call to *func* can tell one copy of the function from another: the body reads the
    function expression's own name, or reaches `arguments.callee` — through its own `arguments`
    binding, which an arrow inside the body shares and a nested regular function does not. Cloning
    such a function into each call site answers a different object at each, so `o.m() === o.m()`
    flips where the original compared one function against itself. A computed `arguments[k]` whose
    key is not statically known counts, since `k` may name `callee` at runtime.
    """
    name = func.id.name if func.id is not None else None
    if name is not None and any(
        isinstance(node, JsIdentifier)
        and node.name == name
        and node is not func.id
        and is_use_position(node)
        for node in func.walk()
    ):
        return True
    for node in walk_receiver_scope(func):
        if not isinstance(node, JsMemberExpression) or node.object is None:
            continue
        base = strip_parens(node.object)
        if not isinstance(base, JsIdentifier) or base.name != 'arguments':
            continue
        key = access_key(node)
        if key is None or key == 'callee':
            return True
    return False


def _binding_inside(binding: Binding, value: Node) -> bool:
    """
    Whether *binding* is declared inside *value* — its scope is introduced by *value* or a node nested
    within it — so that a clone of *value* carries the binding along and a reference to it stays bound
    to the same declaration wherever the clone lands.
    """
    node = binding.scope.node
    return node is value or node.is_descendant_of(value)


def _free_external_bindings(
    model: SemanticModel, value: Node
) -> Iterator[tuple[JsIdentifier, Binding | None]]:
    """
    Yield each free identifier in *value* that is in a use position, paired with the binding it
    resolves to (or `None` for an unresolved external name) — every reference a clone of *value*
    would re-resolve at its destination, excluding the ones bound inside *value* itself, which the
    clone carries along. The shared traversal behind `_value_is_stable` (does any such binding get
    reassigned) and `_resolves_consistently` (does any such name rebind at the fold site).
    """
    for node in value.walk():
        if not isinstance(node, JsIdentifier) or not model.is_reference(node):
            continue
        binding = model.resolve(node)
        if binding is not None and _binding_inside(binding, value):
            continue
        yield node, binding


def _resolves_consistently(
    model: SemanticModel,
    value: Node,
    dest: Scope | None,
    free: list[tuple[JsIdentifier, Binding | None]] | None = None,
) -> bool:
    """
    Whether every free identifier in *value* resolves, from *dest* — the scope the value would be
    folded into — to the same binding it reads at the object literal. A value moved into a use site
    that binds one of its free names anew (a parameter, a block-scoped `let`, or the per-call
    `arguments` of a nested function) would silently rebind there and read a different value than the
    object captured. This is the spatial counterpart to the temporal `_value_is_stable`; an identifier
    bound inside *value* itself places no constraint, since the clone carries its binding with it.

    *free* is the precomputed `_free_external_bindings` list for *value*; it does not depend on *dest*,
    so a caller checking one value against several destinations passes it once to avoid re-walking.
    """
    if free is None:
        free = list(_free_external_bindings(model, value))
    return all(binding is model.lookup(node.name, dest) for node, binding in free)


def _statement_holding(node: Node) -> Node | None:
    """
    The innermost statement *node* stands in, or `None` where it stands in none.
    """
    cursor: Node | None = node
    while cursor is not None and not isinstance(cursor, Statement):
        cursor = cursor.parent
    return cursor


#: The property names a key makes the models read as more than the name of a property: a method
#: that installs a descriptor, a conversion or a prototype, or that reaches one, an intrinsic that
#: compiles a string, a global that runs one, and a key that yields a prototype or names a
#: conversion. A string written where a computed key stands shows the models a fact about the whole
#: program where it names one of these, and otherwise at most one about the global it names.
_NAMES_A_KEY_GIVES_A_MEANING = (
    CONVERSION_INSTALL_METHODS
    | CONVERSION_KEYS
    | REFLECTIVE_INTRINSICS
    | STRING_EVAL_NAMES
    | SPECIES_KEYS
    | frozenset({
        'apply',
        'call',
        'getPrototypeOf',
        'prototype',
        'toPrimitive',
    })
)


class _Shown(enum.IntEnum):
    """
    What a copy shows the models that they did not read where the value stood
    (`_what_a_copy_shows`), ordered by what it costs the held models: a fact about the whole
    program outdates them for every decision after it, and the name of a property outdates what
    they say about the global it names.
    """
    NOTHING = 0
    A_NAME = 1
    A_FACT = 2


def _what_a_copy_shows(
    scan: IntrinsicWrites,
    value: Node,
    landing: Landing | None,
    *,
    handed: bool,
) -> _Shown:
    """
    What a copy of *value* that lands at *landing* shows the models that they did not read where
    the value stood: in an object literal or, where it was *handed*, as the argument of a call
    whose callee is a member no model resolves.

    A string where a computed key or an install's key stands
    (`refinery.lib.scripts.js.deobfuscation.helpers.Landing.KEY`) names a property from then on,
    which is a fact about the whole program where `_NAMES_A_KEY_GIVES_A_MEANING` holds the name.
    A name where a callee stands shows one where it makes the call run a string of code
    (`refinery.lib.scripts.js.analysis.model.STRING_EVAL_NAMES`), and so does a value the models
    follow only through bindings
    (`refinery.lib.scripts.js.analysis.intrinsics.IntrinsicWrites.follows_only_through_bindings`)
    wherever they read one, except as an argument where it was handed to a call already.
    """
    if landing is Landing.KEY:
        name = static_string(value)
        if name is None:
            return _Shown.NOTHING
        return _Shown.A_FACT if name in _NAMES_A_KEY_GIVES_A_MEANING else _Shown.A_NAME
    if landing is Landing.CALLEE:
        callee = strip_parens(value)
        if isinstance(callee, JsIdentifier) and callee.name in STRING_EVAL_NAMES:
            return _Shown.A_FACT
        return _Shown.NOTHING
    if landing is None or landing is Landing.ELSEWHERE:
        return _Shown.NOTHING
    if landing is Landing.ARGUMENT and handed:
        return _Shown.NOTHING
    return _Shown.A_FACT if scan.follows_only_through_bindings(value) else _Shown.NOTHING


def _what_an_inlined_call_shows(
    scan: IntrinsicWrites,
    func: JsFunctionExpression,
    call: JsCallExpression,
) -> _Shown:
    """
    What inlining *call* of *func* shows the models that they did not read (`_what_a_copy_shows`).
    Each argument lands where the expression the call answers reads its parameter: inside the
    expression, or where the call stands where the expression evaluates to it. A name the
    expression reads other than a parameter lands there as a copy of itself.
    """
    answered = expression_a_call_answers(func)
    if answered is None:
        return _Shown.NOTHING
    expression, names = answered
    passed = dict(zip(names, call.arguments))
    where_the_call_lands: Landing | None = None
    shown = _Shown.NOTHING
    for node in expression.walk():
        if not isinstance(node, JsIdentifier) or not is_use_position(node):
            continue
        landing = value_landing(node, expression)
        if landing is None:
            if where_the_call_lands is None:
                where_the_call_lands = value_landing(call)
            landing = where_the_call_lands
        argument = passed.get(node.name)
        if argument is None:
            shown = max(shown, _what_a_copy_shows(scan, node, landing, handed=False))
        else:
            shown = max(shown, _what_a_copy_shows(scan, argument, landing, handed=True))
    return shown


def _runs_code_in_its_scope(model: SemanticModel, value: Node) -> bool:
    """
    Whether *value* holds a direct `eval` the model reads as code that may name any binding in
    scope where it runs. A copy closed over the scope it is copied into would read and write the
    names of that scope instead of the ones around the literal, which no comparison of the names
    the value spells can see. The trusting model reads such code as naming nothing.
    """
    return not model.trust_eval and any(is_direct_eval_call(node) for node in value.walk())


class _Folded(NamedTuple):
    """
    What folding the references of one object did: whether it replaced any, whether every one was
    folded away so the declaration can go, and whether a copy since the last renewal named a
    property the models then read as the name of a global (`_Shown.A_NAME`).
    """
    changed: bool
    can_remove: bool
    named: bool


class JsObjectFold(PinnedTransformer, ScopeProcessingTransformer):
    """
    Inline properties of locally-defined constant objects. Processes at function-scope and
    script-scope boundaries because JavaScript `var` declarations are function-scoped.

    The pass holds the models for an invocation
    (`refinery.lib.scripts.js.deobfuscation.helpers.PinnedTransformer`). A fold replaces the
    references of one object with copies of its values and removes its declaration, and leaves the
    answers about the next object no more permissive than rebuilt ones:

    - Every edit goes through `_replace`, which records the statement the replaced code stood in,
      the names the replaced code spelled, and what the names the inserted code spells reach there:
      the binding the held model resolves each to, or the name where it resolves to none. Removing
      a declarator records the names its literal spelled. A fold adds a reference to a binding
      through inserted code that names it, or through a copy the last point renews after, and it
      detaches a reference only along with code it records. Before deciding an object whose
      binding, or one its literal reads, inserted code names, whose literal holds code the model
      does not know, or one of whose references an edit detached or stands in an edited statement,
      the pass renews.
    - Removing a declarator takes facts away, but for the references in it, which it detaches.
    - A copy that shows the models a fact about the whole program they did not read where the
      value stood (`_what_a_copy_shows`) makes the pass renew at once, before it decides the next
      reference: a value they follow only through bindings that lands where they read one, a
      string that names a method or a key they read as more than a property, a name that makes a
      call run a string of code. A string that names any other property makes it renew once the
      object is done, before the next object is decided on what the models say of the global the
      string may name.
    """

    def __init__(self):
        super().__init__()
        self._inserted_bindings: set[Binding] = set()
        self._inserted_names: set[str] = set()
        self._edited_statements: set[Node] = set()
        self._detached: set[Node] = set()

    def visit_JsScript(self, node: JsScript):
        with self.holding_models(node):
            return super().visit_JsScript(node)

    def _forget_edits(self) -> None:
        self._inserted_bindings = set()
        self._inserted_names = set()
        self._edited_statements = set()
        self._detached = set()

    def _detach(self, removed: Node) -> None:
        """
        Record the names the code *removed*, which an edit took out of the tree, spelled: a held
        model still lists those among the references of the bindings they read.
        """
        self._detached.update(node for node in removed.walk() if isinstance(node, JsIdentifier))

    def _replace(self, old: Node, new: Node) -> None:
        """
        Replace *old* with *new*, recording the statement *old* stood in, the names it spelled
        (`_detach`), and what each name *new* spells reaches there: the binding the held model
        resolves it to from the scope of *old*, or the name itself where the model resolves it to
        none.
        """
        model = self.held_models().model
        scope = model.scope_of(old)
        statement = _statement_holding(old)
        if not _replace_in_parent(old, new):
            return
        if statement is not None:
            self._edited_statements.add(statement)
        self._detach(old)
        for node in new.walk():
            if not isinstance(node, JsIdentifier) or not is_use_position(node):
                continue
            binding = model.lookup(node.name, scope)
            if binding is None:
                self._inserted_names.add(node.name)
            else:
                self._inserted_bindings.add(binding)

    def _names(self, binding: Binding | None, name: JsIdentifier) -> bool:
        """
        Whether code inserted since the last renewal names *binding*, the one *name* reaches, or a
        name spelled like *name* that the held model resolves to no binding.
        """
        return binding in self._inserted_bindings or name.name in self._inserted_names

    def _edited_around(
        self,
        model: SemanticModel,
        binding: Binding,
        name: JsIdentifier,
        init: JsObjectExpression,
        prop_map: dict[str, Node],
    ) -> bool:
        """
        Whether an edit since the last renewal touched what the held models say about the object
        *name* declares with *init*: inserted code names its binding or one its literal reads, its
        literal holds code the model does not know, or an edit detached one of its references or
        changed the statement one stands in, where the code around it may be code the models do not
        know, such as a function an earlier fold wrote where the callee of its call stood.
        """
        if not self._edited_statements and not self._detached:
            return False
        if self._names(binding, name):
            return True
        if not all(model.knows(node) for node in init.walk()):
            return True
        if any(
            self._names(read, identifier)
            for value in prop_map.values()
            for identifier, read in _free_external_bindings(model, value)
        ):
            return True
        return any(
            reference in self._detached or _statement_holding(reference) in self._edited_statements
            for reference in model.references(binding)
        )

    def _process_scope_body(self, scope: Node, body: list[Statement]) -> None:
        for declarator in list(self._find_candidates(body)):
            name = declarator.id
            init = declarator.init
            if not isinstance(name, JsIdentifier) or not isinstance(init, JsObjectExpression):
                continue
            prop_map = _build_property_map(init)
            if (
                prop_map is None
                or _object_binds_this(prop_map)
                or object_sets_prototype(init)
                or self._has_freshly_allocating_value(prop_map)
            ):
                continue
            cache = self.held_models()
            model = cache.model
            binding = model.binding_of(name)
            if binding is None:
                continue
            if self._edited_around(model, binding, name, init, prop_map):
                self.renew_models()
                model = cache.model
                binding = model.binding_of(name)
            if binding is None or binding.writes or model.singular_value(binding) is not init:
                continue
            if a_host_reaches_the_binding(model, binding, self.options):
                continue
            if not cache.effects.is_side_effect_free(init, {name.name}):
                continue
            if not cache.effects.binding_is_immutable_container(binding, member_calls_mutate=False):
                continue
            if self._self_referential(model, binding, init):
                continue
            if any(not self._value_is_stable(model, value) for value in prop_map.values()):
                continue
            if any(
                self._eagerly_reads_mutable_container(model, cache.effects, value)
                for value in prop_map.values()
            ):
                continue
            if any(
                self._reads_lexical_in_dead_zone(model, cache.dominance, value)
                for value in prop_map.values()
            ):
                continue
            folded = self._inline_references(
                model, cache.effects, cache.intrinsic_writes, binding, prop_map, cache.read_established
            )
            if folded.changed:
                if folded.can_remove:
                    remove_declarator(declarator)
                    self._detach(declarator)
                self.mark_changed()
                if folded.named:
                    self.renew_models()

    @staticmethod
    def _find_candidates(body: list[Statement]) -> Iterator[JsVariableDeclarator]:
        """
        Yield each variable declarator in *body* that initializes a variable to an object literal — the
        syntactic precondition for folding. Whether the literal is actually foldable (every key static,
        the name a single immutable binding) is decided per candidate by the caller against models
        renewed after any earlier fold that touched it, and its property map is read from the live
        initializer at that point, so an earlier fold into this initializer is reflected.
        """
        for stmt in body:
            if not isinstance(stmt, JsVariableDeclaration):
                continue
            for decl in stmt.declarations:
                if isinstance(decl, JsVariableDeclarator) and isinstance(decl.init, JsObjectExpression):
                    yield decl

    @staticmethod
    def _value_is_stable(model: SemanticModel, value: Node) -> bool:
        """
        Whether *value* evaluates to the same result wherever it is inlined — the precondition for
        moving a property value from the object literal to each access site. It holds when every
        binding the value reads as a free variable keeps its value: a property whose value reads a
        local that is reassigned (`{ p: x }` where `x` is later written) would, once inlined past
        the reassignment, read the new value instead of the one the object captured at the literal.
        A reassignment through a dynamic scope — a `with` body that names the binding, or a direct
        `eval` in its function — counts too, since it rebinds the name without leaving a static
        write; the model answers this over the binding's dynamic references. Identifiers bound
        inside *value* itself (a function's own parameters) and free references that resolve to no
        binding (external globals) place no constraint, so a string, a numeric literal, a `const`
        reference, or a self-contained function wrapper all remain foldable.
        """
        return all(
            binding is None or model.binding_never_reassigned(binding)
            for _, binding in _free_external_bindings(model, value)
        )

    @staticmethod
    def _eagerly_reads_mutable_container(
        model: SemanticModel, effects: EffectModel, value: Node,
    ) -> bool:
        """
        Whether *value* eagerly reads the contents of a mutable container — a binding holding an object
        or array whose contents are not stable after construction (`{ p: arr + '' }` followed by a later
        `arr.push(9)`). Folding clones the value into every access site, re-evaluating the read there, so
        a mutation made between the object's construction and a later read would be observed at the read
        but not at the literal. A bare-identifier value is exempt: folding it relocates a reference to the
        same binding, so the container's identity — and every mutation through it — stays equally visible
        at each site. A read inside a nested function is not eager: it runs only when the function is
        later called, resolving the container by reference then, so `walk_scope` does not enter one.
        Immutability is judged with the value's own read excluded, so coercing a primitive, or a container
        never mutated elsewhere — whose binding carries no other mutating reference — stays stable and
        still folds. This is the state-reading counterpart to `_value_is_stable`, which guards only against
        the binding being rebound, not against its container's contents being mutated in place.
        """
        if isinstance(value, JsIdentifier):
            return False
        for node in walk_scope(value):
            if not isinstance(node, JsIdentifier) or not model.is_reference(node):
                continue
            binding = model.resolve(node)
            if binding is None or _binding_inside(binding, value):
                continue
            if not effects.binding_is_immutable_container(binding, member_calls_mutate=True, exclude=value):
                return True
        return False

    @staticmethod
    def _reads_lexical_in_dead_zone(
        model: SemanticModel, dominance: DominanceModel, value: Node,
    ) -> bool:
        """
        Whether *value*, evaluated eagerly when the object literal is built, reads a `let`, `const`, or
        `class` binding not yet established there — a read in the binding's temporal dead zone, a
        `ReferenceError` at runtime. Folding clones the value into each access site, which may lie past
        the binding's declaration, so the read would move out of the dead zone and observe the declared
        value instead of throwing. A read inside a nested function is not eager — it runs at call time,
        where folding a called wrapper preserves its position — so `walk_scope` does not enter one. Only
        a lexical binding has a dead zone; a `var`, a parameter, or an external global places no
        constraint. This is the temporal-dead-zone counterpart to `_value_is_stable`, which guards only
        against the binding being rebound, not against the value reading it before its declaration runs.
        """
        for node in walk_scope(value):
            if not isinstance(node, JsIdentifier) or not model.is_reference(node):
                continue
            binding = model.resolve(node)
            if binding is None or _binding_inside(binding, value):
                continue
            if binding.is_lexical and not dominance.binding_established_before(binding, node):
                return True
        return False

    @staticmethod
    def _has_freshly_allocating_value(prop_map: dict[str, Node]) -> bool:
        """
        Whether any property value, when evaluated, may allocate a fresh object whose identity folding
        would duplicate. Folding clones the value into every access site, so a value that builds a new
        array or object — directly as a container literal, or by returning one from a call or `new`
        (only a side-effect-free, hence pure, one reaches this far) — would become a distinct object at
        each site: two `o.arr` reads that name one shared array become two arrays, diverging on identity
        (`o.arr === o.arr` flips from true to false), on a mutation made through one access (or an alias,
        argument, or method call that reaches it) and observed through another, and on element identity
        one level down. Deciding precisely which such folds are safe is the nested-container escape
        analysis the model does not yet provide, so such an object is left unfolded. A function or arrow
        literal value is judged per reference instead — folded only where it is immediately called, so
        its identity is never observed — and a primitive, a binding, a member read, or an operator over
        them duplicates without a fresh identity, so none of those constrains the fold.
        """
        return any(JsObjectFold._value_allocates(value) for value in prop_map.values())

    @staticmethod
    def _value_allocates(value: Node) -> bool:
        """
        Whether evaluating *value* may allocate a fresh object — a container literal it builds directly,
        a regular-expression or class literal (each evaluation mints a new object), or one a call,
        `new`, or tagged template in its evaluation may return. A function or arrow literal value is
        excluded, since its own identity is handled where it is folded; a nested function inside the
        value is not entered, as its body runs only when the function is later called, not when the
        value the object captured is evaluated.

        This is a *may*-allocate question and must not be merged with `EffectModel._fresh_kind`, which is a
        *must*-allocate one. The two answer about different rewrites: this one about identity duplication
        under cloning (`o.arr === o.arr` flipping if the fold mints two arrays), that one about whether a
        write through a base can be observed. They are not even monotone in one another — a bare call counts
        as allocating here and as `NOT_FRESH` there — so neither implies the other in either direction.
        """
        if isinstance(value, (JsFunctionExpression, JsArrowFunctionExpression)):
            return False
        return any(
            isinstance(node, (
                JsArrayExpression,
                JsObjectExpression,
                JsCallExpression,
                JsClassExpression,
                JsNewExpression,
                JsRegExpLiteral,
                JsTaggedTemplateExpression,
            ))
            for node in walk_scope(value)
        )

    @staticmethod
    def _self_referential(model: SemanticModel, binding: Binding, init: JsObjectExpression) -> bool:
        """
        Whether any reference to *binding* lies within its own initializer *init* — the object names
        itself in one of its property values (`var o = { f: function() { return o.x; } }`). Inlining
        such a value into a use site re-introduces a reference to the object there, so removing the
        declaration would leave it dangling; the caller skips folding the object rather than fold it
        into invalid code.
        """
        return any(ref.is_descendant_of(init) for ref in model.references(binding))

    def _inline_references(
        self,
        model: SemanticModel,
        effects: EffectModel,
        scan: IntrinsicWrites,
        binding: Binding,
        prop_map: dict[str, Node],
        read_established: Callable[[JsIdentifier], bool],
    ) -> _Folded:
        """
        Replace each `obj['key']` access through *binding* with the corresponding property value. For
        function-valued properties called as `obj['key'](args)`, inline the call. A key the property
        map does not hold is read off the prototype chain instead, so what it evaluates to is
        `property_provably_absent`'s to say and not this transform's: an inherited member is left
        intact because folding `o.toString` to `undefined` turns `o.toString()` into `undefined()`,
        and every key at all is left intact once the file has written to a prototype the read walks,
        because then `undefined` is not what the read answers. Iterating the binding's resolved
        references (not every textual occurrence of the name) keeps a shadowing inner binding of the
        same name untouched.

        Two per-reference conditions block a fold that would change meaning at the destination, leaving
        the access intact. A function-valued property is folded only where it is immediately called
        (the value's identity never escapes); a bare read of it is kept, since cloning it into two sites
        would make `o.f === o.f` two distinct functions. And a value is folded into a use site only when
        each of its free identifiers resolves to the same binding there as at the literal, so a value
        read inside a nested function that rebinds one of those names — a parameter, a block `let`, or
        that function's own `arguments` — is not silently recaptured.

        Returns `changed`, True when any replacement was made, and `can_remove`, True when every
        reference was folded away, so no use of the binding survives — a bare reference (an alias
        such as `var b = obj`), a retained inherited-member access, or a reference one of the two
        conditions above kept leaves *can_remove* False so the declaration is kept. A reference a
        dynamic scope resolves at runtime — a name inside a `with` body, held in the binding's
        dynamic references and never folded here — likewise keeps the declaration, so it is not
        removed out from under a use the fold left in place. A reference performed through a
        global-object alias (`globalThis.o`, a member node rather than an identifier) also keeps the
        declaration and is not folded: folding through it (`globalThis.o.x` to the property value)
        holds only under the script execution model, where a top-level `var` becomes a global
        property, not when the global is module-scoped. A reference an earlier copy took out of the
        tree with the code around it is no use any more and is passed over.

        A property no access reads is dropped with the declaration when it is removed, so a value
        whose read may throw a `ReferenceError` no completed write establishes keeps the
        declaration: building the object read that value, and dropping the declaration would mute
        the throw. A read the *read_established* proof vouches for, and every value accessed at
        least once (relocated to its use, its read still performed there), places no such
        constraint. Relocating that read does move it past any statement between the literal and the
        use, so a throw it carries is reordered past those statements' effects — a separate,
        unpinned defect (`test_unfixed_defects.TestARelocatedMayThrowReadIsReorderedPastAnEffect`).

        A function value is copied into a call only where no direct `eval` in it reads names the
        copy would read from the scope of the call (`_runs_code_in_its_scope`), and it is written
        where the call's callee stood the way every substitution writes a value there
        (`refinery.lib.scripts.js.deobfuscation.helpers.spelled_for_the_callee_position`), so a bare
        `eval` copied there stays an indirect one.

        It also returns `named`, True when a copy since the last renewal named a property the models
        then read as the name of a global (`_Shown.A_NAME`). A copy that shows them a fact about
        the whole program (`_Shown.A_FACT`) renews the models at once, and the references after it
        are decided on the renewed ones.
        """
        changed = False
        named = False
        can_remove = not binding.dynamic_refs
        consistent: dict[tuple[int, int], bool] = {}
        free_external: dict[int, list[tuple[JsIdentifier, Binding | None]]] = {}
        accessed_keys: set[str] = set()
        for ref in list(model.references(binding)):
            if ref in self._detached or not model.knows(ref):
                continue
            if not isinstance(ref, JsIdentifier):
                can_remove = False
                continue
            member = ref.parent
            if not isinstance(member, JsMemberExpression) or member.object is not ref:
                can_remove = False
                continue
            key = access_key(member)
            if key is None:
                can_remove = False
                continue
            if key not in prop_map:
                if not property_provably_absent(effects, dict, key):
                    can_remove = False
                    continue
                self._replace(member, make_undefined_expression())
                changed = True
                continue
            value = prop_map[key]
            accessed_keys.add(key)
            shown = self._copy(model, scan, member, value, consistent, free_external)
            if shown is None:
                can_remove = False
                continue
            changed = True
            if shown is _Shown.A_FACT:
                self.renew_models()
                held = self.held_models()
                model, effects, scan = held.model, held.effects, held.intrinsic_writes
                consistent.clear()
                free_external.clear()
                named = False
            elif shown is _Shown.A_NAME:
                named = True
        if can_remove and any(
            key not in accessed_keys
            and not effects.is_side_effect_free(
                value, reads_may_throw=True, read_established=read_established)
            for key, value in prop_map.items()
        ):
            can_remove = False
        return _Folded(changed, can_remove, named)

    def _copy(
        self,
        model: SemanticModel,
        scan: IntrinsicWrites,
        member: JsMemberExpression,
        value: Node,
        consistent: dict[tuple[int, int], bool],
        free_external: dict[int, list[tuple[JsIdentifier, Binding | None]]],
    ) -> _Shown | None:
        """
        Copy *value* where *member* reads it, or inline the call *member* is the callee of where
        *value* is a function the call answers an expression of, and tell what the copy shows the
        models (`_what_a_copy_shows`); `None` where the reference has to stay as it is. The two
        caches hold `_free_external_bindings` per value and `_resolves_consistently` per value and
        destination, for the models they were filled from.
        """
        parent = member.parent
        call = parent if isinstance(parent, JsCallExpression) and parent.callee is member else None
        if call is not None and isinstance(value, JsFunctionExpression):
            replacement = try_inline_trivial_function(value, call.arguments, transformer=self)
            if replacement is not None:
                shown = _what_an_inlined_call_shows(scan, value, call)
                self._replace(call, spelled_for_the_callee_position(call, replacement))
                return shown
            if _function_observes_its_identity(value):
                return None
        if isinstance(value, (JsFunctionExpression, JsArrowFunctionExpression)) and call is None:
            return None
        if _runs_code_in_its_scope(model, value):
            return None
        dest = model.scope_of(member)
        ckey = (id(value), id(dest))
        cached = consistent.get(ckey)
        if cached is None:
            free = free_external.get(id(value))
            if free is None:
                free = list(_free_external_bindings(model, value))
                free_external[id(value)] = free
            cached = _resolves_consistently(model, value, dest, free)
            consistent[ckey] = cached
        if not cached:
            return None
        shown = _what_a_copy_shows(scan, value, value_landing(member), handed=False)
        self._replace(member, spelled_for_the_callee_position(member, _clone_node(value)))
        return shown
