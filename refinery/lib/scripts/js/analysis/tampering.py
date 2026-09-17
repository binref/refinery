"""
The anchored tampering oracle: whether the built-ins a fold or an interpreted execution is about to
trust still mean what the language says at one point in the program — the anchor.

The trust questions the effect model answers (`EffectModel.trusted_intrinsic`,
`EffectModel.trusted_prototype`, `EffectModel.read_chain_intact`) are asked without a point: a
reflective surface anywhere withdraws trust everywhere, because code could have replaced a built-in
before any use. That refusal is sound and costs recall in proportion to the program — the obfuscated
files this pipeline reads carry their decoder in an `eval` or a `Function` construction, so every
later fold is refused even where the construction provably runs after the fold it blocks.
`TamperingModel.builtins_intact_at` asks the same question with the point supplied, as the
conjunction of:

- program-wide refusals: no static import, no `with`, no span of source the model never read —
  facts that cannot be ordered against an anchor at all;
- a site enumeration by forward value-flow — every store through a base that may be the global
  object under a key only the runtime resolves, every read of the global object in an argument
  position, every code-execution surface, and every recognized construction, followed to the
  positions that obtain its value: a callee position is an invocation of it, a binding initializer
  flows onward through that binding's reads, and any other position is an unreadable escape;
- multiplicity: the anchor executes at most once, counted by invocation *capability* — the
  activation chain up to the script root holds exactly one alias-resolved invocation each, off
  cycle, with no `callee`/`caller` re-entry spelling and no activation the host may invoke freely;
- ordering: every site is guaranteed to run after the anchor
  (`DominanceModel.runs_before`, the interprocedural first-execution guarantee).

With no sites there is nothing a re-execution could cross, so the answer is `True` without the
multiplicity walk — which is what keeps an ordinary clean program foldable at every anchor in it.

The per-name arms (`EffectModel.trusted_intrinsic`'s written-name check,
`EffectModel.trusted_prototype`'s owner check, `EffectModel.global_key_written`) stay independent of
the oracle: they answer attributed writes, the oracle answers unattributable execution, and a
consumer composes the two — the oracle first, then the per-name arm. A consumer without an anchor
keeps the program-wide question; see the consumers of `ModelCache.builtins_intact_at` for what
asking the oracle presupposes.

The enumeration is model-backed — computed once per model lifetime and memoized, never re-derived —
because it runs inside the pinned-model window of the reflection pass, where splices change the tree
underneath the held models. Its soundness there rests on two legs. A splice that removes a site
leaves the stale site in a memoized list, so the answer stays refused. And every predicate the
enumeration asks fails closed on nodes the model cannot place: a member-write base, an
argument-position read, or a callee the model never saw is treated as may-be-global — a site — so
code spliced in after the model was built refuses rather than clears.
"""
from __future__ import annotations

from typing import Callable, Collection, NamedTuple

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.cycles import CycleModel
from refinery.lib.scripts.js.analysis.cfg import ControlFlowModel
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import EffectModel, side_effect_free
from refinery.lib.scripts.js.analysis.model import (
    REFLECTIVE_INTRINSICS,
    Binding,
    ScopeKind,
    SemanticModel,
    enclosing_function,
    is_member_write_target,
    is_unread_source,
    member_property_name,
    own_arguments_binding,
)
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsCallExpression,
    JsExpressionStatement,
    JsIdentifier,
    JsImportDeclaration,
    JsImportExpression,
    JsMemberExpression,
    JsNewExpression,
    JsObjectPattern,
    JsParenthesizedExpression,
    JsProperty,
    JsStringLiteral,
    JsVariableDeclarator,
    JsWithStatement,
    strip_parens,
    wraps_return,
)
from refinery.lib.scripts.js.strict import strict_mode_at

#: How many name-to-value hops the recognizer follows in search of the `Function` intrinsic. A
#: chain longer than any real spelling of it is a cycle, and the limit answers undecided
#: before walking it.
_CONSTRUCTOR_ALIAS_LIMIT = 8

#: The re-entry spellings: a member read that may return the function it is read on, so a
#: textual invocation count cannot bound how often the activation runs.
_REENTRY_KEYS = frozenset({'callee', 'caller'})


def _static_member_key(member: JsMemberExpression) -> str | None:
    """
    The key a member access statically spells: the property identifier of a dot access, or the
    value of a terminated string-literal computed access. `None` for any other computed key — one
    only the runtime resolves.
    """
    prop = member.property
    if member.computed:
        return prop.value if isinstance(prop, JsStringLiteral) and prop.terminated else None
    return prop.name if isinstance(prop, JsIdentifier) else None


def _may_read_reentry_key(member: JsMemberExpression, model: SemanticModel) -> bool:
    """
    Whether *member* may read one of the re-entry keys — a property whose value is the function
    the access is made on, so reading it hands out a way to run that function again that no
    textual invocation count sees. A statically spelled key counts whether the access writes it
    as a dot or inside brackets. An unknown key counts only where the base is the `arguments`
    object the enclosing function was given, whose `callee` property is the function itself: on
    any other base an unknown key designates a property of that object, so a list dispatched by
    index stays clear. A strict function's `arguments` object has no `callee` property at all,
    and a name the function displaced — bound to a value of its own — is not that object.
    """
    static_key = _static_member_key(member)
    if static_key in _REENTRY_KEYS:
        return True
    if not member.computed or static_key is not None:
        return False
    base = strip_parens(member.object)
    if not isinstance(base, JsIdentifier):
        return False
    binding = model.resolve(base)
    if binding is None:
        return False
    fn = enclosing_function(member)
    while isinstance(fn, JsArrowFunctionExpression):
        fn = enclosing_function(fn)
    if fn is None or strict_mode_at(fn):
        return False
    return binding is own_arguments_binding(model, fn)


def denotes_function_intrinsic(
    callee: Node | None,
    model: SemanticModel,
    effects: EffectModel,
    dominance: DominanceModel,
    *,
    eval_string: Callable[[Node | None], str | None] | None = None,
    read_effect: Callable[[Node], bool] | None = None,
    positioned_value: Callable[[Binding, Node], Node | None] | None = None,
    spliced_names: Collection[str] = (),
    depth: int = 0,
) -> bool | None:
    """
    Whether *callee* denotes the `Function` intrinsic — the callee every spelling of a code
    construction calls — or `None` when that cannot be decided. `True` covers the spellings the
    text can pin: the bare free global, a `.constructor` navigation off a literal or off a name the
    model pins to one plain function, and a name holding one of those, transitively through
    `SemanticModel.singular_value` up to the alias-hop limit. `None` marks the shapes no reading of
    the text decides — a node the model cannot place, a computed key no string resolution reads, an
    alias chain past the limit — and `False` everything else, including every callee that provably
    denotes some other value.

    The one gate every navigation spelling passes first: a program that writes the `constructor`
    key on a chain rooted at `Function` has replaced the intrinsic every navigation hands out, so
    all of them are refused at once. A callee the recognizer declines leaves its construction
    unrecognized, which is sound for the callers this package serves — the value a construction
    produces can only reach a callee position through a position the tampering enumeration reads,
    so an unrecognized spelling costs recall there and never a site.

    *eval_string* resolves a computed key the model cannot read by folding; a caller with no folder
    passes `None` and every unresolvable key answers `None` — undecided. *read_effect* rejects a
    navigation base whose evaluation fires an effect; without it more bases read as side-effect
    free, which recognizes more constructions and never fewer. *positioned_value* resolves the two
    alias hops with the read's position supplied — the value the name holds at the moment it is
    read (`TamperingModel.singular_value_at`), so a binding the program-wide volatility question
    refuses can still answer where ordering proves the read safe. It is asked only where
    `SemanticModel.singular_value` has no value, so every verdict the stock sequence already gives
    is kept and the repair recognizes only what stock declines; on that path the member hop's
    establishment question is answered by the query's own leg — the same
    `SemanticModel.binding_establishment_sites` rules — and the stock
    `DominanceModel.binding_established_before` call runs only beside the stock value.
    """

    def resolved_member(member: JsMemberExpression) -> bool | None:
        if model.scope_of(member) is None:
            return None
        if _static_member_key(member) is None:
            if member.computed:
                key = eval_string(member.property) if eval_string is not None else None
                if key != 'constructor':
                    return None
            else:
                return False
        base = strip_parens(member.object)
        if not isinstance(base, JsIdentifier) or base.name in spliced_names:
            return False
        if model.scope_of(base) is None:
            return None
        binding = model.resolve(base)
        if binding is None:
            return False
        value = model.singular_value(binding)
        if value is None and positioned_value is not None:
            value = positioned_value(binding, base)
            if value is not None:
                return isinstance(value, FUNCTION_NODES) and not wraps_return(value)
        if not isinstance(value, FUNCTION_NODES) or wraps_return(value):
            return False
        return dominance.binding_established_before(binding, member)

    expr = strip_parens(callee)
    if expr is None or depth > _CONSTRUCTOR_ALIAS_LIMIT:
        return None
    if isinstance(expr, JsIdentifier):
        if expr.name in spliced_names:
            return False
        if model.scope_of(expr) is None:
            return None
        binding = model.resolve(expr)
        if binding is None:
            return expr.name == 'Function' and not model.read_has_dynamic_effect(expr)
        if effects.global_key_written('Function', 'constructor'):
            return False
        value = model.singular_value(binding)
        if value is None and positioned_value is not None:
            value = positioned_value(binding, expr)
        if value is None:
            return False
        return denotes_function_intrinsic(
            value, model, effects, dominance,
            eval_string=eval_string, read_effect=read_effect,
            positioned_value=positioned_value,
            spliced_names=spliced_names, depth=depth + 1,
        )
    if effects.global_key_written('Function', 'constructor'):
        return False
    if isinstance(expr, JsMemberExpression):
        return _denotes_function_constructor(expr, read_effect, resolved_member)
    return False


def _denotes_function_constructor(
    expr: JsMemberExpression,
    read_effect: Callable[[Node], bool] | None = None,
    resolved_member: Callable[[JsMemberExpression], bool | None] | None = None,
) -> bool | None:
    """
    Whether *expr* evaluates to the `Function` intrinsic, reached by `.constructor` navigation from
    a side-effect-free base. `Function` is what the reflective `Function("code")` idiom calls, so a
    callee that denotes it under another spelling constructs a function from the same code. Two
    spellings reach it without the model:

        <function literal>.constructor          (a plain function or arrow literal)
        <literal>.constructor.constructor        (any side-effect-free base)

    A plain function or arrow literal's own `.constructor` is `Function`, since every ordinary
    function is an instance of `Function`; an `async` or generator literal is refused, its
    `.constructor` being `AsyncFunction` or `GeneratorFunction`, which build a coroutine or
    generator body rather than the plain function `Function` builds. Any value's
    `.constructor.constructor` is `Function`, because the first hop yields that value's constructor
    — itself a function — whose own `.constructor` is `Function`. Inlining discards the evaluation
    of the base, so it must be side-effect free; a function literal always is, and for the double
    hop *read_effect* rejects a bare-identifier base that resolves through a `with` body's dynamic
    scope (firing a getter or throwing), which the model-free check cannot see.

    The one spelling left is a `.constructor` read whose base is a *name* rather than a literal —
    `f.constructor`, `f[key]` — where only the model can pin the base to one function value and
    only the caller can read the key. That arm is *resolved_member*, a resolver the caller injects
    for exactly those questions, keeping this predicate model-free.
    """
    if _static_member_key(expr) != 'constructor':
        return resolved_member is not None and resolved_member(expr)
    base = strip_parens(expr.object)
    if base is None:
        return False
    if isinstance(base, FUNCTION_NODES):
        return not wraps_return(base)
    if isinstance(base, JsMemberExpression) and _static_member_key(base) == 'constructor':
        inner = base.object
        return inner is not None and side_effect_free(inner, read_effect=read_effect)
    return resolved_member is not None and resolved_member(expr)


class _Flow(NamedTuple):
    """
    The positions a value reaches, as one forward value-flow walk classifies them: the calls and
    constructions that invoke it, and the positions that obtain it where the text alone does not
    say what runs next — an argument, a member store, an array element, an object-literal value, a
    return.
    """
    invocations: list[Node]
    escapes: list[Node]


class TamperingModel:
    """
    The anchored trust oracle for one script, built over a
    `refinery.lib.scripts.js.analysis.model.SemanticModel`, an
    `refinery.lib.scripts.js.analysis.effects.EffectModel`, a
    `refinery.lib.scripts.js.analysis.dominance.DominanceModel`, and the control-flow model the
    cycle questions go through. Ask whether the built-ins are intact at one point with
    `builtins_intact_at`; ask which single value a binding holds at one point with
    `singular_value_at` — the positioned value question the same models answer; ask whether every
    invocation of a function discards its completion value with
    `every_invocation_discards_the_value`. Build through `build_tampering`.
    """

    def __init__(
        self,
        model: SemanticModel,
        effects: EffectModel,
        dominance: DominanceModel,
        control_flow: ControlFlowModel,
        *,
        entrypoint: Callable[[str], bool] | None = None,
    ):
        self.model = model
        self.effects = effects
        self.dominance = dominance
        self._cycles = CycleModel(control_flow)
        self._entrypoint = entrypoint
        self._site_list: list[Node] | None = None
        self._sites_unenumerable = False
        self._program_wide: bool | None = None
        self._reentry_read: bool | None = None
        self._anchor_cache: dict[int, bool] = {}
        self._invocation_cache: dict[int, _Flow] = {}
        self._positioned_cache: dict[tuple[int, int], Node | None] = {}

    def builtins_intact_at(self, anchor: Node) -> bool:
        """
        Whether every built-in is still what the language says at the moment *anchor* is evaluated,
        so a fold or an interpreted execution at that point may trust a name, a prototype, or a
        chain the program-wide questions refuse. The answer is the conjunction of no program-wide
        refusal, every tampering site being guaranteed to run after the anchor, and the anchor
        executing at most once — the conjunct the name does not suggest: a site the anchor's
        re-execution could cross on a second run is a site before it, so a call inside a loop or a
        twice-called function is refused wherever a site exists at all. With no sites there is
        nothing to cross and the answer is `True` without the multiplicity walk.
        """
        cached = self._anchor_cache.get(id(anchor))
        if cached is None:
            cached = self._compute_intact(anchor)
            self._anchor_cache[id(anchor)] = cached
        return cached

    def _compute_intact(self, anchor: Node) -> bool:
        if not self._program_is_clear():
            return False
        sites = self._sites()
        if sites is None:
            return False
        sites = [site for site in sites if site is not anchor]
        if not sites:
            return True
        if not self._at_most_once(anchor):
            return False
        return all(self.dominance.runs_before(anchor, site) for site in sites)

    def singular_value_at(self, binding: Binding | None, at: Node) -> Node | None:
        """
        The single value *binding* provably holds at the moment *at* is evaluated —
        `SemanticModel.singular_value` with the position supplied, so a binding the program-wide
        volatility question refuses can still answer where ordering proves the read safe. The value
        is the one channel the text spells, judged by three legs, each asked of every binding the
        query answers:

        1. establishment: the channel's establishing write has run before the read, judged by the
           `SemanticModel.binding_establishment_sites` rules, so a hoisted function declaration
           needs no ordering;
        2. hazards: every dynamic rebind the located question
           (`SemanticModel.binding_dynamic_rebind_sites`) finds first-executes after the read;
        3. multiplicity: the read executes at most once (`_at_most_once`), since ordering first
           executions does not bound what a read on a cycle sees on its second one.

        The channels and their completeness are read on the ignore view
        (`binding_values` with *ignore_dynamic_rebinds*), the one where a rebind is a located
        hazard rather than a program-wide refusal. A script-scope binding fails closed as leg 2's
        own case: its eval-surface hazards are the whole-program questions the volatility boolean
        already refuses to freeze it on. `None` whenever any leg fails, the binding holds no
        single spelled value, or its only incompleteness is the nodeless entry write. Memoized per
        (binding, read) for the model's lifetime, exactly as the site enumeration is — the
        recognizer asks the same hops from the site enumeration and the flow walk.
        """
        if binding is None:
            return None
        key = (id(binding), id(at))
        if key not in self._positioned_cache:
            self._positioned_cache[key] = self._compute_singular_value_at(binding, at)
        return self._positioned_cache[key]

    def _compute_singular_value_at(self, binding: Binding, at: Node) -> Node | None:
        owner = binding.scope.var_scope
        if owner is None or owner.kind is ScopeKind.SCRIPT:
            return None
        values, complete = self.model.binding_values(
            binding, ignore_dynamic_rebinds=True)
        establishment = self.model.binding_establishment_sites(
            binding, ignore_dynamic_rebinds=True)
        if not complete or establishment is None or len(values) != 1:
            return None
        hazards = self.model.binding_dynamic_rebind_sites(binding)
        if hazards is None or not self._at_most_once(at):
            return None
        if not all(self.dominance.runs_before(site, at) for site in establishment):
            return None
        if not all(self.dominance.runs_before(at, hazard) for hazard in hazards):
            return None
        return values[0]

    def _program_is_clear(self) -> bool:
        """
        Whether the program holds nothing that cannot be ordered against an anchor: no static
        import declaration, no `with` statement, and no span of source the model never read. Each
        of these may rebind or invoke anything at a point no dominance question places, so their
        presence refuses every anchor rather than degrading to an ordering that cannot hold.
        """
        if self._program_wide is None:
            self._program_wide = not any(
                isinstance(node, (JsImportDeclaration, JsWithStatement)) or is_unread_source(node)
                for node in self.model.root.walk()
            )
        return self._program_wide

    def _at_most_once(self, anchor: Node) -> bool:
        """
        Whether *anchor* executes at most once: its own control-flow node is off a cycle, and
        every activation up to the script root is invoked at most once — exactly one
        alias-resolved invocation site, off a cycle, not lexically inside the function it invokes.
        A potential `callee`/`caller` read anywhere breaks it (self-reference no textual count
        sees), and so does an activation the host may invoke freely or that reflective code in its
        own scope could re-invoke by name.
        """
        if self._has_reentry_read():
            return False
        located = self.dominance.locate(anchor)
        if located is None:
            return False
        if self._cycles.on_a_cycle(located[0], located[1]):
            return False
        function = enclosing_function(anchor)
        seen: set[int] = set()
        while function is not None:
            if id(function) in seen:
                return False
            seen.add(id(function))
            flow = self._invocations_of(function)
            if flow.escapes or len(flow.invocations) != 1:
                return False
            point = flow.invocations[0]
            if enclosing_function(point) is function:
                return False
            if not self._invocation_is_singly_executed(function, point):
                return False
            function = enclosing_function(point)
        return True

    def _invocation_is_singly_executed(self, function: Node, point: Node) -> bool:
        """
        Whether the one invocation *point* of *function* runs its callee at most once: the point's
        own node is off a cycle, and the activation is not one the host or reflective code may
        invoke freely.
        """
        if not self._invocation_enumeration_is_complete(function):
            return False
        located = self.dominance.locate(point)
        return located is not None and not self._cycles.on_a_cycle(located[0], located[1])

    def _invocation_enumeration_is_complete(self, function: Node) -> bool:
        """
        Whether nothing can run *function* through a channel the invocation enumeration never saw:
        a host entrypoint pattern, a script-scope name under any opaque surface (executable text in
        the global scope can re-invoke it by name), or a function-local name reflection can reach in
        its own scope. A function whose enumeration is complete is one whose listed invocations are
        every way its body runs.
        """
        binding = self.model.invocation_binding(function)
        if binding is None:
            return True
        if self._entrypoint is not None and self._entrypoint(binding.name):
            return False
        owner = binding.scope.var_scope
        if owner is None or owner.kind is ScopeKind.SCRIPT:
            return not self.model.has_reflection_surface()
        return not self.model.reflection_can_reach(binding)

    def every_invocation_discards_the_value(
        self, function: Node, value_discarded: Callable[[Node], bool],
    ) -> bool:
        """
        Whether every invocation of *function* throws its completion value away, judged by the
        forward value-flow enumeration `_invocations_of` reads: a position the value reaches without
        being invoked — an argument, a store, a return — could hand it to a reader, so one such
        escape refuses the answer, as does a function the text never invokes at all (an entrypoint
        or dead code, neither of which this model can pin). *value_discarded* classifies each
        invocation position, the caller's own reading of the positions it knows; no invocation, or
        one whose value a caller of this method would keep, answers `False`.

        The enumeration must also be complete — nothing may run *function* outside the invocations
        it listed, since a host or reflective caller could read what every listed one discards.
        Multiplicity is deliberately absent: a value discarded at every invocation is discarded at
        each of them however often they run.
        """
        flow = self._invocations_of(function)
        if flow.escapes or not flow.invocations:
            return False
        if not self._invocation_enumeration_is_complete(function):
            return False
        return all(value_discarded(point) for point in flow.invocations)

    def _invocations_of(self, function: Node) -> _Flow:
        """
        The positions *function*'s value reaches: the reads of the name it is invoked through, or
        the function node itself when no name pins it — the immediate-invocation form. Memoized per
        function; the reads are model facts, fixed for the model's lifetime.
        """
        cached = self._invocation_cache.get(id(function))
        if cached is None:
            binding = self.model.naming_binding(function)
            frontier = list(binding.reads) if binding is not None else [function]
            cached = self._flow(frontier, through_constructions=False)
            self._invocation_cache[id(function)] = cached
        return cached

    def _has_reentry_read(self) -> bool:
        if self._reentry_read is None:
            self._reentry_read = any(
                isinstance(node, JsMemberExpression) and _may_read_reentry_key(node, self.model)
                for node in self.model.root.walk()
            )
        return self._reentry_read

    def _flow(self, frontier: list[Node], *, through_constructions: bool) -> _Flow:
        """
        The one forward value-flow walk: every position that obtains a value the walk follows. The
        positions are read the same way whichever value is flowing — the callee of a call or `new`
        invokes it, the initializer of a declarator or `=` assignment stores it in a name whose
        reads the walk follows, an expression statement drops it, and any other position escapes —
        with one variation: a value that flows into the callee of a recognized *construction* is
        built with rather than invoked, so the walk continues from that call's result instead of
        recording an invocation.

        *frontier* holds the nodes whose positions the walk starts from — the reads of a binding,
        or a value expression. A binding the walk follows must have its reads enumerable: dynamic
        references a `with` body records, or a write nothing attributes, make the flow escape
        rather than guess at what runs.
        """
        invocations: list[Node] = []
        escapes: list[Node] = []
        pending = list(frontier)
        visited: set[int] = set()
        while pending:
            node = pending.pop()
            if id(node) in visited:
                continue
            visited.add(id(node))
            cursor = node
            parent = cursor.parent
            while isinstance(parent, JsParenthesizedExpression):
                cursor = parent
                parent = cursor.parent
            if parent is None:
                escapes.append(node)
                continue
            if (
                isinstance(parent, (JsCallExpression, JsNewExpression))
                and parent.callee is cursor
            ):
                if (
                    through_constructions
                    and denotes_function_intrinsic(
                        parent.callee, self.model, self.effects, self.dominance,
                        positioned_value=self.singular_value_at,
                    ) is True
                ):
                    pending.append(parent)
                    continue
                invocations.append(parent)
                continue
            reads = self._stored_reads(parent, cursor)
            if reads is None:
                escapes.append(node)
            else:
                pending.extend(reads)
        return _Flow(invocations, escapes)

    def _stored_reads(
        self, parent: Node, node: Node,
    ) -> list[Node] | None:
        """
        The reads of the binding *node* is stored into by *parent* — a declarator initializer or
        the right side of an `=` assignment — or `None` when *node*'s position neither stores it in
        a name nor drops it as an expression statement, so the value escapes the walk's reading. A
        binding with dynamic references or an unattributed write also escapes: its reads do not
        enumerate what could invoke the value.
        """
        target: JsIdentifier | None = None
        if isinstance(parent, JsVariableDeclarator) and parent.init is node:
            if isinstance(parent.id, JsIdentifier):
                target = parent.id
        elif (
            isinstance(parent, JsAssignmentExpression)
            and parent.operator == '='
            and parent.right is node
        ):
            stripped = strip_parens(parent.left)
            if isinstance(stripped, JsIdentifier):
                target = stripped
        elif isinstance(parent, JsExpressionStatement):
            return []
        else:
            return None
        if target is None:
            return None
        binding = self.model.lookup(target.name, self.model.scope_of(target))
        if binding is None or binding.dynamic_refs or binding.has_indefinite_write:
            return None
        return list(binding.reads)

    def _may_be_global_object(self, node: Node | None) -> bool:
        """
        Whether *node* may be the global object once the program runs —
        `SemanticModel.may_be_the_global_object` — widened by the one case the model cannot answer:
        a node it never placed, spliced into the tree after the model was built. Such a node is
        treated as may-be-global, the fail-closed direction that keeps a spliced base a site.
        """
        if node is None:
            return False
        if self.model.scope_of(node) is None:
            return True
        return self.model.may_be_the_global_object(node)

    def _sites(self) -> list[Node] | None:
        """
        Every point in the program at which a built-in may be replaced or executed code may run,
        or `None` when that cannot be enumerated — the hand-over of the global object to a callee
        that may write it, a fact with no site to order. Computed once over the model's facts and
        memoized; the anchor's own call node is excluded by the caller, its rebind routes owned by
        the gates of the execution that asked.
        """
        if self._sites_unenumerable:
            return None
        if self._site_list is not None:
            return self._site_list
        if self.model.has_opaque_global_write() and self.model.opaque_global_write_sites() is None:
            self._sites_unenumerable = True
            return None
        sites: list[Node] = []
        root = self.model.root
        for member in root.walk():
            if not isinstance(member, JsMemberExpression):
                continue
            if not member.computed or isinstance(member.property, JsStringLiteral):
                continue
            if not is_member_write_target(member):
                continue
            if self._may_be_global_object(member.object):
                sites.append(member)
        for node in root.walk():
            if not isinstance(node, (JsCallExpression, JsNewExpression)):
                continue
            if any(
                self._may_be_global_object(argument)
                for argument in node.arguments
            ):
                sites.append(node)
        for site in self.model.opaque_reflection_sites():
            sites.extend(self._surface_sites(site))
        for node in root.walk():
            if not isinstance(node, (JsCallExpression, JsNewExpression)):
                continue
            verdict = denotes_function_intrinsic(
                node.callee, self.model, self.effects, self.dominance,
                positioned_value=self.singular_value_at,
            )
            if verdict is True:
                flow = self._flow([node], through_constructions=True)
                sites.extend(flow.invocations)
                sites.extend(flow.escapes)
            elif verdict is None:
                sites.append(node)
        self._site_list = sites
        return sites

    def _surface_sites(self, site: Node) -> list[Node]:
        """
        The sites an opaque reflective surface implies. A dynamic `import()` and a string timer run
        code at their own node; every other surface is a value-read of a reflective intrinsic, so
        the sites are the positions that value reaches — its invocations and escapes, by the one
        forward walk. A read of `eval` invokes the code it is handed, while a read of `Function`
        builds with it and the walk continues through the construction; a computed read on the
        global object names an unknown global and is followed without the construction
        continuation, so a call it flows into is a site at that call.
        """
        if isinstance(site, (JsImportExpression, JsCallExpression)):
            return [site]
        through_constructions = True
        if isinstance(site, JsMemberExpression):
            key = member_property_name(site)
            through_constructions = key != 'eval'
        elif isinstance(site, JsIdentifier):
            through_constructions = site.name != 'eval'
        elif isinstance(site, (JsVariableDeclarator, JsAssignmentExpression)):
            flows: list[_Flow] = []
            for name, follows_construction in self._destructured_reflective_names(site):
                binding = self._destructured_binding(site, name)
                if binding is None:
                    return [site]
                flows.append(self._flow(list(binding.reads), through_constructions=follows_construction))
            return [
                position
                for flow in flows
                for position in (*flow.invocations, *flow.escapes)
            ]
        else:
            return [site]
        flow = self._flow([site], through_constructions=through_constructions)
        return [*flow.invocations, *flow.escapes]

    def _destructured_reflective_names(
        self, site: JsVariableDeclarator | JsAssignmentExpression,
    ) -> list[tuple[str, bool]]:
        """
        The reflective-intrinsic names an object pattern binds out of a source that may be the
        global object, each paired with whether its read builds rather than invokes — `Function`
        builds, `eval` runs. `const {eval} = globalThis` is the same value-read of the intrinsic
        the bare name spells, so it starts the same walk.
        """
        if isinstance(site, JsVariableDeclarator):
            pattern, source = site.id, site.init
        else:
            pattern, source = site.left, site.right
        if not isinstance(pattern, JsObjectPattern):
            return []
        if not self._may_be_global_object(source):
            return []
        names: list[tuple[str, bool]] = []
        for prop in pattern.properties:
            if not isinstance(prop, JsProperty) or prop.computed:
                continue
            key = prop.key
            name = (
                key.value if isinstance(key, JsStringLiteral) else (
                    key.name if isinstance(key, JsIdentifier) else None)
            )
            if name in REFLECTIVE_INTRINSICS:
                names.append((name, name != 'eval'))
        return names

    def _destructured_binding(
        self, site: JsVariableDeclarator | JsAssignmentExpression, name: str,
    ) -> Binding | None:
        """
        The binding the name *name* of a destructuring at *site* reads into: the binding its
        pattern position declares for a declarator, or resolves for an assignment pattern. `None`
        when the model places no binding for it.
        """
        if isinstance(site, JsVariableDeclarator):
            for prop in _pattern_properties(site.id):
                value = prop.value
                if isinstance(value, JsIdentifier) and value.name == name:
                    return self.model.binding_of(value)
            return None
        for prop in _pattern_properties(site.left):
            value = prop.value
            if isinstance(value, JsIdentifier) and value.name == name:
                return self.model.resolve(value)
        return None


def _pattern_properties(pattern: Node) -> list[JsProperty]:
    if not isinstance(pattern, JsObjectPattern):
        return []
    return [prop for prop in pattern.properties if isinstance(prop, JsProperty)]


def build_tampering(
    model: SemanticModel,
    effects: EffectModel,
    dominance: DominanceModel,
    control_flow: ControlFlowModel,
    *,
    entrypoint: Callable[[str], bool] | None = None,
) -> TamperingModel:
    """
    Build the `TamperingModel` for a script's analysis models, reusing *dominance* and
    *control_flow* the caller already holds. *entrypoint* reports whether a name matches a host
    entrypoint pattern, so the multiplicity guard can refuse an activation the host may invoke an
    unbounded number of times.
    """
    return TamperingModel(model, effects, dominance, control_flow, entrypoint=entrypoint)
