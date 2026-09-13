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
)
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
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


def denotes_function_intrinsic(
    callee: Node | None,
    model: SemanticModel,
    effects: EffectModel,
    dominance: DominanceModel,
    *,
    eval_string: Callable[[Node | None], str | None] | None = None,
    read_effect: Callable[[Node], bool] | None = None,
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
    free, which recognizes more constructions and never fewer.
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
        if value is None:
            return False
        return denotes_function_intrinsic(
            value, model, effects, dominance,
            eval_string=eval_string, read_effect=read_effect,
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
    The anchored tampering oracle for one script, built over a
    `refinery.lib.scripts.js.analysis.model.SemanticModel`, an
    `refinery.lib.scripts.js.analysis.effects.EffectModel`, a
    `refinery.lib.scripts.js.analysis.dominance.DominanceModel`, and the control-flow model the
    cycle questions go through. Ask whether the built-ins are intact at one point with
    `builtins_intact_at`. Build through `build_tampering`.
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
        invoke freely — a host entrypoint pattern, a script-scope name under any opaque surface
        (executable text in the global scope can re-invoke it by name), or a function-local name
        reflection can reach in its own scope.
        """
        binding = self.model.invocation_binding(function)
        if binding is not None:
            if self._entrypoint is not None and self._entrypoint(binding.name):
                return False
            owner = binding.scope.var_scope
            if owner is None or owner.kind is ScopeKind.SCRIPT:
                if self.model.has_reflection_surface():
                    return False
            elif self.model.reflection_can_reach(binding):
                return False
        located = self.dominance.locate(point)
        return located is not None and not self._cycles.on_a_cycle(located[0], located[1])

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
                isinstance(node, JsMemberExpression)
                and not node.computed
                and isinstance(node.property, JsIdentifier)
                and node.property.name in _REENTRY_KEYS
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
                        parent.callee, self.model, self.effects, self.dominance)
                    is True
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
            verdict = denotes_function_intrinsic(node.callee, self.model, self.effects, self.dominance)
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
