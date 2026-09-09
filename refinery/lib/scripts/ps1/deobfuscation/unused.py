"""
Remove unused variable assignments and junk expression statements.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.ps1.analysis.cache import model_cache
from refinery.lib.scripts.ps1.analysis.callgraph import Ps1CallGraph
from refinery.lib.scripts.ps1.analysis.effects import (
    OutputSink,
    StatementEffect,
    body_is_inert,
    expression_cannot_fault,
    is_side_effect_free,
    opens_a_redirection_target,
    output_path,
    pruning_erases_body,
    statement_effect,
    unconsumed_statement,
)
from refinery.lib.scripts.ps1.analysis.faults import Ps1FaultReach
from refinery.lib.scripts.ps1.analysis.model import Binding, Ps1SemanticModel, Scope
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach
from refinery.lib.scripts.ps1.ast import (
    assignment_of,
    assignment_target_is_all_variables,
    assignment_target_variables,
    fault_operand,
    get_body,
    normalize_command_name,
)
from refinery.lib.scripts.ps1.deobfuscation.constants import (
    _PS1_SKIP_VARIABLES,
    _find_removable_statement,
)
from refinery.lib.scripts.ps1.deobfuscation.helpers import store_dropped_to_value
from refinery.lib.scripts.ps1.deobfuscation.removal import Ps1RemovalPlan, Ps1RemovalPlans
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AssignmentExpression,
    Ps1ExpressionStatement,
    Ps1ForLoop,
    Ps1FunctionDefinition,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1UnaryExpression,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.options import bare_output_is_preserved


def _writes_only_what_cannot_fault(
    stmt: Node,
    faults: Ps1FaultReach,
    world: Ps1WorldReach,
) -> bool:
    """
    Whether a statement writes a value to the output stream and can do nothing else — not even
    raise. `refinery.lib.scripts.ps1.analysis.effects.StatementEffect.OUTPUT` says the first half
    and deliberately says nothing about the second, so a caller about to delete such a statement
    asks the fault question here.

    It is the same question `refinery.lib.scripts.ps1.analysis.effects.fault_is_observed` asks of a
    `DISCARD`, and it goes through the same gate *over the same operand* for that reason: a bare
    `$x` answered fault-free at one of the two sites and not at the other would be deleted as a
    discard and kept as an output in one script, and so would one the two sites disagreed about
    which expression to weigh. `refinery.lib.scripts.ps1.ast.fault_operand` is that
    one reading, and it answers `None` for a statement that is not one expression.
    """
    operand = fault_operand(stmt)
    return operand is not None and expression_cannot_fault(operand, stmt, faults, world)


class _MutationEdit(NamedTuple):
    """
    One intended edit to a dead store: the statement to be removed, and the right-hand side that has
    to be kept as a discard because evaluating it does something, or `None` when it does not.
    """
    statement: Node
    keep_value: Expression | None


def _value_is_movable(rhs: Node) -> bool:
    """
    Whether a dead store's right-hand side can be kept as a statement of its own.

    A right-hand side that is a *statement* rather than an expression — `$x = if ($c) { ... }`, and
    the `switch`/`foreach`/`while`/`try` forms beside it, all legal assignment sources — has no
    expression-statement spelling to be moved into, so the whole assignment stays. Removing it
    instead would take the branch bodies with it.

    Both passes that drop a dead store share this, rather than each spelling the rule: the two
    outcomes are keep-the-value and keep-the-statement, and a pass that learned only one of them
    would delete what the other keeps.
    """
    return isinstance(rhs, Expression)


class Ps1UnusedVariableRemoval(Transformer):
    """
    Remove assignments to variables that are never read anywhere in the outer scope. Liveness comes
    from the shared `refinery.lib.scripts.ps1.analysis.model.Ps1SemanticModel`, so a read that
    reaches the assignment through a nested function, a captured scriptblock, or a scope qualifier
    keeps it alive. When the right-hand side of a removable assignment has side effects, the
    assignment wrapper is stripped but the expression is preserved as a standalone statement.
    """

    def visit(self, node: Node):
        """
        Plan every candidate edit, ask the batch what it would accept, and only then decide which
        bindings are dead.

        The order matters and used to run the other way. A binding is dead because its every read
        sits inside a right-hand side that is going away, so liveness is *restrictive* in the
        survivor set and has to be asked of what the batch will actually do — see
        `refinery.lib.scripts.ps1.deobfuscation.removal.Ps1RemovalPlan.accepted`. Two things keep a
        right-hand side standing, and neither is visible before the edits are planned: a value that
        does something survives as `$Null = <value>`, and a statement the fault veto declines to
        delete survives whole. Deciding first and planning afterwards read both as erased and
        deleted the assignment the surviving read needs.

        Planning up front means the replacements exist before the batch is known to land, which
        costs this pass nothing: registering one gives back whatever it adopted, so the tree the
        liveness question is asked of is the tree as written, and a batch that ends in `abandon` —
        or is simply dropped — owes it nothing.
        """
        cache = model_cache(self, node)
        model = cache.model
        world = cache.world_reach
        candidates: dict[Binding, list[Node]] = {}
        for binding in model.script_scope.bindings.values():
            if binding.dynamic_or_qualified or binding.name in _PS1_SKIP_VARIABLES:
                continue
            mutations = self._removable_mutations(binding)
            if mutations:
                candidates[binding] = mutations
        if not candidates:
            return None
        plans = Ps1RemovalPlans(cache.faults, world, cache.error_state)
        planned: dict[int, _MutationEdit] = {}
        installed: set[int] = set()
        claimed: set[int] = set()
        for mutations in candidates.values():
            for mutation in mutations:
                if id(mutation) in planned:
                    continue
                edit = self._plan_mutation(mutation, world)
                if edit is None or id(edit.statement) in claimed:
                    continue
                replacement = None
                if edit.keep_value is not None:
                    replacement = [store_dropped_to_value(edit.keep_value)]
                if plans.propose(edit.statement, replacement):
                    claimed.add(id(edit.statement))
                    planned[id(mutation)] = edit
                    if replacement is not None:
                        installed.update(id(stmt) for stmt in replacement)
        accepted = {id(statement) for statement in plans.accepted}
        dissolving = {
            key for key, edit in planned.items()
            if edit.keep_value is None and id(edit.statement) in accepted
        }
        dead = self._dead_bindings(candidates, dissolving)
        removable = self._removable_statements(candidates, dead, model) if dead else []
        keep = {id(mutation) for mutation in removable}
        for key, edit in planned.items():
            if key not in keep:
                plans.withdraw(edit.statement)
        if not removable:
            plans.abandon()
            return None
        if get_body(node) is not None and not self._leaves_anything(plans, node, installed):
            plans.abandon()
            return None
        if plans.commit():
            self.mark_changed()

    @staticmethod
    def _leaves_anything(plans: Ps1RemovalPlans, node: Node, installed: set[int]) -> bool:
        """
        Whether the script still says something of its own once this batch lands.

        A pass may not reduce a whole script to nothing, for the reason `_remove_inert_functions`
        spells out: what is left would be a module whose callers the walk never read, and the
        definitions that would prove it live are exactly what is out of reach. Definitions are
        therefore not survivors here.

        Neither is a `$Null = <value>` discard this pass is installing. It preserves a side effect
        and it is genuinely observable, but it is **this pass's own residue**, and a guard against
        erasure that counts its own output as proof it erased nothing answers itself. A script
        reduced to nothing but discards has had everything it said deleted; that the deletions left
        husks behind is not evidence to the contrary.
        """
        surviving = plans.survivors(node)
        return any(
            not isinstance(stmt, Ps1FunctionDefinition) and id(stmt) not in installed
            for stmt in surviving
        )

    @staticmethod
    def _removable_mutations(binding: Binding) -> list[Node]:
        """
        The removable mutation nodes that write `binding`: a bare (unqualified) or `$env:`
        assignment or a `++`/`--` update. A parameter or `foreach` loop variable writes the binding
        but is not a removable mutation, and a scope-qualified write (`$script:x = ...`) is never
        removed, so both are excluded.
        """
        mutations: list[Node] = []
        seen: set[int] = set()
        for write in binding.writes:
            var = write.node
            if not isinstance(var, Ps1Variable):
                continue
            if var.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.ENV):
                continue
            mutation = Ps1UnusedVariableRemoval._mutation_of(var)
            if mutation is not None and id(mutation) not in seen:
                seen.add(id(mutation))
                mutations.append(mutation)
        return mutations

    @staticmethod
    def _mutation_of(var: Ps1Variable) -> Node | None:
        """
        The node this pass would remove to undo the write `var` performs, or `None` when the write
        is one it cannot remove.

        A `[ref]$x` is such a write and must stay `None`: the store happens inside a callee, so
        there is nothing here to delete, and the enclosing call is not this pass's to touch. That
        also makes the reference a use nothing discounts, which is what keeps the assignment it
        stores into alive.
        """
        assignment = assignment_of(var)
        if assignment is not None:
            return assignment
        parent = var.parent
        if isinstance(parent, Ps1UnaryExpression) and parent.operator in ('++', '--'):
            if parent.operand is var:
                return parent
        return None

    def _dead_bindings(
        self, candidates: dict[Binding, list[Node]], dissolving: set[int],
    ) -> list[Binding]:
        """
        From candidate bindings mapped to their removable mutations, return those that are dead. A
        binding is live if it has a use not contained in the right-hand side of any *dissolving*
        assignment — a use in live code, in a live function, or a captured scriptblock. Liveness
        propagates back along right-hand sides: if a live binding's assignment reads another
        candidate, that candidate is live too. The rest, whose every read sits inside the right-hand
        side of an assignment that is itself dead, are dead — removing those assignments removes the
        reads, so nothing observes the value.

        `dissolving` holds the mutations whose planned edit really does take their right-hand side
        with it. A right-hand side that survives — as the value of a `$Null = <value>` discard, or
        because the fault veto declined to delete the whole statement — still holds its reads, so
        the bindings they name stay live and their own assignments stay. Reading every candidate as
        dissolving is what left `$Null = Start-Process -FilePath $a` beside no `$a`.

        The veto is not the only thing that keeps an assignment standing, so this asks the same
        question `_all_targets_dead` asks. A target such as `$a, $arr[0]` names exactly one variable
        and is still never removable, because the slot beside it writes memory this pass reasons
        nothing about; a right-hand side that is only ever going away when that binding dies is a
        right-hand side that is never going away at all.

        The uses are `Binding.uses`, not `Binding.reads`: a write that observes the previous value
        reads the binding as surely as anything in `reads` and is filed among the writes. Such a use
        is discounted when the mutation performing it is itself dissolving, on the same reasoning as
        a read inside a dissolving right-hand side — the store consumes the read, so removing the
        store removes the read, and `$x = 1; $x += 2` that nothing else reads is dead whole. A
        `[ref]$x` has no mutation this pass can remove, so it is never discounted and always keeps
        its binding live.
        """
        bindings = list(candidates)
        rhs_owner: dict[int, Binding] = {}
        for binding, mutations in candidates.items():
            for mutation in mutations:
                if id(mutation) not in dissolving:
                    continue
                if not isinstance(mutation, Ps1AssignmentExpression) or mutation.value is None:
                    continue
                if not assignment_target_is_all_variables(mutation.target):
                    continue
                if len(assignment_target_variables(mutation.target)) == 1:
                    rhs_owner[id(mutation.value)] = binding
        readers: dict[Binding, set[Binding]] = {binding: set() for binding in bindings}
        live: set[Binding] = set()
        for binding in bindings:
            for use in binding.uses:
                mutation = self._mutation_of(use.node)
                if mutation is not None and id(mutation) in dissolving:
                    continue
                owner = self._covering_owner(use.node, rhs_owner)
                if owner is None or owner is binding:
                    live.add(binding)
                else:
                    readers[binding].add(owner)
        changed = True
        while changed:
            changed = False
            for binding in bindings:
                if binding not in live and readers[binding] & live:
                    live.add(binding)
                    changed = True
        return [binding for binding in bindings if binding not in live]

    @staticmethod
    def _covering_owner(node: Node, rhs_owner: dict[int, Binding]) -> Binding | None:
        """
        The candidate binding whose assignment right-hand side encloses *node*, taken at the
        outermost such right-hand side, or `None` when *node* lies outside every candidate
        right-hand side.
        """
        owner: Binding | None = None
        cursor: Node | None = node
        while cursor is not None:
            found = rhs_owner.get(id(cursor))
            if found is not None:
                owner = found
            cursor = cursor.parent
        return owner

    def _removable_statements(
        self, candidates: dict[Binding, list[Node]], dead: list[Binding], model: Ps1SemanticModel,
    ) -> list[Node]:
        dead_set = set(dead)
        removable: list[Node] = []
        seen: set[int] = set()
        for binding in dead:
            for mutation in candidates[binding]:
                if id(mutation) in seen:
                    continue
                if (
                    isinstance(mutation, Ps1AssignmentExpression)
                    and not self._all_targets_dead(mutation, model, dead_set)
                ):
                    continue
                seen.add(id(mutation))
                removable.append(mutation)
        return removable

    @staticmethod
    def _all_targets_dead(
        assign: Ps1AssignmentExpression, model: Ps1SemanticModel, dead: set[Binding],
    ) -> bool:
        """
        Whether every variable written by `assign` is dead. A multi-assignment such as
        `$a, $b = 1, 2` is only removable when all of its targets are dead; removing it while a
        co-target is still live would destroy that live write. A target that contains a non-variable
        slot (e.g. `$arr[0], $b`) writes to memory beyond the named variables and is never
        considered fully dead.
        """
        if not assignment_target_is_all_variables(assign.target):
            return False
        variables = assignment_target_variables(assign.target)
        if not variables:
            return False
        for var in variables:
            binding = model.binding_of(var)
            if binding is None or binding not in dead:
                return False
        return True

    @staticmethod
    def _plan_mutation(mutation: Node, world: Ps1WorldReach) -> _MutationEdit | None:
        """
        What this pass intends to do with the statement holding `mutation`, decided without touching
        the tree: the statement to edit, and the right-hand side that has to survive the edit, or
        `None` where the store can go whole.

        Deciding before building matters because the caller may still abandon the batch. Whether the
        value can be moved is therefore answered here, by `_value_is_movable`, rather than by trying
        to build the replacement and reading the failure.
        """
        keep_value = None
        if isinstance(mutation, Ps1AssignmentExpression):
            rhs = mutation.value
            if rhs is not None and not is_side_effect_free(rhs, world):
                if not _value_is_movable(rhs):
                    return None
                keep_value = rhs
        elif not isinstance(mutation, Ps1UnaryExpression):
            return None
        stmt = _find_removable_statement(mutation)
        if stmt is None:
            return None
        return _MutationEdit(stmt, keep_value)


class Ps1JunkStatementRemoval(Transformer):
    """
    Remove standalone expression statements that produce no observable side effects (junk/noise
    injected for anti-analysis) and function definitions that are never called.
    """

    def visit(self, node: Node):
        """
        Decide the whole batch, then apply it once.

        **Two different sinks are read here and they answer two different questions.** Whether a
        body may be reasoned about at all is positional: `output_path` calls a stored closure or a
        `$( ... )` opaque, and this pass has never touched one. Whether a *write to the output
        stream* inside it may be deleted needs the destination that write reaches, which position
        cannot supply for a function body, so `Ps1OutputFlow` resolves it across the call graph.

        One outward walk answers both. The positional `Ps1OutputPath` is what the resolution reads,
        so asking the two questions separately walked every ancestor chain twice for one answer.

        Collapsing the two costs recall and did: a body the flow reports captured — a function whose
        result someone stores — still holds `$Null = 1` discards that write nothing at all, and
        skipping it over the output question left them standing.
        """
        cache = model_cache(self, node)
        flow = cache.output_flow
        called = cache.call_graph.reachable_names()
        # A name used before it is defined denotes, at that use, whatever bound it earlier rather
        # than the body written below — nothing, at script scope, where the bare word raises a
        # non-terminating CommandNotFoundException and the run carries on to the body below. Such a
        # function is not this pass's to reason about: pruning its body or deleting it with the
        # calls that never reach it erases the error the earlier call raised.
        unreached = cache.used_before_defined
        plans = Ps1RemovalPlans(cache.faults, cache.world_reach, cache.error_state)
        for parent in node.walk():
            body = get_body(parent)
            if body is None:
                continue
            if self._within_unreached_function(parent, unreached):
                continue
            path = output_path(parent)
            if path.sink is OutputSink.CAPTURED:
                continue
            removable = self._removable_in_body(
                parent, flow.resolved(path), path.guarded, called, cache.world_reach, cache.faults)
            for statement in body:
                if statement in removable:
                    plans.propose_in(parent, statement)
        if plans.commit():
            self.mark_changed()
        # A fresh world after the commit, not the one the loop read: the commit advanced the tree
        # version, so a held world would answer at its fail-closed pole for every function this
        # walk still has to weigh. The cache rebuilds it only because a removal landed.
        self._remove_inert_functions(node, cache.call_graph, cache.world_reach, unreached)

    @staticmethod
    def _within_unreached_function(node: Node, unreached: frozenset[str]) -> bool:
        """
        Whether `node` sits in the body of a function some call to it does not reach the definition
        of. This pass cannot reason about a name whose calls it cannot place, so the whole subtree
        is left alone — not only the definition statement but the block that holds its statements,
        which the walk reaches as a parent of its own.
        """
        cursor: Node | None = node
        while cursor is not None:
            if (
                isinstance(cursor, Ps1FunctionDefinition)
                and normalize_command_name(cursor.name) in unreached
            ):
                return True
            cursor = cursor.parent
        return False

    def _remove_inert_functions(
        self,
        node: Node,
        graph: Ps1CallGraph,
        world: Ps1WorldReach,
        unreached: frozenset[str],
    ):
        """
        Remove top-level functions whose body carries no observable output or side effect together
        with the bare call statements that invoke them. After body pruning, an injected junk function
        such as `function j { $Null = 915 }` has an empty body; calling it is a no-op, so the
        definition and its call sites drop out as a unit. Only whole-statement, argument-free
        invocations count as call sites — a name referenced any other way is a name whose value
        could be observed.

        A name is inert only when *every* definition of it is, since the calls are attributed to the
        name rather than to one of its definitions: removing them because one definition is empty
        would silence a payload-bearing other one. `Ps1CallGraph` reports every definition, wherever
        it sits, because a `function` inside an `if` or a loop body is written into the enclosing
        scope just the same — while only a top-level definition is itself removable, since a nested
        one is not this pass's to reason about.

        "Every definition" can only mean every definition standing in this tree, so the tree has to
        be the whole story. That is the graph's own `is_readable`, which this pass no longer answers
        for itself: an open world, an opaque dispatch, an identity-namespace assignment and an
        export all bind a name from somewhere the walk cannot read, and the empty body standing here
        is then not the body the call reaches.

        The graph is built in source order, because removal is by identity scan over the containing
        list: taking the reverse order `Node.walk` yields would delete from the back and make every
        scan traverse the whole body.

        Removals are collected before any is applied so that `pruning_erases_body` sees the whole
        set at once. A script of nothing but inert definitions is inert by every measure this pass
        has and still may not be emptied — it is a module whose functions are dot-sourced from a
        caller the walk never read, and the call sites that would prove them live are exactly what
        is out of reach. The same invariant already governs `_removable_in_body`; enforcing it there
        and not here left one removal site able to erase what the other refuses to.

        Only the definitions are weighed against that invariant, because only they are what a
        dot-sourcing caller would come for. A script holding a call site of its own is not the
        module the guard protects — it uses the function here — so `function j { $Null = 1 }` beside
        a bare `j` reduces to nothing, while the same definition standing alone survives.

        `deletion_is_observable` is applied for the same reason it is applied when a body is pruned:
        emptying a `try` body beside a handler that does something is what makes the handler read as
        unreachable. Both removal sites have to answer that question the same way, and this one
        did not.

        A definition and the calls to it are one edit, and they routinely land in *different* plans,
        so no single plan's `all_or_nothing` can hold them together. The batch is therefore planned
        whole and then asked what it would accept: a name any part of which is declined is withdrawn
        entirely, because half the edit is not a smaller edit. Deleting `function j` while a veto
        keeps `try { j }` leaves the script calling a function it no longer defines, and deleting
        the call while the definition is kept leaves a definition the emitted script never reaches.
        The withdrawals are read back to a fixpoint rather than applied once, so a group broken by
        another group's withdrawal is caught too; it terminates because the batch only shrinks.
        `pruning_erases_body` is asked *before* any of this, against the full set, because it is
        permissive in the survivors and a withdrawal is a veto by another name.

        A call site that runs sets `$?`, so removing one is observable to a later read of that
        variable even where the call's own output is not — the exposure
        `Ps1CommandModel.reads_command_success` already answers for the alias drive. A group
        carrying call statements is therefore kept whole where the script reads `$?`; a definition
        alone is transparent to the flag and drops regardless.

        A name in `unreached` is skipped whole: one of its calls stands where the definition is not
        guaranteed to have run, so the calls are not the inert no-ops this removal takes them for —
        see `refinery.lib.scripts.ps1.analysis.callgraph.names_used_before_defined`.
        """
        if not graph.is_readable:
            return
        cache = model_cache(self, node)
        commands = cache.commands
        reads_success = commands.reads_command_success()
        function_reads = commands.function_drive_reads()
        groups: dict[str, list[Node]] = {}
        removable_definitions: set[Node] = set()
        for key in graph.defined_names:
            if key in unreached:
                continue
            if key in function_reads:
                continue
            definitions = graph.definitions(key)
            if not all(body_is_inert(d.body, world) for d in definitions):
                continue
            if not all(body_is_inert(body, world) for body in graph.keyword_definitions(key)):
                continue
            removable_here = [d for d in definitions if d.parent is node]
            if not removable_here:
                continue
            call_statements = self._inert_call_statements(graph, key)
            if call_statements is None:
                continue
            if call_statements and reads_success:
                continue
            groups[key] = [*call_statements, *removable_here]
            removable_definitions.update(removable_here)
        if not groups:
            return
        if get_body(node) is not None:
            survivors = self._survivors(get_body(node), removable_definitions)
            if pruning_erases_body(node, survivors):
                return
        plans = Ps1RemovalPlans(cache.faults, world, cache.error_state)
        for group in groups.values():
            for statement in group:
                plans.propose(statement)
        while True:
            accepted = {id(statement) for statement in plans.accepted}
            broken = [
                key for key, group in groups.items()
                if any(id(statement) not in accepted for statement in group)
            ]
            if not broken:
                break
            for key in broken:
                for statement in groups.pop(key):
                    plans.withdraw(statement)
        if plans.commit():
            self.mark_changed()

    @staticmethod
    def _inert_call_statements(graph: Ps1CallGraph, key: str) -> list[Node] | None:
        """
        The statements that call `key` and nothing else, or `None` when some reference to the name
        is not one — which means the name and every definition of it stay.

        A call site qualifies only when it is argument-free, its value is what the enclosing
        statement yields, and nothing on the way to that statement opens a file. The two redirection
        questions are separate and both have to be asked: `j > out.txt` sends the value somewhere
        the body cannot see it, which `unconsumed_statement` answers, and `j 2> err.txt` sends
        nothing anywhere while still creating the file, which only `opens_a_redirection_target`
        catches. The call is inert either way; the statement around it is not.
        """
        statements: list[Node] = []
        for site in graph.call_sites(key):
            statement = unconsumed_statement(site.invocation)
            if statement is None or site.invocation.arguments:
                return None
            cursor: Node | None = site.invocation
            while cursor is not None and cursor is not statement:
                if opens_a_redirection_target(cursor):
                    return None
                cursor = cursor.parent
            statements.append(statement)
        return statements

    def _removable_in_body(
        self,
        parent: Node,
        sink: OutputSink,
        guarded: bool,
        called: frozenset[str],
        world: Ps1WorldReach,
        faults: Ps1FaultReach,
    ) -> set[Node]:
        """
        What this pass would drop from the statement list `parent` owns, where `sink` is the
        *resolved* destination of what that body writes and `guarded` says that body runs only on a
        fault. Both set-level guards are answered here, against the **pre-veto** survivors, which is
        the polarity they require — see
        `refinery.lib.scripts.ps1.deobfuscation.removal.Ps1RemovalPlan`.

        A `DISCARD` emits nothing wherever the body's output goes, so nothing about the output makes
        one worth keeping and a body of them turns a junk function inert. It is not by itself a
        licence to drop, because emission is all it claims: a call returning `System.Void` emits as
        little as a discard idiom and can still raise, which is the removal veto's to weigh and not
        this. An `OUTPUT` writes a value someone could see, and dropping it needs four separate
        things to hold, none of which implies another:

        - the caller asks for it, which is `bare_output_is_preserved` read the other way round;
        - the value provably reaches the host and nothing else, which is `sink`. A body whose writes
          land anywhere else keeps every one of them — that is the whole of what the resolution
          across the call graph buys, and the reason this is not the positional answer;
        - the body runs on the normal path and not only on a fault, which is `guarded` read the other
          way round. A `trap` or `catch` body's value is console output exactly when the handler
          fires; deleting it as noise drops what the script prints when it recovers from an error;
        - evaluating it cannot raise, which is `expression_cannot_fault`. `[Int]'abc'` and `1/0`
          are `OUTPUT` like `42` is, and both terminate the script where they stand, so deleting one
          resumes execution that had stopped — and does it across a function boundary, where the
          `try` veto in `Ps1RemovalPlan` cannot see.
        """
        body = get_body(parent)
        removable: set[Node] = set()
        strip_bare_output = (
            sink is OutputSink.HOST
            and not guarded
            and not bare_output_is_preserved(self.options)
        )
        for stmt in body:
            if isinstance(stmt, Ps1FunctionDefinition):
                # `called` is every call site standing in this tree, which is only the whole story
                # while the tree is the whole script. When the world is open, a dot-sourced file, an
                # imported module or an `iex` holds call sites the walk never read, so a definition
                # with none here is not unreachable — it is reachable from somewhere unreadable.
                if (
                    isinstance(parent, Ps1Script)
                    and world.closed_for_the_whole_run
                    and normalize_command_name(stmt.name) not in called
                ):
                    removable.add(stmt)
                continue
            effect = statement_effect(stmt, world)
            if effect is StatementEffect.DISCARD:
                removable.add(stmt)
            elif effect is StatementEffect.OUTPUT and strip_bare_output:
                if _writes_only_what_cannot_fault(stmt, faults, world):
                    removable.add(stmt)
        if not removable:
            return set()
        if pruning_erases_body(parent, self._survivors(body, removable)):
            return set()
        return removable

    @staticmethod
    def _survivors(body: list, removable: set[Node]) -> list[Node]:
        return [stmt for stmt in body if stmt not in removable]


class Ps1DeadStoreElimination(Transformer):
    """
    Remove assignments to a variable that are provably overwritten before their next read within the
    same linear scope. This targets the pattern left behind by tier-2 empty-for rewriting: dozens of
    `$i = N` statements followed by a for-loop whose initializer `$i = 0` overwrites them all. Reads
    come from the shared `refinery.lib.scripts.ps1.analysis.model.Ps1SemanticModel`, so a store read
    only through a nested scriptblock is correctly seen as live rather than skipped.
    """

    def visit(self, node: Node):
        cache = model_cache(self, node)
        model = cache.model
        # Model and world are both re-read per body through the version-keyed cache: removing a
        # store changes what the next body's scope says, and once a removal advances the version a
        # held world would answer at its fail-closed pole for the rest of the pass. A body whose
        # removal bumps the version rebuilds both, and a body that removes nothing reads the same
        # cached objects back, so the fresh read costs a rebuild only where the tree actually moved.
        world = cache.world_reach
        body = get_body(node)
        scope = model.scope_of(node)
        if body is None or scope is None:
            self.generic_visit(node)
            return None
        pending: dict[str, list[Ps1ExpressionStatement]] = {}
        dead: list[Ps1ExpressionStatement] = []
        has_read: set[str] = set()
        for stmt in body:
            reads, kills, writes = self._classify_statement(stmt, scope, model)
            for var in kills:
                if var in pending:
                    dead.extend(pending.pop(var))
                has_read.add(var)
            for var in reads:
                pending.pop(var, None)
                has_read.add(var)
            for var, store in writes:
                if var in pending:
                    dead.extend(pending[var])
                pending[var] = [store]
        if isinstance(node, Ps1Script):
            for var, stores in pending.items():
                if var in has_read:
                    dead.extend(stores)
        if not dead:
            self.generic_visit(node)
            return None
        plan = Ps1RemovalPlan(
            node, faults=cache.faults, world=world, error_state=cache.error_state)
        for stmt in dead:
            if not isinstance(stmt, Ps1ExpressionStatement):
                continue
            rhs = stmt.expression
            if isinstance(rhs, Ps1AssignmentExpression):
                rhs = rhs.value
            if rhs is None or is_side_effect_free(rhs, world):
                plan.propose(stmt)
            elif _value_is_movable(rhs):
                plan.propose(stmt, [store_dropped_to_value(rhs)])
        if plan.commit():
            self.mark_changed()
        self.generic_visit(node)

    def _classify_statement(
        self, stmt, scope: Scope, model: Ps1SemanticModel,
    ) -> tuple[set[str], set[str], list[tuple[str, Ps1ExpressionStatement]]]:
        """
        Return `(reads, kills, writes)` for a top-level statement:
        - `reads`: variable keys read by the statement (flush: pending writes are needed).
        - `kills`: variable keys whose previous pending writes are dead (overwritten before read).
        - `writes`: list of `(key, statement)` pairs for pure assignments to register as pending.

        A for-loop's initializer kills previous stores without itself becoming a pending write
        (the for-loop is not a removable expression statement). Other control-flow constructs
        contribute all internal variable references as reads and produce no kills/writes.
        """
        reads: set[str] = set()
        kills: set[str] = set()
        writes: list[tuple[str, Ps1ExpressionStatement]] = []
        if isinstance(stmt, Ps1ExpressionStatement) and isinstance(
            stmt.expression, Ps1AssignmentExpression
        ):
            assign = stmt.expression
            if (
                assign.operator == '='
                and isinstance(assign.target, Ps1Variable)
                and assign.target.scope is Ps1ScopeModifier.NONE
            ):
                key = assign.target.name.lower()
                if key not in _PS1_SKIP_VARIABLES:
                    if assign.value is not None:
                        reads |= model.reads_in_scope(assign.value, scope)
                    writes.append((key, stmt))
                    return reads, kills, writes
        if isinstance(stmt, Ps1ForLoop):
            if (
                isinstance(stmt.initializer, Ps1AssignmentExpression)
                and stmt.initializer.operator == '='
                and isinstance(stmt.initializer.target, Ps1Variable)
                and stmt.initializer.target.scope is Ps1ScopeModifier.NONE
            ):
                key = stmt.initializer.target.name.lower()
                if key not in _PS1_SKIP_VARIABLES:
                    init_rhs_reads: set[str] = set()
                    if stmt.initializer.value is not None:
                        init_rhs_reads = model.reads_in_scope(stmt.initializer.value, scope)
                    if key in init_rhs_reads:
                        reads.update(init_rhs_reads)
                    else:
                        kills.add(key)
        reads |= model.variables_in_scope(stmt, scope)
        return reads, kills, writes
