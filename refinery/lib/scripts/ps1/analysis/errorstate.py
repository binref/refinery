"""
Whether the record a raise leaves behind is read back at a point that observes the raise.

Windows PowerShell 5.1 records every terminating error in `$Error` — and its stack trace in
`$StackTrace` — whether or not a handler ran, and the record persists session-globally. A script
with no `catch` and no `trap` anywhere can still read it (`$Error.Count`, `$Error[0]`) and branch on
the raise having happened, so deleting the raise as junk empties a `$Error` the original filled, and
a later read answers from an empty record where it read a full one. A removal that weighs handlers
alone does not see that change, and this model is the channel it was missing: the peer of
`refinery.lib.scripts.ps1.analysis.effects.Ps1OutputFlow` for the error record, composing the read
*sites* `refinery.lib.scripts.ps1.analysis.commands` names with the positional reachability
`refinery.lib.scripts.ps1.analysis.dominance` owns, exactly as output flow composes sinks with the
call graph.

**The record has two channels and this model owns both from the start.** `$Error`/`$StackTrace`
*persist*, so a read observes a raise from anywhere forward-reachable before it — the question 1b
answers, `persistent_read_observed_after`. `$?` *resets* on every statement, so only a read that
runs immediately after a write observes that write, and the model owns both directions of it: the
fold `success_flag_at` removes a decidable *reader*, and the veto `success_flag_write_observed`
keeps a *writer* a live reader observes. That is why `build_error_state_reach` receives the success
sites here although 1b places only the persistent ones. Keeping both channels queries on this model
rather than a fresh whole-script gate is the point of building it as a first-class model at all.

**Positional, and node-placed only.** A read *before* the raise sees an empty record, so it is
removable and the whole-script predicate `Ps1CommandModel.reads_the_error_record` cannot answer
this — the read has to be able to run *after* the raise, which is a control-flow question.
Reachability is taken under `refinery.lib.scripts.analysis.cfg.Projection.MAY`, the reading that
keeps a read the raise reaches only on a later loop iteration; a read textually above the raise but
on a back edge is kept, which is the safe direction. Only what the graph places is read: a
`$Error`/`$StackTrace` variable sigil and a cmdlet named-reference. A read spelled in string text or
built from a payload has no control-flow node until it is inlined, so it has no position and stays
with the whole-script scan; a positional channel that also claimed it would duplicate that guard's
territory.

**Deny-side toward keeping.** The query only ever adds a keep: a raiser the graphs cannot place, or
one no placed read is reachable from, answers `False` and the removal veto falls through to the
handler question it always asked. So a wrong answer here withholds a removal, never performs one —
the fail-open direction, consistent with the rest of the veto.
"""
from __future__ import annotations

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.cfg import CfgEdge, CfgNode, ControlFlowModel, Projection
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.analysis.reaching import ReachabilityQuery
from refinery.lib.scripts.ps1.analysis.commands import Ps1ErrorReadSites
from refinery.lib.scripts.ps1.analysis.values import statement_certainly_throws
from refinery.lib.scripts.ps1.model import Ps1ExpressionStatement, Ps1Script


class Ps1ErrorStateReach:
    """
    Where each read of the persistent error record stands, and whether one is reachable after a
    raise. The verdict of `build_error_state_reach`, held in a
    `refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` slot so every pass in a run reads the
    same one. Built without sites — `Ps1ErrorStateReach({}, frozenset(), ...)` — it answers `False`
    everywhere, which is what a script that reads the record nowhere gets.
    """

    def __init__(
        self,
        persistent_by_graph: dict[int, tuple[CfgNode, ...]],
        success_sites: frozenset[Node],
        control_flow: ControlFlowModel,
        reach: ReachabilityQuery,
    ):
        """
        `persistent_by_graph` groups each placed `$Error`/`$StackTrace` read by the identity of the
        graph that places it, so a read in a separate body — a called function, an inline or
        pipeline scriptblock, a dot-sourced block — is never mistaken for one reachable in the
        raiser's own, and a raiser whose graph places none is answered without a flood. `reach` is
        the shared `Projection.MAY` forward-reachability memo. `success_sites` is the `$?` channel,
        received and held for cluster 4, which places and queries it the way this places and queries
        the persistent one.
        """
        self._persistent_by_graph = persistent_by_graph
        self._success_sites = success_sites
        self._control_flow = control_flow
        self._reach = reach
        self._success_site_nodes_by_graph: dict[int, set[int]] | None = None

    def persistent_read_observed_after(self, node: Node) -> bool:
        """
        Whether a read of the persistent error record can run after evaluating *node* — so that a
        raise *node* leaves in the record would be observed and deleting *node* is not meaning-
        preserving. True when some placed `$Error`/`$StackTrace` read, other than one *node* itself
        stands for, is forward-reachable from *node* in *node*'s own graph.

        Reachability is per body, so a read the graphs place in a *different* body than *node*'s is
        not seen here: a called function's body, an inline or pipeline scriptblock (`& { }`,
        `1..3 | ForEach-Object { }`), and a dot-sourced block (`. { }`) each own their own graph.
        `$Error` is session-global, so such a read does observe the raise on a 5.1 host and deleting
        the raiser is unsound — a known limit this model does not close, the same one the
        interprocedural milestone (cluster 1f) closes and which the fixture tests track by xfail. A
        *node* the graphs place nowhere answers `False`, the fail-open pole the veto reads as "keep
        on the handler question alone".
        """
        located = self._control_flow.locate(node)
        if located is None:
            return False
        graph, start = located
        sites = self._persistent_by_graph.get(id(graph))
        if not sites:
            return False
        forward = self._reach.reachable(start, forward=True)
        return any(site is not start and id(site) in forward for site in sites)

    def success_flag_at(self, node: Node) -> bool | None:
        """
        The value of the `$?` automatic variable where *node* reads it, or `None` when the channel
        cannot decide it. `$?` is `$true` after a statement that succeeded and `$false` after one
        that failed, and it *resets on every statement*, so its value is a property of what runs
        immediately before the read rather than of the read itself — which is why it is a positional
        query on this model and not a fixed truth value in `is_truthy`.

        **True** — the read is the first thing the script does: it stands in the root script's own
        graph (`refinery.lib.scripts.ps1.model.Ps1Script`, not a function or scriptblock body, whose
        `$?` reflects the caller), no element-bearing statement precedes it over plain control flow,
        control reaches it from the entry rather than being stranded after a `throw`, the script runs
        no `param`/`dynamicparam` computation that could fail before the body, and the read is not
        inside the `process` block, which the engine re-enters once per pipeline input so that its
        top reflects the previous input's last statement rather than a fresh start. 5.1 starts `$?`
        `$true`.

        **False** — every nearest statement that runs immediately before the read is certain to
        raise a terminating error that steps over to it (`statement_certainly_throws`), *and* no
        plain path reaches the read from the entry. A `throw` or a Stop-disposition failure abandons
        the script and draws no plain edge onward, so it is never such a predecessor: the edge
        structure supplies the statement- versus script-terminating distinction the value domain
        alone cannot. The entry guard is what keeps a loop condition out of this pole: a `$?` read
        guarding a loop whose body certainly raises is reached both from the entry — where the first
        iteration reads `$true` — and from the raising back-edge, so it is a merge and stays `None`,
        never `$false`.

        **None** — anything else: an unprovable predecessor, a mix of raising and non-raising
        predecessors, a live loop back-edge, a handler-body entry, or a read in a non-root body
        (whose `$?` is the caller's, an interprocedural limit). None is the fail-safe pole the
        resolver reads as "leave `$?` in place", keeping the branch 5.1 runs.
        """
        located = self._control_flow.locate(node)
        if located is None:
            return None
        graph, placed = located
        elements, reaches_entry = self._nearest_normal_element_predecessors(placed)
        if (
            not elements
            and reaches_entry
            and isinstance(graph.owner, Ps1Script)
            and not self._root_may_fail_before_body(graph.owner)
            and not self._reads_at_the_top_of_a_rerunning_block(node, graph.owner)
        ):
            return True
        if (
            elements
            and not reaches_entry
            and all(statement_certainly_throws(element) for element in elements)
        ):
            return False
        return None

    @staticmethod
    def writes_success_flag(statement: Node | None) -> bool:
        """
        Whether *statement* is certain to reset `$?` when it runs — the KILL set of the success-flag
        register. True for a leaf `refinery.lib.scripts.ps1.model.Ps1ExpressionStatement` — an
        assignment, a discard, a command, a pipeline, a bare expression — each measured to write `$?`
        on every path it takes. False, *transparent*, for every compound statement (`if`, `foreach`,
        `while`, `for`, `switch`, `try`, a trap-guarded block), a function definition, and the
        synthetic entry and exit, whose element is `None`: each leaves `$?` untouched on at least one
        path — an empty or never-entered body runs no statement, an unknown condition's no-run branch
        writes nothing, a definition evaluates nothing — so a value written before it can still reach
        a read after it.

        The asymmetry is the soundness of the veto. Reading a writer as transparent over-keeps, which
        withholds a removal; reading a transparent statement as a writer under-keeps, which deletes a
        live write, so only a leaf expression-statement — provably a writer on every path — ever
        blocks the reaching-definition walk or gates it.
        """
        return isinstance(statement, Ps1ExpressionStatement)

    def success_flag_write_observed(self, statement: Node) -> bool:
        """
        Whether removing *statement* would change the value a live `$?` read sees — the success-flag
        removal veto, the reset-channel peer of `persistent_read_observed_after`. `$?` resets on
        every statement, so a write is observed only by a read that runs before the next writer
        overwrites it: this is the reaching-definition of the `$?` register, the dual of the
        `success_flag_at` fold that removes the reader rather than protecting the writer.

        **Gate** — *statement* must itself write `$?` (`writes_success_flag`). Removing a transparent
        statement never changes `$?` and is never kept here, the precision analogue of the
        `statement_can_raise` gate the persistent channel pairs with a read.

        **Observed** — a placed `$?` read is reachable from *statement* over plain
        (`refinery.lib.scripts.analysis.cfg.CfgEdge.NORMAL`) control flow through only transparent
        nodes: a forward walk from *statement*'s node that steps *through* the synthetic and
        transparent ones and **blocks** at any other `writes_success_flag` node, since that node
        overwrites `$?` and kills *statement*'s definition before a later read can observe it. A
        script that reads `$?` nowhere has no success site, and the walk short-circuits before it
        starts, so such a script pays nothing.

        Deny-side toward keeping, exactly as `persistent_read_observed_after`: a *statement* the
        graph cannot place, or one no read is reachable from, answers `False` and the removal veto
        falls through to the questions it already asked.
        """
        if not self.writes_success_flag(statement):
            return False
        sites_by_graph = self._success_site_nodes()
        if not sites_by_graph:
            return False
        located = self._control_flow.locate(statement)
        if located is None:
            return False
        graph, start = located
        sites = sites_by_graph.get(id(graph))
        if not sites:
            return False
        seen: set[int] = {id(start)}
        stack: list[CfgNode] = [start]
        while stack:
            current = stack.pop()
            for successor in current.successors:
                if id(successor) in seen:
                    continue
                if graph.edge_kind(current, successor) is not CfgEdge.NORMAL:
                    continue
                seen.add(id(successor))
                if id(successor) in sites:
                    return True
                if self.writes_success_flag(successor.element):
                    continue
                stack.append(successor)
        return False

    def _success_site_nodes(self) -> dict[int, set[int]]:
        """
        The graph nodes that place a `$?` read, grouped by the graph that places them and memoized.
        The forward walk asks which of them it reaches, so locating them once keeps the veto's cost
        the walk itself rather than a re-scan of every site per proposal. A read the graph places
        nowhere — one spelled in text, or read in a different body — is dropped, the same fail-open
        the fold takes; an empty map is the short-circuit for a script that reads `$?` nowhere.
        """
        if self._success_site_nodes_by_graph is None:
            by_graph: dict[int, set[int]] = {}
            for site in self._success_sites:
                located = self._control_flow.locate(site)
                if located is not None:
                    graph, node = located
                    by_graph.setdefault(id(graph), set()).add(id(node))
            self._success_site_nodes_by_graph = by_graph
        return self._success_site_nodes_by_graph

    @staticmethod
    def _nearest_normal_element_predecessors(node: CfgNode) -> tuple[list[Node], bool]:
        """
        The AST elements of the nearest statements that run immediately before *node* over plain
        (`refinery.lib.scripts.analysis.cfg.CfgEdge.NORMAL`) control flow, and whether the backward
        walk reaches the graph's synthetic entry. The walk steps *through* synthetic nodes — the
        entry and the resumption fan-outs carry no element — to the first element-bearing predecessor
        on each path, so a read whose only predecessor is the entry answers with an empty list and
        `True`, and one preceded by a real statement answers with that statement. Resumption edges
        are not `NORMAL`, so the walk never leaves plain control flow into a handler body, and a
        `throw`/Stop predecessor is unreachable here because it draws no `NORMAL` edge onward.
        """
        graph = node.graph
        entry = graph.entry
        elements: list[Node] = []
        seen_elements: set[int] = set()
        reaches_entry = False
        seen: set[int] = {id(node)}
        stack: list[CfgNode] = [node]
        while stack:
            current = stack.pop()
            for pred in current.predecessors:
                if id(pred) in seen:
                    continue
                if graph.edge_kind(pred, current) is not CfgEdge.NORMAL:
                    continue
                seen.add(id(pred))
                if pred is entry:
                    reaches_entry = True
                elif pred.element is None:
                    stack.append(pred)
                elif id(pred.element) not in seen_elements:
                    seen_elements.add(id(pred.element))
                    elements.append(pred.element)
        return elements, reaches_entry

    @staticmethod
    def _root_may_fail_before_body(script: Ps1Script) -> bool:
        """
        Whether the root script runs a `param` default, a parameter attribute, or a `dynamicparam`
        block before its first body statement — any of which can raise, which 5.1 records in `$?` as
        a failure the body's first read then observes. Measured: a `param` whose default runs a
        command that fails leaves `$?` `$false` at the first body statement, so a "first statement is
        `$true`" rule must stand down wherever such a pre-body computation is present.
        """
        param_block = script.param_block
        if param_block is not None:
            if param_block.attributes:
                return True
            for parameter in param_block.parameters:
                if parameter.default_value is not None or parameter.attributes:
                    return True
        dynamicparam = script.dynamicparam_block
        return dynamicparam is not None and bool(dynamicparam.body)

    @staticmethod
    def _reads_at_the_top_of_a_rerunning_block(node: Node, script: Ps1Script) -> bool:
        """
        Whether *node* is written inside *script*'s `process` block. The engine runs `begin`, `end`,
        `dynamicparam` and the unnamed body once, but re-enters `process` once per pipeline input,
        and `$?` persists across those entries — on the second input it holds what the first input's
        last statement left. So a read at the top of `process` is *not* the first thing the script
        does the way one at the top of a run-once block is, and the `$true` verdict must stand down
        for it: measured on 5.1, `1, 2 | & { process { Write-Host $?; $Null = [Int]'abc' } }` prints
        `True` then `False`. The control-flow graph sequences the block once and draws no per-input
        back-edge, so this lexical check is what supplies the distinction the graph does not.
        """
        process = script.process_block
        if process is None:
            return False
        cursor: Node | None = node
        while cursor is not None and cursor is not script:
            if cursor is process:
                return True
            cursor = cursor.parent
        return False


def build_error_state_reach(
    read_sites: Ps1ErrorReadSites,
    control_flow: ControlFlowModel,
    dominance: DominatorModel,
) -> Ps1ErrorStateReach:
    """
    Place every persistent error-record read of the script into the graph that evaluates it, so the
    reach model can ask whether one runs after a raise. A read the graphs place nowhere is dropped
    rather than kept as a placeless keep: it has no position, so it cannot be ordered against a
    raise, and the whole-script scan already keeps the shapes that have no node. The placed reads
    are grouped by graph so a raiser in a body that places none is answered without a flood, and
    reachability is asked through the shared, memoized `Projection.MAY` forward walk that
    `refinery.lib.scripts.analysis.reaching.ReachabilityQuery` holds — the `frozenset` reader
    two siblings already read.

    `read_sites.success` — the `$?` channel — is received and passed through unplaced: cluster 4
    layers its reset rule on this model and needs the sites here, and receiving both channels now is
    what keeps that a query on this model rather than a new gate. See `Ps1ErrorStateReach`.
    """
    by_graph: dict[int, list[CfgNode]] = {}
    for site in read_sites.persistent:
        located = control_flow.locate(site)
        if located is not None:
            graph, node = located
            by_graph.setdefault(id(graph), []).append(node)
    return Ps1ErrorStateReach(
        {graph_id: tuple(nodes) for graph_id, nodes in by_graph.items()},
        read_sites.success,
        control_flow,
        ReachabilityQuery(dominance, Projection.MAY),
    )
