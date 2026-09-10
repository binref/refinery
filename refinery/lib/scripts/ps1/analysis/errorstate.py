"""
Whether a raise's error record is read back where the raise is observed.

Windows PowerShell 5.1 records every terminating error in `$Error` (and its stack trace in
`$StackTrace`) session-globally, whether or not a handler ran, so a script can read it and branch on
a raise having happened. Deleting such a raise as junk empties a record a later read observes. This
model is the peer of `refinery.lib.scripts.ps1.analysis.effects.Ps1OutputFlow` for that channel: it
composes the read sites `refinery.lib.scripts.ps1.analysis.commands` names with the positional
reachability `refinery.lib.scripts.ps1.analysis.dominance` owns.

The record has two channels. `$Error`/`$StackTrace` persist, so a read observes a raise from
anywhere forward-reachable before it (`persistent_read_observed_after`). `$?` resets on every
statement, so only a read running immediately after a write observes it; the model owns both
directions — the fold `success_flag_at` removes a decidable reader, the veto
`success_flag_write_observed` keeps a writer a live reader observes.

Only nodes the control-flow graph places are read; a read spelled in string text has no position and
stays with the whole-script scan. Reachability is taken under
`refinery.lib.scripts.analysis.cfg.Projection.MAY`, keeping a read the raise reaches only on a later
loop iteration. Every query is deny-side toward keeping: an unplaceable or unreachable node answers
`False`, withholding a removal rather than performing one.
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
    Where each read of the error record stands, and whether one is reachable after a raise. Built by
    `build_error_state_reach` and held in a `refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache`
    slot. With no sites it answers `False` everywhere.
    """

    def __init__(
        self,
        persistent_by_graph: dict[int, tuple[CfgNode, ...]],
        success_sites: frozenset[Node],
        control_flow: ControlFlowModel,
        reach: ReachabilityQuery,
    ):
        """
        `persistent_by_graph` groups each placed `$Error`/`$StackTrace` read by the graph that
        places it, so a read in a separate body is never mistaken for one reachable in the raiser's
        own. `reach` is the shared `Projection.MAY` forward-reachability memo. `success_sites` is the
        `$?` channel, placed and queried by the reset rule below.
        """
        self._persistent_by_graph = persistent_by_graph
        self._success_sites = success_sites
        self._control_flow = control_flow
        self._reach = reach
        self._success_site_nodes_by_graph: dict[int, set[int]] | None = None

    def persistent_read_observed_after(self, node: Node) -> bool:
        """
        Whether a read of the persistent error record can run after evaluating *node*, so a raise it
        leaves in the record would be observed and deleting *node* is not meaning-preserving. True
        when a placed `$Error`/`$StackTrace` read other than *node*'s own is forward-reachable from
        *node* in its graph.

        Reachability is per body: a read the graphs place in a different body — a called function, an
        inline or pipeline scriptblock, a dot-sourced block — is not seen, an interprocedural limit
        the fixture tests track by xfail. A *node* placed nowhere answers `False`.
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
        The value of `$?` where *node* reads it, or `None` when it cannot be decided. `$?` is
        `$true` after a statement succeeds and `$false` after one fails, and resets on every
        statement, so its value is a property of what runs immediately before the read — a
        positional query, not a fixed truth value in `is_truthy`.

        **True** — the read is the first thing the script does: it stands in the root script's own
        graph, no element-bearing statement precedes it over plain control flow, control reaches it
        from the entry, the script runs no `param`/`dynamicparam` computation that could fail before
        the body, and it is not inside the `process` block (which the engine re-enters once per
        pipeline input).

        **False** — every nearest statement running immediately before the read is certain to raise
        (`statement_certainly_throws`) and no plain path reaches the read from the entry. A `throw`
        or Stop-disposition failure draws no plain edge onward, so it is never such a predecessor,
        and the entry guard keeps a live loop condition — reached both from the entry and a raising
        back-edge — out of this pole.

        **None** — anything else: an unprovable predecessor, a mix of raising and non-raising
        predecessors, a live loop back-edge, a handler-body entry, or a non-root body.
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
        Whether *statement* is certain to reset `$?` — the KILL set of the success-flag register.
        True for a leaf `refinery.lib.scripts.ps1.model.Ps1ExpressionStatement` (an assignment,
        discard, command, pipeline, or bare expression); False, transparent, for every compound
        statement, a function definition, and the synthetic entry and exit, each of which leaves `$?`
        untouched on at least one path.

        Reading a writer as transparent over-keeps (withholds a removal); reading a transparent
        statement as a writer deletes a live write. Only a leaf expression-statement, a writer on
        every path, blocks or gates the reaching-definition walk.
        """
        return isinstance(statement, Ps1ExpressionStatement)

    def success_flag_write_observed(self, statement: Node) -> bool:
        """
        Whether removing *statement* would change the value a live `$?` read sees — the success-flag
        removal veto, the reset-channel peer of `persistent_read_observed_after` and dual of the
        `success_flag_at` fold. `$?` resets on every statement, so a write is observed only by a read
        that runs before the next writer overwrites it.

        *statement* must itself write `$?` (`writes_success_flag`); a transparent one is never kept
        here. Observed means a placed `$?` read is reachable over plain
        (`refinery.lib.scripts.analysis.cfg.CfgEdge.NORMAL`) control flow through only transparent
        nodes, blocking at any other writer since it overwrites `$?` first. A script that reads `$?`
        nowhere short-circuits. Deny-side toward keeping: an unplaceable or unreachable *statement*
        answers `False`.
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
        The graph nodes that place a `$?` read, grouped by graph and memoized so the veto's cost is
        the walk rather than a per-proposal re-scan. A read placed nowhere is dropped; an empty map
        short-circuits a script that reads `$?` nowhere.
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
        The AST elements of the nearest statements running immediately before *node* over plain
        (`refinery.lib.scripts.analysis.cfg.CfgEdge.NORMAL`) control flow, and whether the backward
        walk reaches the graph's synthetic entry. The walk steps through element-less synthetic nodes
        to the first real predecessor on each path. Resumption edges are not `NORMAL`, so it never
        leaves plain control flow into a handler body.
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
        a failure the body's first read observes, so the "first statement is `$true`" rule stands
        down wherever such a pre-body computation is present.
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
        Whether *node* is written inside *script*'s `process` block, which the engine re-enters once
        per pipeline input with `$?` persisting across entries — so a read at its top is not the
        first thing the script does, and the `$true` verdict stands down. The graph sequences the
        block once and draws no per-input back-edge, so this lexical check supplies the distinction
        it does not.
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
    Place every persistent error-record read into the graph that evaluates it, grouped by graph so a
    raiser in a body that places none is answered without a flood. A read placed nowhere is dropped:
    it has no position to order against a raise, and the whole-script scan already keeps the shapes
    with no node. `read_sites.success` — the `$?` channel — is passed through unplaced for the reset
    rule to place and query. Reachability uses the shared, memoized `Projection.MAY` forward walk of
    `refinery.lib.scripts.analysis.reaching.ReachabilityQuery`.
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
