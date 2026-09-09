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
runs immediately after a raise observes it — a rule cluster 4 layers on this same model, which is
why `build_error_state_reach` receives the success sites here although 1b places only the persistent
ones. Keeping the second channel a query on this model rather than a fresh whole-script gate is the
point of building it as a first-class model at all.

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
from refinery.lib.scripts.analysis.cfg import CfgNode, ControlFlowModel, Projection
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.analysis.reaching import ReachabilityQuery
from refinery.lib.scripts.ps1.analysis.commands import Ps1ErrorReadSites


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
