"""
The backward live-variable worklist, over one control-flow graph and a caller's gen/kill oracle.

A value is *live* at a point when some path from there may read it before overwriting it. The solver
is the standard backward fixpoint and knows nothing about what it is tracking: the domain is whatever
hashable thing the oracle returns, which for a language with a binding model is a binding and for one
without could be a name. What a language contributes is the two sets per node — what this node reads,
and what it definitely overwrites — and nothing else.

**The transfer function is deliberately not the textbook one.** A node's live-in is

    use ∪ (normal_out − kill) ∪ exceptional_out

where the textbook rule subtracts `kill` from the whole of live-out. The difference is the
exceptional successors: a statement that may throw part-way through has not necessarily performed
its store, so along that edge the store must not mask an earlier one. Subtracting the kill from the
exceptional set too reports a store as dead whose value the handler can still read, which is a
deletion of live code — and the asymmetry is why this rule is stated here once rather than
rediscovered per language.
"""
from __future__ import annotations

from typing import Callable, Hashable, TypeVar

from refinery.lib.scripts.analysis.cfg import CfgNode, ControlFlowGraph, distinct

_T = TypeVar('_T', bound=Hashable)

#: What a language answers for one control-flow node: what it reads, and what it definitely
#: overwrites. A node whose store is conditional — guarded by a short-circuit, a ternary, a
#: destructuring default — contributes it to neither set, because the kill is what licenses calling
#: an earlier store dead and a conditional one licenses nothing.
NodeSets = Callable[[ControlFlowGraph, CfgNode], tuple[set[_T], set[_T]]]


def solve_liveness(
    graph: ControlFlowGraph,
    node_sets: NodeSets[_T],
) -> tuple[dict[int, frozenset[_T]], dict[int, frozenset[_T]]]:
    """
    The live-in and live-out sets of every node in *graph*, keyed by node identity.

    Iterated in reverse graph order until nothing moves, which converges because the sets only grow
    and the domain is finite. Reverse order is a heuristic for how many rounds that takes and never
    a correctness condition — the fixpoint is the same whichever order the nodes are visited in.
    """
    use: dict[int, set[_T]] = {}
    kill: dict[int, set[_T]] = {}
    normal_successors: dict[int, list[CfgNode]] = {}
    exceptional_successors: dict[int, list[CfgNode]] = {}
    for node in graph.nodes:
        use[id(node)], kill[id(node)] = node_sets(graph, node)
        completed: list[CfgNode] = []
        raising: list[CfgNode] = []
        for successor in distinct(node.successors):
            if graph.completes_into(node, successor):
                completed.append(successor)
            if graph.raise_taken(node, successor):
                raising.append(successor)
        normal_successors[id(node)] = completed
        exceptional_successors[id(node)] = raising
    live_in: dict[int, set[_T]] = {id(node): set() for node in graph.nodes}
    live_out: dict[int, set[_T]] = {id(node): set() for node in graph.nodes}
    changed = True
    while changed:
        changed = False
        for node in reversed(graph.nodes):
            normal: set[_T] = set()
            exceptional: set[_T] = set()
            for successor in normal_successors[id(node)]:
                normal |= live_in[id(successor)]
            for successor in exceptional_successors[id(node)]:
                exceptional |= live_in[id(successor)]
            out = normal | exceptional
            inn = use[id(node)] | (normal - kill[id(node)]) | exceptional
            if out != live_out[id(node)] or inn != live_in[id(node)]:
                live_out[id(node)] = out
                live_in[id(node)] = inn
                changed = True
    return (
        {key: frozenset(value) for key, value in live_in.items()},
        {key: frozenset(value) for key, value in live_out.items()},
    )
