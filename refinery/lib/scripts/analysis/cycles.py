"""
Whether a point in a script can be reached more than once, over the control-flow graphs of one
script.

This is the question every loop-awareness check in a transform is really asking. A value established
at a point holds until something changes it — but if control can come back to that point, the value
it establishes on the second visit is not the one an earlier reader saw, and a fact derived from a
single visit is not a fact about the program. Loops are the obvious way that happens and the reason
the check is usually written as a walk up the ancestors looking for loop node types, which is a
guess at the graph rather than a reading of it: it misses a construct that iterates without being
spelled as a loop, and it claims one for a body that runs once.

Read off the graph, the question is exactly whether the node lies on a cycle, which is whether it
belongs to a strongly connected component with more than one member or carries an edge to itself.
Nothing else in the shape of the source matters.

Exceptional edges take part like any other edge. A body a handler resumes into is genuinely reached
again — `trap { continue }` is a loop spelled as error handling — and a caller asking whether a
single-visit fact still holds must be told so. The cost is that a cycle closed only by a throw is
reported as one, which over-approximates in the safe direction here but is the wrong reading for a
caller that would take `on_a_cycle` as licence to rotate or unroll.

**One body's graph only answers for one invocation of that body.** A block written inside a loop is
invoked once per iteration, so everything in it repeats even though its own graph is acyclic — the
repetition is the *owner's*, and `CycleModel.repeats` asks the owner in turn.

That walk is lexical by default: it follows a body to where its value is *written*, not to where it
is called, so a body repeated by something other than the code around it reads as running once. A
language closes that gap by supplying a `BodySite`, which names the element that actually runs a body
and says whether that site runs it more than once — the `ForEach-Object` a PowerShell pipeline is
mostly made of runs its block once per input element while the statement handing it over runs once.
What no `BodySite` can answer from a tree alone is a block stored in a variable and invoked from a
loop somewhere else; that is a call-graph question, and these graphs do not hold it.
"""
from __future__ import annotations

from typing import Callable, Iterable, Iterator, TypeVar

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.cfg import CfgNode, ControlFlowGraph, ControlFlowModel

#: What a language may answer about the body a control-flow graph belongs to: the element whose
#: evaluation runs that body, and whether the site runs it more than once. `None` means the language
#: has nothing to say and the walk falls back to where the body is *written*, which is the lexical
#: reading the module docstring describes. A site given here replaces that reading, so answering is
#: how a language reports a body run by something other than the code around it.
BodySite = Callable[[Node], 'tuple[Node, bool] | None']

_Vertex = TypeVar('_Vertex')


def strongly_connected_components(
    nodes: Iterable[_Vertex],
    successors: Callable[[_Vertex], Iterable[_Vertex]],
) -> list[list[_Vertex]]:
    """
    The strongly connected components of the graph *successors* spans from *nodes*, each a list of
    nodes that can all reach one another; every node reachable from one of *nodes* is in exactly one
    of them, and nodes are told apart by identity. Each component is listed after every component it
    has an edge into, so a caller combining answers along the edges finds those of everything a
    component reaches already listed.

    Tarjan's algorithm, driven by an explicit stack rather than by recursion: the graphs are as deep
    as the script is long and a deeply nested body would otherwise exhaust the interpreter's stack
    on a script that parses fine.
    """
    index: dict[int, int] = {}
    lowlink: dict[int, int] = {}
    stacked: set[int] = set()
    pending: list[_Vertex] = []
    components: list[list[_Vertex]] = []

    def enter(node: _Vertex) -> tuple[_Vertex, Iterator[_Vertex]]:
        index[id(node)] = lowlink[id(node)] = len(index)
        pending.append(node)
        stacked.add(id(node))
        return node, iter(successors(node))

    for start in nodes:
        if id(start) in index:
            continue
        work = [enter(start)]
        while work:
            node, unvisited = work[-1]
            for successor in unvisited:
                if id(successor) not in index:
                    work.append(enter(successor))
                    break
                if id(successor) in stacked:
                    lowlink[id(node)] = min(lowlink[id(node)], index[id(successor)])
            else:
                work.pop()
                if work:
                    parent = work[-1][0]
                    lowlink[id(parent)] = min(lowlink[id(parent)], lowlink[id(node)])
                if lowlink[id(node)] == index[id(node)]:
                    component: list[_Vertex] = []
                    while True:
                        member = pending.pop()
                        stacked.discard(id(member))
                        component.append(member)
                        if member is node:
                            break
                    components.append(component)
    return components


def nodes_on_a_cycle(graph: ControlFlowGraph) -> frozenset[int]:
    """
    The ids of the nodes of *graph* that control can return to: those in a strongly connected
    component of more than one node, and those carrying an edge to themselves.

    A component of one node is not a cycle unless that edge is there, which is the case a plain
    component-size test gets wrong — a construct that iterates over nothing but its own head, such as
    a dispatch whose every arm is empty, is one node reaching only itself.
    """
    found: set[int] = set()
    for component in strongly_connected_components(graph.nodes, lambda node: node.successors):
        if len(component) > 1:
            found.update(id(node) for node in component)
            continue
        node = component[0]
        if any(successor is node for successor in node.successors):
            found.add(id(node))
    return frozenset(found)


class CycleModel:
    """
    Which points of one script can be reached more than once. A graph's cycle set is computed once,
    on the first question asked about that graph, and kept for as long as this model lives: a caller
    that asks about one node almost always asks about many and the sets are fixed for as long as the
    tree is. Computing them all on construction instead would charge every caller for the whole
    script — the graph of one obfuscated body can carry hundreds of thousands of edges — including
    the caller that ends up asking nothing.
    """

    def __init__(self, flow: ControlFlowModel, body_site: BodySite | None = None):
        self._flow = flow
        self._body_site = body_site
        self._on_a_cycle: dict[int, frozenset[int]] = {}

    def on_a_cycle(self, graph: ControlFlowGraph, node: CfgNode) -> bool:
        """
        Whether control can return to *node* within one invocation of the body *graph* is the graph
        of. The node-level counterpart of `repeats`, for a caller that has already located it.
        """
        found = self._on_a_cycle.get(id(graph))
        if found is None:
            found = self._on_a_cycle[id(graph)] = nodes_on_a_cycle(graph)
        return id(node) in found

    def repeats(self, element: Node) -> bool:
        """
        Whether *element* can be evaluated more than once by one run of the script — because the
        statement evaluating it lies on a cycle, because the body it is written in does, or because
        the graphs do not place it at all.

        That last answer is the conservative one, and it is the reason this reports *may repeat*
        rather than *does*: an element no node stands for — the default of a parameter, an attribute
        on a body — is evaluated when its body is invoked, which is a point these graphs do not
        hold. A caller asks this to find out whether a fact taken from one visit still holds, and
        the answer to that question over an unplaced element is no. See the module docstring for
        what the walk out through the enclosing bodies does and does not see.
        """
        located = self._flow.locate(element)
        if located is None:
            return True
        while located is not None:
            graph, node = located
            if self.on_a_cycle(graph, node):
                return True
            owner = graph.owner
            site = self._body_site(owner) if self._body_site is not None else None
            if site is None:
                located = self._flow.locate(owner)
                continue
            invoked_at, repeatedly = site
            if repeatedly:
                return True
            located = self._flow.locate(invoked_at)
        return False
