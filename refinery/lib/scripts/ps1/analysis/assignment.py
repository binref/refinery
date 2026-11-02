"""
Definite assignment for PowerShell locals: a forward must-analysis over the per-body control-flow
graphs answering whether a store to a name has certainly completed before a read of it runs. A store
counts only along an edge its statement leaves by completing; an edge taken because the statement
raised carries nothing, so no answer here rests on whether a statement can fail.
"""
from __future__ import annotations

from typing import Callable, NamedTuple

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.cfg import CfgNode, ControlFlowGraph, ControlFlowModel
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1CastExpression,
    Ps1ExpressionStatement,
    Ps1ScopeModifier,
    Ps1UnaryExpression,
    Ps1Variable,
)


def _plain_local(variable: Node | None) -> str | None:
    """
    The name *variable* reads or writes where it is a plain local: no splat, no drive, and no scope
    other than the local one.
    """
    if not isinstance(variable, Ps1Variable) or variable.splatted or variable.drive:
        return None
    if variable.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL):
        return None
    return variable.name.lower()


def _stored(element: Node | None) -> str | None:
    """
    The plain local the graph element *element* stores into, through a cast on the target or by an
    increment, or `None` where it stores into none.
    """
    if isinstance(element, Ps1ExpressionStatement):
        element = element.expression
    if isinstance(element, Ps1AssignmentExpression):
        target = element.target
        while isinstance(target, Ps1CastExpression):
            target = target.operand
        return _plain_local(target)
    if isinstance(element, Ps1UnaryExpression) and element.operator in ('++', '--'):
        return _plain_local(element.operand)
    return None


class _Facts(NamedTuple):
    """
    The solution for one graph: a bit per name some node stores and the graph's owner reads, and for
    each node control reaches, the names certainly stored on every run that arrives there.
    """
    bits: dict[str, int]
    state: dict[int, int]


class Ps1DefiniteAssignment:
    """
    Whether a store to the name of a read certainly completed before the read, over the graphs of
    *control_flow*, solved once per graph on the first question about it. A name *may_be_removed*
    names is never certainly stored: a removal between the store and the read leaves it unset.
    """

    def __init__(self, control_flow: ControlFlowModel, may_be_removed: Callable[[str], bool]):
        self._flow = control_flow
        self._may_be_removed = may_be_removed
        self._facts: dict[int, _Facts] = {}

    def assigned_before(self, read: Node) -> bool:
        """
        Whether a store to the plain local *read* reads certainly completed, in the body *read*
        stands in, before *read* runs.
        """
        name = _plain_local(read)
        if name is None or self._may_be_removed(name):
            return False
        located = self._flow.locate(read)
        if located is None:
            return False
        graph, node = located
        facts = self._facts.get(id(graph))
        if facts is None:
            facts = self._facts[id(graph)] = self._solve(graph)
        bit = facts.bits.get(name)
        return bit is not None and bool(facts.state.get(id(node), 0) & bit)

    @staticmethod
    def _solve(graph: ControlFlowGraph) -> _Facts:
        stored: dict[int, str] = {}
        for node in graph.nodes:
            name = _stored(node.element)
            if name is not None:
                stored[id(node)] = name
        read: set[str] = set()
        for inner in graph.owner.walk():
            if isinstance(inner, Ps1Variable) and (local := _plain_local(inner)) is not None:
                read.add(local)
        bits: dict[str, int] = {}
        for name in stored.values():
            if name in read and name not in bits:
                bits[name] = 1 << len(bits)
        gens = {key: bits[name] for key, name in stored.items() if name in bits}
        if not gens:
            return _Facts({}, {})
        top = (1 << len(bits)) - 1
        state: dict[int, int] = {id(node): top for node in graph.nodes}
        state[id(graph.entry)] = 0
        reachable: set[int] = set()
        frontier: list[CfgNode] = [graph.entry]
        while frontier:
            node = frontier.pop()
            if id(node) in reachable:
                continue
            reachable.add(id(node))
            frontier.extend(node.successors)
        changed = True
        while changed:
            changed = False
            for node in graph.nodes:
                if node is graph.entry:
                    continue
                met = -1
                for pred in node.predecessors:
                    out = state[id(pred)]
                    gen = gens.get(id(pred))
                    if gen is not None and graph.completes_into(pred, node):
                        out |= gen
                    met &= out
                if met == -1:
                    met = 0
                if met != state[id(node)]:
                    state[id(node)] = met
                    changed = True
        return _Facts(bits, {key: value for key, value in state.items() if key in reachable})
