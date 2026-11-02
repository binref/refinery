"""
Definite assignment for PowerShell locals: a forward must-analysis over the per-body control-flow
graphs answering whether a store to a name has certainly completed before a read of it runs. A store
counts only along an edge its statement leaves by completing, and only where the statement certainly
completes: where nothing takes an error, 5.1 reports it and carries on along the very edge a
completed statement leaves by, so the edge alone does not say that the store was made.
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


def _store_of(element: Node | None) -> tuple[str, Node] | None:
    """
    The plain local the graph element *element* stores into, through a cast on the target or by an
    increment, beside the expression making the store, or `None` where it stores into none.
    """
    if isinstance(element, Ps1ExpressionStatement):
        element = element.expression
    if isinstance(element, Ps1AssignmentExpression):
        target = element.target
        while isinstance(target, Ps1CastExpression):
            target = target.operand
        name = _plain_local(target)
    elif isinstance(element, Ps1UnaryExpression) and element.operator in ('++', '--'):
        name = _plain_local(element.operand)
    else:
        return None
    return None if name is None or element is None else (name, element)


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

    *completes* says whether the expression making a store certainly completes where it stands,
    given a test that answers for a read whether a store to its name certainly completed before the
    store; a store counts only where it does. The test is read off the state this solves, so a
    store of a name read after a store that certainly completed counts as well.
    """

    def __init__(
        self,
        control_flow: ControlFlowModel,
        may_be_removed: Callable[[str], bool],
        completes: Callable[[Node, Callable[[Node], bool]], bool],
    ):
        self._flow = control_flow
        self._may_be_removed = may_be_removed
        self._completes = completes
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

    def _solve(self, graph: ControlFlowGraph) -> _Facts:
        stored: dict[int, tuple[str, Node]] = {}
        for node in graph.nodes:
            store = _store_of(node.element)
            if store is not None:
                stored[id(node)] = store
        read: set[str] = set()
        for inner in graph.owner.walk():
            if isinstance(inner, Ps1Variable) and (local := _plain_local(inner)) is not None:
                read.add(local)
        bits: dict[str, int] = {}
        for name, _ in stored.values():
            if name in read and name not in bits:
                bits[name] = 1 << len(bits)
        stores = {key: (bits[name], made) for key, (name, made) in stored.items() if name in bits}
        if not stores:
            return _Facts({}, {})
        may_be_removed = self._may_be_removed
        completes = self._completes
        decided: dict[tuple[int, int], int] = {}

        def gen(node: CfgNode, before: int) -> int:
            store = stores.get(id(node))
            if store is None:
                return 0
            key = (id(node), before)
            found = decided.get(key)
            if found is None:
                bit, made = store

                def assigned(read: Node) -> bool:
                    name = _plain_local(read)
                    return name is not None and not may_be_removed(name) and bool(before & bits.get(name, 0))

                found = decided[key] = bit if completes(made, assigned) else 0
            return found

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
                    if id(pred) in stores and graph.completes_into(pred, node):
                        out |= gen(pred, out)
                    met &= out
                if met == -1:
                    met = 0
                if met != state[id(node)]:
                    state[id(node)] = met
                    changed = True
        return _Facts(bits, {key: value for key, value in state.items() if key in reachable})
