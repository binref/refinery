"""
Per-function control-flow graphs for JavaScript, derived from the AST. Each function (and the script
itself) gets one `ControlFlowGraph`: a graph whose nodes wrap the statements and loop-head expressions
the body evaluates, connected by the order in which control may pass between them — sequential flow,
the branches of `if`/`switch`, loop back-edges, the non-local jumps of `break`/`continue`/`return`, and
*exceptional* edges from any point inside a `try` to the handler that would catch a throw.

This is a third layer of the analysis substrate, built on the same AST the
`refinery.lib.scripts.js.analysis.model.SemanticModel` describes and keyed to AST node identity
(`node_of`). The graph is a disposable, per-function view — the tree stays the spine — that a later
pass walks for flow-sensitive questions such as which definitions reach a use and which stores are
dead.

It is *conservative by construction*: where modelling control flow precisely would be intricate (the
order of evaluation inside an expression, the exact point a statement throws, `finally` on an
exceptional path) the graph adds edges rather than omits them, so an analysis reading it sees at least
every path the program can take. Nested function bodies are not descended into; each has its own graph.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass, field
from typing import Sequence

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsBlockStatement,
    JsBreakStatement,
    JsContinueStatement,
    JsDoWhileStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIfStatement,
    JsLabeledStatement,
    JsReturnStatement,
    JsScript,
    JsSwitchStatement,
    JsThrowStatement,
    JsTryStatement,
    JsWhileStatement,
    JsWithStatement,
)

FUNCTION_NODES = (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)

_LOOP_NODES = (
    JsWhileStatement,
    JsDoWhileStatement,
    JsForStatement,
    JsForInStatement,
    JsForOfStatement,
)


class EdgeKind(enum.Enum):
    NORMAL      = 'normal'       # noqa
    EXCEPTIONAL = 'exceptional'  # noqa


@dataclass(eq=False)
class CfgNode:
    """
    One vertex of a control-flow graph. `element` is the AST node it stands for — a statement, or a
    loop-head expression (`for` init/test/update) whose reads and writes occur at this point — or
    `None` for the synthetic entry and exit. `successors` lists the nodes control may pass to next.
    """
    element: Node | None
    successors: list[CfgNode] = field(default_factory=list)
    predecessors: list[CfgNode] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False


class ControlFlowGraph:
    """
    The control-flow graph of one function or script body. `entry` and `exit` are synthetic; every
    other node wraps an AST element reachable through `node_of`.
    """

    def __init__(self, owner: Node):
        self.owner = owner
        self.entry = CfgNode(None, is_entry=True)
        self.exit = CfgNode(None, is_exit=True)
        self.nodes: list[CfgNode] = [self.entry, self.exit]
        self._node_of: dict[int, CfgNode] = {}
        self.exceptional_edges: set[tuple[int, int]] = set()

    def node_of(self, element: Node) -> CfgNode | None:
        """
        The graph node standing for *element*, or `None` if *element* is not part of this body (or is a
        node the graph does not represent on its own, such as a plain expression inside a statement).
        """
        return self._node_of.get(id(element))

    def is_exceptional(self, source: CfgNode, target: CfgNode) -> bool:
        """
        Whether the edge from *source* to *target* is taken only when *source* throws rather than
        completing normally. A definition *source* makes is not guaranteed to have happened along such
        an edge, so a flow-sensitive analysis must not treat it as a kill there.
        """
        return (id(source), id(target)) in self.exceptional_edges


class ElementLocator:
    """
    Locates an AST node among the per-function control-flow graphs of one script. Built once from the
    graph set, it maps an element to the graph and node that evaluate it — directly for an element a
    graph node stands for (`node_of`), or by climbing to the enclosing statement for one nested inside an
    expression (`locate`). The flow-sensitive analysis layers built on the graphs share it, so the
    AST-to-graph mapping and its parent-climb live in one place.
    """

    def __init__(self, graphs: dict[int, ControlFlowGraph]):
        self._element_graph: dict[int, ControlFlowGraph] = {}
        for graph in graphs.values():
            for node in graph.nodes:
                if node.element is not None:
                    self._element_graph[id(node.element)] = graph

    def node_of(self, element: Node) -> CfgNode | None:
        """
        The control-flow node standing for *element* in whichever graph owns it, or `None` when
        *element* is not itself a node the graphs represent (a plain expression inside a statement).
        """
        graph = self._element_graph.get(id(element))
        return graph.node_of(element) if graph is not None else None

    def locate(self, element: Node) -> tuple[ControlFlowGraph, CfgNode] | None:
        """
        The graph and node that evaluate *element*, climbing out of any expression it is nested in to the
        enclosing statement (or loop head), or `None` when it has no enclosing graph node.
        """
        cursor: Node | None = element
        while cursor is not None:
            graph = self._element_graph.get(id(cursor))
            if graph is not None:
                node = graph.node_of(cursor)
                if node is not None:
                    return graph, node
            cursor = cursor.parent
        return None


@dataclass
class _Target:
    """
    A jump destination active while a breakable or continuable construct is being built. `breaks`
    collects the nodes that `break` out of it (wired to whatever follows once it is known); `continue_to`
    is the node a `continue` jumps to, or `None` for a construct that only `break` can leave.
    """
    label: str | None
    breaks: list[CfgNode]
    continue_to: CfgNode | None
    is_loop: bool
    is_switch: bool


def _body_statements(owner: Node) -> list[Node]:
    if isinstance(owner, JsScript):
        return list(owner.body)
    body = getattr(owner, 'body', None)
    if isinstance(body, JsBlockStatement):
        return list(body.body)
    if isinstance(body, Node):
        return [body]
    return []


class _Builder:
    """
    Single-pass construction of one `ControlFlowGraph` by structural recursion over the body, threading
    a *frontier* — the set of nodes from which normal control currently falls through — into each
    statement and out the other side.
    """

    def __init__(self, owner: Node):
        self.cfg = ControlFlowGraph(owner)
        self._handlers: list[CfgNode] = []
        self._targets: list[_Target] = []
        self._pending_label: str | None = None

    def build(self) -> ControlFlowGraph:
        frontier = self._sequence(_body_statements(self.cfg.owner), [self.cfg.entry])
        self._link(frontier, self.cfg.exit)
        return self.cfg

    def _node(self, element: Node) -> CfgNode:
        node = CfgNode(element)
        self.cfg.nodes.append(node)
        self.cfg._node_of[id(element)] = node
        if self._handlers:
            self._exceptional_edge(node, self._handlers[-1])
        return node

    @staticmethod
    def _add_edge(source: CfgNode, target: CfgNode):
        source.successors.append(target)
        target.predecessors.append(source)

    def _exceptional_edge(self, source: CfgNode, target: CfgNode):
        self._add_edge(source, target)
        self.cfg.exceptional_edges.add((id(source), id(target)))

    def _link(self, frontier: list[CfgNode], target: CfgNode):
        for node in frontier:
            self._add_edge(node, target)

    def _sequence(self, statements: Sequence[Node], frontier: list[CfgNode]) -> list[CfgNode]:
        for statement in statements:
            frontier = self._statement(statement, frontier)
        return frontier

    def _statement(self, statement: Node, frontier: list[CfgNode]) -> list[CfgNode]:
        if isinstance(statement, JsBlockStatement):
            return self._sequence(statement.body, frontier)
        if isinstance(statement, JsIfStatement):
            return self._if(statement, frontier)
        if isinstance(statement, JsWhileStatement):
            return self._while(statement, frontier)
        if isinstance(statement, JsDoWhileStatement):
            return self._do_while(statement, frontier)
        if isinstance(statement, JsForStatement):
            return self._for(statement, frontier)
        if isinstance(statement, (JsForInStatement, JsForOfStatement)):
            return self._for_each(statement, frontier)
        if isinstance(statement, JsSwitchStatement):
            return self._switch(statement, frontier)
        if isinstance(statement, JsTryStatement):
            return self._try(statement, frontier)
        if isinstance(statement, JsLabeledStatement):
            return self._labeled(statement, frontier)
        if isinstance(statement, JsReturnStatement):
            node = self._node(statement)
            self._link(frontier, node)
            self._add_edge(node, self.cfg.exit)
            return []
        if isinstance(statement, JsThrowStatement):
            node = self._node(statement)
            self._link(frontier, node)
            self._exceptional_edge(node, self._handlers[-1] if self._handlers else self.cfg.exit)
            return []
        if isinstance(statement, JsBreakStatement):
            return self._break(statement, frontier)
        if isinstance(statement, JsContinueStatement):
            return self._continue(statement, frontier)
        if isinstance(statement, JsWithStatement):
            node = self._node(statement)
            self._link(frontier, node)
            return self._statement(statement.body, [node]) if statement.body else [node]
        node = self._node(statement)
        self._link(frontier, node)
        return [node]

    def _if(self, statement: JsIfStatement, frontier: list[CfgNode]) -> list[CfgNode]:
        node = self._node(statement)
        self._link(frontier, node)
        exits = self._branch(statement.consequent, node)
        exits += self._branch(statement.alternate, node) if statement.alternate else [node]
        return exits

    def _body(self, body: Node | None, frontier: list[CfgNode]) -> list[CfgNode]:
        return self._statement(body, list(frontier)) if body is not None else list(frontier)

    def _branch(self, body: Node | None, head: CfgNode) -> list[CfgNode]:
        return self._body(body, [head])

    def _capture_body(
        self, body: Node | None, frontier: list[CfgNode],
    ) -> tuple[CfgNode | None, list[CfgNode]]:
        """
        Build *body* and return its entry node — the node control reaches first — alongside its exit
        frontier. Used where a back-edge must target the body's own entry — a `do`/`while` or a `for`
        with no test — which the plain frontier threading does not expose.

        The entry is the first successor the incoming *frontier* gains while *body* is built, not the
        first node created. A body that opens with a `try` builds its handler or finalizer node before
        any guarded statement, so creation order would return that handler — a node with no edge back
        into the body — and the loop's back-edge would be wired to it, hiding the real body head from a
        backward reachability walk. The frontier instead links to the first guarded statement, which is
        the node control actually enters.
        """
        before = [(node, len(node.successors)) for node in frontier]
        exits = self._body(body, frontier)
        for node, count in before:
            if len(node.successors) > count:
                return node.successors[count], exits
        return None, exits

    def _take_label(self) -> str | None:
        label = self._pending_label
        self._pending_label = None
        return label

    def _while(self, statement: JsWhileStatement, frontier: list[CfgNode]) -> list[CfgNode]:
        head = self._node(statement)
        self._link(frontier, head)
        target = _Target(self._take_label(), [], head, is_loop=True, is_switch=False)
        self._targets.append(target)
        body_exits = self._branch(statement.body, head)
        self._targets.pop()
        self._link(body_exits, head)
        return [head] + target.breaks

    def _do_while(self, statement: JsDoWhileStatement, frontier: list[CfgNode]) -> list[CfgNode]:
        test = self._node(statement)
        target = _Target(self._take_label(), [], test, is_loop=True, is_switch=False)
        self._targets.append(target)
        entry, body_exits = self._capture_body(statement.body, frontier)
        self._targets.pop()
        self._link(body_exits, test)
        self._add_edge(test, entry if entry is not None else test)
        return [test] + target.breaks

    def _for(self, statement: JsForStatement, frontier: list[CfgNode]) -> list[CfgNode]:
        label = self._take_label()
        if statement.init is not None:
            init = self._node(statement.init)
            self._link(frontier, init)
            frontier = [init]
        head = self._node(statement.test) if statement.test is not None else None
        if head is not None:
            self._link(frontier, head)
            body_frontier: list[CfgNode] = [head]
        else:
            body_frontier = list(frontier)
        update = self._node(statement.update) if statement.update is not None else None
        target = _Target(label, [], update or head, is_loop=True, is_switch=False)
        self._targets.append(target)
        entry, body_exits = self._capture_body(statement.body, body_frontier)
        self._targets.pop()
        latch = body_exits
        if update is not None:
            self._link(body_exits, update)
            latch = [update]
        back_to = head if head is not None else entry
        if back_to is not None:
            self._link(latch, back_to)
        exits = list(target.breaks)
        if head is not None:
            exits.append(head)
        return exits

    def _for_each(self, statement: Node, frontier: list[CfgNode]) -> list[CfgNode]:
        head = self._node(statement)
        self._link(frontier, head)
        target = _Target(self._take_label(), [], head, is_loop=True, is_switch=False)
        self._targets.append(target)
        body_exits = self._branch(getattr(statement, 'body', None), head)
        self._targets.pop()
        self._link(body_exits, head)
        return [head] + target.breaks

    def _switch(self, statement: JsSwitchStatement, frontier: list[CfgNode]) -> list[CfgNode]:
        head = self._node(statement)
        self._link(frontier, head)
        target = _Target(self._take_label(), [], None, is_loop=False, is_switch=True)
        self._targets.append(target)
        fallthrough: list[CfgNode] = []
        has_default = False
        for case in statement.cases:
            entry = [head] + fallthrough
            fallthrough = self._sequence(list(case.body), entry)
            if case.test is None:
                has_default = True
        self._targets.pop()
        exits = list(fallthrough) + target.breaks
        if not has_default:
            exits.append(head)
        return exits

    def _try(self, statement: JsTryStatement, frontier: list[CfgNode]) -> list[CfgNode]:
        handler_entry: CfgNode | None = None
        if statement.handler is not None:
            handler_entry = self._node(statement.handler)
        finalizer_entry: CfgNode | None = None
        if statement.finalizer is not None:
            finalizer_entry = CfgNode(statement.finalizer)
            self.cfg.nodes.append(finalizer_entry)
        guard = handler_entry or finalizer_entry
        if guard is not None:
            self._handlers.append(guard)
        block_exits = self._statement(statement.block, frontier) if statement.block else list(frontier)
        if guard is not None:
            self._handlers.pop()
        normal_exits = list(block_exits)
        if statement.handler is not None and handler_entry is not None:
            body = statement.handler.body
            normal_exits += self._statement(body, [handler_entry]) if body is not None else [handler_entry]
        if statement.finalizer is not None:
            assert finalizer_entry is not None
            self._link(normal_exits, finalizer_entry)
            self.cfg._node_of[id(statement.finalizer)] = finalizer_entry
            final_exits = self._sequence(list(statement.finalizer.body), [finalizer_entry])
            self._exceptional_edge(
                finalizer_entry, self._handlers[-1] if self._handlers else self.cfg.exit)
            return final_exits
        return normal_exits

    def _labeled(self, statement: JsLabeledStatement, frontier: list[CfgNode]) -> list[CfgNode]:
        label = statement.label.name if statement.label is not None else None
        body = statement.body
        if isinstance(body, (*_LOOP_NODES, JsSwitchStatement)):
            self._pending_label = label
            return self._statement(body, frontier)
        target = _Target(label, [], None, is_loop=False, is_switch=False)
        self._targets.append(target)
        exits = self._statement(body, frontier) if body is not None else list(frontier)
        self._targets.pop()
        return exits + target.breaks

    def _break(self, statement: JsBreakStatement, frontier: list[CfgNode]) -> list[CfgNode]:
        node = self._node(statement)
        self._link(frontier, node)
        label = statement.label.name if statement.label is not None else None
        target = self._break_target(label)
        if target is not None:
            target.breaks.append(node)
        else:
            self._add_edge(node, self.cfg.exit)
        return []

    def _continue(self, statement: JsContinueStatement, frontier: list[CfgNode]) -> list[CfgNode]:
        node = self._node(statement)
        self._link(frontier, node)
        label = statement.label.name if statement.label is not None else None
        target = self._continue_target(label)
        if target is not None and target.continue_to is not None:
            self._add_edge(node, target.continue_to)
        else:
            self._add_edge(node, self.cfg.exit)
        return []

    def _break_target(self, label: str | None) -> _Target | None:
        for target in reversed(self._targets):
            if label is None:
                if target.is_loop or target.is_switch:
                    return target
            elif target.label == label:
                return target
        return None

    def _continue_target(self, label: str | None) -> _Target | None:
        for target in reversed(self._targets):
            if not target.is_loop:
                continue
            if label is None or target.label == label:
                return target
        return None


def build_cfg(owner: Node) -> ControlFlowGraph:
    """
    Build the control-flow graph of *owner*, a `refinery.lib.scripts.js.model.JsScript` or a
    function node, over its own body without descending into nested function bodies.
    """
    return _Builder(owner).build()


def build_control_flow(root: JsScript) -> dict[int, ControlFlowGraph]:
    """
    Build one control-flow graph per function and for the script itself, keyed by the owner node's
    identity. The graphs are independent: a nested function appears in its parent's graph only as the
    statement that defines it, never as descended-into control flow.
    """
    graphs: dict[int, ControlFlowGraph] = {id(root): build_cfg(root)}
    for node in root.walk():
        if isinstance(node, FUNCTION_NODES):
            graphs[id(node)] = build_cfg(node)
    return graphs
