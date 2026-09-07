"""
JavaScript's contribution to the shared control-flow substrate: which node types are which
control-flow shape, and where the parts of each are stored.

Everything structural — the graph, the frontier threading, the jump-target and handler stacks, and
the shapes themselves — lives in `refinery.lib.scripts.analysis.cfg`. What remains here is
`_Builder.statement`, the recognition of `Js*` node types, and the accessors that pull a construct
apart. Three of the shape parameters are answered from JavaScript semantics rather than from syntax:
`switch` falls through from one case to the next, an unlabelled `break` may leave a `switch` as well
as a loop, and a `catch` carries no type filter, so a throw the guarded block makes gets past it only
where binding the caught value can itself throw — see `_catch_may_rethrow`.
"""
from __future__ import annotations

from typing import Sequence

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.cfg import (
    ArmFlow,
    CfgBuilder,
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    ElementLocator,
)
from refinery.lib.scripts.analysis.cfg import build_control_flow as _build_control_flow
from refinery.lib.scripts.js.analysis.model import FUNCTION_NODES
from refinery.lib.scripts.js.model import (
    JsArrayPattern,
    JsBlockStatement,
    JsBreakStatement,
    JsCatchClause,
    JsContinueStatement,
    JsDoWhileStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsIfStatement,
    JsLabeledStatement,
    JsObjectPattern,
    JsReturnStatement,
    JsScript,
    JsSwitchCase,
    JsSwitchStatement,
    JsThrowStatement,
    JsTryStatement,
    JsWhileStatement,
    JsWithStatement,
)

__all__ = [
    'CfgNode',
    'ControlFlowGraph',
    'ControlFlowModel',
    'ElementLocator',
    'build_cfg',
    'build_control_flow',
    'build_control_flow_model',
]

_LOOP_NODES = (
    JsWhileStatement,
    JsDoWhileStatement,
    JsForStatement,
    JsForInStatement,
    JsForOfStatement,
)


def _catch_may_rethrow(handler: JsCatchClause | None) -> bool:
    """
    Whether a throw offered to *handler* may still reach whatever guards the construct.

    A `catch` carries no type filter, so the clause always matches and the throw stops there — with
    one exception, which is why this is a question rather than a constant. Binding the caught value
    is a destructuring assignment when the parameter is a pattern, and destructuring evaluates:
    `catch ({ a })` over a thrown `null` throws again while binding, and that second throw leaves
    the construct. A plain identifier binds by name and an omitted parameter binds nothing, so
    neither can.
    """
    if handler is None:
        return False
    return isinstance(handler.param, (JsObjectPattern, JsArrayPattern))


def _label_name(statement: Node) -> str | None:
    label = getattr(statement, 'label', None)
    return label.name if label is not None else None


class _Builder(CfgBuilder):
    """
    The JavaScript dispatch over `refinery.lib.scripts.analysis.cfg.CfgBuilder`.
    """

    def body_blocks(self, owner: Node) -> Sequence[Sequence[Node]]:
        """
        The one block a JavaScript body is. A concise arrow function's body is an expression rather
        than a block, and it is reported as the single statement it evaluates.
        """
        if isinstance(owner, JsScript):
            return [list(owner.body)]
        body = getattr(owner, 'body', None)
        if isinstance(body, JsBlockStatement):
            return [list(body.body)]
        if isinstance(body, Node):
            return [[body]]
        return []

    def statement(self, statement: Node, frontier: list[CfgNode]) -> list[CfgNode]:
        if isinstance(statement, JsBlockStatement):
            return self.sequence(statement.body, frontier)
        if isinstance(statement, JsIfStatement):
            arms: list[Node | None] = [statement.consequent]
            if statement.alternate is not None:
                arms.append(statement.alternate)
            return self.branch_on(
                statement, arms, frontier, exhaustive=statement.alternate is not None)
        if isinstance(statement, JsWhileStatement):
            return self.loop_head_tested(statement, statement.body, frontier)
        if isinstance(statement, JsDoWhileStatement):
            return self.loop_tail_tested(statement, statement.body, frontier)
        if isinstance(statement, JsForStatement):
            return self.loop_counted(
                statement.init, statement.test, statement.update, statement.body, frontier)
        if isinstance(statement, (JsForInStatement, JsForOfStatement)):
            return self.loop_head_tested(statement, getattr(statement, 'body', None), frontier)
        if isinstance(statement, JsSwitchStatement):
            return self._switch(statement, frontier)
        if isinstance(statement, JsTryStatement):
            handler = statement.handler
            finalizer = statement.finalizer
            return self.guarded(
                statement.block,
                [(handler, handler.body)] if handler is not None else (),
                finalizer,
                list(finalizer.body) if finalizer is not None else (),
                frontier,
                escapes=_catch_may_rethrow(handler),
            )
        if isinstance(statement, JsLabeledStatement):
            return self.labelled(
                _label_name(statement),
                statement.body,
                frontier,
                binds_to_body=isinstance(statement.body, (*_LOOP_NODES, JsSwitchStatement)),
            )
        if isinstance(statement, JsReturnStatement):
            return self.terminate(statement, frontier, exceptional=False)
        if isinstance(statement, JsThrowStatement):
            return self.terminate(statement, frontier, exceptional=True)
        if isinstance(statement, JsBreakStatement):
            return self.jump_out(statement, _label_name(statement), frontier)
        if isinstance(statement, JsContinueStatement):
            return self.jump_back(statement, _label_name(statement), frontier)
        if isinstance(statement, JsWithStatement):
            node = self.node(statement)
            self.link(frontier, node)
            return self.statement(statement.body, [node]) if statement.body else [node]
        return self.opaque(statement, frontier)

    def _switch(self, statement: JsSwitchStatement, frontier: list[CfgNode]) -> list[CfgNode]:
        cases = [case for case in statement.cases if isinstance(case, JsSwitchCase)]
        if len(cases) != len(statement.cases):
            return self.opaque(statement, frontier)
        arms: list[Sequence[Node]] = [list(case.body) for case in cases]
        exhaustive = any(case.test is None for case in cases)
        return self.dispatch(
            statement, arms, frontier, arm_flow=ArmFlow.SEQUENTIAL, exhaustive=exhaustive)


def build_cfg(owner: Node) -> ControlFlowGraph:
    """
    Build the control-flow graph of *owner*, a `refinery.lib.scripts.js.model.JsScript` or a
    function node, over its own body without descending into nested function bodies.
    """
    return _Builder(owner).build()


def build_control_flow(root: JsScript) -> dict[int, ControlFlowGraph]:
    """
    Build one control-flow graph per function and for the script itself, keyed by the owner node's
    identity.
    """
    return _build_control_flow(root, _Builder, FUNCTION_NODES)


def build_control_flow_model(root: JsScript) -> ControlFlowModel:
    """
    Build the `refinery.lib.scripts.analysis.cfg.ControlFlowModel` for a script root — the shared
    control-flow layer the `DominanceModel` and `LivenessModel` consume.
    """
    return ControlFlowModel(build_control_flow(root))
