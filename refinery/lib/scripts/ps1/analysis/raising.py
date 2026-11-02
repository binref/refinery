"""
What a point of a PowerShell script may raise: the one answer to whether a line can fail, and how.

`Ps1RaiseModel` answers it for one version of one tree under one reading of the world: without one,
for a caller that holds none, and under the flow-sensitive world of
`refinery.lib.scripts.ps1.analysis.worldflow`, which is the reading every pass that holds a world
asks. Every reader of a point in the tree reads `Ps1RaiseModel.kinds`: the trap removal, the removal
veto, the store sweep, the `catch` lift, and the grant the variable flow makes for a store that
cannot fail.

What a point raises is read off what it evaluates (`refinery.lib.scripts.ps1.ast.point_operands`):
an operand the clearing rules clear raises nothing, and every other one raises what
`refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.kinds_the_try_catches` reads it as raising,
with what the bodies it may run hand back read off those bodies, bottom-up over the calls between
them. Where the error goes from there is the fault model's question, not this one's.
"""
from __future__ import annotations

from typing import Callable, Sequence

from refinery.lib.scripts import Block, Node, tree_version
from refinery.lib.scripts.analysis.cfg import ControlFlowGraph
from refinery.lib.scripts.ps1 import data
from refinery.lib.scripts.ps1.analysis.assignment import Ps1DefiniteAssignment
from refinery.lib.scripts.ps1.analysis.callgraph import Ps1CallGraph
from refinery.lib.scripts.ps1.analysis.calls import call_reader
from refinery.lib.scripts.ps1.analysis.cfg import Ps1ControlFlowModel
from refinery.lib.scripts.ps1.analysis.commands import CommandKind, Ps1CommandModel
from refinery.lib.scripts.ps1.analysis.dispatch import EVERY_KIND, HANDED_BACK, Ps1ErrorKind
from refinery.lib.scripts.ps1.analysis.faults import Ps1FaultReach
from refinery.lib.scripts.ps1.analysis.model import Ps1NameSet
from refinery.lib.scripts.ps1.analysis.values import UNKNOWN, convert, evaluate, is_fault_free
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach
from refinery.lib.scripts.ps1.ast import get_command_name, point_operands
from refinery.lib.scripts.ps1.data import PS1_AUTOMATIC_VARIABLES, PS1_KNOWN_VARIABLES
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1Attribute,
    Ps1CatchClause,
    Ps1CommandArgument,
    Ps1CommandInvocation,
    Ps1Exit,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1FunctionDefinition,
    Ps1InvokeMember,
    Ps1Jump,
    Ps1ParameterDeclaration,
    Ps1ScopeModifier,
    Ps1ScriptBlock,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1TypeExpression,
    Ps1Variable,
)


class TreeStamp:
    """
    The tree version a set of verdicts was decided for. Once the tree moves, every verdict is
    refused, the way `refinery.lib.scripts.ps1.analysis.worldflow.Ps1WorldReach` refuses once its
    tree moves; each refusal is the answer that keeps the code.
    """

    def __init__(self, root: Node):
        self._root = root
        self._version = tree_version(root)

    def moved(self) -> bool:
        return tree_version(self._root) != self._version


def _is_bare_variable_read(node: Node) -> bool:
    """
    Whether *node* is an unqualified variable read and nothing else — the one expression shape whose
    only way to raise is a setting of the script rather than a property of its operands.

    Splatting is excluded because `@x` is not a read of the value at all, and every qualified
    spelling is excluded because none of them shares the fact this rests on. `$global:x` and
    `$script:x` read the same store and were measured not to raise, but `$using:x` is a different
    construct outside the block that binds it; and a drive qualifier reads no store at all —
    `${SomeDrive:path}` runs a provider, and what an arbitrary provider raises is not a question
    this can answer for the drives it has never seen. One test covers them because the lexer spells
    a drive as `Ps1ScopeModifier.DRIVE` like every other qualifier.

    **Purity does not gain this gate and must not.** `is_side_effect_free` accepts a bare read
    unconditionally, because reading a variable changes nothing whether or not the read raises. The
    two questions are separate here, and a reader expecting them to be symmetric would be wrong.
    """
    return (
        isinstance(node, Ps1Variable)
        and not node.splatted
        and node.scope is Ps1ScopeModifier.NONE
    )


def expression_cannot_fault(
    operand: Node,
    position: Node,
    faults: Ps1FaultReach,
    world: Ps1WorldReach | None,
) -> bool:
    """
    Whether evaluating *operand* cannot raise **where *position* stands**, read without the name
    sets and the stores `Ps1RaiseModel.cannot_fault` reads besides: the question a removal site that
    holds no raise model asks before it deletes an expression whose fault would have been observed.

    `refinery.lib.scripts.ps1.analysis.values.is_fault_free` is the context-free half and stays
    exactly that: it grants only what cannot raise under any semantics, so a bare `$x` is not
    fault-free there and must not become so. What is added here is the one fault the *script*
    decides rather than the expression. Reading a variable that was never set yields `$null` under
    the default semantics and raises only where strict mode is armed, so a script that never arms
    it cannot fault on such a read — and the padding an obfuscator writes as
    `$junk | ForEach-Object { [void]$_ }` goes.

    **Two models answer that, and neither half alone is enough.**
    `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.strict_mode_may_be_in_force` reads what
    the script itself arms, wherever it is written;
    `refinery.lib.scripts.ps1.analysis.worldflow.Ps1WorldReach.closed_at` says whether anything the
    analysis cannot read may have run before *position*, and a payload it cannot read may arm strict
    mode as easily as a spelled-out call does. A caller with no world therefore gets the
    context-free answer alone, which is the fail-closed direction: a grant refused keeps a
    statement, a grant made in error deletes one whose handler runs.

    **The world half is a bound and not an answer.** What it reports is the type world's openers,
    and a command that runs code no tree holds is not always one of them — `Set-PSDebug -Strict`
    arms strict mode for the *global* scope, so any call this analysis cannot read through can arm
    it without being a leak the world names. The bound it does give is the one that covers the
    shapes an obfuscator writes, and everything it misses is stated with the entry-scope assumption
    on `strict_mode_may_be_in_force` rather than left silent.
    """
    if is_fault_free(operand):
        return True
    if world is None:
        return False
    if not evaluate(operand, calls=call_reader(world)).may_throw:
        return True
    return (
        _is_bare_variable_read(operand)
        and world.closed_at(position)
        and not faults.strict_mode_may_be_in_force()
    )


def _stores_without_fault(target: Node | None, constrained: Ps1NameSet) -> bool:
    """
    Whether storing any value into *target* cannot fail: a plain local that is no automatic or
    preference variable and that is not among the names the script may constrain, *constrained*.
    """
    if not isinstance(target, Ps1Variable) or target.splatted or target.drive:
        return False
    if target.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL):
        return False
    name = target.name.lower()
    return not (name in PS1_AUTOMATIC_VARIABLES or name in PS1_KNOWN_VARIABLES or name in constrained)


def point_raise_kinds(
    point: Node,
    position: Node,
    faults: Ps1FaultReach,
    world: Ps1WorldReach | None,
    model: Ps1RaiseModel | None = None,
) -> Ps1ErrorKind:
    """
    The kinds of error a `try` catches that what the graphs evaluate at *point* may raise, judged
    at *position*: the error of a `throw` where *point* is one, and those
    `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.kinds_the_try_catches` reads an operand
    it evaluates as raising, with every operand the clearing rules clear read as raising nothing. A
    function definition and a block raise nothing where they stand; a point whose operands
    `refinery.lib.scripts.ps1.ast.point_operands` cannot name may raise every kind; the head of a
    `foreach` raises a statement-terminating error where its loop variable may fail the store.

    *model* supplies what the bodies an operand runs hand back, and the clearing rules that read
    the script's name sets and its certain stores; one built for a tree that has moved since may
    raise every kind. Without it, a body may hand back every kind a body can, every operand that is
    not cleared raises a statement-terminating error besides, and only `expression_cannot_fault`
    clears: the reading of a caller that holds no raise model.
    """
    if isinstance(point, (Ps1FunctionDefinition, Block)):
        return Ps1ErrorKind.NONE
    kinds = Ps1ErrorKind.THROWN if isinstance(point, Ps1ThrowStatement) else Ps1ErrorKind.NONE
    operands = point_operands(point)
    if operands is None:
        return kinds | EVERY_KIND
    if model is None:
        if isinstance(point, Ps1ForEachLoop):
            kinds |= Ps1ErrorKind.STATEMENT

        def cleared(operand: Node) -> bool:
            return expression_cannot_fault(operand, position, faults, world)

        def handed_back(operand: Node) -> Ps1ErrorKind:
            return HANDED_BACK if faults.hands_back_a_body_error(operand) else Ps1ErrorKind.NONE

        for operand in operands:
            if not cleared(operand):
                kinds |= faults.kinds_the_try_catches(operand, cleared, handed_back) | Ps1ErrorKind.STATEMENT
        return kinds
    if model.moved():
        return EVERY_KIND
    if isinstance(point, Ps1ForEachLoop) and not _stores_without_fault(point.variable, model.constrained()):
        kinds |= Ps1ErrorKind.STATEMENT

    def cleared_by_the_model(operand: Node) -> bool:
        return model.cannot_fault(operand, position)

    for operand in operands:
        if cleared_by_the_model(operand):
            continue
        kinds |= faults.kinds_the_try_catches(operand, cleared_by_the_model, model.handed_back)
        if not model.raises_only_what_its_bodies_hand_back(operand):
            kinds |= Ps1ErrorKind.STATEMENT
    return kinds


def lies_in_a_block_within(site: Node, stmt: Node) -> bool:
    """
    Whether *site* stands inside a script block that is itself written inside *stmt*. A script block
    is the boundary asked about because it is what the graph builder gives a body of its own; a
    `catch` or `trap` body written in *stmt* stays in the same graph and is judged there.
    """
    if site is stmt:
        return False
    cursor = site.parent
    crossed = False
    while cursor is not None and cursor is not stmt:
        crossed = crossed or isinstance(cursor, Ps1ScriptBlock)
        cursor = cursor.parent
    return crossed and cursor is stmt


def statement_raise_kinds(
    stmt: Node,
    position: Node,
    faults: Ps1FaultReach,
    world: Ps1WorldReach | None,
    model: Ps1RaiseModel | None = None,
) -> Ps1ErrorKind:
    """
    Every kind of error a point of *stmt* may raise, judged at *position*: the question asked of a
    statement that is not in the tree yet, at the statement it would replace. A statement the graphs
    were built from is judged by the points they place in it, where a point inside a script block
    written in *stmt* raises at the point that runs the block and is left out; one they place
    nothing of is judged as one point.

    A statement made since is judged as one point where that point is all it evaluates. A compound
    one holds tests and bodies the graphs would place apart, and they place none of its own tests,
    so judging it by the parts it reuses from the tree leaves those tests out: it may raise every
    kind.
    """
    if not faults.control_flow.built_from(stmt):
        if not isinstance(stmt, (Ps1ExpressionStatement, Ps1Exit, Ps1Jump, Ps1FunctionDefinition)):
            return EVERY_KIND
        return point_raise_kinds(stmt, position, faults, world, model)
    kinds = Ps1ErrorKind.NONE
    judged = False
    for point in faults.points_in(stmt):
        if lies_in_a_block_within(point, stmt):
            continue
        judged = True
        kinds |= point_raise_kinds(point, position, faults, world, model)
    if not judged:
        return point_raise_kinds(stmt, position, faults, world, model)
    return kinds


def bound_default_may_throw(parameter: Ps1ParameterDeclaration) -> bool:
    """
    Whether the conversion a type constraint runs over this parameter's default value can raise. A
    default with no constraint is stored as it is written and a constraint with no default converts
    nothing; only the two together reach a conversion, and it runs on every call that omits the
    argument. Measured on 5.1, `[int] $x = 'abc'` throws it and `[int] $x = '42'` binds the Int32
    42.

    Not knowing is a throw, the direction `refinery.lib.scripts.ps1.analysis.values.Ps1Outcome`
    already reads as safe: a default the value domain cannot evaluate, or a constraint naming a type
    it does not model, is one this cannot prove converts, so its call is kept rather than dropped.
    """
    default = parameter.default_value
    constraint = next(
        (a for a in parameter.attributes if isinstance(a, Ps1TypeExpression)),
        None,
    )
    if default is None or constraint is None:
        return False
    target = data.resolve_type(constraint.name)
    if target is None:
        return True
    outcome = evaluate(default)
    if outcome.may_throw or outcome.value is UNKNOWN:
        return True
    return convert(outcome.value, target).may_throw


def _strongly_connected(nodes: Sequence[Node], edges: dict[int, list[Node]]) -> list[list[Node]]:
    """
    The strongly connected components of the graph *edges* draws over *nodes*, each component after
    every component it reaches, found without recursion.
    """
    index: dict[int, int] = {}
    low: dict[int, int] = {}
    on_stack: set[int] = set()
    stack: list[Node] = []
    components: list[list[Node]] = []
    for root in nodes:
        if id(root) in index:
            continue
        index[id(root)] = low[id(root)] = len(index)
        stack.append(root)
        on_stack.add(id(root))
        work: list[tuple[Node, int]] = [(root, 0)]
        while work:
            node, position = work[-1]
            successors = edges.get(id(node), [])
            if position < len(successors):
                work[-1] = (node, position + 1)
                successor = successors[position]
                if id(successor) not in index:
                    index[id(successor)] = low[id(successor)] = len(index)
                    stack.append(successor)
                    on_stack.add(id(successor))
                    work.append((successor, 0))
                elif id(successor) in on_stack:
                    low[id(node)] = min(low[id(node)], index[id(successor)])
                continue
            work.pop()
            if work:
                caller = work[-1][0]
                low[id(caller)] = min(low[id(caller)], low[id(node)])
            if low[id(node)] == index[id(node)]:
                component: list[Node] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(id(member))
                    component.append(member)
                    if member is node:
                        break
                components.append(component)
    return components


class Ps1RaiseModel:
    """
    What each point of one tree may raise under one reading of the world, *world*, or none: the one
    answer every reader of a point asks, `kinds`, and the one reader of which bodies a call runs,
    `bodies_run_by`. Every model it reads is handed in at construction and belongs to the tree
    version it was built for; once that tree moves (`moved`), `kinds` answers every kind and so does
    `point_raise_kinds` handed the model, and the model is discarded with the cache that built it.
    A model a question may not need is handed in as the function the cache answers it with, so that
    a reading which never asks about a call or a name never builds the models that answer one.

    *calls* and *commands* say which bodies a call runs; *defined* gives the calls a definition of
    the name they call certainly ran before (see
    `refinery.lib.scripts.ps1.analysis.callgraph.calls_after_a_definition`). *removed* and
    *constrained* give the names the script may remove or constrain, which the clearing rules read,
    and *control_flow* holds the graphs the stores certainly made before a read are solved over.

    **The clearing rules.** Beside `expression_cannot_fault`, two rules clear an operand, and both
    hold only where the world is closed at the position, since code nobody can read may remove or
    constrain any name before it; a model without a world applies neither:

    - a plain `=` store into a plain local of a cleared value cannot fail, where the name is no
      automatic or preference variable and is not among the names the script may constrain;
    - a bare read of a plain local cannot fail where a store to it certainly completed earlier in
      the same body, which `refinery.lib.scripts.ps1.analysis.assignment.Ps1DefiniteAssignment`
      answers; a name the script may remove is never certainly stored.

    **What a body hands back** to whatever runs it is read off the body, bottom-up over the calls
    between bodies: a statement-terminating error that leaves it arrives as one the caller's list
    passes outward (`refinery.lib.scripts.ps1.analysis.dispatch.Ps1ErrorKind.CALLED`), and so does
    one the body disposes of otherwise when its caller passes errors outward; the error of a
    `throw` and one no list reports arrive as they leave. A body on a cycle of calls hands back
    every kind a body can, and so does one whose parameters may fail to bind.
    """

    def __init__(
        self,
        faults: Ps1FaultReach,
        world: Ps1WorldReach | None,
        calls: Callable[[], Ps1CallGraph],
        commands: Callable[[], Ps1CommandModel],
        defined: Callable[[], frozenset[int]],
        removed: Callable[[], Ps1NameSet],
        constrained: Callable[[], Ps1NameSet],
        control_flow: Ps1ControlFlowModel,
        root: Node,
    ):
        self.faults = faults
        self.world = world
        self.constrained = constrained
        self._calls = calls
        self._commands = commands
        self._defined = defined
        self._removed = removed
        self._control_flow = control_flow
        self._stamp = TreeStamp(root)
        self._assignment: Ps1DefiniteAssignment | None = None
        self._kinds: dict[int, Ps1ErrorKind] = {}
        self._summaries: dict[int, Ps1ErrorKind] | None = None
        self._cyclic: set[int] = set()
        self._consulted: dict[int, tuple[tuple[Ps1ScriptBlock, ...], bool]] = {}

    def kinds(self, point: Node) -> Ps1ErrorKind:
        """
        What *point* may raise, judged where it stands; every kind once the tree has moved.
        """
        if self.moved():
            return EVERY_KIND
        found = self._kinds.get(id(point))
        if found is None:
            found = self._kinds[id(point)] = point_raise_kinds(point, point, self.faults, self.world, self)
        return found

    def moved(self) -> bool:
        """
        Whether the tree this model was built for has moved since, after which no answer it holds
        speaks for the tree.
        """
        return self._stamp.moved()

    def cannot_fault(self, operand: Node, position: Node) -> bool:
        """
        Whether evaluating *operand* cannot raise where *position* stands: `expression_cannot_fault`,
        and the two clearing rules of the class docstring where the world is closed there.
        """
        return self._cleared(operand, position, self._certainly_stored_before)

    def _cleared(self, operand: Node, position: Node, stored: Callable[[Node], bool]) -> bool:
        """
        `cannot_fault`, with *stored* saying of a bare read whether a store to its name certainly
        completed before it. `expression_cannot_fault` is asked first and clears a bare read where
        the world is closed and the script arms no strict mode, so *stored* is asked only where
        strict mode may be armed.
        """
        if expression_cannot_fault(operand, position, self.faults, self.world):
            return True
        world = self.world
        if world is None or not world.closed_at(position):
            return False
        if self._stores_a_cleared_value(operand, position, stored):
            return True
        return _is_bare_variable_read(operand) and stored(operand)

    def _stores_a_cleared_value(self, operand: Node, position: Node, stored: Callable[[Node], bool]) -> bool:
        if not isinstance(operand, Ps1AssignmentExpression) or operand.operator != '=':
            return False
        if not _stores_without_fault(operand.target, self.constrained()):
            return False
        value = operand.value
        return value is not None and self._cleared(value, position, stored)

    def _certainly_stored_before(self, read: Node) -> bool:
        if not isinstance(read, Ps1Variable):
            return False
        removed = self._removed()
        if read.name.lower() in removed:
            return False
        assignment = self._assignment
        if assignment is None:
            assignment = self._assignment = Ps1DefiniteAssignment(
                self._control_flow, lambda name: name in removed, self._completes)
        return assignment.assigned_before(read)

    def _completes(self, store: Node, stored: Callable[[Node], bool]) -> bool:
        """
        Whether the expression *store*, which stores into a plain local, certainly completes where
        it stands, with *stored* saying of a bare read whether a store to its name certainly
        completed before it. Where nothing takes an error, 5.1 reports it and carries on along the
        edge a completed store leaves by, so a store that may fail is no certain store.
        """
        return self._cleared(store, store, stored)

    def handed_back(self, operand: Node) -> Ps1ErrorKind:
        """
        What the bodies evaluating *operand* may run hand back to it.
        """
        bodies, unknown = self.bodies_consulted(operand)
        if unknown:
            return HANDED_BACK
        if not bodies:
            return Ps1ErrorKind.NONE
        table = self._summary_table()
        kinds = Ps1ErrorKind.NONE
        for body in bodies:
            kinds |= table.get(id(body), HANDED_BACK)
        return kinds

    def is_recursive(self, body: Node) -> bool:
        """
        Whether *body* may run itself again, through the calls its points make.
        """
        self._summary_table()
        return id(body) in self._cyclic

    def bodies_run_by(self, call: Node) -> tuple[Ps1ScriptBlock, ...] | None:
        """
        The bodies of the script *call* may run, or `None` where it may run one this cannot name:
        the script block it runs with `&` or `.`, or the definitions of the script function its
        name denotes where it stands, read through the call graph where it can be read and no
        keyword statement defines the name as well.
        """
        if not isinstance(call, Ps1CommandInvocation):
            return None
        if isinstance(call.name, Ps1ScriptBlock):
            return (call.name,) if call.invocation_operator in ('&', '.') else None
        if call.invocation_operator not in ('', '&', '.'):
            return None
        name = get_command_name(call)
        if name is None:
            return None
        calls = self._calls()
        if not calls.is_readable or calls.keyword_definitions(name):
            return None
        if self._commands().denotation(call).kind is not CommandKind.FUNCTION:
            return None
        definitions = calls.definitions(name)
        bodies = tuple(definition.body for definition in definitions if definition.body is not None)
        if not bodies or len(bodies) != len(definitions):
            return None
        return bodies

    def raises_only_what_its_bodies_hand_back(self, operand: Node) -> bool:
        """
        Whether evaluating *operand* raises nothing but what the bodies it runs hand back: a bare
        call — no argument, no redirection — of a script block, or of a script function a definition
        of which certainly ran before it, where every body it may run binds without fault.
        """
        if not isinstance(operand, Ps1CommandInvocation) or operand.redirections or operand.arguments:
            return False
        bodies = self.bodies_run_by(operand)
        if not bodies:
            return False
        if not isinstance(operand.name, Ps1ScriptBlock) and id(operand) not in self._defined():
            return False
        return all(self.binds_without_fault(body) for body in bodies)

    def binds_without_fault(self, body: Ps1ScriptBlock) -> bool:
        """
        Whether a call handing *body* no argument binds its parameters without fault: no dynamic
        parameters, no attribute on the block or a parameter, every default fault-free, and a type
        on a parameter only where it converts the default without fault.
        """
        if body.dynamicparam_block is not None:
            return False
        block = body.param_block
        if block is None:
            return True
        if block.attributes:
            return False
        for parameter in block.parameters:
            if any(isinstance(attribute, Ps1Attribute) for attribute in parameter.attributes):
                return False
            default = parameter.default_value
            if default is None:
                if parameter.attributes:
                    return False
                continue
            if not is_fault_free(default) or bound_default_may_throw(parameter):
                return False
        return True

    def bodies_consulted(self, node: Node) -> tuple[tuple[Ps1ScriptBlock, ...], bool]:
        """
        The bodies evaluating *node* may run, and whether it may run one this cannot name: what a
        call there runs, and a script block handed to a command there. A script block written as a
        value runs only where something runs it, so what it holds is not read here. Kept for every
        node the walk passes, so that a nest of `$( )` costs its size.
        """
        memo = self._consulted
        found = memo.get(id(node))
        if found is not None:
            return found
        calls = self._calls()
        stack: list[tuple[Node, bool]] = [(node, False)]
        while stack:
            current, expanded = stack.pop()
            if id(current) in memo:
                continue
            children = current.children()
            if not expanded:
                stack.append((current, True))
                stack.extend(
                    (child, False) for child in children
                    if not isinstance(child, Ps1ScriptBlock) and id(child) not in memo
                )
                continue
            bodies: dict[int, Ps1ScriptBlock] = {}
            unknown = False
            if isinstance(current, (Ps1CommandInvocation, Ps1InvokeMember)) and calls.may_run_a_body(current):
                run = self.bodies_run_by(current)
                if run is None:
                    unknown = True
                else:
                    bodies.update((id(body), body) for body in run)
            handed = isinstance(current, (Ps1CommandInvocation, Ps1CommandArgument))
            for child in children:
                if isinstance(child, Ps1ScriptBlock):
                    if handed:
                        bodies[id(child)] = child
                    continue
                below, below_unknown = memo[id(child)]
                bodies.update((id(body), body) for body in below)
                unknown = unknown or below_unknown
            memo[id(current)] = (tuple(bodies.values()), unknown)
        return memo[id(node)]

    def _summary_table(self) -> dict[int, Ps1ErrorKind]:
        """
        What every body hands back, computed once for the tree, a body after every body it runs; a
        body that may run itself again hands back every kind a body can. The table is in place
        before it is filled, so a summary read while another is computed finds the bodies it runs
        summarized already.
        """
        table = self._summaries
        if table is not None:
            return table
        table = self._summaries = {}
        graphs = {id(graph.owner): graph for graph in self.faults.control_flow.graphs.values()}
        bodies: list[Node] = [graph.owner for graph in graphs.values() if isinstance(graph.owner, Ps1ScriptBlock)]
        edges: dict[int, list[Node]] = {}
        for body in bodies:
            runs: dict[int, Node] = {}
            for cfg_node in graphs[id(body)].nodes:
                point = cfg_node.element
                if point is None or isinstance(point, (Ps1CatchClause, Ps1TrapStatement)):
                    continue
                for operand in point_operands(point) or ():
                    run, _ = self.bodies_consulted(operand)
                    runs.update((id(callee), callee) for callee in run)
            edges[id(body)] = list(runs.values())
        for component in _strongly_connected(bodies, edges):
            first = component[0]
            if len(component) > 1 or any(callee is first for callee in edges.get(id(first), ())):
                for body in component:
                    table[id(body)] = HANDED_BACK
                    self._cyclic.add(id(body))
                continue
            graph = graphs.get(id(first))
            table[id(first)] = HANDED_BACK if graph is None else self._summarize(first, graph)
        return table

    def _summarize(self, body: Node, graph: ControlFlowGraph) -> Ps1ErrorKind:
        """
        What *body*, whose graph is *graph*, hands back to whatever runs it.
        """
        kinds = Ps1ErrorKind.NONE
        if not isinstance(body, Ps1ScriptBlock) or not self.binds_without_fault(body):
            kinds |= HANDED_BACK
        evaluation = self.faults.dispatch.evaluation
        for cfg_node in graph.nodes:
            point = cfg_node.element
            if point is None or isinstance(point, (Ps1CatchClause, Ps1TrapStatement)):
                continue
            raised = self.kinds(point)
            if not raised:
                continue
            unguarded = evaluation.fate(point, raised, False)
            guarded = evaluation.fate(point, raised, True)
            if unguarded is None or guarded is None:
                kinds |= HANDED_BACK
                continue
            leaving = unguarded.to_caller | guarded.to_caller
            if leaving & Ps1ErrorKind.STATEMENT or unguarded != guarded:
                kinds |= Ps1ErrorKind.CALLED
            kinds |= leaving & (Ps1ErrorKind.THROWN | Ps1ErrorKind.MARKED)
        return kinds

