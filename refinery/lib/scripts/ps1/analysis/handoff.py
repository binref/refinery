"""
Where the object a variable occurrence reads goes once the expression around it has run.

A read hands over the object a name holds and not a copy of it, and PowerShell keeps that object in
many more places than a second variable: an element of an array literal, the value of a hash entry,
a slot of a container that already exists, the parameter of a body it is passed to, the pipeline
variable of a block it is piped into, a `foreach` variable, and the output a caller of a body
collects. A store reaching the object through any of those places changes what the name holds, and
none of them is an occurrence of the name. `object_handoff` classifies a read by which of those it
reaches; `refinery.lib.scripts.ps1.analysis.objects.Ps1ObjectFlow` orders the stores against it.

The climb follows the object outwards and counts how deep inside the value at the cursor it sits.
An expression that may give back the very object it was handed passes it on at the same depth;
which expressions those are is `refinery.lib.scripts.ps1.analysis.identity.passage_out_of`'s to
say. Building a container around it puts it one level deeper; unrolling a value — a pipeline,
`@( )`, an operator, the output of a body — takes the elements out of their container, so the object
itself survives only if it was inside one, and otherwise only its elements go on. Taking an index or
a member hands on a part of the value and no more. Where the climb ends, a place that keeps what it
is handed keeps the object itself if the depth is not negative and only objects inside it if it is.

Objects a command writes are collected when a value is made of them, and the collection is a
container around them: `@(,$x)` holds the array `$x` holds as its one element, and a `foreach` over
it hands that very array to the loop variable.
"""
from __future__ import annotations

import enum
import typing

from typing import Callable

from refinery.lib.scripts import Expression, Node
from refinery.lib.scripts.ps1 import data
from refinery.lib.scripts.ps1.analysis.arguments import RECEIVER, keeps_nothing
from refinery.lib.scripts.ps1.analysis.identity import passage_out_of
from refinery.lib.scripts.ps1.analysis.model import written_slots_of
from refinery.lib.scripts.ps1.analysis.naming import Ps1NameRole, named_references
from refinery.lib.scripts.ps1.analysis.values import UNKNOWN, read, resolve_expression_type
from refinery.lib.scripts.ps1.ast import (
    binds_parameter,
    get_command_name,
    get_member_name,
    unwrap_assignment_target,
)
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1FunctionDefinition,
    Ps1HashLiteral,
    Ps1IndexExpression,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1MethodMember,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1PropertyMember,
    Ps1RangeExpression,
    Ps1ReturnStatement,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1SubExpression,
    Ps1SwitchStatement,
    Ps1ThrowStatement,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)


class Ps1Handoff(enum.Enum):
    """
    What keeps the object a read produces once the expression around the read has run.

    `NOWHERE` — nothing keeps the object or anything inside it.
    `PARTS` — something keeps objects the value holds but not the value itself: `$y = @($x)`,
    `foreach ($e in $x)`, `$q = $x[0]`.
    `OBJECT` — something keeps the object itself: a second name, as `$y = $x` gives it one, an
    element of a new array, a hash entry, a slot of another container, a callee, a caller
    collecting the output of a body.
    """
    NOWHERE = 0
    PARTS   = 1  # noqa
    OBJECT  = 2  # noqa

    def widest(self, other: Ps1Handoff) -> Ps1Handoff:
        """
        Whichever of the two keeps more of the object.
        """
        return self if self.value >= other.value else other


#: Commands that consume what they are handed and keep nothing of it: each writes a rendering of it
#: somewhere that is not a value of the script. `Write-Information` is not one of them, because the
#: record it writes holds the object itself and `6>&1` hands that record to whoever collects it.
_CONSUMING_COMMANDS = frozenset({
    'out-host',
    'out-null',
    'out-string',
    'write-debug',
    'write-host',
    'write-verbose',
    'write-warning',
})

#: Commands that write out the objects they are handed and keep none of them. What they write goes
#: wherever their own output goes. `Write-Output` writes the elements of a value handed to it as an
#: argument unless it is told `-NoEnumerate`.
_PASSING_COMMANDS = frozenset({
    'write-output',
})

#: Commands that write out the objects piped into them, one at a time, and keep none of them while
#: every argument they are given is a constant. A script block or a calculated property among the
#: arguments runs with `$_` bound to each object, and a value handed as `-InputObject` is written as
#: one record rather than element by element; either is a place that keeps what it is handed.
_FILTERING_COMMANDS = frozenset({
    'select-object',
    'sort-object',
    'where-object',
})


def binds_a_name(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether *cmd* gives one of the values it is handed to a name that outlives it, as
    `Set-Variable y $x` and `New-Variable y $x` do.
    """
    return any(
        reference.role is not Ps1NameRole.READS
        for reference in named_references(cmd)
    )


class Ps1CallTrust(typing.NamedTuple):
    """
    What the classifier may believe about the code a read is handed to. `trusts` says whether a
    command name still runs the command it names: a name the script may have taken over runs code
    this cannot see, which may keep anything. `closed_at` says whether no code this analysis cannot
    read has run by the time a node is evaluated, so that a type still names the type the metadata
    describes: such code can put another type behind `[string]`, and what a call on it keeps is then
    anything at all.
    """
    trusts: Callable[[str], bool]
    closed_at: Callable[[Node], bool]


def object_handoff(var: Ps1Variable, trust: Ps1CallTrust) -> Ps1Handoff:
    """
    What keeps the object *var* reads once the expression around it has run. What a command or a
    call is believed to let go of is what *trust* allows.
    """
    return _climb(var, _Position(0, streamed=False), trust)


def assignment_handoff(
    assignment: Ps1AssignmentExpression,
    trust: Ps1CallTrust,
) -> Ps1Handoff:
    """
    What keeps the object *assignment* stores, apart from its own target, once the assignment is
    used as a value. `$y = $x = 1, 2, 3` gives the one array to both names, and
    `@{ k = ($x = 1, 2, 3) }` puts it into the table. `Ps1Handoff.NOWHERE` for an assignment that
    stands as a statement of its own, which writes nothing out.
    """
    if not _yields_its_value(assignment):
        return Ps1Handoff.NOWHERE
    return _climb(assignment, _Position(0, streamed=False), trust)


class _Position(typing.NamedTuple):
    """
    What the climb knows about the value at its cursor. `depth` is how deep inside that value the
    object sits, negative where only objects inside it are there; `streamed` says that the value is
    the objects a command wrote rather than the value of an expression, so writing it out does not
    take it apart again, and making a value of it collects it.
    """
    depth: int
    streamed: bool


#: The places that hand on the objects a command wrote as they are, without collecting them into a
#: value first: the next element of a pipeline, and a statement writing them out.
_STREAMING_PARENTS = (
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1ExpressionStatement,
    Ps1ReturnStatement,
)


def _wrapped(depth: int) -> int:
    """
    The depth once the value is made an element of a new container. Parts stay parts.
    """
    return depth + 1 if depth >= 0 else depth


def _unrolled(depth: int) -> int:
    """
    The depth relative to one element once a value is taken apart into its elements: the object
    stays whole only if it was inside the value, and otherwise only its elements go on.
    """
    return depth - 1 if depth > 0 else min(depth, -1)


def _kept(depth: int) -> Ps1Handoff:
    """
    What a place that keeps the value at *depth* keeps of the object.
    """
    return Ps1Handoff.OBJECT if depth >= 0 else Ps1Handoff.PARTS


def _takes_a_part(node: Ps1IndexExpression | Ps1MemberAccess | Ps1InvokeMember) -> bool:
    """
    Whether reading *node* off its object yields something inside that object rather than the
    object itself. A member that may be the object is a passage and never reaches this; a method
    whose name the source does not spell may be one that gives back its receiver.
    """
    if isinstance(node, Ps1InvokeMember):
        return get_member_name(node.member) is not None
    return True


def _is_no_enumerate(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether *cmd* is told to write what it is handed as one object rather than element by element.
    """
    return any(
        isinstance(argument, Ps1CommandArgument)
        and argument.kind is not Ps1CommandArgumentKind.POSITIONAL
        and binds_parameter(argument.name, 'noenumerate')
        for argument in cmd.arguments
    )


def _hands_only_constants(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether every argument *cmd* is given is a switch or a constant, so that no block it is given
    runs for the objects it is handed and none of them is handed to it as an argument.
    """
    for argument in cmd.arguments:
        value = argument.value if isinstance(argument, Ps1CommandArgument) else argument
        if value is not None and read(value) is UNKNOWN:
            return False
    return True


def _yields_its_value(assignment: Ps1AssignmentExpression) -> bool:
    """
    Whether *assignment* is used as a value. One standing as a statement of its own writes nothing
    out; anywhere else it is the value it stored, the very object and not a copy of it.
    """
    return not isinstance(assignment.parent, Ps1ExpressionStatement)


def _is_a_store_target(index: Ps1IndexExpression) -> bool:
    """
    Whether *index* is a place an assignment stores into, so that the index is handed to the store:
    a hashtable keeps the key `$h[$x] = 'v'` is given, and hands it back through `Keys`.
    """
    cursor: Node = index
    parent = cursor.parent
    while isinstance(parent, (Ps1ParenExpression, Ps1CastExpression, Ps1ArrayLiteral)):
        cursor = parent
        parent = cursor.parent
    return isinstance(parent, Ps1AssignmentExpression) and parent.target is cursor


def _is_a_method_body(block: Ps1ScriptBlock) -> bool:
    """
    Whether *block* is the body of a method of a class, which writes out nothing but what it
    returns and returns that whole.
    """
    definition = block.parent
    return isinstance(definition, Ps1FunctionDefinition) and isinstance(
        definition.parent, Ps1MethodMember)


def _assigned(assignment: Ps1AssignmentExpression, at: _Position) -> Ps1Handoff:
    """
    What an assignment keeps of the object its value holds. Every target keeps what it is given,
    a second name as much as a container, and a multi-assignment gives each target one element of
    it.
    """
    target = unwrap_assignment_target(assignment.target)
    if assignment.operator == '=' and isinstance(target, Ps1ArrayLiteral):
        return _kept(_unrolled(at.depth))
    return _kept(at.depth)


def _climb(start: Node, at: _Position, trust: Ps1CallTrust) -> Ps1Handoff:
    """
    What keeps the object once the expression around *start* has run, the value at *start* holding
    it as *at* says.
    """
    depth, streamed = at
    cursor: Node = start
    while True:
        parent = cursor.parent
        if parent is None:
            return Ps1Handoff.NOWHERE
        if streamed and not isinstance(parent, _STREAMING_PARENTS):
            depth = _wrapped(depth)
            streamed = False
        if isinstance(parent, Ps1AssignmentExpression):
            if parent.value is not cursor:
                return Ps1Handoff.NOWHERE
            kept = _assigned(parent, _Position(depth, streamed))
            if not _yields_its_value(parent):
                return kept
            return kept.widest(_climb(parent, _Position(depth, False), trust))
        passage = passage_out_of(cursor)
        if passage is not None:
            cursor = passage.expression
            continue
        if isinstance(parent, Ps1BinaryExpression) and parent.operator.lower() == '-as':
            return Ps1Handoff.NOWHERE
        if isinstance(parent, (Ps1ArrayLiteral, Ps1HashLiteral)):
            depth = _wrapped(depth)
        elif isinstance(parent, (Ps1IndexExpression, Ps1MemberAccess, Ps1InvokeMember)):
            if parent.object is not cursor:
                if isinstance(parent, Ps1InvokeMember):
                    if any(argument is cursor for argument in parent.arguments):
                        return _kept_by_callee(parent, cursor, depth, trust)
                elif isinstance(parent, Ps1IndexExpression):
                    if parent.index is cursor and _is_a_store_target(parent):
                        return _kept(depth)
                return Ps1Handoff.NOWHERE
            if isinstance(parent, Ps1InvokeMember) and _hands_its_receiver_on(parent):
                return _kept(_unrolled(depth))
            if _takes_a_part(parent):
                depth = _unrolled(depth)
        elif isinstance(parent, (Ps1BinaryExpression, Ps1UnaryExpression)):
            if depth <= 0:
                depth = _unrolled(depth)
        elif isinstance(parent, Ps1CommandInvocation):
            if parent.name is cursor:
                return Ps1Handoff.NOWHERE
            kept = _handed_to_command(parent, depth, trust)
            if kept is not None:
                return kept
            if not _is_no_enumerate(parent):
                depth = _unrolled(depth)
            streamed = True
        elif isinstance(parent, Ps1Pipeline):
            return _piped(parent, cursor, _Position(depth, streamed), trust)
        elif isinstance(parent, (Ps1ExpressionStatement, Ps1ReturnStatement)):
            return _written_out(parent, _Position(depth, streamed), trust)
        elif isinstance(parent, (Ps1ForEachLoop, Ps1SwitchStatement)):
            iterated = parent.iterable if isinstance(parent, Ps1ForEachLoop) else parent.value
            return _kept(_unrolled(depth)) if iterated is cursor else Ps1Handoff.NOWHERE
        elif isinstance(parent, Ps1ParameterDeclaration):
            return _kept(depth) if parent.default_value is cursor else Ps1Handoff.NOWHERE
        elif isinstance(parent, Ps1PropertyMember):
            return _kept(depth) if parent.initial_value is cursor else Ps1Handoff.NOWHERE
        elif isinstance(parent, Ps1ThrowStatement):
            return _kept(depth)
        elif isinstance(parent, (Ps1ExpandableString, Ps1RangeExpression)):
            return Ps1Handoff.NOWHERE
        elif isinstance(parent, (Ps1CommandArgument, Ps1PipelineElement)):
            pass
        elif isinstance(parent, Expression):
            return _kept(depth)
        else:
            return Ps1Handoff.NOWHERE
        cursor = parent


def _hands_its_receiver_on(call: Ps1InvokeMember) -> bool:
    """
    Whether *call* may hand what its receiver holds to a place other than its own result: a call
    that writes through an argument slot may fill it from the receiver, as `$a.CopyTo($b, 0)` puts
    the elements of `$a` into `$b`, and a block among the arguments may be run with `$_` bound to
    each of them, as `.ForEach({ })` and `.Where({ })` do.
    """
    if any(isinstance(argument, Ps1ScriptBlock) for argument in call.arguments):
        return True
    member = call.member
    return not isinstance(member, str) or bool(written_slots_of(call, member).slots)


def _kept_by_callee(
    call: Ps1InvokeMember,
    argument: Node,
    depth: int,
    trust: Ps1CallTrust,
) -> Ps1Handoff:
    """
    What a .NET call keeps of an object handed to it as *argument*.

    A call is code this does not read, so in general it may keep anything — `$list.Add($x)` keeps
    `$x` inside the list. Two kinds of call are the exception, because what they do is known. One
    keeps nothing at all: `refinery.lib.scripts.ps1.analysis.arguments.keeps_nothing` names it —
    `[string]::Join(' ', $b)` and `[Text.Encoding]::UTF8.GetString($b)` return a String built from
    what `$b` holds. The other is a call
    `refinery.lib.scripts.ps1.analysis.arguments.written_slots` knows to write through a slot: each
    fills or rearranges the buffer in a slot it writes, and an argument it does not write is read
    for what it holds. `[Array]::Copy($a, $b, 3)` puts the elements of `$a` into `$b` and never `$a`
    itself, and `[Buffer]::BlockCopy` copies bytes. A call that writes its *receiver* — `SetValue` —
    stores an argument into it whole, and one that writes the slot *argument* stands in changes
    the very object it is handed.

    Both hold only where no code this cannot read has run by the time the call is evaluated, since
    such code can put another type behind the name the call is spelled on.
    """
    member = call.member
    if not isinstance(member, str) or not trust.closed_at(call):
        return _kept(depth)
    if _keeps_nothing(call, member):
        return Ps1Handoff.NOWHERE
    written = written_slots_of(call, member).slots
    slot = next(
        (position for position, candidate in enumerate(call.arguments) if candidate is argument),
        None,
    )
    if not written or RECEIVER in written or slot in written:
        return _kept(depth)
    return _kept(_unrolled(depth))


def _keeps_nothing(call: Ps1InvokeMember, member: str) -> bool:
    """
    Whether *call* is a call of a member that keeps nothing it is handed: a static one on the type
    it spells, or one on a value whose type the spelling of the receiver names, as
    `[Text.Encoding]::UTF8.GetString($b)` names an `Encoding`.
    """
    named = call.object
    if named is None:
        return False
    if call.access is Ps1AccessKind.STATIC:
        if not isinstance(named, Ps1TypeExpression):
            return False
        resolved = data.resolve_type(named.name)
        return resolved is not None and keeps_nothing(resolved, member, static=True)
    resolved = resolve_expression_type(named)
    return resolved is not None and keeps_nothing(resolved, member, static=False)


def _handed_to_command(
    cmd: Ps1CommandInvocation,
    depth: int,
    trust: Ps1CallTrust,
) -> Ps1Handoff | None:
    """
    What *cmd* keeps of an object it is handed, as an argument or as pipeline input. `None` where
    the command only writes what it is handed out again, so that the question moves on to wherever
    its output goes.
    """
    if binds_a_name(cmd):
        return _kept(depth)
    name = get_command_name(cmd)
    if name is None or not trust.trusts(name.lower()):
        return _kept(depth)
    name = name.lower()
    if name in _CONSUMING_COMMANDS:
        return Ps1Handoff.NOWHERE
    if name in _PASSING_COMMANDS:
        return None
    if name in _FILTERING_COMMANDS and _hands_only_constants(cmd):
        return None
    return _kept(depth)


def _piped(
    pipeline: Ps1Pipeline,
    element: Node,
    at: _Position,
    trust: Ps1CallTrust,
) -> Ps1Handoff:
    """
    Where the objects a pipeline element writes go: into the next element, one at a time, or out of
    the pipeline as its value where the element is the last one. The value of an expression is
    taken apart on its way into the next element; what a command wrote already is its objects.
    """
    depth, streamed = at
    elements = pipeline.elements
    for position, candidate in enumerate(elements):
        if candidate is not element:
            continue
        for following in elements[position + 1:]:
            if not streamed:
                depth = _unrolled(depth)
                streamed = True
            command = following.expression
            if not isinstance(command, Ps1CommandInvocation):
                return _kept(depth)
            kept = _handed_to_command(command, depth, trust)
            if kept is not None:
                return kept
        return _climb(pipeline, _Position(depth, streamed), trust)
    return _kept(depth)


def _written_out(statement: Node, at: _Position, trust: Ps1CallTrust) -> Ps1Handoff:
    """
    Where a value a statement writes to the output goes: nowhere at the top of the script, to
    whoever runs a body, and into the value around it where the statement stands in an expression.
    The value of an expression is taken apart as it is written; what a command wrote is not.

    A method of a class is the exception on both counts. It writes out nothing but what it returns,
    and its `return` hands the value back whole rather than element by element.
    """
    depth = at.depth if at.streamed else _unrolled(at.depth)
    written = _Position(depth, True)
    cursor = statement
    while True:
        parent = cursor.parent
        if parent is None or isinstance(parent, Ps1Script):
            return Ps1Handoff.NOWHERE
        if isinstance(parent, Ps1ScriptBlock):
            if not _is_a_method_body(parent):
                return _kept(depth)
            if isinstance(statement, Ps1ReturnStatement):
                return _kept(at.depth)
            return Ps1Handoff.NOWHERE
        if isinstance(parent, (Ps1ArrayExpression, Ps1SubExpression)):
            return _climb(parent, written, trust)
        if isinstance(parent, Expression):
            return _climb(cursor, written, trust)
        cursor = parent
