"""
Where the object a variable occurrence reads goes once the expression around it has run.

A read hands over the object a name holds and not a copy of it, and PowerShell keeps that object in
many more places than a second variable: an element of an array literal, the value of a hash entry,
a slot of a container that already exists, the parameter of a body it is passed to, the pipeline
variable of a block it is piped into, a `foreach` variable, and the output a caller of a body
collects. A store reaching the object through any of those places changes what the name holds, and
none of them is an occurrence of the name. `object_handoff` classifies a read by which of those it
reaches; `refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow` orders the stores against it.

The climb follows the object outwards and counts how deep inside the value at the cursor it sits.
Building a container around it puts it one level deeper; unrolling a value — a pipeline, `@( )`, an
operator, the output of a body — takes the elements out of their container, so the object itself
survives only if it was inside one, and otherwise only its elements go on. Taking an index or a
member hands on a part of the value and no more. Where the climb ends, a place that keeps what it
is handed keeps the object itself if the depth is not negative and only objects inside it if it is.
"""
from __future__ import annotations

import enum
import typing

from typing import Callable

from refinery.lib.scripts import Expression, Node
from refinery.lib.scripts.ps1.analysis.arguments import RECEIVER
from refinery.lib.scripts.ps1.analysis.model import written_slots_of
from refinery.lib.scripts.ps1.analysis.naming import Ps1NameRole, named_references
from refinery.lib.scripts.ps1.ast import get_command_name, get_member_name, unwrap_assignment_target
from refinery.lib.scripts.ps1.model import (
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
    Ps1HashLiteral,
    Ps1IndexExpression,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1RangeExpression,
    Ps1ReturnStatement,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1SubExpression,
    Ps1SwitchStatement,
    Ps1ThrowStatement,
    Ps1UnaryExpression,
    Ps1Variable,
)


class Ps1Handoff(enum.Enum):
    """
    What keeps the object a read produces once the expression around the read has run.

    `NOWHERE` — nothing keeps the object or anything inside it.
    `A_NAME` — a plain `=` stores the whole of it under one variable, as in `$y = $x` or
    `$y = [array]$x`. The semantic model links the two names and files the stores of either against
    both, so this is the one hand-off that needs nothing further.
    `PARTS` — something keeps objects the value holds but not the value itself: `$y = @($x)`,
    `foreach ($e in $x)`, `$q = $x[0]`.
    `OBJECT` — something keeps the object itself: an element of a new array, a hash entry, a slot of
    another container, a callee, a caller collecting the output of a body.
    """
    NOWHERE = 0
    A_NAME  = 1  # noqa
    PARTS   = 2  # noqa
    OBJECT  = 3  # noqa

    def widest(self, other: Ps1Handoff) -> Ps1Handoff:
        """
        Whichever of the two keeps more of the object.
        """
        return self if self.value >= other.value else other


#: Members whose value is the object they are read from rather than a part of it: an array's
#: `SyncRoot` is the array, and `PSObject` wraps the very object it is read from.
_IDENTITY_MEMBERS = frozenset({
    'psobject',
    'syncroot',
})

#: Commands that consume what they are handed and keep nothing of it: each writes a rendering of it
#: somewhere that is not a value of the script.
_CONSUMING_COMMANDS = frozenset({
    'out-host',
    'out-null',
    'out-string',
    'write-debug',
    'write-host',
    'write-information',
    'write-verbose',
    'write-warning',
})

#: Commands that write out the objects they are handed and keep none of them. What they write goes
#: wherever their own output goes.
_PASSING_COMMANDS = frozenset({
    'select-object',
    'sort-object',
    'where-object',
    'write-output',
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


def object_handoff(var: Ps1Variable, trusts: Callable[[str], bool]) -> Ps1Handoff:
    """
    What keeps the object *var* reads once the expression around it has run.

    *trusts* says whether a command name still runs the command it names in this script. A name the
    script may have taken over runs code this cannot see, which may keep anything, so only a command
    this module lets go of the object asks it.
    """
    return _climb(var, _Position(0, direct=True, streamed=False), trusts)


class _Position(typing.NamedTuple):
    """
    What the climb knows about the value at its cursor. `depth` is how deep inside that value the
    object sits, negative where only objects inside it are there; `direct` says that nothing but
    parentheses and conversions stand between the read and the cursor; `streamed` says that the
    value is the objects a command wrote rather than the value of an expression, so writing it out
    does not take it apart again.
    """
    depth: int
    direct: bool
    streamed: bool


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


def _converted_operand(node: Node) -> Node | None:
    """
    The operand a cast or an `-as` hands on unchanged where it already is what it names, or `None`
    where *node* converts nothing.
    """
    if isinstance(node, Ps1CastExpression):
        return node.operand
    if isinstance(node, Ps1BinaryExpression) and node.operator.lower() == '-as':
        return node.left
    return None


def _takes_a_part(node: Ps1IndexExpression | Ps1MemberAccess | Ps1InvokeMember) -> bool:
    """
    Whether reading *node* off its object yields something inside that object rather than the
    object itself.
    """
    if isinstance(node, Ps1IndexExpression):
        return True
    return get_member_name(node.member) not in _IDENTITY_MEMBERS


def _is_no_enumerate(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether *cmd* is told to write what it is handed as one object rather than element by element.
    """
    return any(
        isinstance(argument, Ps1CommandArgument)
        and argument.kind is not Ps1CommandArgumentKind.POSITIONAL
        and 'noenumerate'.startswith(argument.name.lstrip('-').lower() or '?')
        for argument in cmd.arguments
    )


def _assigned(assignment: Ps1AssignmentExpression, at: _Position) -> Ps1Handoff:
    """
    What an assignment keeps of the object its value holds. A plain `=` of the read itself to one
    variable is the link the semantic model owns; every other target keeps what it is given, and a
    multi-assignment gives each target one element of it.
    """
    target = unwrap_assignment_target(assignment.target)
    if assignment.operator == '=':
        if isinstance(target, Ps1Variable):
            return Ps1Handoff.A_NAME if at.direct else _kept(at.depth)
        if isinstance(target, Ps1ArrayLiteral):
            return _kept(_unrolled(at.depth))
    return _kept(at.depth)


def _climb(start: Node, at: _Position, trusts: Callable[[str], bool]) -> Ps1Handoff:
    """
    What keeps the object once the expression around *start* has run, the value at *start* holding
    it as *at* says.
    """
    depth, direct, streamed = at
    cursor: Node = start
    while True:
        parent = cursor.parent
        if parent is None:
            return Ps1Handoff.NOWHERE
        if isinstance(parent, Ps1ParenExpression):
            cursor = parent
            continue
        if isinstance(parent, Ps1CastExpression) or (
            isinstance(parent, Ps1BinaryExpression) and parent.operator.lower() == '-as'
        ):
            if _converted_operand(parent) is not cursor:
                return Ps1Handoff.NOWHERE
            cursor = parent
            continue
        if isinstance(parent, Ps1AssignmentExpression):
            if parent.value is not cursor:
                return Ps1Handoff.NOWHERE
            return _assigned(parent, _Position(depth, direct, streamed))
        direct = False
        if isinstance(parent, (Ps1ArrayLiteral, Ps1HashLiteral)):
            depth = _wrapped(depth)
            streamed = False
        elif isinstance(parent, (Ps1IndexExpression, Ps1MemberAccess, Ps1InvokeMember)):
            if parent.object is not cursor:
                if isinstance(parent, Ps1InvokeMember) and any(
                    argument is cursor for argument in parent.arguments
                ):
                    return _kept_by_callee(parent, depth)
                return Ps1Handoff.NOWHERE
            if _takes_a_part(parent):
                depth = _unrolled(depth)
            streamed = False
        elif isinstance(parent, (Ps1BinaryExpression, Ps1UnaryExpression)):
            if depth <= 0:
                depth = _unrolled(depth)
            streamed = False
        elif isinstance(parent, Ps1CommandInvocation):
            if parent.name is cursor:
                return Ps1Handoff.NOWHERE
            kept = _handed_to_command(parent, depth, trusts)
            if kept is not None:
                return kept
            if not _is_no_enumerate(parent):
                depth = _unrolled(depth)
            streamed = True
        elif isinstance(parent, Ps1Pipeline):
            return _piped(parent, cursor, _Position(depth, False, streamed), trusts)
        elif isinstance(parent, (Ps1ExpressionStatement, Ps1ReturnStatement)):
            return _written_out(parent, _Position(depth, False, streamed), trusts)
        elif isinstance(parent, (Ps1ForEachLoop, Ps1SwitchStatement)):
            iterated = parent.iterable if isinstance(parent, Ps1ForEachLoop) else parent.value
            return _kept(_unrolled(depth)) if iterated is cursor else Ps1Handoff.NOWHERE
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


def _kept_by_callee(call: Ps1InvokeMember, depth: int) -> Ps1Handoff:
    """
    What a .NET call keeps of an object handed to it as an argument.

    A call is code this does not read, so in general it may keep anything — `$list.Add($x)` keeps
    `$x` inside the list. The calls `refinery.lib.scripts.ps1.analysis.arguments.written_slots`
    knows to write through a slot are the exception, because what they do is known: each fills or
    rearranges the buffer in a slot it writes, and an argument it does not write is read for what
    it holds. `[Array]::Copy($a, $b, 3)` puts the elements of `$a` into `$b` and never `$a` itself,
    and `[Buffer]::BlockCopy` copies bytes. Only a call that writes its *receiver* — `SetValue` —
    stores an argument into it whole.
    """
    member = call.member
    if not isinstance(member, str):
        return _kept(depth)
    written = written_slots_of(call, member).slots
    if not written or RECEIVER in written:
        return _kept(depth)
    return _kept(_unrolled(depth))


def _handed_to_command(
    cmd: Ps1CommandInvocation,
    depth: int,
    trusts: Callable[[str], bool],
) -> Ps1Handoff | None:
    """
    What *cmd* keeps of an object it is handed, as an argument or as pipeline input. `None` where
    the command only writes what it is handed out again, so that the question moves on to wherever
    its output goes.
    """
    if binds_a_name(cmd):
        return _kept(depth)
    name = get_command_name(cmd)
    if name is None or not trusts(name.lower()):
        return _kept(depth)
    name = name.lower()
    if name in _CONSUMING_COMMANDS:
        return Ps1Handoff.NOWHERE
    if name in _PASSING_COMMANDS:
        return None
    return _kept(depth)


def _piped(
    pipeline: Ps1Pipeline,
    element: Node,
    at: _Position,
    trusts: Callable[[str], bool],
) -> Ps1Handoff:
    """
    Where the objects a pipeline element writes go: into the next element, one at a time, or out of
    the pipeline as its value where the element is the last one. The value of an expression is
    taken apart on its way into the next element; what a command wrote already is its objects.
    """
    depth, _, streamed = at
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
            kept = _handed_to_command(command, depth, trusts)
            if kept is not None:
                return kept
        return _climb(pipeline, _Position(depth, False, streamed), trusts)
    return _kept(depth)


def _written_out(statement: Node, at: _Position, trusts: Callable[[str], bool]) -> Ps1Handoff:
    """
    Where a value a statement writes to the output goes: nowhere at the top of the script, to
    whoever runs a body, and into the value around it where the statement stands in an expression.
    The value of an expression is taken apart as it is written; what a command wrote is not.
    """
    depth = at.depth if at.streamed else _unrolled(at.depth)
    written = _Position(depth, False, True)
    cursor = statement
    while True:
        parent = cursor.parent
        if parent is None or isinstance(parent, Ps1Script):
            return Ps1Handoff.NOWHERE
        if isinstance(parent, Ps1ScriptBlock):
            return _kept(depth)
        if isinstance(parent, (Ps1ArrayExpression, Ps1SubExpression)):
            return _climb(parent, written._replace(streamed=False), trusts)
        if isinstance(parent, Expression):
            return _climb(cursor, written, trusts)
        cursor = parent
