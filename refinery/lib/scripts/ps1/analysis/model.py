"""
A semantic model for PowerShell: a tree of scopes with resolved variable bindings and def/use sets,
computed once over an AST and then queried by the deobfuscation transforms instead of each
transform re-deriving scope, binding, and liveness facts on its own. This is the foundation layer of
the ps1 analysis substrate; later layers (effect and control-flow models) attach behind the same
representation-agnostic surface.

Only three constructs introduce a scope: the script itself and every
`refinery.lib.scripts.ps1.model.Ps1ScriptBlock` (a function or method body, a stored closure, or a
bare `&{ ... }`). PowerShell has no block scoping — a variable assigned in an `if`/loop/`try` body
is visible after it — so those bodies share the scope of their enclosing script or scriptblock.

The model encodes two PowerShell scoping rules:

- **Write-local.** A bare (unqualified) assignment inside a scriptblock creates a scriptblock-local
  binding; it does not write the enclosing binding of that name.
- **Read fall-through.** A bare read inside a scriptblock references the nearest enclosing binding
  of that name. Because PowerShell creates the local only at the first assignment and a read before
  it falls through at runtime, the model resolves a bare read *conservatively*: it records the read
  on every enclosing scope that binds the name, so a read that might observe an outer value keeps
  that outer binding live. Distinguishing which definition actually reaches a use needs a
  control-flow graph and is left to a later layer.

Where PowerShell scoping is genuinely dynamic — a scope qualifier (`$script:`, `$global:`, …), a
name reachable through `Invoke-Expression`, `&`/`.` dispatch, or a function invoked elsewhere
reading a caller's variables — the model errs toward keeping a binding live rather than risk
treating a live reference as free. A qualified read marks the binding of that name reachable, so it
is never reported dead.
"""
from __future__ import annotations

import enum
import typing

from collections import deque
from dataclasses import dataclass, field
from typing import Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1 import data
from refinery.lib.scripts.ps1.analysis.arguments import (
    RECEIVER,
    Ps1WrittenSlots,
    written_slots,
)
from refinery.lib.scripts.ps1.analysis.naming import (
    Ps1NamedReference,
    Ps1NameRole,
    Ps1NameTarget,
    named_references,
    unreadable_name_target,
)
from refinery.lib.scripts.ps1.ast import (
    assignment_of,
    binding_key,
    is_reference_cast,
)
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandInvocation,
    Ps1ForEachLoop,
    Ps1FunctionDefinition,
    Ps1IndexExpression,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1ParameterDeclaration,
    Ps1PropertyMember,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)


@enum.unique
class Ps1OccurrenceRole(enum.Enum):
    """
    What one occurrence of a variable does to the value the name holds. Every occurrence has exactly
    one role, and the transforms ask for it rather than each assembling an answer from a handful of
    positional predicates — which is how `[ref]$n` came to be read as a plain read by every one of
    them at once.

    `NOT_A_REFERENCE` — the occurrence does not reference a variable at all: a class property member
    declaration names a member of the class, a namespace of its own.
    `READ` — observes the value and does not change it.
    `WRITE_REPLACING` — stores without observing what was there: `$x = v`, a `foreach` variable, a
    parameter.
    `WRITE_OBSERVING` — stores *and* observes: `$x += v`, `$x++`, and `[ref]$x`, whose callee may
    store back through the wrapper it is handed.
    `WRITE_THROUGH` — reads the variable to reach a place inside it that is written: the `$x` of
    `$x[0] = 'z'` or `$x.Length = 5`. The name still holds whatever it held, so this observes the
    value like a read and installs none of its own; but *what* it holds is no longer what it held,
    so it is a write of the binding all the same and no value may be installed in its place.

    Each member carries the four answers a consumer needs, in the order the fields are declared
    below, rather than being compared against a list of members at every site. A question answered
    by a membership test lives at each of its call sites and has to be found again by grep whenever
    a role is added or its meaning moves; a field lives here, beside the member it is about.

    `enum.unique` because the answers *are* the value: two members answering alike would be one
    member under two names, dispatching as whichever was declared first while every `is` test
    against the other still passed.
    """
    NOT_A_REFERENCE = (False, False, False, False)
    READ            = (False, True, True, False)    # noqa
    WRITE_REPLACING = (True, False, False, False)
    WRITE_OBSERVING = (True, True, False, False)
    WRITE_THROUGH   = (True, True, False, True)     # noqa

    #: Whether the occurrence is filed among the binding's writes, because it changes what a read
    #: below it observes.
    stores: bool
    #: Whether the occurrence observes the value the name holds.
    observes: bool
    #: Whether a value may be installed in the occurrence's place. Only a plain read, and even then
    #: `is_substitutable_position` has a caveat of its own to add.
    substitutable: bool
    #: Whether the occurrence reaches a place *inside* the value rather than the binding itself, so
    #: that the name is left holding whatever it held.
    through: bool

    def __init__(self, stores: bool, observes: bool, substitutable: bool, through: bool):
        self.stores = stores
        self.observes = observes
        self.substitutable = substitutable
        self.through = through


def occurrence_role(var: Ps1Variable) -> Ps1OccurrenceRole:
    """
    The `Ps1OccurrenceRole` of `var`.

    The order the cases are tried in is the order they nest. An occurrence an assignment stores
    through is a target position as much as a plain target is, and is decided first because
    `assignment_of` deliberately answers `None` for it; a reference cast is decided last among the
    writes because everything above it is a syntactic position and a cast is a value form.
    """
    if _is_member_declaration(var):
        return Ps1OccurrenceRole.NOT_A_REFERENCE
    if _stores_through(var) or _stores_through_a_call_slot(_enclosing_call_slot(var)):
        return Ps1OccurrenceRole.WRITE_THROUGH
    assignment = assignment_of(var)
    if assignment is not None:
        if assignment.operator == '=':
            return Ps1OccurrenceRole.WRITE_REPLACING
        return Ps1OccurrenceRole.WRITE_OBSERVING
    parent = var.parent
    if isinstance(parent, Ps1UnaryExpression) and parent.operator in ('++', '--'):
        if parent.operand is var:
            return Ps1OccurrenceRole.WRITE_OBSERVING
    if isinstance(parent, Ps1ForEachLoop) and parent.variable is var:
        return Ps1OccurrenceRole.WRITE_REPLACING
    if isinstance(parent, Ps1ParameterDeclaration) and parent.variable is var:
        return Ps1OccurrenceRole.WRITE_REPLACING
    if is_reference_cast(parent) and parent.operand is var:
        return Ps1OccurrenceRole.WRITE_OBSERVING
    return Ps1OccurrenceRole.READ


def is_substitutable_position(var: Ps1Variable) -> bool:
    """
    Whether a value may be installed where `var` stands, replacing the occurrence.

    This is not the complement of writing, and reading it off the role alone is what let two
    corruptions through. A splatted `@p` observes the value like any read, but it spreads an array
    over a command's parameters, and the array written in its place is one argument rather than
    several. A `[ref]$n` observes the value too, and the literal put in its place is a reference to
    nothing that the callee's store is silently lost through.
    """
    return occurrence_role(var).substitutable and not var.splatted


def declares_binding(var: Ps1Variable) -> bool:
    """
    Whether the occurrence brings the binding into existence in the scope it resolves to.

    Every write that installs a value does, except a reference: PowerShell resolves `[ref]$n` by
    ordinary lookup and creates nothing, so filing one as a declaration invents a local binding in
    whatever body the reference is written in and hides the outer one the callee actually stores
    through. A write that reaches *through* the value declares nothing for the same reason: it needs
    a value to reach into, so the binding it names already exists wherever it exists.
    """
    if is_reference_cast(var.parent):
        return False
    role = occurrence_role(var)
    return role.stores and not role.through


def is_assignment_write_target(var: Ps1Variable) -> bool:
    """
    Whether `var` occupies the target position of an enclosing
    `refinery.lib.scripts.ps1.model.Ps1AssignmentExpression`, including as an element of a
    multi-assignment `refinery.lib.scripts.ps1.model.Ps1ArrayLiteral` target. Enclosing casts and
    parentheses are transparent.

    A question about syntax rather than about role, which is why it is not derived from
    `occurrence_role`: a `foreach` variable and a parameter replace the value exactly as a plain
    assignment target does and occupy no assignment at all.
    """
    return assignment_of(var) is not None


def replaces_value(var: Ps1Variable) -> bool:
    """
    Whether `var` occupies the target position of a plain `=` assignment, which overwrites the
    variable without observing its previous value. The target of a compound assignment (`+=`, `-=`,
    `.=`, …) is excluded: it reads the variable as well as writing it.
    """
    assignment = assignment_of(var)
    return assignment is not None and assignment.operator == '='


def observes_previous_value(var: Ps1Variable) -> bool:
    """
    Whether `var` occupies a position that reads the variable as part of writing it: the target of a
    compound assignment (`+=`, `.=`, …), the operand of `++`/`--`, a `[ref]` cast the callee may
    store back through, or a store *through* the value — the `$x` of `$x[0] = 9` and of
    `[Array]::Reverse($x)`, each of which has to reach the object before it can change it. Such a
    write is also a use, so a binding that has one is not dead however many of its `Binding.reads`
    a caller has accounted for.
    """
    role = occurrence_role(var)
    return role.stores and role.observes


def is_mutated_in_place(var: Ps1Variable) -> bool:
    """
    Whether an assignment stores *through* `var` rather than into it — the `$x` of `$x[0] = 'z'`, of
    `$x.Length = 5`, of `$x[0][1] = 'z'` and of the multi-assignment `$x[0], $x[1] = 'p', 'q'`.

    Such an occurrence reads the variable in order to reach the part that is written, and the value
    it installs is no value at all: what a read below it observes is the object the name was already
    bound to, changed. So it is a write with a position and no value, which is what
    `Ps1SemanticModel` files it as.
    """
    return occurrence_role(var).through


def _stores_through(var: Ps1Variable) -> bool:
    """
    The receiver-chain climb behind `Ps1OccurrenceRole.WRITE_THROUGH`.

    The whole chain counts, not just its innermost step. A target is only a target once the index
    and member accesses, the parentheses, the casts and the multi-assignment slots between it and
    the assignment have been climbed, and stopping at the first of them answers `$x[0] = 'z'` while
    missing `$x[0][1] = 'z'`.
    """
    cursor: Node = var
    parent = cursor.parent
    through = False
    while parent is not None:
        if isinstance(parent, (Ps1IndexExpression, Ps1MemberAccess)):
            if parent.object is not cursor:
                return False
            through = True
        elif isinstance(parent, Ps1CastExpression):
            if parent.operand is not cursor:
                return False
        elif isinstance(parent, (Ps1ParenExpression, Ps1ArrayLiteral)):
            pass
        elif isinstance(parent, Ps1AssignmentExpression):
            return through and parent.target is cursor
        else:
            return False
        cursor = parent
        parent = cursor.parent
    return False


class Ps1CallSlot(typing.NamedTuple):
    """
    A slot of a .NET call that the callee writes through, and what is known about the call's other
    slots. `slot` is `refinery.lib.scripts.ps1.analysis.arguments.RECEIVER` for a call's receiver
    and the argument's position otherwise.
    """
    call: Ps1InvokeMember
    slot: int
    written: Ps1WrittenSlots
    #: Whether the slot holds a *part* of what the name holds rather than the whole of it — the `$p`
    #: of `[Array]::Reverse($p[0])`. The name is written through either way, but what the call
    #: leaves under it is the outer value with one element changed, which is a different question
    #: from what it leaves in the slot.
    through_a_part: bool
    #: Whether a cast stands between the name and the slot, so that what the callee writes may be a
    #: conversion of the value rather than the value. `[Array]::Reverse([array]$x)` hands over the
    #: very array `$x` holds and `[Array]::Reverse([int[]]$x)` hands over a fresh one built from it;
    #: which of the two a cast is depends on the operand's runtime type, which nothing here has. The
    #: name is refused a substitution either way, and a rule computing what the call left
    #: behind must refuse the pair outright — measured, `[Array]::Reverse([int[]]$x)` leaves
    #: `$x` in its original order.
    through_a_conversion: bool


def _stores_through_a_call_slot(found: _CallSlotPosition | None) -> bool:
    """
    Whether the callee may write the slot *found* names: because a row of the table says it does, or
    because the member cannot be named and so no row can say it does not.

    **A member nobody can read is a store-through and not merely a position no value may stand in.**
    The table is keyed on a member name and `[Array]::$m($x)` has none to look up, so a miss there
    means *no row was consulted* where a miss elsewhere means *no row claims this*. Refusing only
    the substitution would leave the name looking unwritten and the read below the call answered by
    the write above it — measured, `$m = 'Reverse'; $x = 1, 2, 3; [Array]::$m($x); $x[0]` is `3` on
    5.1 and was folded to `1`. A member spelled indirectly is resolved by the next pass in almost
    every script that has one, so what this costs is a fold delayed by an iteration.

    The two questions share one climb because they are one question about one position, and asking
    them separately made `occurrence_role` walk every occurrence's ancestors twice.
    """
    if found is None:
        return False
    member = found.call.member
    if not isinstance(member, str):
        return True
    return found.slot in _written_slots_of(found.call, member).slots


def _written_slots_of(call: Ps1InvokeMember, member: str) -> Ps1WrittenSlots:
    """
    Which slots of *call* the callee writes through, given only the call and the name of the member
    it runs. The receiver's type is not asked for; see `written_call_slot`.

    The member is a parameter rather than read off the call, because a call whose member cannot be
    named has no answer here at all — `NOTHING` would be the claim that it writes nothing and
    `UNBOUND` a doubt about an arity that was never in question. `_stores_through_a_call_slot` is
    where that call is answered, and every caller here has already read the name.
    """
    static = call.access is Ps1AccessKind.STATIC
    named = call.object
    resolved = (
        data.resolve_type(named.name)
        if static and isinstance(named, Ps1TypeExpression) else None
    )
    return written_slots(resolved, member, len(call.arguments), static=static)


def written_call_slot(var: Ps1Variable) -> Ps1CallSlot | None:
    """
    The slot of a .NET call *var* fills that the callee writes through — the `$x` of
    `[Array]::Reverse($x)`, of `$x.SetValue(9, 0)`, of `[Array]::Copy($src, $x, 3)` — or `None`
    where it fills none. Which slots those are is
    `refinery.lib.scripts.ps1.analysis.arguments.written_slots`.

    The receiver's type is not asked for. This is a question about a *position*, answered wherever
    an occurrence stands and long before any flow model exists, so a call on a value is answered by
    the union over every type carrying a member of that name: `$x.CopyTo($y, 0)` refuses without
    knowing what `$x` is, and `$x.Substring(1, 2)` is left alone because no row of the table mentions
    `Substring`.

    What stands between the name and the slot is `_enclosing_call_slot`'s to climb and to report.
    A member this cannot name is not answered here at all: no row can be looked up for it, so no
    row can be reported. That the occurrence is a write all the same is what
    `_stores_through_a_call_slot` says, which is the refusal that belongs to it.
    """
    found = _enclosing_call_slot(var)
    if found is None or not isinstance(member := found.call.member, str):
        return None
    written = _written_slots_of(found.call, member)
    if found.slot not in written.slots:
        return None
    return Ps1CallSlot(
        found.call, found.slot, written, found.through_a_part, found.through_a_conversion)


class _CallSlotPosition(typing.NamedTuple):
    call: Ps1InvokeMember
    slot: int
    through_a_part: bool
    through_a_conversion: bool


def _enclosing_call_slot(var: Ps1Variable) -> _CallSlotPosition | None:
    """
    Which slot of which call *var* fills, whatever the callee does with it, and what stands between
    the name and the slot. `None` where the occurrence fills none.

    Four kinds of wrapper are climbed on the way out, and each for its own reason. A parenthesis is
    transparent to PowerShell's binding — measured, `[Array]::Reverse(($x))` reverses the array `$x`
    holds. A conversion, written `[array]$x` or `$x -as [array]`, is climbed because whether it
    allocates is a question about the operand's type: `[Array]::Reverse([char[]]$s)` converts a
    String and never reaches `$s`, while `[Array]::Reverse([array]$x)` hands over the very array,
    and climbing costs the first a substitution rather than making the second a wrong answer. An
    index and a member access are climbed because what they fetch out of the name is still part of
    what the name holds: `[Array]::Reverse($p[0])` turns around the inner array `$p`'s first element
    *is*, so a value written where `$p` stands loses it.
    """
    cursor: Node = var
    parent: Node | None = cursor.parent
    part = False
    converted = False
    while parent is not None:
        conversion = isinstance(parent, Ps1CastExpression) or is_conversion_operator(parent)
        reaching = isinstance(parent, (Ps1IndexExpression, Ps1MemberAccess))
        grouping = isinstance(parent, Ps1ParenExpression)
        if not conversion and not reaching and not grouping:
            break
        if not grouping and _climbed_operand(parent) is not cursor:
            return None
        part = part or reaching
        converted = converted or conversion
        cursor = parent
        parent = cursor.parent
    if not isinstance(parent, Ps1InvokeMember):
        return None
    slot = _call_slot_of(parent, cursor)
    return None if slot is None else _CallSlotPosition(parent, slot, part, converted)


def _constraint_on(var: Ps1Variable) -> str | None:
    """
    The type a constrained assignment target names for *var* — the `string` of `[string]$q = 5` and
    of `$a, [string]$q = 1, 5` — or `None` where the occurrence is not one.

    Only a cast between the occurrence and the assignment counts, so `$q = [string]5` is not a
    constraint: it converts what is stored once and leaves the variable free.
    """
    assignment = assignment_of(var)
    if assignment is None:
        return None
    cursor: Node = var
    parent = cursor.parent
    while parent is not None and parent is not assignment:
        if isinstance(parent, Ps1CastExpression):
            return parent.type_name
        cursor = parent
        parent = cursor.parent
    return None


def _climbed_operand(node: Node) -> Node | None:
    """
    The part of *node* a store reaching through it has to have come from: what a cast or an `-as`
    converts, and what an index or a member access is taken out of. An occurrence anywhere else
    under one of these — the `$i` of `$p[$i]`, the `[array]` of `$x -as [array]` — is read and not
    reached through.
    """
    if isinstance(node, Ps1CastExpression):
        return node.operand
    if isinstance(node, (Ps1IndexExpression, Ps1MemberAccess)):
        return node.object
    if is_conversion_operator(node):
        return node.left
    return None


def is_conversion_operator(node: Node | None) -> typing.TypeGuard[Ps1BinaryExpression]:
    """
    Whether *node* is `-as`, which converts its left operand the way a cast does and hands over the
    very object where nothing needs converting: measured, `$x -as [array]` over an `Object[]` is the
    array `$x` holds, so `[Array]::Reverse($x -as [array])` reverses it.
    """
    return isinstance(node, Ps1BinaryExpression) and node.operator.lower() == '-as'


def _call_slot_of(call: Ps1InvokeMember, node: Node) -> int | None:
    """
    Which slot of *call* the expression *node* occupies, or `None` when it occupies none.
    """
    if call.object is node:
        return RECEIVER
    for position, argument in enumerate(call.arguments):
        if argument is node:
            return position
    return None


def is_write_occurrence(var: Ps1Variable) -> bool:
    """
    Whether `var` occurs in a position that writes it: the target of an assignment (including a
    multi-assignment slot), the operand of a `++`/`--` update, the loop variable of a `foreach`, a
    parameter declaration, the operand of a `[ref]` cast, or a position an assignment stores
    *through*. Every other occurrence reads the variable.

    A store through is one of these although it installs nothing. `$x[0] = 'z'` leaves the name
    bound to the object it was bound to, but a read below it observes a different value, and that
    is the whole of what a write is to the layer that orders reads against writes. Counting it a
    read instead is what forced `Ps1VariableFlow` to give up on every occurrence of the name.
    """
    return occurrence_role(var).stores


def _is_member_declaration(var: Ps1Variable) -> bool:
    """
    Whether `var` names a class property member (`class C { [int]$x }`) rather than referencing a
    variable. A property declares a member of the class, a namespace distinct from the script's
    variables, so the model binds nothing for it and attributes neither a read nor a write.
    """
    parent = var.parent
    return isinstance(parent, Ps1PropertyMember) and parent.variable is var


class ScopeKind(enum.Enum):
    SCRIPT      = 'script'       # noqa
    FUNCTION    = 'function'     # noqa
    SCRIPTBLOCK = 'scriptblock'  # noqa


#: Scope qualifiers that reach a binding beyond the lexical fall-through a bare reference resolves
#: by, so a read through one keeps the binding it names live rather than resolving it locally. Which
#: scope each names is decided by `Ps1SemanticModel._qualified_read_scopes`. `$env:` is excluded —
#: it names an operating-system environment variable, a namespace distinct from script variables —
#: as is the bare (unqualified) case.
_QUALIFIED_SCOPES = frozenset({
    Ps1ScopeModifier.GLOBAL,
    Ps1ScopeModifier.LOCAL,
    Ps1ScopeModifier.SCRIPT,
    Ps1ScopeModifier.PRIVATE,
    Ps1ScopeModifier.USING,
    Ps1ScopeModifier.VARIABLE,
})


class Ps1AliasLink(typing.NamedTuple):
    """
    One definition that gave two names the same object, and the two bindings it stands between.

    `definition` is the occurrence that took the object — the `$y` of `$y = $x`. The two bindings
    are unordered: the link says they name one object from that point, and a rebinding of either
    ends it, so a consumer asking whether the link still holds asks the same question of both.

    `certain` says whether the definition handed the object over or may have built a new one from
    it. `$y = $x` hands it over; `$y = [array]$x`, `$y = $x -as [array]` and `[int[]]$y = $x` hand
    over the very object where nothing needs converting and a fresh one where something does, which
    depends on the operand's runtime type. The distinction is not academic, because the two
    directions of a link fail differently: a link the class *lacks* loses a kill and answers a read
    with a value the store had already changed, and a link the class holds too strongly names a
    value the other name never received. An uncertain link is therefore filed — it kills — and
    never promoted.
    """
    definition: Node
    first: Binding
    second: Binding
    certain: bool

    def across(self, binding: Binding) -> Binding | None:
        """
        The binding on the other side of the link from *binding*, or `None` where the link does not
        touch it.
        """
        if binding is self.first:
            return self.second
        return self.first if binding is self.second else None


def _link_adjacency(links: list[Ps1AliasLink]) -> dict[int, list[Ps1AliasLink]]:
    """
    The links touching each binding, keyed by the binding's identity. One map per alias class and
    not one per walk over it: the map is a fact about the class, and rebuilding it for every name a
    walk starts at costs the class its own size again for each of them.
    """
    adjacent: dict[int, list[Ps1AliasLink]] = {}
    for link in links:
        adjacent.setdefault(id(link.first), []).append(link)
        adjacent.setdefault(id(link.second), []).append(link)
    return adjacent


def _alias_chains_from(
    adjacent: dict[int, list[Ps1AliasLink]],
    source: Binding,
) -> dict[int, tuple[Ps1AliasLink, ...]]:
    """
    A shortest run of links joining *source* to every binding it reaches, keyed by the reached
    binding's identity, over the adjacency `_link_adjacency` built for the class.

    Shortest because every link on the chain is a claim the ordering layer has to find intact, so a
    detour is a refusal waiting to happen rather than extra evidence. Which end the run is walked
    from does not matter: `Ps1AliasLink` joins its two bindings without ordering them, and
    `Ps1VariableFlow._alias_holds_at` asks the same question of every link on the run.

    One walk per name a store is spelled on, and not one per pair of names, nor one per store. A
    walk from that name already reaches every other name on the way, so asking it again for each of
    them is the difference between a class costing its own size and costing the square of it —
    measured, a chain of eighty names took a second and a half to file and now takes a hundredth.
    """
    reached: dict[int, tuple[Ps1AliasLink, ...]] = {}
    frontier: deque[tuple[Binding, tuple[Ps1AliasLink, ...]]] = deque([(source, ())])
    seen = {id(source)}
    while frontier:
        here, chain = frontier.popleft()
        for link in adjacent.get(id(here), ()):
            there = link.across(here)
            if there is None or id(there) in seen:
                continue
            seen.add(id(there))
            walked = (*chain, link)
            reached[id(there)] = walked
            frontier.append((there, walked))
    return reached


@dataclass(eq=False)
class Occurrence:
    """
    One reference to one binding: the node that makes it, what it does to the value, and the key it
    was attributed under.

    A *node* rather than a variable, because not every reference is spelled as one. `Set-Variable X`
    and `Get-Process -OutVariable x` address the name as a string, and the node that makes the
    reference is the whole command; `Set-Variable -Name a, b` is a single node referring to two
    keys, which is why the key belongs to the reference and not to the node.

    `eq=False` so that two references alike in every field are still two references, and so that a
    caller may key a map by identity.
    """
    node: Node
    role: Ps1OccurrenceRole
    key: str
    #: The definitions this occurrence reaches the binding *through*, where it is spelled on another
    #: name for the same object — Chow's χ. Empty for an occurrence of the binding's own name.
    #:
    #: A shared reference always kills: a read below it can no longer be answered by the value from
    #: before, whether or not the store landed here. Whether it also *defines* is the question the
    #: chain is carried for, and it is an ordering question this layer does not answer: the link
    #: holds where its definition runs first and neither name is rebound between it and the store.
    #: `refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow` is the layer that asks.
    shared_through: tuple[Ps1AliasLink, ...] = ()

    @property
    def may_define(self) -> bool:
        """
        Whether the occurrence only *may* write this binding, so that nothing may read a value out
        of it until the links it came through are shown to hold.
        """
        return bool(self.shared_through)


@dataclass(eq=False)
class Binding:
    """
    A single variable name bound within one scope. `writes` holds every occurrence that writes it
    (an assignment target, a `++`/`--` operand, a `foreach` variable, a parameter, a `[ref]`, a
    command that addresses the name as a string, a store *through* the value such as the `$x` of
    `$x[0] = 9` or of `[Array]::Reverse($x)`, and a store shared in from another name for the same
    object); `reads` holds every occurrence that reads it, including a bare read that fell through
    from a nested block. `dynamic_or_qualified` marks a binding a scope qualifier or dynamic scope
    could reach with no occurrence in `reads` — conservatively kept live.

    Not every occurrence in `writes` installs a value, so a consumer reading one has to ask.
    `Occurrence.role` says whether the store replaces the value or reaches through it, and
    `Occurrence.shared_through` whether the occurrence is spelled on this name at all.
    """
    name: str
    scope: Scope
    reads: list[Occurrence] = field(default_factory=list)
    writes: list[Occurrence] = field(default_factory=list)
    dynamic_or_qualified: bool = False
    #: Every type a constrained write of this binding names — the `string` of `[string]$q = 5`.
    #: PowerShell stores the constraint on the *variable*, not on the write, so it converts what
    #: every later write stores as well: measured, `[string]$q = 5; $q = 1, 2, 3; $q.Length` is 5,
    #: because `$q` holds the String `1 2 3`, not the array. Empty for a name no write constrains.
    #:
    #: Resolved rather than spelled, so that `[string]` and `[System.String]` are the one constraint
    #: they are. A set of source spellings would read those two as a name constrained twice, which
    #: a consumer has to refuse outright — and spelling a type two ways is obfuscation rather than
    #: an oddity. A spelling the data resolves to nothing is `None`, which is a constraint whose
    #: conversion cannot be named and is refused on its own account.
    constraints: set[Ps1TypeName | None] = field(default_factory=set)

    @property
    def is_read(self) -> bool:
        """
        Whether any occurrence reads the binding's value.
        """
        return bool(self.reads)

    @property
    def uses(self) -> list[Occurrence]:
        """
        Every occurrence that observes the binding's value: its `reads`, and those of its `writes`
        that read what was there in order to write it.

        The two lists are buckets, not roles, and an occurrence that both reads and writes has no
        bucket of its own — `$x += 1` and `[ref]$x` are filed under `writes` and observe the value
        as surely as anything in `reads`. Every consumer deciding whether a value is still wanted
        asks this rather than `reads`, because asking `reads` is exactly how a store whose only
        reader is a compound assignment came to be deletable.
        """
        return [
            *self.reads,
            *(write for write in self.writes if write.role.observes),
        ]

    @property
    def is_dead(self) -> bool:
        """
        Whether no use observes the binding's value: no occurrence observes it and no qualifier or
        dynamic scope reaches it. The write occurrences of a dead binding can be removed when they
        carry no other side effect (which the caller decides).
        """
        return not self.uses and not self.dynamic_or_qualified


@dataclass(eq=False)
class Scope:
    """
    A lexical scope introduced by the script or a `refinery.lib.scripts.ps1.model.Ps1ScriptBlock`.
    `node` is the introducing AST node, `bindings` maps a lowercased variable name to its `Binding`.
    """
    kind: ScopeKind
    node: Node
    parent: Scope | None = None
    children: list[Scope] = field(default_factory=list)
    bindings: dict[str, Binding] = field(default_factory=dict)
    #: Whether a write this cannot place reaches every binding here: one aimed at the script scope
    #: from anywhere — `Set-Variable $n 'v' -Scope Global` — or at a scope the lexical chain cannot
    #: name at all, of which `-Scope 1` is the one that occurs. Every binding is then in doubt for
    #: as long as the tree stands, since the write may have landed on any of them and nothing says
    #: when.
    #:
    #: A write landing in the scope it is *written* in is not one of these. That one happens at a
    #: point, and `refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow.unattributable_writes`
    #: holds it there, which leaves the reads before it answerable. Kept apart from
    #: `Binding.dynamic_or_qualified`, which says a *known* name is reachable another way; these are
    #: different reasons and a consumer may be able to live with one and not the other.
    writes_unreadable_names: bool = False


def scope_local_nodes(scope_node: Node) -> Iterator[Node]:
    """
    Yield every descendant of *scope_node* that belongs to its scope, yielding but not descending
    into a nested `refinery.lib.scripts.ps1.model.Ps1ScriptBlock` — each introduces its own scope,
    so its contents are attributed there instead.

    The same partition the control-flow graphs take, one graph per block plus one for the root, so
    a layer that asks this per graph asks after each node exactly once.
    """
    stack: list[Node] = list(scope_node.children())
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, Ps1ScriptBlock):
            continue
        stack.extend(node.children())


#: What each `Ps1NameRole` does to a value, in the vocabulary every other occurrence uses. An
#: appending out-variable reads what is there before it writes, which is exactly what
#: `Ps1OccurrenceRole.WRITE_OBSERVING` says; unbinding a name replaces whatever it held with nothing
#: at all, which for the purpose of tracking a value is a replacing write.
NAME_ROLES: dict[Ps1NameRole, Ps1OccurrenceRole] = {
    Ps1NameRole.READS: Ps1OccurrenceRole.READ,
    Ps1NameRole.WRITES: Ps1OccurrenceRole.WRITE_REPLACING,
    Ps1NameRole.APPENDS: Ps1OccurrenceRole.WRITE_OBSERVING,
    Ps1NameRole.UNBINDS: Ps1OccurrenceRole.WRITE_REPLACING,
}


class Ps1SemanticModel:
    """
    The resolved scope/binding/def-use model for one PowerShell script. Build it with
    `build_semantic_model` and query it through `scope_of` and `binding_of`, through the `bindings`
    of a `Scope`, and — for the flow-sensitive dead-store sweep — through `reads_in_scope` and
    `variables_in_scope`.
    """

    def __init__(self, root: Ps1Script):
        self.root = root
        self._node_scope: dict[int, Scope] = {}
        self._binding_of: dict[int, Binding] = {}
        self.root_scope = Scope(kind=ScopeKind.SCRIPT, node=root)
        self._node_scope[id(root)] = self.root_scope
        self._changes_in_place: bool | None = None
        self._populate(self.root_scope)
        self._build_def_use()

    @property
    def script_scope(self) -> Scope:
        """
        The scope the script itself introduces — the outermost scope, whose bindings are the
        script-level variables.
        """
        return self.root_scope

    @property
    def changes_an_object_in_place(self) -> bool:
        """
        Whether any occurrence in the script stores *through* a value rather than into a name — the
        `$x` of `$x[0] = 9`, of `$h.k = 9` and of `[Array]::Reverse($x)`.

        A script with none never changes an object after it is built, so there a copy of one and a
        second name for it are indistinguishable, and a consumer weighing the two may stop asking.
        That is the question every sharing guard is really about, and it is a fact about the script
        rather than about the name a guard happens to be standing on: an object handed to a
        hashtable key, to a property or to a callee is changed under a name the guard cannot see.
        """
        if self._changes_in_place is None:
            self._changes_in_place = any(
                write.role.through for write in self._every_write())
        return self._changes_in_place

    def scope_of(self, node: Node) -> Scope | None:
        """
        The innermost scope that contains *node*, or `None` if the node was not part of the script
        the model was built from. A node in an `if`/loop/`try` body resolves to the enclosing script
        or scriptblock scope, since those bodies introduce no scope of their own.
        """
        return self._node_scope.get(id(node))

    def binding_of(self, var: Ps1Variable) -> Binding | None:
        """
        The binding a variable occurrence resolves to — for a write, the binding in its defining
        scope; for a bare read, the nearest enclosing binding of the name — or `None` when the
        occurrence is free (an automatic or external variable the model never binds) or names a
        namespace outside the script's variables.
        """
        return self._binding_of.get(id(var))

    def reads_in_scope(self, node: Node, scope: Scope) -> set[str]:
        """
        The names of *scope*'s bindings read anywhere within *node*'s subtree — every bare read of a
        name *scope* binds, including one nested in a scriptblock, but not the target of a plain `=`
        assignment, which replaces the value without observing it. A compound-assignment target
        (`$x += 1`) does observe it and counts as a read. This is the read set the dead-store sweep
        flushes pending stores against: unlike the walk it replaces, it does not stop at a nested
        scriptblock, so a store read only through a captured block is correctly seen as live.
        """
        names: set[str] = set()
        for descendant in node.walk():
            if not isinstance(descendant, Ps1Variable):
                continue
            if descendant.scope is not Ps1ScopeModifier.NONE:
                continue
            name = descendant.name.lower()
            if name in scope.bindings and not replaces_value(descendant):
                names.add(name)
        return names

    def variables_in_scope(self, node: Node, scope: Scope) -> set[str]:
        """
        The names of *scope*'s bindings referenced in any way — read or written — within *node*'s
        subtree. The conservative flush set for a control-flow statement whose internal effect on a
        variable the linear sweep does not model: any mention of a bound name defers its pending
        store.
        """
        names: set[str] = set()
        for descendant in node.walk():
            if isinstance(descendant, Ps1Variable) and descendant.scope is Ps1ScopeModifier.NONE:
                name = descendant.name.lower()
                if name in scope.bindings:
                    names.add(name)
        return names

    def _populate(self, scope: Scope):
        for node in scope_local_nodes(scope.node):
            if isinstance(node, Ps1ScriptBlock):
                child = Scope(kind=self._scriptblock_kind(node), node=node, parent=scope)
                scope.children.append(child)
                self._node_scope[id(node)] = child
                self._populate(child)
                continue
            self._node_scope[id(node)] = scope
            if isinstance(node, Ps1Variable) and declares_binding(node):
                self._declare(node, scope)
            elif isinstance(node, Ps1CommandInvocation):
                self._declare_named(node, scope)

    @staticmethod
    def _scriptblock_kind(node: Ps1ScriptBlock) -> ScopeKind:
        if isinstance(node.parent, Ps1FunctionDefinition) and node.parent.body is node:
            return ScopeKind.FUNCTION
        return ScopeKind.SCRIPTBLOCK

    def _declare(self, var: Ps1Variable, current: Scope):
        scope = self._defining_scope(var, current)
        if scope is None:
            return
        key = binding_key(var)
        if key not in scope.bindings:
            scope.bindings[key] = Binding(name=key, scope=scope)

    def _declare_named(self, cmd: Ps1CommandInvocation, current: Scope):
        """
        Create the bindings a command addresses by string, and record a name it addresses that
        cannot be read.

        This is why the census is consulted while the model is built rather than applied to it
        afterwards: `Get-Process -OutVariable x` in a script that never writes `$x` any other way is
        the only mention of the name there is, so nothing exists to hang the reference on unless the
        binding is created here.

        An unreadable name landing in the command's own scope is *not* recorded here. That write
        happens at a point, and a point is what
        `refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow.unattributable_writes` holds, so
        a read before it keeps the value it would have observed anyway. Only a write this cannot
        place against the reads it may reach — one aimed at the script scope, or at a scope the
        lexical chain cannot name — is a fact about the scope as a whole.
        """
        unreadable = unreadable_name_target(cmd)
        if unreadable is not None and unreadable is not Ps1NameTarget.LOCAL:
            self._doubt(unreadable, current)
        for reference in named_references(cmd):
            if reference.role is Ps1NameRole.READS:
                continue
            scope = self._named_scope(reference, current)
            if scope is None:
                continue
            if reference.key not in scope.bindings:
                scope.bindings[reference.key] = Binding(name=reference.key, scope=scope)

    def _named_scope(self, reference: Ps1NamedReference, current: Scope) -> Scope | None:
        """
        The scope a named reference resolves in: the one the command is written in for the measured
        default, the script scope for an explicitly script- or global-qualified form, and none at
        all for a target the lexical chain cannot name — `-Scope 1` writes the *caller's* scope,
        which is not an ancestor of anything here. An unplaceable write is recorded on the scope
        instead, where it puts every name in doubt rather than the wrong one.
        """
        if reference.target is Ps1NameTarget.SCRIPT:
            return self.root_scope
        if reference.target is Ps1NameTarget.LOCAL:
            return current
        self._doubt(Ps1NameTarget.UNREADABLE, current)
        return None

    def _doubt(self, target: Ps1NameTarget, current: Scope) -> None:
        """
        Record that a write nobody can attribute lands in *target*, so every binding it could reach
        is in doubt.

        A target the lexical chain cannot name reaches anywhere, and the script scope is the one
        scope every other can see through, so it is marked as well as the scope holding the command:
        under-marking here is a fold across a write, which is the direction that corrupts.
        """
        if target is Ps1NameTarget.SCRIPT:
            self.root_scope.writes_unreadable_names = True
            return
        current.writes_unreadable_names = True
        if target is Ps1NameTarget.UNREADABLE:
            self.root_scope.writes_unreadable_names = True

    def _defining_scope(self, var: Ps1Variable, current: Scope) -> Scope | None:
        """
        The scope a write to *var* binds. A bare, `$local:`, or `$private:` assignment binds in the
        current scope (write-local); a `$script:`, `$global:`, or `$using:` assignment, and an
        `$env:` assignment (a process-global environment variable, bound under an `env:`-prefixed
        key), bind at the script scope. The provider namespaces (`variable:`, `function:`,
        `alias:`, `drive:`) name a namespace distinct from script variables and bind nothing here.
        """
        modifier = var.scope
        if modifier in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL, Ps1ScopeModifier.PRIVATE):
            return current
        if modifier in (
            Ps1ScopeModifier.SCRIPT,
            Ps1ScopeModifier.GLOBAL,
            Ps1ScopeModifier.USING,
            Ps1ScopeModifier.ENV,
        ):
            return self.root_scope
        return None

    def _build_def_use(self):
        for node in self.root.walk():
            scope = self._node_scope.get(id(node))
            if scope is None:
                continue
            if isinstance(node, Ps1CommandInvocation):
                self._attribute_named(node, scope)
                continue
            if not isinstance(node, Ps1Variable) or _is_member_declaration(node):
                continue
            role = occurrence_role(node)
            if not role.stores:
                self._attribute_read(node, scope)
            elif role.through:
                self._attribute_write_through(node, scope)
            elif declares_binding(node):
                self._attribute_write(node, scope)
            else:
                self._attribute_reference(node, scope)
        self._record_type_constraints()
        self._share_stores_through_aliases()

    def _record_type_constraints(self):
        """
        File the type each constrained write names against the binding it writes.

        The constraint outlives the statement that carries it: `[string]$q = 5` stores an
        `ArgumentTypeConverterAttribute` on the variable, and every later write is converted through
        it. So this is a fact about the binding rather than about the occurrence, and a caller
        reading a value out of an *unconstrained* write of a constrained name has to know.
        """
        for binding in self._every_binding():
            for write in binding.writes:
                if write.may_define or not isinstance(write.node, Ps1Variable):
                    continue
                named = _constraint_on(write.node)
                if named is not None:
                    binding.constraints.add(data.resolve_type(named))

    def _every_binding(self) -> Iterator[Binding]:
        stack = [self.root_scope]
        while stack:
            scope = stack.pop()
            stack.extend(scope.children)
            yield from scope.bindings.values()

    def _share_stores_through_aliases(self):
        """
        File every store-through against each binding that names the same object.

        `$y = $x` does not copy the array; it gives the one array a second name. So
        `[Array]::Reverse($x)` changes what a read of `$y` observes and `$y[0] = 9` changes what a
        read of `$x` observes, and neither is an occurrence of the other name. This is Chow's χ —
        a may-def filed against every member of an alias class — at the one depth a syntactic model
        can see: a definition whose whole value is a bare variable.

        **A shared store-through is a may-def and nothing stronger, which is what keeps it from
        corrupting.** Whether the alias still holds where the store runs is an ordering question,
        and this layer sees no order: `$x = 1, 2, 3; $y = $x; $y = 9, 9, 9; [Array]::Reverse($x)`
        leaves `$y` holding `9, 9, 9` — measured — although the definition `$y = $x` is filed all
        the same. So every occurrence shared here carries the chain of definitions it came through,
        and only kills until
        `refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow.reaching_definition` finds that
        chain intact at the store. Filing one where the alias does not hold then costs a fold and
        can never install a value the name never held.

        The class is closed under the relation rather than read off one definition, because a name
        reached through two of them is reached: `$y = $x; $z = $y` gives all three the one array,
        and a member that missed a store it did receive is the direction that answers with the value
        from before. The chain is what the second link is checked by: filed for `$z`, the store on
        `$x` carries both definitions, and either one broken breaks the answer.
        """
        for members, links in self._alias_classes():
            stores = [
                (binding, write)
                for binding in members
                for write in binding.writes
                if write.role.through and not write.may_define
            ]
            if not stores:
                continue
            adjacent = _link_adjacency(links)
            reached: dict[int, dict[int, tuple[Ps1AliasLink, ...]]] = {}
            for source, _ in stores:
                if id(source) not in reached:
                    reached[id(source)] = _alias_chains_from(adjacent, source)
            for binding in members:
                filed = {id(write.node) for write in binding.writes}
                for source, write in stores:
                    if source is binding or id(write.node) in filed:
                        continue
                    chain = reached[id(source)].get(id(binding))
                    if chain is None:
                        continue
                    filed.add(id(write.node))
                    binding.writes.append(
                        Occurrence(write.node, write.role, binding.name, chain))

    def _alias_classes(self) -> Iterator[tuple[list[Binding], list[Ps1AliasLink]]]:
        """
        The bindings a chain of definitions gives one object to, grouped, each beside the
        definitions that joined them. A definition qualifies when its whole value is a bare variable
        read — `$y = $x`, and `$y = ($x)`, since a parenthesis hands over what it wraps — or that
        read under a conversion, which qualifies as an *uncertain* link.

        One shape that reads like a definition is refused outright. A subexpression is not a
        parenthesis: measured, `$y = $($x)` unrolls the array to the pipeline and collects a fresh
        one, and `[object]::ReferenceEquals($x, $y)` is `False`. That is not doubt about whether the
        two names share, it is a definition that certainly copies, and filing it would cost folds
        for nothing.
        """
        classes: dict[int, list[Binding]] = {}
        joined: dict[int, list[Ps1AliasLink]] = {}
        for link in self._alias_definitions():
            here = classes.setdefault(id(link.first), [link.first])
            there = classes.get(id(link.second))
            if there is not here:
                if there is None:
                    here.append(link.second)
                else:
                    here.extend(there)
                    joined.setdefault(id(here), []).extend(joined.pop(id(there), []))
                for binding in there or (link.second,):
                    classes[id(binding)] = here
            joined.setdefault(id(here), []).append(link)
        seen: set[int] = set()
        for members in classes.values():
            if id(members) in seen:
                continue
            seen.add(id(members))
            yield members, joined.get(id(members), [])

    def _alias_definitions(self) -> Iterator[Ps1AliasLink]:
        """
        Each definition that hands one object to a second name, as the link between the two
        bindings it joins.

        A conversion on either side of the `=` is passed through and makes the link uncertain: it is
        the same object where nothing needed converting and a fresh one where something did, and
        which of the two ran is a question about the operand's runtime type. Both spellings count —
        `$y = [array]$x` and `$y = $x -as [array]` convert the value, `[int[]]$y = $x` constrains
        the variable — because the object either name ends up holding is the same question in all
        three. Measured: `$x = 1, 2, 3; $y = [array]$x; $y[0] = 9` leaves `$x` reading `9 2 3`.

        A constraint the *target* binding carries counts as much as one this occurrence spells,
        because PowerShell stores it on the variable and converts every later write through it.
        Measured: `[string]$y = 0; $x = 1, 2, 3; $y = $x; [Array]::Reverse($x); $y` writes `1 2 3`,
        because `$y` was handed the String `1 2 3` and never the array — so the definition that
        reads as the plainest of all is the one a constraint three statements above has already
        converted. `Binding.constraints` is therefore filed before this runs; see `_build_def_use`.

        A constraint the *named* binding carries is not one of these. It converted what that name
        was written with, at the write that carried it, and a read of the name hands over whatever
        it holds with nothing converting on the way out — measured, `[array]$x = 1, 2, 3; $y = $x;
        [Array]::Reverse($x); $y` writes `3 2 1`, the same as the script without the constraint.
        """
        for write in self._every_write():
            if write.may_define or not isinstance(write.node, Ps1Variable) or write.role.through:
                continue
            assignment = assignment_of(write.node)
            if assignment is None or assignment.operator != '=' or assignment.value is None:
                continue
            certain = True
            source: Node | None = assignment.value
            while source is not None and not isinstance(source, Ps1Variable):
                if isinstance(source, Ps1ParenExpression):
                    source = source.expression
                    continue
                if isinstance(source, Ps1CastExpression) or is_conversion_operator(source):
                    certain = False
                    source = _climbed_operand(source)
                    continue
                break
            if not isinstance(source, Ps1Variable):
                continue
            target = self._binding_of.get(id(write.node))
            named = self._binding_of.get(id(source))
            if target is None or named is None or target is named:
                continue
            yield Ps1AliasLink(write.node, target, named, certain and not target.constraints)

    def _every_write(self) -> Iterator[Occurrence]:
        for binding in self._every_binding():
            yield from binding.writes

    def _attribute_write(self, var: Ps1Variable, scope: Scope):
        binding = self._lookup_write_binding(var, scope)
        if binding is not None:
            self._record(binding, var, binding.writes)

    def _attribute_reference(self, var: Ps1Variable, scope: Scope):
        """
        Attribute a `[ref]$x` occurrence: resolved the way a read is, recorded the way a write is.

        The two halves are not the same question. PowerShell resolves the name by ordinary lookup,
        so a reference written inside a body reaches the enclosing binding and declares nothing —
        resolving it the way a write is resolved would look for a local binding that was never
        created and attribute the occurrence to nothing at all, losing the very use this exists to
        keep. What it then does to that binding is store into it, so it is recorded among the
        writes, where it both keeps the binding alive through `Binding.uses` and stops an earlier
        value reaching a later read.
        """
        if var.scope is not Ps1ScopeModifier.NONE:
            self._attribute_read(var, scope)
            return
        for binding in self._bindings_a_read_reaches(var, scope):
            self._record(binding, var, binding.writes)

    def _attribute_write_through(self, var: Ps1Variable, scope: Scope):
        """
        Attribute an occurrence a store reaches *through* — the `$x` of `$x[0] = 'z'`: resolved the
        way a read is, recorded the way a write is, and declaring nothing.

        Resolving it as a write would look for a binding in the scope the occurrence is written in
        and declare one PowerShell never creates, hiding the outer binding the store actually
        reaches. What it does to that binding is change the value under it, so it is recorded among
        the writes, where it kills whatever stood before it and leaves a read below it with a value
        nothing here can name.

        Unlike `[ref]`, a scope qualifier does not stop it. Measured: `[Array]::Reverse($script:x)`
        and `$script:x[0] = 9` both reach the script scope's array, so a qualified occurrence is
        recorded against the bindings the qualifier names rather than dropped to a read.

        It leaves `Binding.dynamic_or_qualified` alone, and so does every other write. That flag is
        what keeps a binding *no read names* alive, which is a question about reads; a qualified
        write of any kind — `$script:x = 5` as much as `$script:x[0] = 9` — is resolved through
        the scopes the qualifier names and needs nothing further.
        """
        for binding in self._bindings_a_read_reaches(var, scope):
            self._record(binding, var, binding.writes)

    def _bindings_a_read_reaches(self, var: Ps1Variable, scope: Scope) -> Iterator[Binding]:
        """
        Every binding an ordinary read of *var* written in *scope* could observe: the binding of the
        name in each enclosing scope for a bare reference, and the scopes `_qualified_read_scopes`
        names for a qualified one.

        Which one of several a reference resolves to depends on what ran, so every one of them is
        yielded and the caller records against all of them. For a write that is the conservative
        direction: a binding credited with a write it did not receive answers nothing about the
        values below it, where one that missed a write it did receive answers the value from before.
        """
        name = binding_key(var)
        if var.scope is Ps1ScopeModifier.NONE:
            cursor: Scope | None = scope
            while cursor is not None:
                binding = cursor.bindings.get(name)
                if binding is not None:
                    yield binding
                cursor = cursor.parent
            return
        for target in self._qualified_read_scopes(var, scope):
            binding = target.bindings.get(name)
            if binding is not None:
                yield binding

    def _attribute_named(self, cmd: Ps1CommandInvocation, scope: Scope):
        """
        File a command's string-addressed references against the bindings they name.

        A read resolves the way a bare variable read does, up the scope chain, and is recorded on
        every enclosing binding of the name — `Get-Variable x` inside a body observes whichever `$x`
        is in reach, and which one that is depends on what ran. A write resolves to the one scope
        the census placed it in.
        """
        for reference in named_references(cmd):
            role = NAME_ROLES[reference.role]
            if reference.role is Ps1NameRole.READS:
                cursor: Scope | None = scope
                while cursor is not None:
                    binding = cursor.bindings.get(reference.key)
                    if binding is not None:
                        binding.reads.append(
                            Occurrence(node=cmd, role=role, key=reference.key))
                    cursor = cursor.parent
                continue
            target = self._named_scope(reference, scope)
            if target is None:
                continue
            binding = target.bindings.get(reference.key)
            if binding is not None:
                binding.writes.append(Occurrence(node=cmd, role=role, key=reference.key))

    def _record(self, binding: Binding, var: Ps1Variable, into: list[Occurrence]) -> None:
        """
        File one variable occurrence against *binding*, and make it the occurrence's own binding
        unless an inner scope already claimed it — a bare reference is recorded on every enclosing
        binding of the name and resolves to the innermost.
        """
        into.append(Occurrence(node=var, role=occurrence_role(var), key=binding.name))
        self._binding_of.setdefault(id(var), binding)

    def _lookup_write_binding(self, var: Ps1Variable, scope: Scope) -> Binding | None:
        defining = self._defining_scope(var, scope)
        if defining is None:
            return None
        return defining.bindings.get(binding_key(var))

    def _attribute_read(self, var: Ps1Variable, scope: Scope):
        if var.scope is Ps1ScopeModifier.NONE:
            self._attribute_bare_read(var, scope)
        elif var.scope is Ps1ScopeModifier.ENV:
            binding = self.root_scope.bindings.get(binding_key(var))
            if binding is not None:
                self._record(binding, var, binding.reads)
        elif var.scope in _QUALIFIED_SCOPES:
            self._attribute_qualified_read(var, scope)

    def _attribute_qualified_read(self, var: Ps1Variable, scope: Scope):
        """
        Mark every binding a scope-qualified read can reach as `Binding.dynamic_or_qualified`, so it
        is never reported dead even though no occurrence in `Binding.reads` names it.
        """
        name = var.name.lower()
        primary: Binding | None = None
        for target in self._qualified_read_scopes(var, scope):
            binding = target.bindings.get(name)
            if binding is None:
                continue
            binding.dynamic_or_qualified = True
            if primary is None:
                primary = binding
        if primary is not None:
            self._binding_of[id(var)] = primary

    def _qualified_read_scopes(self, var: Ps1Variable, scope: Scope) -> Iterator[Scope]:
        """
        The scopes a scope-qualified read of *var* can reach. `$variable:` addresses the Variable
        provider drive, which resolves like a bare reference, so it reaches every enclosing scope;
        every other qualifier names the one scope `_defining_scope` binds a write through it in —
        the scope of the reference itself for `$local:` and `$private:`, the script scope for
        `$script:`, `$global:`, and `$using:`.
        """
        if var.scope is Ps1ScopeModifier.VARIABLE:
            cursor: Scope | None = scope
            while cursor is not None:
                yield cursor
                cursor = cursor.parent
            return
        defining = self._defining_scope(var, scope)
        if defining is not None:
            yield defining

    def _attribute_bare_read(self, var: Ps1Variable, scope: Scope):
        name = var.name.lower()
        cursor: Scope | None = scope
        while cursor is not None:
            binding = cursor.bindings.get(name)
            if binding is not None:
                self._record(binding, var, binding.reads)
            cursor = cursor.parent


def build_semantic_model(root: Ps1Script) -> Ps1SemanticModel:
    """
    Build the `Ps1SemanticModel` for a parsed PowerShell script.
    """
    return Ps1SemanticModel(root)
