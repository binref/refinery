"""
The .NET type a variable carries where it is read.

A variable has no type of its own — the value it holds does — so the question is which write a read
observes and what type that write establishes. The first half is
`refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow.reaching_definition` and the second is
`refinery.lib.scripts.ps1.analysis.values.resolve_expression_type`; what is left here is the join.

The type must follow the reaching definition, not the name: a per-name scan crosses every scope
boundary the language has. A write inside a function body would type a read at the top level, so
`function f { $q = New-Object Net.WebClient }` followed by `($q | Get-Member)[0].Name` would fold to
a member of a type the top-level `$q` never holds — it holds `$null`, and `Get-Member` over `$null`
is an error rather than a member list.
"""
from __future__ import annotations

from typing import TypeGuard

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.dataflow import Ps1FlowUnknown, Ps1VariableFlow
from refinery.lib.scripts.ps1.analysis.model import Binding, is_mutated_in_place
from refinery.lib.scripts.ps1.analysis.values import (
    convert,
    read,
    render,
    resolve_expression_type,
)
from refinery.lib.scripts.ps1.ast import assignment_of, unwrap_parens
from refinery.lib.scripts.ps1.data import named_type, resolve_type
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1CastExpression,
    Ps1ForEachLoop,
    Ps1HereString,
    Ps1StringLiteral,
    Ps1Variable,
)

#: The reasons a binding's values cannot be tracked that no reasoning about its *type* can survive:
#: each of the four is a way for the writes this layer sees to say nothing about what the name holds
#: where it is read. Three of them are a store of any type by something out of view. The fourth is
#: `SHADOWS_A_WIDER_SCOPE`, which is the opposite shape and has the same consequence: the writes are
#: all in view, and some of them land on a name a bare read never resolves to, so
#: `$q = 'text'; $global:q = 5` reads as one name typed twice where the language has two.
#: A write nothing can place is not among them — it says which write ran cannot be settled, and
#: where the writes agree that question has no bearing on the type. Writes spread over several
#: bodies are of that kind too, and `type_at` refuses them on its own account rather than
#: here, because its first rule can still name one of them.
_INSTALLS_ANY_TYPE = (
    Ps1FlowUnknown.REACHED_BY_QUALIFIER
    | Ps1FlowUnknown.SHADOWS_A_WIDER_SCOPE
    | Ps1FlowUnknown.WRITTEN_BY_DEFERRED_BODY
    | Ps1FlowUnknown.WRITTEN_BY_UNREADABLE_NAME
)


def type_at(var: Ps1Variable, flow: Ps1VariableFlow) -> Ps1TypeName | None:
    """
    The type of the value *var* reads where it stands, or `None` where no single type is.

    **Two rules, and either one alone answers.** The write the read observes is the first and the
    precise one: it names the type even where the binding's writes disagree. Where the ordering
    names no single write, a binding *all* of whose writes establish the same type still has that
    type at every read of it, because which of them ran cannot matter. The second rule is what
    keeps this answering at the positions the ordering declines and a type survives anyway — a
    name stored through a member, and a write and a read inside one `$( ... )`, which the graphs
    hold as a single point — and dropping it took the member spellings off a real sample.

    The second rule has to establish two things the first gets for free. **That a write has run at
    all**, which `written_before` answers: writes that agree say nothing about a read that precedes
    every one of them, where the name holds what it held before the script started. And **that the
    writes it is agreeing over are all of them**, which `foreign_write_before` answers:
    `Invoke-Expression $code` stores a value of any type under any name and `. { $q = … }` stores
    into the caller's scope from a binding of its own, so agreement among the writes this binding
    holds is no claim about the ones it does not. Writes spread over several bodies are refused
    there too, because whether one body runs before another is what this layer does not answer.

    **A store through the name is not one of the writes the second rule agrees over.** It installs
    no value, and what it does to the one already there cannot change its type: `$q.Proxy = $null`
    leaves `$q` naming the object it named before. Counting it in the set instead makes it
    contribute the refusal it is and takes the whole agreement down with it, which costs the member
    spellings inside a `$( ... )` — where the graphs hold the writes and the read as one point, so
    the second rule is the only one answering at all.
    """
    return _type_at(var, flow, frozenset())


def _type_at(
    var: Ps1Variable,
    flow: Ps1VariableFlow,
    chased: frozenset[int],
) -> Ps1TypeName | None:
    binding = flow.semantic.binding_of(var)
    if binding is None or not binding.writes:
        return None
    if flow.unknowns(binding) & _INSTALLS_ANY_TYPE:
        return None
    observed = flow.reaching_definition(var)
    if observed is not None:
        return _installed_by(observed, flow, chased)
    if flow.unknowns(binding) & Ps1FlowUnknown.WRITES_IN_SEVERAL_BODIES:
        return None
    if flow.foreign_write_before(var) or not flow.written_before(var):
        return None
    named = {
        _installed_by(write.node, flow, chased)
        for write in binding.writes
        if not _stores_through(write.node)
    }
    return named.pop() if len(named) == 1 else None


def _stores_through(write: Node) -> TypeGuard[Ps1Variable]:
    """
    Whether *write* changes the value under the name without installing one of its own.
    """
    return isinstance(write, Ps1Variable) and is_mutated_in_place(write)


def _installed_by(
    write: Node,
    flow: Ps1VariableFlow,
    chased: frozenset[int],
) -> Ps1TypeName | None:
    """
    The type the name holds once *write* has run.

    A write that stores *through* the name installs no value of its own: `$q.Proxy = $null` leaves
    `$q` naming the object it already named, so the type is the one whichever write put that object
    there established. It is chased rather than refused because refusing it costs every member
    spelling below the first store through, which was measured on a real sample.

    `chased` bounds the chase, and the bound is not decoration. A store through does not observe
    itself where the statement runs once, but inside a loop it does — the previous visit's store is
    what it reads — so `while ($c) { $x.P = 1 }` is a write whose reaching definition is itself.
    """
    if not _stores_through(write):
        return _established_by(write, flow)
    if id(write) in chased:
        return None
    return _type_at(write, flow, chased | {id(write)})


def _established_by(write: Node, flow: Ps1VariableFlow) -> Ps1TypeName | None:
    """
    The type a write occurrence puts into the name, or `None` for a write whose type this cannot
    name.

    Only the two writes that carry a type with them are read. A plain assignment establishes the
    type of what was assigned, and a `foreach` binding the type of one element of what is iterated.
    Everything else — a compound assignment, a `[ref]` cast, a parameter with no default, a `++`,
    a name a command writes — is a write whose type is not written down beside it, and a write
    this cannot type is one it must refuse rather than look past: looking past it is what the
    whole-script scan did.

    The assigned expression is typed with no variable typing of its own, so `$b = $a` leaves `$b`
    untyped rather than chasing `$a`'s write in turn. That is what the scan did as well, and the
    chase is a recursion this would have to bound — `$x = $x` inside a loop is a cycle in it.

    Which occurrences are assignment targets is `refinery.lib.scripts.ps1.ast.assignment_of`'s to
    say, and asking it is what brings the two spellings a test of `write.parent` cannot see: a
    constrained target, whose type the constraint decides rather than the value — `[string]$q =
    'abc'` types `$q` as `String` and every member spelling below it reads against that — and a
    multi-assignment slot, where the value is the element standing opposite it.
    """
    if isinstance(write, Ps1Variable):
        assignment = assignment_of(write)
        if assignment is not None:
            return _assigned_type(write, assignment, flow)
    parent = write.parent
    if isinstance(parent, Ps1ForEachLoop) and parent.variable is write:
        return _element_type(parent.iterable)
    return None


def _assigned_type(
    write: Ps1Variable,
    assignment: Ps1AssignmentExpression,
    flow: Ps1VariableFlow,
) -> Ps1TypeName | None:
    """
    The type `assignment` puts into *write*, or `None` where it names none.

    The walk from the occurrence up to the assignment is what reads the target apart: a cast passed
    on the way is a type constraint, and PowerShell converts to it rather than storing what was
    written — `[string]$q = 5` leaves a String. An array literal passed on the way is a
    multi-assignment, and the slot's own value is the element opposite it, which only holds where
    the two sides have the same number of elements: `$a, $b = 1, 2, 3` gives `$b` the *rest* as an
    array, and `$a, $b = 1` gives it `$null`.
    """
    if assignment.operator != '=':
        return None
    cursor: Node = write
    parent = cursor.parent
    constraint: str | None = None
    slot: int | None = None
    while parent is not None and parent is not assignment:
        if isinstance(parent, Ps1CastExpression) and constraint is None:
            constraint = parent.type_name
        elif isinstance(parent, Ps1ArrayLiteral):
            if slot is not None:
                return None
            slot = next(
                (at for at, element in enumerate(parent.elements) if element is cursor), None)
            if slot is None:
                return None
        cursor = parent
        parent = cursor.parent
    if constraint is not None:
        return resolve_type(constraint)
    value = assignment.value
    if not isinstance(value, Expression):
        return None
    if slot is None:
        return _stored_type(value, flow.semantic.binding_of(write))
    written = unwrap_parens(value)
    if not isinstance(written, Ps1ArrayLiteral):
        return None
    targets = _multi_assignment_targets(assignment.target)
    if targets is None or len(targets) != len(written.elements):
        return None
    element = written.elements[slot]
    if not isinstance(element, Expression):
        return None
    return _stored_type(element, flow.semantic.binding_of(write))


def _stored_type(value: Expression, binding: Binding | None) -> Ps1TypeName | None:
    """
    The type an unconstrained write of *value* leaves under the name, or `None` where it names none.

    Where the binding carries no constraint that is just the value's own type. Where it carries one,
    the value is converted on the way in and the answer is the constraint's — but only from the
    point the constraint runs, which the ordering here does not settle, so the two are separated
    only where they disagree: a value already of the constrained type is stored unchanged whether or
    not the constraint is yet in force, and one of any other type is refused.
    """
    named = resolve_expression_type(value)
    return named if not constraint_converts(binding, value) else None


def constraint_converts(binding: Binding | None, value: Expression) -> bool:
    """
    Whether the binding's type constraint changes *value* before it is stored, so that what the name
    holds is not what the source wrote.

    `[string]$q = 5` stores an `ArgumentTypeConverterAttribute` on the *variable* rather than on the
    statement, so every later write is converted through it too: measured, `[string]$q = 5;
    $q = 1, 2, 3; Write-Output $q.Length` prints 5, because `$q` holds the String `1 2 3` rather
    than the array. A value whose own type is already the constrained one passes through untouched,
    which is what keeps `[string]$q = 'abc'` answering.

    Two constraints on one name are refused without asking which: which of them is in force at a
    given write is an ordering question, and the answer would have to be the value under whichever
    ran. `Binding.constraints` holds resolved types rather than spellings, so `[string]` written
    beside `[System.String]` is the one constraint it is and not two.
    """
    if binding is None or not binding.constraints:
        return False
    if len(binding.constraints) > 1:
        return True
    constrained = next(iter(binding.constraints))
    return constrained is None or resolve_expression_type(value) != constrained


def _declared_constraint_type(write: Node) -> Ps1TypeName | None:
    """
    The type a cast on *write*'s target constrains it to, when *write* is the target of a plain
    assignment that carries one — the `[string]` of `[string]$q = 5`. `None` for a target with no
    cast, or one reached through anything but a plain `=`: a compound assignment carries no fresh
    constraint and is answered by the value it accumulates.
    """
    if not isinstance(write, Ps1Variable):
        return None
    assignment = assignment_of(write)
    if assignment is None or assignment.operator != '=':
        return None
    cursor: Node = write
    parent = cursor.parent
    while parent is not None and parent is not assignment:
        if isinstance(parent, Ps1CastExpression):
            return resolve_type(parent.type_name)
        cursor = parent
        parent = cursor.parent
    return None


def value_under_declared_constraint(write: Node, value: Expression) -> Expression | None:
    """
    The literal a constrained assignment stores, when *write* is the target that declares the
    constraint: `[string]$q = 5` holds the String `5`, so a read of `$q` observes `'5'` and not the
    integer written. `None` where *write* carries no constraining cast, or where converting *value*
    to the constrained type is a question `refinery.lib.scripts.ps1.analysis.values.convert` does not
    settle — a collection to a String needs the session's `$OFS`, and a value the domain cannot read
    has no conversion at all.

    Only the declaring write is answered. A constraint converts a write only from the point it is in
    force, and which writes a constraint declared elsewhere reaches is an ordering question this does
    not settle; at the cast that installs the constraint there is none, because the cast that
    constrains the variable is the cast that converts the value written through it.
    """
    constrained = _declared_constraint_type(write)
    if constrained is None:
        return None
    outcome = convert(read(value), constrained)
    return None if outcome.may_throw else render(outcome.value)


def _multi_assignment_targets(target: Node | None) -> list[Node] | None:
    """
    The slots a multi-assignment target holds, or `None` where the target is not one.
    """
    target = unwrap_parens(target) if target is not None else None
    return list(target.elements) if isinstance(target, Ps1ArrayLiteral) else None


#: What `foreach` yields from a string: the string itself, not its characters.
_STRING = named_type('System.String')


def _element_type(iterable: Expression | None) -> Ps1TypeName | None:
    """
    The type of one element a `foreach` iterable yields, or `None` where its elements do not share
    one this can name. A string yields itself rather than its characters, which is measured.
    """
    if isinstance(iterable, (Ps1StringLiteral, Ps1HereString)):
        return _STRING
    if not isinstance(iterable, Ps1ArrayLiteral) or not iterable.elements:
        return None
    named = set()
    for element in iterable.elements:
        if not isinstance(element, Expression):
            return None
        one = resolve_expression_type(element)
        if one is None:
            return None
        named.add(one)
    return named.pop() if len(named) == 1 else None
