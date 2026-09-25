"""
What a call leaves in the slot it writes through.

`refinery.lib.scripts.ps1.analysis.arguments` says *which* slots a call writes; this says what is in
one afterwards. The two are separate because they are used separately: a caller refusing to install
a value only needs the first, and every refusal it makes is safe whether or not the second answers.

Nothing here computes a value. `[Array]::Reverse` reverses a collection, and what a collection is
and how one is spelled is `refinery.lib.scripts.ps1.analysis.values`' to say, so this reads the
value in and writes the value out through that module and holds only the rule between them.

**A rule answers only over the values the call is total on.** `[Array]::Reverse` and `[Array]::Clear`
throw when the range runs off the end, so each is answered only for a range that fits and refuses the
rest rather than clamping it: a value where 5.1 raised is worse than no answer, because a refusal
costs a fold and this would print something the script never printed. `[Array]::Sort` throws on an
array whose elements do not compare, a sub-domain the values here do not settle, so it has no rule.
"""
from __future__ import annotations

from typing import Sequence

from refinery.lib.scripts import Expression, _clone_node
from refinery.lib.scripts.ps1 import data
from refinery.lib.scripts.ps1.analysis.arguments import RECEIVER
from refinery.lib.scripts.ps1.analysis.model import written_call_slot
from refinery.lib.scripts.ps1.analysis.values import (
    integer_of,
    null_expression,
    read,
    sort_key,
    type_of,
    unwrap_to_array_literal,
)
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1ArrayLiteral,
    Ps1TypeExpression,
    Ps1Variable,
)

#: The members whose effect on their slot is written down here, each a canonical type key and a
#: lowercased member name.
_REVERSE = (data.required_type_key('array'), 'reverse')
_CLEAR = (data.required_type_key('array'), 'clear')
_SORT = (data.required_type_key('array'), 'sort')


def value_after(occurrence: Ps1Variable, previous: Expression) -> Expression | None:
    """
    The value the name *occurrence* stands for holds once the call around it has run, given the
    value `previous` it held before it, or `None` where no rule names one.

    `None` is the answer to every kind of doubt: a member with no rule, a call that writes more
    than the one slot, a conversion standing between the name and the slot, an operand this cannot
    read as a collection, and a range that would throw. A caller must fold nothing on it.

    It does *not* refuse a call the arity leaves unsettled. `[Array]::Sort($x)` binds two captured
    overloads at one argument — `Sort(Array)` and the generic `Sort<T>(T[])` — and every member
    dispatched below has a rule total over its same-arity overloads that write the one slot: both
    Sort overloads order the array ascending, and Reverse and Clear are positional. So the write
    being exactly the one slot is the whole precondition, and `settled` is left to the one caller
    that must tell an empty write set from an unbound call.
    """
    found = written_call_slot(occurrence)
    if found is None or found.written.slots != {found.slot}:
        # The write is exactly the one slot; not that the arity settled the overload. Every member
        # dispatched below has a value rule total over its same-arity overloads that write that
        # slot, so an unsettled arity (Sort at one argument) is still answered. The witness in
        # `test_witnessed` fails if a `settled` term is put back here.
        return None
    if found.slot == RECEIVER:
        # No rule here is about a receiver yet, and the bounds below are the arguments *after* the
        # written slot, which for a receiver would be the whole list: `$x.SetValue(9, 0)` would be
        # read as reversing a range.
        return None
    if found.through_a_part:
        # `[Array]::Reverse($p[0])` turns around the array `$p`'s first element is, so what `$p`
        # holds afterwards is the outer array with that one element replaced. Naming it is Knobe
        # and Sarkar's element update, which needs the index to be constant and the element to be
        # unshared; until it is built, answering the *slot* here would report the inner array's new
        # order as the outer array's.
        return None
    if found.may_be_a_copy:
        # A cast between the name and the slot may hand the callee a fresh value built from what the
        # name holds rather than the value itself — measured, `[Array]::Reverse([int[]]$x)` over an
        # `Object[]` reverses a temporary and leaves `$x` in its original order. Which of the two a
        # cast is depends on the operand's runtime type, so the pair is refused rather than read.
        return None
    call = found.call
    if call.access is not Ps1AccessKind.STATIC or not isinstance(call.member, str):
        return None
    named = call.object
    if not isinstance(named, Ps1TypeExpression):
        return None
    resolved = data.resolve_type(named.name)
    if resolved is None:
        return None
    member = (resolved.generic_definition, call.member.lower())
    bounds = call.arguments[found.slot + 1:]
    if member == _REVERSE:
        return _reversed(previous, bounds)
    if member == _CLEAR:
        return _cleared(previous, bounds)
    if member == _SORT:
        return _sorted(previous, bounds)
    return None


def _reversed(previous: Expression, bounds: Sequence[Expression]) -> Expression | None:
    """
    The collection `previous` names with a run of it turned around, or `None` where this names none.

    `bounds` is what the call passes after the array: nothing for the whole of it, an index and a
    length for a part. A part that does not fit inside the collection is refused rather than
    clamped, because 5.1 does not reverse anything there at all — measured,
    `[Array]::Reverse($b, 0, 99)` over three elements throws `ArgumentException`, and answering with
    a value would put one where the script raised.

    Only a collection is answered for. A String bound to the `System.Array` parameter is converted
    to a one-element `object[]` holding the string, which the call turns around and discards, so the
    variable is left holding exactly what it held — measured, and a fact about the *conversion*
    rather than about reversal, which is why it is refused here rather than answered.

    The elements are copied before the answer is built out of them. A node adopts the children
    it is handed, so building the answer over the ones still standing in the tree would leave
    the array the script wrote with children naming a node that is nowhere in it — and every
    guard that asks what encloses a statement climbs out of the tree from there. This answer is
    a value, not a rewrite, and a value has to be free of the tree it was read from whether the
    caller installs it or not.
    """
    array = unwrap_to_array_literal(previous)
    if array is None:
        return None
    if bounds:
        if len(bounds) != 2:
            return None
        start = integer_of(read(bounds[0]))
        length = integer_of(read(bounds[1]))
        if start is None or length is None:
            return None
        if start < 0 or length < 0 or start + length > len(array.elements):
            return None
    else:
        start, length = 0, len(array.elements)
    stop = start + length
    elements = [_clone_node(element) for element in array.elements]
    return Ps1ArrayLiteral(
        elements=[*elements[:start], *elements[start:stop][::-1], *elements[stop:]])


def _cleared(previous: Expression, bounds: Sequence[Expression]) -> Expression | None:
    """
    The collection `previous` names with a run of it set to `$null`, or `None` where this names none.

    `[Array]::Clear` takes an index and a length and has no whole-collection form, so a call that
    does not pass exactly those two is refused. A range that runs off the end is refused rather than
    clamped, for the reason `_reversed` refuses one: 5.1 raises there, and a value would stand where
    the script did not.

    Only a bare array literal is answered for, and every one of those is an `Object[]` whose element
    default is `$null` — a typed array clears to that type's default instead, and a cast standing
    between the literal and the call is one `unwrap_to_array_literal` does not read through, so the
    element the answer writes is always `$null`.

    The surviving elements are copied before the answer is built, for the reason `_reversed` copies
    them: a node adopts the children it is handed, and a value read out of the tree has to be free
    of it.
    """
    array = unwrap_to_array_literal(previous)
    if array is None or len(bounds) != 2:
        return None
    start = integer_of(read(bounds[0]))
    length = integer_of(read(bounds[1]))
    if start is None or length is None:
        return None
    if start < 0 or length < 0 or start + length > len(array.elements):
        return None
    stop = start + length
    elements = [_clone_node(element) for element in array.elements]
    cleared = [null_expression() for _ in range(start, stop)]
    return Ps1ArrayLiteral(elements=[*elements[:start], *cleared, *elements[stop:]])


def _sorted(previous: Expression, bounds: Sequence[Expression]) -> Expression | None:
    """
    The collection `previous` names put in the order `[Array]::Sort` leaves it, or `None` where this
    names none.

    Only the whole-array form is answered. A comparer, a range or a two-array form takes more than
    one argument, so at every such arity the written-slot union is `{0, 1}` — `Sort(Array, Array)`
    writes both — and `value_after`'s slot guard refuses it before dispatch. Only the one-argument
    form reaches here, where `bounds` is always empty; refusing a non-empty one is a defensive floor.
    The elements must share one real type — 5.1 throws on an array whose elements do not compare, so
    a value over a heterogeneous or unreadable one would stand where the script raised — and their
    keys must be distinct, because `[Array]::Sort` is not a stable sort and elements that compare
    equal are left in an order 5.1 does not fix, observable wherever they render differently.

    The elements are copied before the answer is built out of them, for the reason `_reversed` copies
    them: a node adopts the children it is handed, and a value read out of the tree has to be free of
    it whether the caller installs it or not.
    """
    array = unwrap_to_array_literal(previous)
    if array is None or bounds:
        return None
    facts = [read(element) for element in array.elements]
    if len({type_of(fact) for fact in facts}) != 1 or type_of(facts[0]) is None:
        return None
    keys: list[tuple] = []
    for fact in facts:
        key = sort_key(fact)
        if key is None:
            return None
        keys.append(key)
    if len(set(keys)) != len(keys):
        return None
    order = sorted(range(len(keys)), key=keys.__getitem__)
    return Ps1ArrayLiteral(elements=[_clone_node(array.elements[index]) for index in order])
