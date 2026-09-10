"""
Which slots of a .NET call the callee writes through.

A *slot* is the receiver or one argument, addressed by position. `[Array]::Reverse($buffer)` leaves
`$buffer` bound to the array it was bound to and turns that array around, so the call is a write of
slot 0 and every later read of the variable observes it. Nothing in the signature says so: the
argument is passed by value, and an array is a reference the callee writes through with no `out` or
`byref` marker on it. That is why this is a hand-kept table rather than a reading of the metadata,
and why `refinery.lib.scripts.ps1.data.static_overloads` can only floor it.

The polarity is the opposite of the purity tables'. A purity allow-list is a *grant* table: a miss
withholds a rewrite, so a missing entry costs a fold. This is a *deny* table: a miss lets a caller
put a value where the callee was going to write, and the write is then lost — `[Array]::Copy($x,
$y, 3)` with `$y` replaced by the array it held fills a temporary
and the script prints what `$y` started with. A missing entry here is a wrong answer, so the answer
carries whether it is settled and a caller that cannot live with doubt refuses on it.

**Keyed on the arity, and the arity may not settle the overload.** `[Array]::Sort($a, $b)` runs
`Sort(Array, Array)`, which writes both slots, when `$b` is an array and `Sort(Array, IComparer)`,
which writes only the first, when it is a comparer — a difference no reading of the source decides.
`written_slots` therefore answers the *union* over the arity-matched overloads, which is what a
caller refusing to substitute needs, and reports `settled` as false, which is what a caller
computing the resulting value needs to see.

This module is rank 0 within `refinery.lib.scripts.ps1.analysis`: it imports nothing from the
package, so nothing here can consult a type oracle. The type of a call's receiver is a question for
a layer that has one, and it arrives as a parameter.
"""
from __future__ import annotations

import functools
import typing

from refinery.lib.scripts.ps1 import data
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName

#: The slot a call's receiver occupies, so that `$a.CopyTo($b, 0)` and `[Array]::Copy($a, $b, 3)`
#: address their parts the same way. Negative because an argument's slot is its own position.
RECEIVER = -1


class Ps1WrittenSlots(typing.NamedTuple):
    """
    Which slots of one call the callee may write through.

    `slots` is the union over every overload the call's arity matches, so a caller may read it as
    *every* slot that could be written and none that could not. `settled` says whether the arity
    picked out a single overload. Its one reader is the empty-`slots` distinction below: a rule
    computing the value a call leaves behind does not consult it, because that rule is total over
    the same-arity overloads that write its one slot whether or not the arity picked one out.

    An empty `slots` therefore means two different things and the difference is `settled`.
    Exact and empty is a claim: this call writes nothing. Unsettled and empty is a refusal: the
    table names the member but not this call, so nothing is claimed about it either way. A
    consumer that reads the pair as one truth value collapses them, which is why there is no
    `__bool__` here.
    """
    slots: frozenset[int]
    settled: bool


#: Nothing is written and the answer is exact: the member is not one that writes through a slot.
NOTHING = Ps1WrittenSlots(frozenset(), True)

#: The table names the member but no overload of it takes this many arguments, so which slots the
#: call writes is not a question this can answer — 5.1 binds no overload and raises. Distinct from
#: `NOTHING`, which is the claim that a call was found and writes nothing.
UNBOUND = Ps1WrittenSlots(frozenset(), False)


def _floored(
    entries: dict[tuple[str, str], dict[int, tuple[int, ...]]],
    *,
    static: bool,
) -> dict[tuple[Ps1TypeName, str], dict[int, frozenset[int]]]:
    """
    A written-slot table keyed by canonical type, with every row checked against the collected
    metadata: the type must resolve, the member must carry overloads on the side the row is about,
    each arity must be one some overload of it has, and each slot must address a part that call
    has.

    The flooring is what stops a row rotting into silence: a row the collected metadata cannot back
    — a member 5.1 does not carry, an arity no overload has — is rejected rather than trusted.

    The slot check is the one that keeps a typo from flipping the polarity. A row naming a slot the
    arity does not reach is skipped by every consumer that indexes the arguments by it, so the call
    reads as writing nothing shared and the whole statement becomes removable — the deny table
    failing open, which is the one failure this module exists to prevent. `RECEIVER` is a part only
    a call on a *value* has, so it is a reachable slot only on the instance side. An occurrence does
    stand at a static receiver — `$t = [Array]; $t::Reverse($x)` spells one — but what it holds
    there is the `System.Type`, and a static member writes through its arguments and never through
    the type it is declared on, so a row naming that slot would deny a hand-off no call makes.
    """
    table: dict[tuple[Ps1TypeName, str], dict[int, frozenset[int]]] = {}
    for (type_name, member), by_arity in entries.items():
        key = data.required_type_key(type_name)
        overloads = (
            data.static_overloads(key, member) if static
            else data.instance_overloads(key, member)
        )
        available = {len(overload.get('parameters') or ()) for overload in overloads}
        if not available:
            raise ValueError(
                F'the written-slot table names {type_name}::{member}, which the collected metadata '
                F'carries no {"static" if static else "instance"} overload of.'
            )
        if set(by_arity) != available:
            raise ValueError(
                F'the written-slot table gives {type_name}::{member} entries at '
                F'{sorted(by_arity)} arguments where the collected overloads take '
                F'{sorted(available)}; a row is answered by arity, so one short of what the type '
                F'offers would answer an uncovered call with silence rather than with doubt.'
            )
        for arity, slots in by_arity.items():
            unreachable = [
                slot for slot in slots
                if not (0 <= slot < arity or (slot == RECEIVER and not static))
            ]
            if unreachable:
                raise ValueError(
                    F'the written-slot table gives {type_name}::{member} at {arity} arguments the '
                    F'slots {sorted(unreachable)}, which that call has no part at; a slot nothing '
                    F'can address is one every consumer skips, and the row would grant what it was '
                    F'written to deny.'
                )
        table[(key, member.lower())] = {
            arity: frozenset(slots) for arity, slots in by_arity.items()
        }
    return table


#: What each static call writes through, by the number of arguments it is given. `Sort` is the entry
#: that the arity does not settle: at two arguments `(Array, Array)` writes both slots and
#: `(Array, IComparer)` writes only the first, and the source does not say which runs.
#:
#: `[Array]::Resize` is deliberately absent. Its parameter is marked `byref` in the shipped capture,
#: which `refinery.lib.scripts.ps1.analysis.effects` already reads, so a hand-written row for it
#: would be a second place to keep the same fact.
_STATIC_WRITES = _floored({
    ('array', 'clear')              : {3: (0,)},
    ('array', 'constrainedcopy')    : {5: (2,)},
    ('array', 'copy')               : {3: (1,), 5: (2,)},
    ('array', 'reverse')            : {1: (0,), 3: (0,)},
    ('array', 'sort')               : {1: (0,), 2: (0, 1), 3: (0, 1), 4: (0, 1), 5: (0, 1)},
    ('buffer', 'blockcopy')         : {5: (2,)},
    ('buffer', 'setbyte')           : {3: (0,)},
    ('convert', 'tobase64chararray'): {5: (3,), 6: (3,)},
}, static=True)

#: What each call on a *value* writes through. `SetValue` writes the array it is called on, which is
#: the receiver rather than any argument; `CopyTo` writes an argument, and which one depends on the
#: type it is called on — `System.Array` fills the first, `System.String` the second.
#:
#: A row is answered by member *name* here, because `written_slots` is asked where no receiver type
#: is known — so one row per name is what the union needs and a second type spelling the same name
#: adds nothing. `System.IO.Stream` stands for every reader that fills a buffer at three arguments,
#: `System.Collections.ArrayList` for every collection that fills one at one, and
#: `System.Security.Cryptography.ICryptoTransform` for `HashAlgorithm` as well.
#:
#: `[Text.Encoding]::ASCII.GetBytes($s)` is why the encoders carry an empty row at every arity but
#: the last: the name they share with `RNGCryptoServiceProvider::GetBytes`, which fills its *first*
#: slot, cannot be told apart without a receiver type, and a row for that member would refuse the
#: single most-folded call in an obfuscated script. It is left out deliberately, and it is the one
#: written slot this module knows of and does not answer — see `written_slots`.
_INSTANCE_WRITES = _floored({
    ('array', 'copyto')                 : {2: (0,)},
    ('array', 'setvalue')               : {2: (RECEIVER,), 3: (RECEIVER,), 4: (RECEIVER,)},
    ('collections.arraylist', 'copyto') : {1: (0,), 2: (0,), 4: (1,)},
    ('io.stream', 'read')               : {3: (0,)},
    ('random', 'nextbytes')             : {1: (0,)},
    ('security.cryptography.icryptotransform', 'transformblock'): {5: (3,)},
    ('string', 'copyto')                : {4: (1,)},
    ('text.encoding', 'getbytes')       : {1: (), 3: (), 4: (), 5: (3,)},
    ('text.encoding', 'getchars')       : {1: (), 3: (), 4: (), 5: (3,)},
}, static=False)


@functools.lru_cache(maxsize=None)
def written_slots(
    type_name: Ps1TypeName | None,
    member: str,
    arity: int,
    *,
    static: bool,
) -> Ps1WrittenSlots:
    """
    The slots a `[Type]::Member(...)` or `value.Member(...)` call of *arity* arguments may write
    through, given the canonical type it is called on.

    Memoized over the whole run, and soundly: the two tables are built at import and the collected
    metadata behind `_across_every_type` does not change either, so the answer depends on nothing
    but the four arguments. What it saves is a rescan of a type's member dictionary per occurrence
    standing in a call slot — measured over the corpus, 809 calls resolving to eleven answers.

    `type_name` is `None` where the type is not known, which is the ordinary case for a call on a
    value: the answer is then the union over every type carrying a member of that name, since which
    of them it is cannot be decided here. That answer is never `settled`.

    **One written slot is knowingly unanswered.** `RNGCryptoServiceProvider::GetBytes` fills its
    first argument and shares its name with `Encoding::GetBytes`, which fills none at that arity;
    with no receiver type to separate them a row would refuse every `[Text.Encoding]::UTF8
    .GetBytes($s)` in the corpus. Answering it needs the receiver's type, which is what
    `_across_every_type` exists because this layer does not have.
    """
    if type_name is None:
        return _across_every_type(member, arity, static=static)
    table = _STATIC_WRITES if static else _INSTANCE_WRITES
    by_arity = table.get((type_name.generic_definition, member.lower()))
    if by_arity is None:
        return NOTHING
    slots = by_arity.get(arity)
    if slots is None:
        # A row covers every arity its member has — `_floored` refuses to build one that does not —
        # so an arity with no entry is an arity no overload takes. 5.1 binds none of them and
        # raises, which is neither a write to lose nor a call to reason about.
        return UNBOUND
    overloads = (
        data.static_overloads(type_name, member) if static
        else data.instance_overloads(type_name, member)
    )
    matched = sum(1 for one in overloads if len(one.get('parameters') or ()) == arity)
    return Ps1WrittenSlots(slots, matched == 1)


def _across_every_type(member: str, arity: int, *, static: bool) -> Ps1WrittenSlots:
    """
    What a call of a member of this name may write where the type it is called on is unknown.

    Every row of that name contributes, whatever type it is written for, because nothing here rules
    any of them out. A name no row mentions writes nothing, and that answer *is* settled: the table
    is the whole of what is claimed to write through a slot, so a member outside it is one this says
    does not.
    """
    wanted = member.lower()
    table = _STATIC_WRITES if static else _INSTANCE_WRITES
    slots: set[int] = set()
    named = False
    for (_, name), by_arity in table.items():
        if name != wanted:
            continue
        named = True
        slots.update(by_arity.get(arity, frozenset()))
    return Ps1WrittenSlots(frozenset(slots), False) if named else NOTHING
