"""
What a PowerShell error handler means, read off the tree alone: which errors a `catch` clause or a
`trap` filter takes, which member of a `trap` set Windows PowerShell 5.1 hands an error, what the
error becomes once a `trap` body has run, and whether running a handler is something a run can see.

The control-flow builder `refinery.lib.scripts.ps1.analysis.cfg` wires its handler edges from these
answers and the dispatch evaluator `refinery.lib.scripts.ps1.analysis.dispatch` follows every error
by them, so neither holds a reading of its own; the builder asks the evaluator where an error goes
outward of a `trap` set or a `throw`. How a `trap` body ends
is the one fact that takes a walk over control flow rather than over the tree, and it is a fact of
the body alone: `refinery.lib.scripts.ps1.analysis.cfg.trap_disposition` builds the body on its own
to read it.
"""
from __future__ import annotations

import enum

from typing import AbstractSet, Sequence

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.model import (
    Ps1BreakStatement,
    Ps1CatchClause,
    Ps1ContinueStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
)

#: The type names a `catch` clause may carry that take every terminating error Windows PowerShell
#: 5.1 raises, in the spellings 5.1 resolves. `System.Exception` is the root of the .NET hierarchy
#: and matches by definition; `RuntimeException` is what the engine wraps a terminating error in,
#: measured to match a failed cast, a division by zero, `throw` of a string, `throw` of a .NET
#: exception, a method that threw, a member access on `$null`, and a cmdlet stopped by
#: `-ErrorAction Stop`.
#:
#: The spellings are the measurement too, and they are not symmetric: a bare name is resolved
#: against `System` alone, so `[Exception]` names `System.Exception` while `[RuntimeException]`
#: names nothing at all and the clause it filters matches no error whatsoever. Listing the short
#: form of the second would grant a clause that in fact declines everything, which is the one
#: direction that deletes code.
_CATCHES_EVERY_ERROR = frozenset({
    'exception',
    'system.exception',
    'management.automation.runtimeexception',
    'system.management.automation.runtimeexception',
})


def names_every_error(name: str) -> bool:
    """
    Whether *name* is a type filter every terminating error matches. An empty name is a `trap`
    carrying no type filter, which takes every error the way a bare `catch` does. A `catch` clause
    reaches this only with the names it could read: whether it carried a filter at all is
    `Ps1CatchClause.filtered`, so an unreadable one is never spelled here as the empty name.
    """
    return not name.strip() or name.strip().lower() in _CATCHES_EVERY_ERROR


def catch_takes_every_error(clause: Ps1CatchClause) -> bool:
    """
    Whether *clause* is certain to be the one that takes a throw the guarded block makes: it carries
    no type filter at all, or one of the filters it carries names a type every terminating error is.

    A clause carrying several types matches when *any* of them does, so one universal name among
    them settles it however narrow the others are. A clause whose filter was written but could not
    be read carries an empty `types` for a different reason than an unfiltered clause does, and
    `filtered` is what tells the two apart: erring towards *takes everything* would close the
    exceptional edge an enclosing handler still needs, so the unread filter takes nothing certain.
    """
    if not clause.filtered:
        return True
    return any(names_every_error(name) for name in clause.types)


def swallows_every_error(statement: Ps1TryCatchFinally) -> bool:
    """
    Whether every terminating error the `try` body of *statement* raises is certain to land in one
    of that statement's own `catch` clauses.

    The quantifier is the whole question, and it is an `any`: one clause that takes everything
    settles it however narrow the others are, and a construct carrying no `catch` at all swallows
    nothing, which an `all` reads as vacuously true. Answering it wrong in that direction hands a
    caller a raise it believes confined.

    What this licenses is confinement and not invisibility. A caught error is still recorded, and
    whether the script reads that record back is a different question with a different owner.
    """
    return any(catch_takes_every_error(clause) for clause in statement.catch_clauses)


def handler_acts(handler: Ps1CatchClause | Ps1TrapStatement) -> bool:
    """
    Whether running *handler* changes what the script does.

    An empty `catch { }` swallows the error and lets execution resume after the construct, so a
    script that never raises reaches the same next statement — which is why an obfuscator writes one
    and why removing what it guards costs nothing. A `trap` is the same rule with one more spelling:
    a body holding only an unlabelled `break` or `continue` decides how the error is disposed of and
    emits nothing, while a body holding anything else — a call, an assignment, or a bare value the
    engine writes to the output stream — is a handler whose running is observable.
    """
    body = handler.body.body if handler.body is not None else ()
    if isinstance(handler, Ps1CatchClause):
        return bool(body)
    for statement in body:
        if isinstance(statement, (Ps1BreakStatement, Ps1ContinueStatement)):
            if statement.label is not None:
                return True
            continue
        return True
    return False


def declared_traps(statements: Sequence[Node]) -> list[Ps1TrapStatement]:
    """
    The `trap` statements *statements* declares, in source order.

    A `trap` belongs to the statement block it is written in and to no other: it catches for that
    block entire, including the statements written above it, and an error raised outside the block
    is never offered to it. Collecting the traps of a nested block for the block around it hands
    those errors to a handler no run reaches, and — where the nested one is typed — reports a filter
    that may miss as guarding statements it does not guard at all.
    """
    return [statement for statement in statements if isinstance(statement, Ps1TrapStatement)]


class Ps1TrapDisposition(enum.Flag):
    """
    What running a `trap` body may do with the error it took. A body that branches may do several.
    """
    NONE = 0
    #: An unlabelled `continue` resumes the block at the statement after the one that raised.
    RESUMES = enum.auto()
    #: The body runs off its end, which writes the error record and hands the decision to
    #: `$ErrorActionPreference`: the block resumes, unless the preference is `Stop`.
    FALLS_THROUGH = enum.auto()
    #: A `break` that leaves the body re-raises the error to whatever guards the block.
    RETHROWS = enum.auto()


def settled(disposition: Ps1TrapDisposition, stops: bool) -> Ps1TrapDisposition:
    """
    What *disposition* comes to once the error preference has decided for a body that runs off its
    end: it resumes, since a script always starts out reporting, and re-raises as well where *stops*
    says a `Stop` may be in force. Neither `continue` nor `break` reads the preference.
    """
    if Ps1TrapDisposition.FALLS_THROUGH not in disposition:
        return disposition
    disposition = disposition & ~Ps1TrapDisposition.FALLS_THROUGH | Ps1TrapDisposition.RESUMES
    if stops:
        disposition |= Ps1TrapDisposition.RETHROWS
    return disposition


class Ps1TrapSelection:
    """
    The `trap` statements one block declares, read as 5.1 picks among them.

    5.1 picks the member by the error's type and not by where it is written: a member naming the
    error's own type, then one naming a type the error derives from, and only then the first member
    carrying no type at all. So every typed member may take an error, in source order, and after
    them the first untyped member takes whatever no typed member matched; an untyped member after
    that one takes nothing. A typed member naming a type every terminating error is takes everything
    before the untyped members are tried at all. `selectable` holds the members 5.1 may select, in
    the order it tries them, and `catching` says which of them take an error no narrower member
    names. A filter naming any other type is read as one that may or may not match.
    """

    def __init__(self, traps: Sequence[Ps1TrapStatement]):
        self.members = tuple(traps)
        typed = tuple(trap for trap in traps if trap.type_name.strip())
        self._universal = tuple(trap for trap in typed if names_every_error(trap.type_name))
        self._untyped = tuple(trap for trap in traps if not trap.type_name.strip())
        self.selectable = (*typed, *(trap for trap in self.catching() if not trap.type_name.strip()))
        self._chosen = {id(trap) for trap in self.selectable}
        self.never_selected = tuple(trap for trap in traps if id(trap) not in self._chosen)

    def catching(self, removed: AbstractSet[int] = frozenset()) -> tuple[Ps1TrapStatement, ...]:
        """
        The members that take an error no narrower member names, once the members whose identities
        *removed* holds are gone: every typed member left naming a type every error is, which of
        them depending on the error's type, or where none is left, the first untyped member left.
        Empty where what is left lets such an error past. Costs the members naming every error and
        the untyped members removed ahead of the first one left, not the whole set.
        """
        universal = tuple(trap for trap in self._universal if id(trap) not in removed)
        if universal:
            return universal
        return next(((trap,) for trap in self._untyped if id(trap) not in removed), ())

    def is_selectable(self, trap: Ps1TrapStatement) -> bool:
        """
        Whether 5.1 may hand *trap* an error.
        """
        return id(trap) in self._chosen

    def takes_every_error(self) -> bool:
        """
        Whether some member takes every error, so that the set lets none past it untaken.
        """
        return bool(self.catching())
