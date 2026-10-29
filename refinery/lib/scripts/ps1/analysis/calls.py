"""
What a call answers where a measured fact covers it.

`refinery.lib.scripts.ps1.data.CALL_FACTS` says what Windows PowerShell 5.1 was measured to do with a
call: which arguments the fact covers, whether such a call can still fail, and what it hands back.
A fact holds only where the call still runs what was measured. That is a question about the script
around the call, so it is answered here, and nowhere else, before a fact is read: no write to the
type system may have run before a method call, the name of a command must still denote the command,
and the script must not bind default parameter values, which change what a command does without a
word at the call.

`Ps1CallReader` answers for one script under one world, and
`refinery.lib.scripts.ps1.analysis.values.evaluate` asks it of every call it meets when a caller
hands one in, so that a call is followed wherever it stands: as the receiver of another call, as an
argument, or as the operand of an operator.
"""
from __future__ import annotations

from weakref import WeakKeyDictionary, ref

from refinery.lib.scripts.ps1.analysis.session import session_of
from refinery.lib.scripts.ps1.analysis.values import (
    NOTHING,
    NULL,
    UNKNOWN,
    Ps1Outcome,
    Ps1Throws,
    Ps1Typed,
    evaluate,
    throw_join,
    type_of,
)
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach
from refinery.lib.scripts.ps1.ast import get_command_name
from refinery.lib.scripts.ps1.data import CallFact, CallKind, call_facts, named_type, resolve_type
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1CommandInvocation,
    Ps1InvokeMember,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1TypeExpression,
)

_VOID = named_type('System.Void')


def _matching_fact(facts: tuple[CallFact, ...], arguments: list[Ps1Outcome] | None) -> CallFact | None:
    """
    The first of *facts* that covers *arguments*, or `None` where none does. An argument a fact
    covers is a value of one of the types the fact names at its position, which `$null` never is;
    *arguments* is `None` for an argument list no fact can cover, and such a list is covered only by
    a fact covering every argument list.
    """
    for fact in facts:
        covered = fact.arguments
        if covered is None:
            return fact
        if arguments is None or len(arguments) != len(covered):
            continue
        if all(
            (named := type_of(argument.value)) is not None and named.generic_definition in types
            for argument, types in zip(arguments, covered)
        ):
            return fact
    return None


class Ps1CallReader:
    """
    The calls `refinery.lib.scripts.ps1.data.CALL_FACTS` covers, answered for one script under one
    world. A static call is matched by the type literal it names, a call on a value by the type the
    value is known to carry, and a command by its literal name. A command is matched only where it
    writes to no redirection, is not reached through a call operator, and receives no pipeline input,
    because every fact about a command was measured on a call standing on its own.

    The world is held weakly, so that the reader `call_reader` keeps for a world never keeps that
    world, or the tree it was measured over, alive. A reader whose world is gone trusts no position
    and reads no fact. That is what the world itself answers once the tree changes under it, which
    is how a pass holding the reader across its own edits outlives it, and it is never unsound.
    """

    def __init__(self, world: Ps1WorldReach):
        self._world = ref(world)

    def _closed_at(self, call: Ps1InvokeMember) -> bool:
        world = self._world()
        return world is not None and world.closed_at(call)

    def _may_trust_command_name_at(self, name: str, command: Ps1CommandInvocation) -> bool:
        world = self._world()
        return world is not None and world.may_trust_command_name_at(name, command)

    def outcome(self, call: Ps1InvokeMember | Ps1CommandInvocation) -> Ps1Outcome:
        """
        What *call* answers: the outcome its fact records once its receiver and arguments are
        evaluated, or `NOTHING` where no fact covers it.
        """
        if isinstance(call, Ps1InvokeMember):
            return self._method(call)
        return self._command(call)

    def vouch(self, call: Ps1InvokeMember, receiver: Ps1TypeName) -> Ps1TypeName | None:
        """
        The type a call on a value of *receiver* hands back where a fact covers it, never `$null`,
        or `None` where no fact covers it. The receiver is typed by the caller, who can type a
        variable where this cannot.
        """
        if not self._may_trust_the_method(call) or call.access is not Ps1AccessKind.INSTANCE:
            return None
        assert isinstance(call.member, str)
        fact = _matching_fact(
            call_facts(CallKind.INSTANCE, receiver.generic_definition, call.member),
            self._arguments(call),
        )
        if fact is None or fact.returns == _VOID:
            return None
        return fact.returns

    def _may_trust_the_method(self, call: Ps1InvokeMember) -> bool:
        return isinstance(call.member, str) and self._closed_at(call)

    def _arguments(self, call: Ps1InvokeMember) -> list[Ps1Outcome]:
        return [evaluate(argument, None, self) for argument in call.arguments]

    def _method(self, call: Ps1InvokeMember) -> Ps1Outcome:
        if not self._may_trust_the_method(call):
            return NOTHING
        assert isinstance(call.member, str)
        if call.access is Ps1AccessKind.STATIC:
            if not isinstance(call.object, Ps1TypeExpression):
                return NOTHING
            owner = resolve_type(call.object.name)
            receiver = Ps1Outcome(Ps1Throws.NEVER, UNKNOWN)
            kind = CallKind.STATIC
        else:
            receiver = evaluate(call.object, None, self)
            owner = type_of(receiver.value)
            kind = CallKind.INSTANCE
        if owner is None:
            return NOTHING
        arguments = self._arguments(call)
        fact = _matching_fact(call_facts(kind, owner.generic_definition, call.member), arguments)
        return NOTHING if fact is None else self.recorded(fact, receiver, arguments)

    def _command(self, command: Ps1CommandInvocation) -> Ps1Outcome:
        if command.redirections or command.invocation_operator or session_of(command).defaults:
            return NOTHING
        name = get_command_name(command)
        if name is None or not self._may_trust_command_name_at(name.lower(), command):
            return NOTHING
        element = command.parent
        if isinstance(element, Ps1PipelineElement):
            pipeline = element.parent
            if not isinstance(pipeline, Ps1Pipeline) or pipeline.elements[0] is not element:
                return NOTHING
        arguments = None if command.arguments else []
        fact = _matching_fact(call_facts(CallKind.COMMAND, None, name), arguments)
        receiver = Ps1Outcome(Ps1Throws.NEVER, UNKNOWN)
        return NOTHING if fact is None else self.recorded(fact, receiver, arguments or [])

    @staticmethod
    def recorded(fact: CallFact, receiver: Ps1Outcome, arguments: list[Ps1Outcome]) -> Ps1Outcome:
        """
        The outcome *fact* records for a call whose receiver and arguments evaluated to these: the
        call fails where they may, and where the fact says it may.
        """
        throws = throw_join(
            receiver.throws,
            *(argument.throws for argument in arguments),
            Ps1Throws.MAYBE if fact.fails else Ps1Throws.NEVER,
        )
        return Ps1Outcome(throws, NULL if fact.returns == _VOID else Ps1Typed(fact.returns))


def call_reader(world: Ps1WorldReach) -> Ps1CallReader:
    """
    The one `Ps1CallReader` of *world*, so that what it answered is shared by every question asked
    under that world.
    """
    reader = _READERS.get(world)
    if reader is None:
        reader = _READERS[world] = Ps1CallReader(world)
    return reader


_READERS: WeakKeyDictionary[Ps1WorldReach, Ps1CallReader] = WeakKeyDictionary()
