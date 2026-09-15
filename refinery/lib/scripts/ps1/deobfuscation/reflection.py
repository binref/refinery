"""
A reflection property read spelled as the direct member it resolves to.
"""
from __future__ import annotations

from refinery.lib.scripts import Expression, Transformer
from refinery.lib.scripts.ps1.analysis.effects import reflection_read_cannot_throw
from refinery.lib.scripts.ps1.ast import get_member_name, is_builtin_variable, string_value
from refinery.lib.scripts.ps1.data import (
    MemberLookup,
    canonical_member,
    member_record,
    resolve_type,
)
from refinery.lib.scripts.ps1.deobfuscation.substitution import substituted
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1TypeExpression,
)


class Ps1ReflectionReads(Transformer):
    """
    Rewrite `[T].GetProperty('P').GetValue($Null)` to `[T]::P`.

    The rewrite is a re-spelling and not an evaluation, so what it has to preserve is only the two
    ways the spellings can differ. A getter that throws surfaces through `GetValue` wrapped in a
    `MethodInvocationException` and through the direct read as itself — measured on 5.1 with
    `[Console]::KeyAvailable` on a redirected stdin — which is why the member has to be one the
    curated cannot-throw table vouches for. And `GetProperty` finds properties only, so a field the
    same shape spells is a read 5.1 throws on; there is no `GetField` arm, because no sample has
    needed one and a rewrite of a read the script never made is a different program.

    The argument binder is the reason no `GetMethod` arm exists: a `$null` argument an
    `Invoke`d method receives as raw null throws where the direct spelling converts it, and a
    wrong type throws with a different exception — measured — so a reflection method call is left
    standing and this pass owns the one question a re-spelling can answer exactly.
    """

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        self.generic_visit(node)
        return substituted(node, self._direct_member(node))

    def _direct_member(self, node: Ps1InvokeMember) -> Expression | None:
        """
        The direct member read the `GetValue` call spells, or `None` where this will not answer.
        """
        member = get_member_name(node.member)
        if member is None or member.lower() != 'getvalue':
            return None
        if node.access != Ps1AccessKind.INSTANCE:
            return None
        if not self._reads_a_static_target(node.arguments):
            return None
        lookup = node.object
        if not isinstance(lookup, Ps1InvokeMember):
            return None
        if lookup.access != Ps1AccessKind.INSTANCE:
            return None
        getter = get_member_name(lookup.member)
        if getter is None or getter.lower() != 'getproperty':
            return None
        if lookup.object is None or not isinstance(lookup.object, Ps1TypeExpression):
            return None
        if len(lookup.arguments) != 1:
            return None
        name = string_value(lookup.arguments[0])
        if name is None:
            return None
        resolved = resolve_type(lookup.object.name)
        if resolved is None:
            return None
        record = member_record(resolved, name)
        if isinstance(record, MemberLookup):
            return None
        if record.get('kind') != 'property' or record.get('static') is not True:
            return None
        if record.get('source') != 'reflection':
            return None
        if not reflection_read_cannot_throw(resolved, name):
            return None
        spelled = canonical_member(resolved, name)
        if spelled is None:
            return None
        return Ps1MemberAccess(
            access=Ps1AccessKind.STATIC,
            object=lookup.object,
            member=spelled,
        )

    @staticmethod
    def _reads_a_static_target(arguments) -> bool:
        """
        Whether the `GetValue` arguments are the `$null` target alone — one spelling of it, or the
        two-argument one carrying no index, which a non-indexed property accepts and answers the
        same value for. Any other target is a read of an instance the receiver does not vouch for.
        """
        if len(arguments) not in (1, 2):
            return False
        if not all(
            is_builtin_variable(argument, {'null'})
            for argument in arguments
        ):
            return False
        return True
