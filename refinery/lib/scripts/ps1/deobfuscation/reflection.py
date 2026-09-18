"""
Reflection property reads and method calls rewritten as the direct members they resolve to.
"""
from __future__ import annotations

from refinery.lib.scripts import Expression, Node
from refinery.lib.scripts.ps1.analysis.effects import reflection_read_cannot_throw
from refinery.lib.scripts.ps1.analysis.values import non_null_type
from refinery.lib.scripts.ps1.ast import (
    get_member_name,
    is_builtin_variable,
    string_value,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.data import (
    CONCRETE_GENERIC_METHODS,
    MemberLookup,
    canonical_member,
    instance_overloads,
    is_assignable_to,
    is_enumerable,
    member_record,
    named_type,
    resolve_type,
    static_overloads,
    type_is_value_type,
)
from refinery.lib.scripts.ps1.deobfuscation.substitution import substituted
from refinery.lib.scripts.ps1.deobfuscation.typenames import VariableTypeAwareTransformer
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1CastExpression,
    Ps1ExpressionStatement,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1Pipeline,
    Ps1SubExpression,
    Ps1TypeExpression,
)

#: A void return is refused rather than argued: `Invoke` on a void method answers a `$null` the
#: direct call writes nothing for, and what the two spellings leave the script holding is not
#: settled for every context a script can put one in.
_VOID = named_type('System.Void')

#: What the `[type[]]` cast of the type-array spelling names.
_TYPE_ARRAY = named_type('System.Type[]')

#: The one reference type the argument guard passes as a scalar: a `String` is not enumerated by
#: `@()`, where a `String[]` — the same `definition` with a rank — is. The comparison is to the
#: whole type for exactly that reason.
_STRING = named_type('System.String')


def _spells_a_concrete_type(spelling: str | None) -> Ps1TypeName | None:
    """
    The type a collected overload spelling names, or `None` where the spelling names nothing, a
    by-reference, or an open generic. A method generic in its parameters or its return is one a
    folded call cannot spell — the direct binder closes the generic where `Invoke` on the
    definition throws — and a closed generic is fine, because its arguments are spelled.
    """
    if not spelling:
        return None
    resolved = resolve_type(spelling)
    if resolved is None or resolved.byref or (resolved.arity and not resolved.arguments):
        return None
    return resolved


class Ps1ReflectionMembers(VariableTypeAwareTransformer):
    """
    Rewrite a reflection property read or method call as the direct member it resolves to:
    `[T].GetProperty('P').GetValue($Null)` as `[T]::P`, and
    `[T].GetMethod('M', [type[]]@(...)).Invoke($Null, @($a))` as `[T]::M($a)`.

    The rewrite is a re-spelling, so what it has to preserve is only the ways the spellings can
    differ. A getter that throws surfaces through `GetValue` wrapped in a
    `MethodInvocationException` and through the direct read as itself — measured on 5.1 — so a
    folded property has to be one the curated cannot-throw table vouches for; a method's own
    throw surfaces identically in both spellings, so the method arm needs no such table. Both
    `GetProperty` and `GetMethod` are case-sensitive where member access is not, so a spelling
    in another case is left standing.

    On the method arm the .NET binder sits between the spellings: `Invoke` hands the arguments
    to the overload `GetMethod` selected, while the direct call lets the binder select again.
    Each argument is therefore judged (`non_null_type`) for a non-null type the binder is
    definitely given as it stands, and the selected overload has to be the only one of that
    arity those types accept. A generic or a void return is refused — a generic one because the
    direct binder closes it where `Invoke` on the definition throws, a void one because what the
    spellings leave the script holding is not settled — as are the spellings this does not
    answer: `InvokeMember`, `Activator::CreateInstance`, the three-argument `Invoke`,
    `MakeGenericMethod`, a static target other than `$Null`, and an argument array that is not
    the `@(...)` spelling of plain expressions.
    """

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        self.generic_visit(node)
        return substituted(node, self._direct_member(node))

    def _direct_member(self, node: Ps1InvokeMember) -> Expression | None:
        """
        The direct member the reflection call spells, or `None` where this will not answer.
        """
        read = self._direct_read(node)
        if read is not None:
            return read
        return self._direct_call(node)

    @staticmethod
    def _reflection_lookup(
        lookup: Node | None,
        getter: str,
        arity: int,
    ) -> tuple[Ps1TypeExpression, str, list[Expression]] | None:
        """
        The receiver, member name, and arguments a reflection getter's lookup spells, or `None`
        where the lookup is not an instance call of *getter* on a type literal naming the member as
        the first of *arity* arguments: the shape the `GetProperty` read and the `GetMethod` call
        below share.
        """
        if not isinstance(lookup, Ps1InvokeMember):
            return None
        if lookup.access != Ps1AccessKind.INSTANCE:
            return None
        named = get_member_name(lookup.member)
        if named is None or named.lower() != getter:
            return None
        receiver = lookup.object
        if not isinstance(receiver, Ps1TypeExpression):
            return None
        if len(lookup.arguments) != arity:
            return None
        name = string_value(lookup.arguments[0])
        if name is None:
            return None
        return receiver, name, lookup.arguments

    def _direct_read(self, node: Ps1InvokeMember) -> Expression | None:
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
        found = self._reflection_lookup(node.object, 'getproperty', 1)
        if found is None:
            return None
        receiver, name, _ = found
        resolved = resolve_type(receiver.name)
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
        if name != spelled:
            return None
        return Ps1MemberAccess(
            access=Ps1AccessKind.STATIC,
            object=receiver,
            member=spelled,
        )

    def _direct_call(self, node: Ps1InvokeMember) -> Expression | None:
        """
        The direct static method call the `Invoke` on a `GetMethod` result spells, or `None` where
        this will not answer.
        """
        member = get_member_name(node.member)
        if member is None or member.lower() != 'invoke':
            return None
        if node.access != Ps1AccessKind.INSTANCE:
            return None
        if len(node.arguments) != 2:
            return None
        if not is_builtin_variable(node.arguments[0], {'null'}):
            return None
        arguments = self._invocation_arguments(node.arguments[1])
        if arguments is None:
            return None
        found = self._reflection_lookup(node.object, 'getmethod', 2)
        if found is None:
            return None
        receiver, name, lookup_arguments = found
        type_array = self._type_array(lookup_arguments[1])
        if type_array is None or len(type_array) != len(arguments):
            return None
        resolved = resolve_type(receiver.name)
        if resolved is None:
            return None
        record = member_record(resolved, name)
        if isinstance(record, MemberLookup):
            return None
        if record.get('kind') != 'method' or record.get('source') != 'reflection':
            return None
        if (resolved.generic_definition, name.lower()) in CONCRETE_GENERIC_METHODS:
            return None
        spelled = canonical_member(resolved, name)
        if spelled is None:
            return None
        if name != spelled:
            return None
        overloads = [
            *static_overloads(resolved, name),
            *instance_overloads(resolved, name),
        ]
        matching = [
            overload for overload in overloads
            if self._matches_type_array(overload, type_array)
        ]
        if len(matching) != 1 or matching[0].get('static') is not True:
            return None
        selected = matching[0]
        if _spells_a_concrete_type(selected.get('returns')) in (None, _VOID):
            return None
        if any(
            _spells_a_concrete_type(parameter.get('type')) is None
            for parameter in selected.get('parameters') or ()
        ):
            return None
        judged = []
        for argument, parameter in zip(arguments, selected.get('parameters') or ()):
            origin = non_null_type(argument, self._type_of_variable, self._origin_of_variable)
            if origin is None or not self._argument_binds_identically(origin, parameter):
                return None
            judged.append(origin)
        applicable = [
            overload for overload in overloads
            if len(overload.get('parameters') or ()) == len(arguments)
            and all(
                is_assignable_to(origin, parameter['type']) is True
                for origin, parameter in zip(judged, overload['parameters'])
            )
        ]
        if len(applicable) != 1 or applicable[0] is not selected:
            return None
        return Ps1InvokeMember(
            access=Ps1AccessKind.STATIC,
            object=receiver,
            member=name,
            arguments=arguments,
        )

    @staticmethod
    def _invocation_arguments(argument: Expression) -> list[Expression] | None:
        """
        The argument expressions the array subexpression hands `Invoke`, or `None` where the
        second `Invoke` argument is not the `@(...)` spelling of plain expression statements. A
        comma list without the wrapper, a scalar and a variable are declined spellings, and a
        statement naming a value whose element count the wrapper decides is one the count guard
        cannot see through.
        """
        spelled = unwrap_parens(argument)
        if not isinstance(spelled, Ps1ArrayExpression):
            return None
        arguments: list[Expression] = []
        for statement in spelled.body:
            if not isinstance(statement, Ps1ExpressionStatement) or statement.expression is None:
                return None
            expression = unwrap_parens(statement.expression)
            if isinstance(expression, (Ps1ArrayLiteral, Ps1SubExpression, Ps1Pipeline)):
                return None
            if not isinstance(expression, Expression):
                return None
            arguments.append(expression)
        return arguments

    @staticmethod
    def _type_array(argument: Expression) -> list[Ps1TypeName] | None:
        """
        The types the type-array argument names, or `None` where it is not the `[type[]]@(...)`
        spelling of type literals. A statement of the body may hold one type literal or a comma
        list of them, which `@(...)` unrolls into one element each — a literal count is exact
        where the argument arm's is not, which is why this accepts the array-literal statement
        `_invocation_arguments` refuses.
        """
        cast = unwrap_parens(argument)
        if not isinstance(cast, Ps1CastExpression):
            return None
        if resolve_type(cast.type_name) != _TYPE_ARRAY:
            return None
        spelled = None if cast.operand is None else unwrap_parens(cast.operand)
        if not isinstance(spelled, Ps1ArrayExpression):
            return None
        types: list[Ps1TypeName] = []
        for statement in spelled.body:
            if not isinstance(statement, Ps1ExpressionStatement) or statement.expression is None:
                return None
            expression = unwrap_parens(statement.expression)
            if isinstance(expression, Ps1ArrayLiteral):
                literals = expression.elements
            else:
                literals = [expression]
            for literal in literals:
                literal = unwrap_parens(literal)
                if not isinstance(literal, Ps1TypeExpression):
                    return None
                resolved = resolve_type(literal.name)
                if resolved is None:
                    return None
                types.append(resolved)
        return types

    @staticmethod
    def _matches_type_array(overload: dict, type_array: list[Ps1TypeName]) -> bool:
        """
        Whether the overload is the one `Type.GetMethod(String, Type[])` selects for *type_array*:
        the same number of parameters, none by reference, each of the type the array names in its
        position. .NET matches the parameter types exactly, and a byref parameter never matches,
        because the array a script spells names `System.String` where the method wants
        `System.String&`.
        """
        parameters = overload.get('parameters') or ()
        if len(parameters) != len(type_array):
            return False
        for parameter, spelled in zip(parameters, type_array):
            if parameter.get('byref') or resolve_type(parameter.get('type')) != spelled:
                return False
        return True

    @staticmethod
    def _argument_binds_identically(judged: Ps1TypeName, parameter: dict) -> bool:
        """
        Whether an argument of the judged non-null type reaches the method the same way in both
        spellings. A type it is definitely assignable to the parameter cannot be converted in one
        spelling and not the other, and an argument of a kind `@(...)` does not enumerate — a
        String or a value type, read from `is_enumerable`, the one authority for which types the
        pipeline enumerates — reaches `Invoke` as exactly one argument where a collection
        flattens into several.
        """
        if is_assignable_to(judged, parameter['type']) is not True:
            return False
        return (judged == _STRING or type_is_value_type(judged)) and is_enumerable(judged) is not True

    @staticmethod
    def _reads_a_static_target(arguments) -> bool:
        """
        Whether the `GetValue` arguments are the `$null` target alone — one spelling of it, or the
        two-argument one carrying no index, which a non-indexed property accepts and answers the
        same value for.
        """
        return len(arguments) in (1, 2) and all(
            is_builtin_variable(argument, {'null'})
            for argument in arguments
        )
