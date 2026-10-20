"""
An object literal whose members stand for names: each key has a getter that answers with one
name, with `typeof` of one name or with a literal, a setter that stores into one name, or a method
that calls one name with its own arguments. An access through such an object means what the same
access on the name means, and `NameProxy.stand_in` writes that access down.

    {
      get k() { return V; },
      set k(v) { V = v; },
      get t() { return typeof W; },
      c(...a) { return F(...a); },
    }
"""
from __future__ import annotations

import enum

from dataclasses import dataclass, field

from refinery.lib.scripts import Expression, Node, _clone_node
from refinery.lib.scripts.js.analysis.model import (
    Role,
    SemanticModel,
    enclosing_operator,
    is_invocation_target,
    reference_role,
    tolerates_unresolvable,
)
from refinery.lib.scripts.js.deobfuscation.helpers import access_key, is_literal, property_key
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsObjectExpression,
    JsProperty,
    JsPropertyKind,
    JsRestElement,
    JsReturnStatement,
    JsSpreadElement,
    JsUnaryExpression,
    JsUpdateExpression,
    strip_parens,
)


class Reading(enum.Enum):
    """
    What a getter answers with: a name, `typeof` of a name, or a literal.
    """
    NAME = 'name'
    TYPEOF = 'typeof'
    LITERAL = 'literal'


@dataclass
class NameMember:
    """
    The members one key of the object has: what its getter answers with, the name its setter
    stores into, and the name its method calls. Each is an identifier written inside the member,
    or a literal for a getter answering with one.
    """
    reading: Reading | None = None
    read: Expression | None = None
    stored: JsIdentifier | None = None
    called: JsIdentifier | None = None
    paired: bool = False


@dataclass
class StandIn:
    """
    What an access through the object is written as on the names: the expression, and each
    identifier in it paired with the identifier inside the member it stands for. Where the name
    is found from the access must be where it is found from the member, which the caller asks;
    so are two differences the expression keeps. A call through a method reads the name after the
    arguments, where the call on the name reads it before them (`late` holds that call), and a
    call through a getter runs the function with the object as `this`, where the call on the name
    runs it with none (`receiver`).
    """
    node: Expression
    names: list[tuple[JsIdentifier, JsIdentifier]] = field(default_factory=list)
    late: JsCallExpression | None = None
    receiver: bool = False


_OWN_NAMES = frozenset({'arguments', 'eval'})
"""
Names a member cannot stand for: `arguments` is the member's own, and a write to `eval` or a call
of it means something else where it is written down.
"""


def _single_return(function: JsFunctionExpression) -> Expression | None:
    """
    The value of the one `return` statement that is the body of *function*.
    """
    body = function.body
    if body is None or len(body.body) != 1:
        return None
    if not isinstance(statement := body.body[0], JsReturnStatement):
        return None
    return statement.argument


def _plain(function: Node | None) -> JsFunctionExpression | None:
    """
    The function *function* where it is a function expression that is neither a generator nor
    async, and so runs its body when called and answers with what the body returns.
    """
    if not isinstance(function, JsFunctionExpression) or function.generator or function.is_async:
        return None
    return function


def _getter(function: JsFunctionExpression) -> tuple[Reading, Expression] | None:
    """
    What the getter *function* answers with: `return V`, `return typeof V` or a literal.
    """
    if function.params:
        return None
    value = _single_return(function)
    if isinstance(value, JsIdentifier) and value.name != 'arguments':
        return Reading.NAME, value
    if (
        isinstance(value, JsUnaryExpression)
        and value.operator == 'typeof'
        and isinstance(value.operand, JsIdentifier)
        and value.operand.name != 'arguments'
    ):
        return Reading.TYPEOF, value.operand
    if value is not None and is_literal(value):
        return Reading.LITERAL, value
    return None


def _setter(function: JsFunctionExpression, model: SemanticModel) -> JsIdentifier | None:
    """
    The name the setter *function* stores its parameter into: `V = v` or `return V = v`.
    """
    if len(function.params) != 1 or not isinstance(parameter := function.params[0], JsIdentifier):
        return None
    body = function.body
    if body is None or len(body.body) != 1:
        return None
    statement = body.body[0]
    if isinstance(statement, JsReturnStatement):
        store = statement.argument
    elif isinstance(statement, JsExpressionStatement):
        store = statement.expression
    else:
        return None
    if (
        not isinstance(store, JsAssignmentExpression)
        or store.operator != '='
        or not isinstance(target := store.left, JsIdentifier)
        or not isinstance(source := store.right, JsIdentifier)
        or target.name in _OWN_NAMES
        or target.name == parameter.name
        or model.resolve(source) is not model.binding_of(parameter)
    ):
        return None
    return target


def _method(function: JsFunctionExpression, model: SemanticModel) -> JsIdentifier | None:
    """
    The name the method *function* calls with its own arguments, which it takes as one rest
    parameter `a` and spreads into the call `F(...a)` it returns.
    """
    if len(function.params) != 1 or not isinstance(rest := function.params[0], JsRestElement):
        return None
    if not isinstance(rest.argument, JsIdentifier):
        return None
    call = _single_return(function)
    if (
        not isinstance(call, JsCallExpression)
        or call.optional
        or not isinstance(callee := call.callee, JsIdentifier)
        or callee.name in _OWN_NAMES
        or len(call.arguments) != 1
        or not isinstance(spread := call.arguments[0], JsSpreadElement)
        or not isinstance(spread.argument, JsIdentifier)
        or model.resolve(spread.argument) is not model.binding_of(rest.argument)
    ):
        return None
    return callee


def _same_name(model: SemanticModel, a: JsIdentifier, b: JsIdentifier) -> bool:
    """
    Whether the identifiers *a* and *b* name the same variable.
    """
    return a.name == b.name and model.resolve(a) is model.resolve(b)


class NameProxy:
    """
    An object literal whose members stand for names, read by `NameProxy.read`.
    """

    def __init__(self, members: dict[str, NameMember]):
        self.members = members

    @classmethod
    def read(cls, literal: JsObjectExpression, model: SemanticModel) -> NameProxy | None:
        """
        The members of *literal*, or `None` where one of them stands for no name or a key is
        given twice. A key whose getter and setter name the same variable reads and writes it,
        which a compound write and an update through the key do.
        """
        members: dict[str, NameMember] = {}
        for prop in literal.properties:
            if not isinstance(prop, JsProperty) or (function := _plain(prop.value)) is None:
                return None
            if (key := property_key(prop)) is None:
                return None
            member = members.setdefault(key, NameMember())
            if member.called is not None:
                return None
            if prop.kind is JsPropertyKind.GET:
                if member.reading is not None or (read := _getter(function)) is None:
                    return None
                member.reading, member.read = read
            elif prop.kind is JsPropertyKind.SET:
                if member.stored is not None or (stored := _setter(function, model)) is None:
                    return None
                member.stored = stored
            elif prop.method and member.reading is None and member.stored is None:
                if (called := _method(function, model)) is None:
                    return None
                member.called = called
            else:
                return None
        for member in members.values():
            member.paired = (
                member.reading is Reading.NAME
                and isinstance(member.read, JsIdentifier)
                and member.stored is not None
                and _same_name(model, member.read, member.stored)
            )
        return cls(members)

    def stand_in(self, member: JsMemberExpression) -> StandIn | None:
        """
        What the access *member*, whose object is a reference to this object, is written as on
        the names, or `None` where no access on a name means the same: a key without a member for
        the access, a `delete`, an optional call or write, a method read as a value, and a getter
        answering with a name under `typeof`, which throws where nothing binds the name and
        `typeof` of the name does not.
        """
        key = access_key(member)
        if key is None or (entry := self.members.get(key)) is None:
            return None
        operator = enclosing_operator(member)
        if isinstance(operator, JsUnaryExpression) and operator.operator == 'delete':
            return None
        role = reference_role(member)
        if role is Role.READ:
            return self._read(member, entry, operator)
        if member.optional:
            return None
        stored = entry.stored
        if stored is None:
            return None
        if role is Role.WRITE:
            written = JsIdentifier(name=stored.name)
            return StandIn(written, [(written, stored)])
        if not (
            isinstance(operator, JsAssignmentExpression) and strip_parens(operator.left) is member
            or isinstance(operator, JsUpdateExpression) and strip_parens(operator.argument) is member
        ):
            return None
        if not entry.paired:
            return None
        written = JsIdentifier(name=stored.name)
        return StandIn(written, [(written, stored)])

    def _read(
        self,
        member: JsMemberExpression,
        entry: NameMember,
        operator: Node | None,
    ) -> StandIn | None:
        invoked = is_invocation_target(member)
        if entry.called is not None:
            if (
                not invoked
                or not isinstance(operator, JsCallExpression)
                or strip_parens(operator.callee) is not member
                or operator.optional
            ):
                return None
            written = JsIdentifier(name=entry.called.name)
            return StandIn(written, [(written, entry.called)], late=operator)
        read = entry.read
        if read is None:
            return None
        if entry.reading is Reading.LITERAL:
            if invoked:
                return None
            return StandIn(_clone_node(read))
        assert isinstance(read, JsIdentifier)
        written = JsIdentifier(name=read.name)
        if entry.reading is Reading.TYPEOF:
            if invoked:
                return None
            return StandIn(JsUnaryExpression(operator='typeof', operand=written), [(written, read)])
        if tolerates_unresolvable(member):
            return None
        if invoked and read.name == 'eval':
            return None
        return StandIn(written, [(written, read)], receiver=invoked)
