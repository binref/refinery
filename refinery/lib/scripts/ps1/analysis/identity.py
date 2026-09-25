"""
Which object the value of an expression may be.

PowerShell hands objects on rather than copying them, and several expressions give back the very
object one of their operands evaluated to: a parenthesis, an assignment used as a value, a
conversion that finds nothing to convert, `*` by a count of one, `$null + $x`, and `@( )` around an
expression whose compiled type is already an array. Every question about which name, container or
callee holds an object passes through these, so `object_sources` is the one place that reads them.

This reads the tree and the type names it spells and nothing else, so the semantic model can ask it
while it is being built.
"""
from __future__ import annotations

import typing

from typing import Callable
from weakref import WeakKeyDictionary

from refinery.lib.scripts import Expression, Node, mutation_epoch
from refinery.lib.scripts.ps1.ast import (
    extract_new_object,
    get_command_name,
    get_member_name,
    is_builtin_variable,
    is_reference_cast,
    target_constraint,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.data import is_type
from refinery.lib.scripts.ps1.dotnet import parse_type_name
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandInvocation,
    Ps1ExpandableHereString,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1HashLiteral,
    Ps1HereString,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1RangeExpression,
    Ps1RealLiteral,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)


class Ps1ObjectSources(typing.NamedTuple):
    """
    What the value of an expression may be. `operand` is the part of the expression whose very
    object the value may be; `made_here` says the value may be an object made where the expression
    runs, which nothing else holds yet; `unknown` says it may be any object at all, one this cannot
    name.
    """
    operand: Node | None = None
    made_here: bool = False
    unknown: bool = False

    @property
    def certain(self) -> bool:
        """
        Whether the value is the object of `operand` and nothing else.
        """
        return self.operand is not None and not self.made_here and not self.unknown


class Ps1Passage(typing.NamedTuple):
    """
    The expression around a node whose value may be the very object the node evaluates to, and
    whether it certainly is. `whole` says the value is otherwise one made where the expression
    runs, never another object: a conversion may copy what it is handed, but a member whose name
    the source does not spell may just as well be a part of the object as the object itself, so a
    store through `$h.$k[0]` reaches two steps into what `$h` holds, not one.
    """
    expression: Expression
    certain: bool
    whole: bool


#: What the value of an expression is when this says nothing else about it.
_UNKNOWN = Ps1ObjectSources(unknown=True)

#: What the value of an expression is when the expression makes it.
_MADE_HERE = Ps1ObjectSources(made_here=True)

#: Members whose value is the object they are read from, or reaches it, rather than a part of it,
#: lowercased: an array's `SyncRoot` is the array, `PSObject` wraps the very object it is read from,
#: and the `BaseObject` and `ImmediateBaseObject` of that wrapper are the object again. Other types
#: answer `SyncRoot` with an object of their own, so none of these is certain.
_IDENTITY_MEMBERS = frozenset({
    'baseobject',
    'immediatebaseobject',
    'psobject',
    'syncroot',
})

#: The scope qualifiers under which 5.1 may give a variable a slot typed by its constraint: those of
#: a local variable. A variable of any other scope is looked up by name and typed `Object`.
_LOCAL_QUALIFIERS = frozenset({
    Ps1ScopeModifier.NONE,
    Ps1ScopeModifier.LOCAL,
    Ps1ScopeModifier.PRIVATE,
})


def object_sources(
    expression: Node,
    trusts: Callable[[str], bool] = lambda name: False,
) -> Ps1ObjectSources:
    """
    What the value of *expression* may be.

    *trusts* says whether a command name still runs the command it names; the default trusts none,
    so every command's result is unknown. It matters only for `New-Object`, whose result is an
    object it makes where it constructs an array or calls a constructor with no arguments.
    """
    if isinstance(expression, Ps1ParenExpression):
        if expression.expression is None:
            return _UNKNOWN
        return Ps1ObjectSources(expression.expression)
    if isinstance(expression, Ps1CastExpression):
        return _converted(expression)
    if isinstance(expression, Ps1BinaryExpression):
        return _operated(expression)
    if isinstance(expression, Ps1AssignmentExpression):
        return _assigned(expression)
    if isinstance(expression, Ps1ArrayExpression):
        return _collected(expression)
    if isinstance(expression, Ps1MemberAccess):
        return _member(expression)
    if isinstance(expression, Ps1InvokeMember):
        return _MADE_HERE if _constructs_an_array(expression) else _UNKNOWN
    if isinstance(expression, Ps1CommandInvocation):
        return _MADE_HERE if _makes_an_object(expression, trusts) else _UNKNOWN
    if isinstance(expression, (
        Ps1ArrayLiteral,
        Ps1HashLiteral,
        Ps1ScriptBlock,
        Ps1RangeExpression,
        Ps1UnaryExpression,
        Ps1StringLiteral,
        Ps1HereString,
        Ps1ExpandableString,
        Ps1ExpandableHereString,
        Ps1IntegerLiteral,
        Ps1RealLiteral,
    )):
        return _MADE_HERE
    return _UNKNOWN


def passage_out_of(node: Node) -> Ps1Passage | None:
    """
    The expression around *node* whose value may be the very object *node* evaluates to, or `None`
    where the expression around it gives back no such object.

    The statement `@( )` holds its one expression in is stepped over, so the passage out of the
    `[object[]]$x` of `@([object[]]$x)` is the `@( )`. An assignment is a passage only for the value
    it stores and only where it is used as a value; one standing as a statement of its own gives
    back nothing, and its target is what it stores into rather than what it gives back.
    """
    outer = node.parent
    if isinstance(outer, Ps1ExpressionStatement):
        outer = outer.parent
        if not isinstance(outer, Ps1ArrayExpression):
            return None
    elif isinstance(outer, Ps1AssignmentExpression):
        if outer.value is not node or isinstance(outer.parent, Ps1ExpressionStatement):
            return None
    if not isinstance(outer, Expression):
        return None
    sources = object_sources(outer)
    if sources.operand is not node:
        return None
    return Ps1Passage(outer, sources.certain, not sources.unknown)


def _converted(cast: Ps1CastExpression) -> Ps1ObjectSources:
    """
    A conversion hands on its operand where the operand already is what it names and makes a new
    object where it converts, which depends on the operand's runtime type. A `[ref]` makes a
    reference to the variable rather than converting the value, and `[void]` discards it.
    """
    if is_reference_cast(cast):
        return _UNKNOWN
    if is_type(cast.type_name, 'System.Void'):
        return _MADE_HERE
    return Ps1ObjectSources(cast.operand, made_here=True)


def _operated(expression: Ps1BinaryExpression) -> Ps1ObjectSources:
    """
    Every operator makes its result, with three exceptions. `-as` converts the way a cast does.
    `*` gives back its left operand where the count converts to one: measured, `$y * 1`, `$y * '1'`
    and `$y * 1.4` are all the array `$y` holds, and `$y * 2` is a new one. `+` gives back its right
    operand where the left is `$null`: measured, `$null + $x` is the array `$x` holds, and
    `@() + $x` is a new one.
    """
    operator = expression.operator.lower()
    if operator == '-as':
        return Ps1ObjectSources(expression.left, made_here=True)
    if operator == '*':
        if _is_a_count_other_than_one(expression.right):
            return _MADE_HERE
        return Ps1ObjectSources(expression.left, made_here=True)
    if operator == '+':
        if _is_never_null(expression.left):
            return _MADE_HERE
        return Ps1ObjectSources(expression.right, made_here=True)
    return _MADE_HERE


def _is_a_count_other_than_one(count: Node | None) -> bool:
    """
    Whether *count* is an integer numeral that does not spell one. A numeral of any other kind, or
    any other expression, may convert to the count one.
    """
    if count is None:
        return False
    count = unwrap_parens(count)
    return isinstance(count, Ps1IntegerLiteral) and count.value != 1


def _is_never_null(node: Node | None) -> bool:
    """
    Whether *node* is written as a value that is never `$null`: a literal, a collection it builds, a
    block, a type, `$true` or `$false`.
    """
    if node is None:
        return False
    node = unwrap_parens(node)
    if is_builtin_variable(node, {'true', 'false'}):
        return True
    return isinstance(node, (
        Ps1ArrayExpression,
        Ps1ArrayLiteral,
        Ps1ExpandableHereString,
        Ps1ExpandableString,
        Ps1HashLiteral,
        Ps1HereString,
        Ps1IntegerLiteral,
        Ps1RealLiteral,
        Ps1ScriptBlock,
        Ps1StringLiteral,
        Ps1TypeExpression,
    ))


def _assigned(assignment: Ps1AssignmentExpression) -> Ps1ObjectSources:
    """
    An assignment used as a value gives back what it stored. That is the very object it was handed
    where the target is a local variable nothing constrains; a constraint or a typed property may
    convert it. A multi-assignment stores parts of it, and of the compound operators only `+=` may
    store its operand whole, onto a name that held `$null`.
    """
    value = assignment.value
    if assignment.operator == '+=':
        return Ps1ObjectSources(value, made_here=True)
    if assignment.operator != '=':
        return _UNKNOWN
    target = assignment.target
    while isinstance(target, Ps1ParenExpression):
        target = target.expression
    if isinstance(target, Ps1ArrayLiteral):
        return Ps1ObjectSources(value, unknown=True)
    if (
        isinstance(target, Ps1Variable)
        and target.scope in _LOCAL_QUALIFIERS
        and target.name.lower() not in _constraints_in(_body_of(target))
    ):
        return Ps1ObjectSources(value)
    return Ps1ObjectSources(value, made_here=True)


def _collected(array: Ps1ArrayExpression) -> Ps1ObjectSources:
    """
    `@( )` collects what its statements write into a new array, except around one expression whose
    compiled type is already an array, which it gives back unwrapped: an array literal, another
    `@( )`, a conversion to an array type, and a local variable a constraint types as one. Measured,
    `@([object[]]$x)` is the array `$x` holds, and so is `@($a)` in a function body that writes
    `[object[]]$a`. Whether a local is typed depends on how 5.1 compiled the block — not at all
    where it is dot-sourced — so that one is not certain.
    """
    body = array.body
    if len(body) != 1:
        return _MADE_HERE
    statement = body[0]
    if not isinstance(statement, Ps1ExpressionStatement) or statement.expression is None:
        return _MADE_HERE
    expression = statement.expression
    pure = unwrap_parens(expression)
    if isinstance(pure, (Ps1ArrayLiteral, Ps1ArrayExpression)):
        return Ps1ObjectSources(expression)
    if isinstance(pure, Ps1CastExpression) and not is_reference_cast(pure):
        if _names_an_array_type(pure.type_name):
            return Ps1ObjectSources(expression)
    if isinstance(pure, Ps1Variable) and _may_be_a_typed_array(pure):
        return Ps1ObjectSources(expression, made_here=True)
    return _MADE_HERE


def _member(access: Ps1MemberAccess) -> Ps1ObjectSources:
    """
    A member that is the object it is read from, or one whose name the source does not spell and so
    may be one, hands on that object; any other member is a value this cannot name.
    """
    if access.access is Ps1AccessKind.STATIC:
        return _UNKNOWN
    name = get_member_name(access.member)
    if name is None or name.lower() in _IDENTITY_MEMBERS:
        return Ps1ObjectSources(access.object, unknown=True)
    return _UNKNOWN


def _constructs_an_array(call: Ps1InvokeMember) -> bool:
    """
    Whether *call* is `[T[]]::new(n)`, which makes a new array.
    """
    if call.access is not Ps1AccessKind.STATIC or not isinstance(call.object, Ps1TypeExpression):
        return False
    name = get_member_name(call.member)
    return name is not None and name.lower() == 'new' and _names_an_array_type(call.object.name)


def _makes_an_object(cmd: Ps1CommandInvocation, trusts: Callable[[str], bool]) -> bool:
    """
    Whether *cmd* is a `New-Object` that makes the object it writes: an array, or an object whose
    constructor is given nothing it could keep.
    """
    name = get_command_name(cmd)
    if name is None or not trusts(name.lower()):
        return False
    extracted = extract_new_object(cmd)
    if extracted is None:
        return False
    type_name, arguments = extracted
    return not arguments or _names_an_array_type(type_name)


def _names_an_array_type(name: str) -> bool:
    parsed = parse_type_name(name)
    return parsed is not None and parsed.is_array


def _may_be_a_typed_array(var: Ps1Variable) -> bool:
    """
    Whether 5.1 may give *var* a slot typed as an array: a local some write in the same body
    constrains to an array type, or a parameter declared as one, or `$args`, which every block
    types as `Object[]`.
    """
    if var.scope not in _LOCAL_QUALIFIERS:
        return False
    name = var.name.lower()
    if name == 'args':
        return True
    return _constraints_in(_body_of(var)).get(name, False)


def _body_of(node: Node) -> Node:
    """
    The block whose locals *node* reads and writes: the nearest script block around it, or the
    script.
    """
    cursor: Node = node
    while cursor.parent is not None and not isinstance(cursor.parent, (Ps1ScriptBlock, Ps1Script)):
        cursor = cursor.parent
    return cursor.parent or cursor


def _constraints_in(body: Node) -> dict[str, bool]:
    """
    The local names a write in *body* constrains, each with whether some constraint on it names an
    array type. A block nested in *body* has locals of its own and is not read.
    """
    global _CONSTRAINED_AT
    epoch = mutation_epoch()
    if epoch != _CONSTRAINED_AT:
        _CONSTRAINED.clear()
        _CONSTRAINED_AT = epoch
    found = _CONSTRAINED.get(body)
    if found is None:
        found = _CONSTRAINED[body] = _collect_constraints(body)
    return found


def _collect_constraints(body: Node) -> dict[str, bool]:
    constrained: dict[str, bool] = {}
    stack: list[Node] = list(body.children())
    while stack:
        node = stack.pop()
        if isinstance(node, Ps1ScriptBlock):
            continue
        stack.extend(node.children())
        named: Ps1Variable | None = None
        type_name: str | None = None
        if isinstance(node, Ps1Variable):
            named, type_name = node, target_constraint(node)
        elif isinstance(node, Ps1ParameterDeclaration):
            for attribute in node.attributes:
                if isinstance(attribute, Ps1TypeExpression):
                    named, type_name = node.variable, attribute.name
        if named is None or type_name is None or named.scope not in _LOCAL_QUALIFIERS:
            continue
        name = named.name.lower()
        constrained[name] = constrained.get(name, False) or _names_an_array_type(type_name)
    return constrained


#: The local names each body constrains, and the mutation counter the entries stand on.
_CONSTRAINED: WeakKeyDictionary[Node, dict[str, bool]] = WeakKeyDictionary()
_CONSTRAINED_AT = -1
