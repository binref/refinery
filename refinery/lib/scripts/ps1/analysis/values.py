"""
What a PowerShell expression evaluates to and what type that value carries: the value when the
source pins it, the .NET type when the static surface determines it, and *nothing known* when this
module cannot say. These are language semantics rather than deobfuscation policy — the truth value
of `''` and the type of `'abc'` are properties of PowerShell, not of any pass — so they sit in the
analysis layer where both the effect substrate and the transforms can read them without either
importing the other. This is the only module in `refinery.lib.scripts.ps1.analysis` that answers
either question.

**A value and its type are one fact, not two.** `Ps1Fact` is that fact, and it is what makes a Char
and a one-character String different things: both carry the Python string `'A'`, and only the type
they are stamped with tells them apart. Nothing here dispatches on the Python type of a payload —
the `Ps1TypeName` decides, always, because the Python type is the erasure this module exists to
undo. The four elements are *nothing is known*, *`$null`*, *a value of this type*, and *this exact
value of this type*. When an interval or a known-bits refinement is built it becomes a field on
`Ps1Typed`, not a fifth element.

Throwing is a separate axis, which is why an operation answers a `Ps1Outcome` rather than a fact:
`[int] $s` over a String is *an Int32, or it throws*, and a domain that had to fold that into one
element could only answer that it knows nothing. The axis is three-valued (`Ps1Throws`): `NEVER`
where this module claims an operation cannot throw, `ALWAYS` where it claims one must, and `MAYBE`
for the rest — both a throw known on some state and one this declines to judge. `may_throw` and
`certainly_throws` are the two readings of it; not knowing is `Ps1Outcome(MAYBE, UNKNOWN)`.

`read` is what the source pins an expression to, `convert` a cast, `apply` an operator and `render`
the way back, and each of those answers about one step. `evaluate` is the composition over a whole
expression and the entry a caller with a tree wants: it refuses wherever a step does, and it never
answers something a step would have answered differently. It is also the one thing here that keeps
state — what it last answered for a node, discarded as soon as any tree is mutated, so that being
the entry a caller with a tree wants does not cost that caller a walk per node. Nothing else here
remembers anything, and remembering does not make `evaluate` answer differently; see there for why.

The type side has two views over one engine. `resolve_expression_type` is the single-type core: one
expression, one `refinery.lib.scripts.ps1.dotnet.Ps1TypeName` or `None`. `candidate_types` is the
set-valued view the effect layer reasons over, and it is a strict superset — it additionally
resolves a static method call, a cmdlet whose declared output is closed, and the `$_` such a cmdlet
binds downstream of it, any of which can name several types. The set is the primitive and the single type the derived view, because a caller
reasoning about a value must have its conclusion hold for every type the value could carry.
"""
from __future__ import annotations

import dataclasses
import decimal
import enum
import functools
import math
import operator as operator_module
import re
import typing

from typing import Callable, TypeAlias, TypeVar
from weakref import WeakKeyDictionary

from refinery.lib.scripts import Node, _clone_node, mutation_epoch
from refinery.lib.scripts.ps1.analysis.blocks import binds_the_pipeline_variable
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach
from refinery.lib.scripts.ps1.ast import (
    extract_first_positional_string,
    fault_operand,
    get_command_name,
    get_member_name,
    is_builtin_variable,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.data import (
    NON_NULL_RETURNS,
    OBJ_COMMANDS,
    TYPE_ARG_COMMANDS,
    VARIABLE_TYPES,
    WMI_COMMANDS,
    binary_outcome,
    command_output_types,
    conversion_outcome,
    enum_name,
    enum_ordinal,
    enum_storage,
    instance_overloads,
    is_assignable_to,
    named_type,
    operand_witnesses,
    resolve_member_type,
    resolve_type,
    static_overloads,
    unary_outcome,
)
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName
from refinery.lib.scripts.ps1.model import (
    MULTIPLIERS,
    Expression,
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandInvocation,
    Ps1ExpandableHereString,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1HereString,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1RealLiteral,
    Ps1ScopeModifier,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1ThrowStatement,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.token import BACKTICK_ENCODE

#: What a caller knows about the type of a variable *occurrence*. A function and not a table keyed
#: by name, because a name is not a variable: two bodies may write the same name, and which write a
#: read observes is a question only the caller's flow model can answer.
#: `refinery.lib.scripts.ps1.analysis.variable_types.type_at` is the one implementation of it, and
#: it is what keeps this module free of flow while still letting a pass answer per occurrence.
Ps1VariableTyping: TypeAlias = Callable[['Ps1Variable'], 'Ps1TypeName | None']

_T = TypeVar('_T')

#: The characters a literal cannot carry verbatim, which is every one the backtick table escapes
#: except the newline: a newline is what a here-string exists to hold.
_NONPRINT_CONTROL = frozenset(BACKTICK_ENCODE) - {'\n'}


def is_truthy(node: Node | None) -> bool | None:
    """
    Whether an expression counts as true to PowerShell, or `None` where this cannot say.

    This is 5.1's conversion to a `Boolean` and nothing else, which is the one predicate `if`,
    `while`, `for`, `do`, `-and`, `-or`, `-xor`, `-not` and a `[bool]` cast all reach. It is
    answered by reading the value the expression names and converting *that*, rather than by a rule
    spelled out here, so that a spelling this module has never seen is refused instead of being
    given a truth of its own invention.

    A rule spelled out here rather than read from the value gets `- '0'` wrong: a minus sign in
    front of a String converts the String to a number, so the text `'0'` is true while the number
    it negates to is false. A rule reading the minus as leaving truth alone — which holds for a
    number and for nothing else — answers `True` where a host answers `False`.

    **Both throws are refused, and they are two.** `evaluate` says whether reaching the value may
    throw and `convert` says whether making a Boolean of it may, and the second does not carry the
    first: `$null * [int]'abc'` evaluates to a definite `$null` that may throw, and converting that
    `$null` alone is a `$False` that cannot. Reading only the conversion would report a truth for an
    expression a host never finishes, and a caller that prunes on it would delete the throw.
    """
    if node is None:
        return None
    outcome = evaluate(node, None)
    if outcome.may_throw or outcome.value is UNKNOWN:
        return None
    converted = convert(outcome.value, _BOOLEAN)
    if converted.may_throw or not isinstance(converted.value, Ps1Constant):
        return None
    return converted.value.payload if isinstance(converted.value.payload, bool) else None


def unwrap_to_array_literal(node: Node) -> Ps1ArrayLiteral | None:
    node = unwrap_parens(node)
    if isinstance(node, Ps1ArrayLiteral):
        return node
    if isinstance(node, Ps1ArrayExpression) and len(node.body) == 1:
        stmt = node.body[0]
        if isinstance(stmt, Ps1ExpressionStatement) and isinstance(stmt.expression, Ps1ArrayLiteral):
            return stmt.expression
    return None


def collect_facts(node: Node | None) -> list[Ps1Fact] | None:
    """
    The values an expression names, as facts, or `None` where it names anything else. A scalar is a
    list of one, which is what a caller reading a command's or an operator's operand wants:
    PowerShell hands one value and a collection of one to the same place.

    This is the only place the elements of a collection are taken apart, and every caller that wants
    something *of* each of them — an integer, a text, a number-or-text — asks the element that
    question itself. A collector per question would each have to state again which spellings build a
    collection, and `read` already knows: `@(1, 2)`, `(1, 2)`, `1, 2`, a `[char[]]` over any of them
    and a cast over any of those are one answer here.
    """
    fact = read(node)
    if isinstance(fact, Ps1Constant) and fact.type in (_OBJECT_ARRAY, _CHAR_ARRAY):
        payload = fact.payload
        return None if not isinstance(payload, tuple) else list(payload)
    return None if fact is UNKNOWN else [fact]


def collect_integers(node: Node | None) -> list[int] | None:
    """
    The integers an expression names, as a list, or `None` where it names anything else.

    What counts as an integer is `integer_of`, so a numeral whose spelling makes it something else
    is not one, and neither is a `$null`.
    """
    return _each(collect_facts(node), integer_of)


def collect_texts(node: Node | None) -> list[str] | None:
    """
    The texts an expression's values contribute where PowerShell coerces each of them to a String,
    or `None` where one of them names no text. See `coerced_text` for what that coercion is and
    which operators perform it.
    """
    return _each(collect_facts(node), coerced_text)


def _each(facts: list[Ps1Fact] | None, of: Callable[[Ps1Fact], _T | None]) -> list[_T] | None:
    """
    What each of `facts` answers to `of`, or `None` where any one of them answers nothing. One
    element the caller cannot read makes the whole collection unreadable: a shorter list than the
    script builds is a different value, and there is nothing to stand in for the element dropped.
    """
    if facts is None:
        return None
    answers: list[_T] = []
    for fact in facts:
        answer = of(fact)
        if answer is None:
            return None
        answers.append(answer)
    return answers


def collect_byte_array(node: Expression) -> bytes | None:
    """
    The bytes an expression names, or `None` where it names something that is not a list of them.
    A number outside a byte is not one, which is a refusal rather than a truncation.
    """
    numbers = collect_integers(node)
    if numbers is None:
        return None
    try:
        return bytes(numbers)
    except (ValueError, OverflowError):
        return None


#: A type this module names, resolved through the one resolver rather than spelled here — a name
#: written out as text would be a second vocabulary inside the module whose purpose is to have one.
#: A name the table does not resolve raises at import, which is what `named_type` is for: every
#: answer below is keyed by the result, so a missing row would not move an answer, it would make
#: every comparison silently false.
_type = named_type


#: The type every string literal has, and the narrowest one a numeral can. A numeral's is decided by
#: its spelling and so is read rather than named here; `_INT32` is where the numeric ladder starts
#: and what a shift is masked at, not what an integer literal is.
_STRING = _type('System.String')
_INT32 = _type('System.Int32')

#: What an array literal builds. PowerShell collects the elements into an `Object[]` whatever they
#: are, which is measured rather than assumed: an array of integers and an array of strings both
#: report `System.Object[]`. The rank is what makes a member read on one resolve against
#: `System.Array`, which is where an array's members actually live.
_OBJECT_ARRAY = _type('System.Object[]')

#: The array a `[char[]]` cast builds, whose element type a `-is [string]` test reads as *not* a
#: String. It is a container of Char and not the String its characters spell, which is the whole
#: distinction the Char-erasure phase exists to keep — a `Char[]` has no literal, so `render` writes
#: none and a fold that observes one reads its type rather than spelling its value.
_CHAR_ARRAY = _type('System.Char[]')

#: The enums whose values the domain computes, which are the two the engine's preference variables
#: hold. An enum value is a `Ps1Constant` of its type whose payload is the ordinal, and the rules
#: `_to_enum` and `_from_enum` apply are the ones 5.1 applies to an enum that carries no `[Flags]`
#: and has no negative member: an integer is stored at the width the record's `value__` names and
#: the ordinal that leaves is accepted only where a member holds it. A `[Flags]` enum accepts any
#: combination of its members and an enum with a negative member accepts every ordinal, and the
#: capture does not record whether an enum carries `[Flags]`, so no other enum is computed and a
#: cast to one is left to the grid, which has no cell for it.
_FOLDABLE_ENUMS = frozenset({
    _type('System.Management.Automation.ActionPreference'),
    _type('System.Management.Automation.ConfirmImpact'),
})


def resolve_expression_type(
    expr: Expression,
    type_of_variable: Ps1VariableTyping | None = None,
) -> Ps1TypeName | None:
    """
    Trace the .NET type of a PowerShell expression by walking member access chains. Returns the one
    canonical `Ps1TypeName`, or `None` if the type cannot be determined.

    A numeral is asked of `read` rather than answered here, because how wide a numeral is written
    decides its type and only the spelling knows: `1L` is an Int64, `2147483648` is an Int64,
    `9223372036854775808` is a Decimal and `1e32` a Double, every one of them measured. Answering
    `System.Int32` for all of them resolved a member against a type the value did not have.
    """
    unwrapped = unwrap_parens(expr)
    if not isinstance(unwrapped, Expression):
        return None
    expr = unwrapped
    if isinstance(expr, (Ps1StringLiteral, Ps1HereString)):
        return _STRING
    if isinstance(expr, (Ps1IntegerLiteral, Ps1RealLiteral)):
        return type_of(read(expr))
    if isinstance(expr, Ps1ArrayLiteral):
        return _OBJECT_ARRAY
    if isinstance(expr, Ps1ArrayExpression):
        if (
            len(expr.body) == 1
            and isinstance(expr.body[0], Ps1ExpressionStatement)
            and isinstance(expr.body[0].expression, Ps1ArrayLiteral)
        ):
            return _OBJECT_ARRAY
    if isinstance(expr, Ps1Variable):
        if type_of_variable is not None:
            named = type_of_variable(expr)
            if named is not None:
                return named
        declared = VARIABLE_TYPES.get(expr.name.lower())
        return None if declared is None else resolve_type(declared)
    if isinstance(expr, Ps1TypeExpression):
        return resolve_type(expr.name)
    if isinstance(expr, Ps1CastExpression):
        return resolve_type(expr.type_name)
    if isinstance(expr, Ps1CommandInvocation):
        cmd_name = get_command_name(expr)
        if cmd_name is not None:
            cmd_lower = cmd_name.lower()
            if cmd_lower in OBJ_COMMANDS:
                type_str = extract_first_positional_string(expr)
                if type_str is not None:
                    return resolve_type(type_str)
            elif cmd_lower in WMI_COMMANDS:
                class_str = extract_first_positional_string(expr)
                if class_str is not None:
                    return resolve_type(class_str)
    if isinstance(expr, Ps1MemberAccess):
        if expr.object is None:
            return None
        obj_type = resolve_expression_type(expr.object, type_of_variable)
        if obj_type is None:
            return None
        member_name = get_member_name(expr.member)
        if member_name is None:
            return None
        return resolve_member_type(obj_type, member_name)
    return None


def non_null_type(
    expr: Expression,
    type_of_variable: Ps1VariableTyping | None,
    join: Ps1VariableTyping | None,
) -> Ps1TypeName | None:
    """
    The type this expression's value carries where the value is established not to be `$null`, or
    `None` where that is not established. Three origins establish one: a literal, read through
    `read` — which answers `$null` for the `$null` literal and refuses here; an instance call of
    a member the curated `non_null` table vouches for, answering the return type its overloads
    agree on; and a variable, which is the *join*'s to answer,
    `refinery.lib.scripts.ps1.analysis.variable_types.non_null_type_at` being the one
    implementation. Everything else refuses, which is a fold declined and never a guess.
    """
    unwrapped = unwrap_parens(expr)
    if not isinstance(unwrapped, Expression):
        return None
    fact = read(unwrapped)
    if isinstance(fact, (Ps1Typed, Ps1Constant)):
        return fact.type
    if isinstance(unwrapped, Ps1Variable):
        return None if join is None else join(unwrapped)
    if isinstance(unwrapped, Ps1InvokeMember):
        return _vouched_return(unwrapped, type_of_variable)
    return None


def _vouched_return(
    call: Ps1InvokeMember,
    type_of_variable: Ps1VariableTyping | None,
) -> Ps1TypeName | None:
    """
    The return a curated non-null vouch answers an instance call with, or `None` where the call is
    not one it covers. The receiver is typed rather than origin-traced, because a receiver that is
    `$null` at runtime makes the call throw before the caller's question is reached, and the
    sealedness floor on every vouch is what keeps the answer from naming a subtype member.
    """
    if call.object is None or call.access is not Ps1AccessKind.INSTANCE:
        return None
    member = get_member_name(call.member)
    if member is None:
        return None
    receiver = resolve_expression_type(call.object, type_of_variable)
    if receiver is None:
        return None
    if (receiver.generic_definition, member.lower()) not in NON_NULL_RETURNS:
        return None
    returns = {
        resolve_type(overload['returns'])
        for overload in instance_overloads(receiver, member)
        if overload.get('returns')
    }
    if None in returns or len(returns) != 1:
        return None
    return next(iter(returns))


#: Commands whose declared `[OutputType]` is a trustworthy *superset* of what they emit at runtime,
#: not merely a lower bound. Most commands under-declare: one that forwards its input emits the
#: input's type, which it never lists — `Get-Random -InputObject $procs` returns a `Process`,
#: `Get-Content` on a non-filesystem provider returns whatever that provider yields — so trusting
#: the declaration lets the member gate prove `(...).Path` pure over an incomplete candidate set and
#: delete a live effect. Only commands that emit their own output and cannot pass input through
#: belong here; a read on any other command's result stays unresolved, and therefore kept.
_CLOSED_OUTPUT_CMDLETS = frozenset({
    'get-date',
    'measure-object',
})


#: The names the pipeline binds the current object to. `$PSItem` is the same variable spelled out,
#: and a script that uses one spelling to defeat a rule written over the other is the reason both
#: are listed here rather than only the short one.
_PIPELINE_VARIABLES = frozenset({'_', 'psitem'})


def _is_pipeline_variable(node) -> bool:
    """
    Whether *node* reads the current pipeline object. A splatted or scope-qualified spelling is not
    one: neither reads the automatic variable the pipeline binds.
    """
    return (
        isinstance(node, Ps1Variable)
        and not node.splatted
        and node.scope is Ps1ScopeModifier.NONE
        and node.name.lower() in _PIPELINE_VARIABLES
    )


def _pipeline_variable_candidates(
    node: Ps1Variable,
    world: Ps1WorldReach,
    type_of_variable: Ps1VariableTyping | None,
) -> frozenset[Ps1TypeName]:
    """
    The types the current pipeline object may carry where *node* reads it: the output types of the
    command feeding the element whose body *node* stands in.

    **Only a command upstream answers.** A cmdlet's declared output describes what it writes to the
    pipeline *per object*, which is already the type `$_` is bound to. Every other expression is a
    value the pipeline enumerates, and its type is the type of the whole — `@(1, 2) | ForEach-Object
    { $_ }` binds an `Int32` where the array is an `Int32[]` — so an upstream that is not a command
    contributes nothing rather than the collection's type.

    The block has to be one the command runs once per input object, which is what binds the variable
    at all; `refinery.lib.scripts.ps1.analysis.blocks.binds_the_pipeline_variable` decides it. A read
    in a `-Begin` body, or in a block written where the enclosing scope's `$_` is what is read, is
    refused there and answers nothing here.
    """
    block = node.parent
    while block is not None and not isinstance(block, Ps1ScriptBlock):
        block = block.parent
    if block is None:
        return frozenset()
    command = binds_the_pipeline_variable(block, world.shadowed_names)
    if command is None:
        return frozenset()
    element = command.parent
    if not isinstance(element, Ps1PipelineElement):
        return frozenset()
    pipeline = element.parent
    if not isinstance(pipeline, Ps1Pipeline):
        return frozenset()
    upstream = None
    for candidate in pipeline.elements:
        if candidate is element:
            break
        upstream = candidate
    if upstream is None or not isinstance(upstream.expression, Ps1CommandInvocation):
        return frozenset()
    return _command_candidates(upstream.expression, world, type_of_variable)


def candidate_types(
    expr: Expression,
    world: Ps1WorldReach,
    type_of_variable: Ps1VariableTyping | None = None,
) -> frozenset[Ps1TypeName]:
    """
    The set of canonical .NET type names the expression's value could have, or the empty set when
    the type cannot be determined. A static method call contributes the return its overloads agree
    on, a cmdlet call the output types it declares, and `$_` the output types of whatever feeds the
    pipeline element it is bound in; each can be several, so a caller reasoning about the value must
    have its conclusion hold for every candidate. The single-type forms — literals, variables,
    casts, `New-Object`, WMI, and property chains — are delegated to `resolve_expression_type`
    rather than re-derived here.

    `world` is what decides whether a command name still denotes what the metadata says, so a cmdlet
    whose name the script has taken over contributes nothing. It is asked at the position of the
    command it resolves rather than over the whole run, so a name some later statement rebinds still
    denotes the built-in everywhere no path places that statement first.
    """
    unwrapped = unwrap_parens(expr)
    if not isinstance(unwrapped, Expression):
        return frozenset()
    expr = unwrapped
    if isinstance(expr, Ps1InvokeMember):
        return _static_method_candidates(expr)
    if isinstance(expr, Ps1CommandInvocation):
        return _command_candidates(expr, world, type_of_variable)
    if _is_pipeline_variable(expr):
        return _pipeline_variable_candidates(expr, world, type_of_variable)
    single = resolve_expression_type(expr, type_of_variable)
    return frozenset() if single is None else frozenset({single})


def _static_method_candidates(node: Ps1InvokeMember) -> frozenset[Ps1TypeName]:
    """
    The return type of a `[Type]::Method(...)` call, taken only when every matching static overload
    agrees on it; disagreement or an unrecognized call is the empty set. An instance method call is
    not resolved — its receiver type would have to be traced and its overloads selected by argument
    type — so it contributes nothing rather than a guess.
    """
    if node.access is not Ps1AccessKind.STATIC:
        return frozenset()
    obj = node.object
    member = node.member
    if not isinstance(obj, Ps1TypeExpression) or not isinstance(member, str):
        return frozenset()
    returns = {
        resolve_type(overload['returns'])
        for overload in static_overloads(obj.name, member)
        if overload.get('returns')
    }
    if len(returns) != 1:
        return frozenset()
    single = next(iter(returns))
    return frozenset() if single is None else frozenset({single})


def _command_candidates(
    cmd: Ps1CommandInvocation,
    world: Ps1WorldReach,
    type_of_variable: Ps1VariableTyping | None,
) -> frozenset[Ps1TypeName]:
    """
    The types a command's result could have: the constructed or queried type for the `New-Object`
    and WMI forms the single-type ladder already knows, otherwise the output types a command
    declares through `[OutputType]` — but only for a command whose declaration is a trustworthy
    *superset* of what it emits (`_CLOSED_OUTPUT_CMDLETS`). `[OutputType]` is a lower bound in
    general: a command that forwards its input emits types it never declares, and trusting the
    declaration there would let the member gate prove an effectful read pure over an incomplete
    candidate set. Every other command contributes nothing, so a read on its result stays
    unresolved and is kept.

    The name is trusted by position (`may_trust_command_name_at`), which grants wherever the
    whole-run verdict grants *and* wherever neither flood reaches — a widening, not a narrowing.
    It is sound because the two floods bound every position at which a rebinding could have run,
    and because what is granted here is a proof about a known built-in rather than a guess about
    an artifact: relaxing such a proof by position only widens what it already covers.
    `refinery.lib.scripts.ps1.deobfuscation.deadcode._is_injected_noise_bareword` reads the same
    query for a guess rather than a proof, and states there what that costs; the soundness argument
    above is this site's own and does not carry over to it.
    """
    name = get_command_name(cmd)
    if name is None:
        return frozenset()
    lower = name.lower()
    if not world.may_trust_command_name_at(lower, cmd):
        return frozenset()
    if lower in TYPE_ARG_COMMANDS:
        single = resolve_expression_type(cmd, type_of_variable)
        return frozenset() if single is None else frozenset({single})
    if lower not in _CLOSED_OUTPUT_CMDLETS:
        return frozenset()
    declared = command_output_types(name)
    if declared is None:
        return frozenset()
    resolved = {resolve_type(one) for one in declared}
    return frozenset(one for one in resolved if one is not None)


#: The types the domain names. Resolved once through the one resolver, so that a fact carries the
#: same `Ps1TypeName` a member lookup or a grid cell is keyed by and the two can be compared.
_BYTE = _type('System.Byte')
_BOOLEAN = _type('System.Boolean')
_CHAR = _type('System.Char')
_DECIMAL = _type('System.Decimal')
_DOUBLE = _type('System.Double')
_INT16 = _type('System.Int16')
_INT64 = _type('System.Int64')
_SBYTE = _type('System.SByte')
_UINT16 = _type('System.UInt16')
_UINT32 = _type('System.UInt32')
_UINT64 = _type('System.UInt64')

#: The widths the numeric ladder is written in terms of. `System.Decimal`'s bound is its documented
#: maximum rather than a power of two, because its range is not a bit width.
#:
#: Its lower bound is written down rather than spelled `-_DECIMAL_MAX`, because that expression is
#: not the number it reads as: arithmetic on a `Decimal` is a *context* operation in Python and
#: rounds to the ambient precision, which is 28 digits where this value has 29, so `-_DECIMAL_MAX`
#: reads as `-79228162514264337593543950340` — a bound wider than the type has, and one that moves
#: whenever anything in the process sets `decimal.getcontext().prec`.
_INT32_RANGE = (-0x80000000, 0x7FFFFFFF)
_INT64_RANGE = (-0x8000000000000000, 0x7FFFFFFFFFFFFFFF)
_DECIMAL_MAX = decimal.Decimal('79228162514264337593543950335')
_DECIMAL_MIN = decimal.Decimal('-79228162514264337593543950335')


class Ps1Fact:
    """
    What is known about one PowerShell value: nothing (`UNKNOWN`), that it is `$null` (`NULL`), that
    it has a type (`Ps1Typed`), or that it is a particular value of a particular type
    (`Ps1Constant`). These are the four elements of the lattice every question in this module is
    answered in, ordered `Ps1Constant` below `Ps1Typed` below `UNKNOWN`, with `NULL` beside the
    typed ones rather than under them: `$null.GetType()` throws, so there is no type it could carry.

    The base is a marker and carries no accessor: `type_of` is where a fact's type is read, so that
    the one place a caller asks the question is a function it can be pointed at, and an element that
    has no type does not have to pretend to answer.
    """

    __slots__ = ()


@dataclasses.dataclass(frozen=True)
class _Ps1Unknown(Ps1Fact):
    """
    Nothing is known about the value. This is the answer to every question this module declines,
    and it never means *the value is absent* — that is `NULL`.
    """

    def __repr__(self) -> str:
        return 'UNKNOWN'


@dataclasses.dataclass(frozen=True)
class _Ps1Null(Ps1Fact):
    """
    The value is `$null`. Its own element rather than a `Ps1Constant` of some type, because it has
    no type to be constant *of*: reading `GetType()` off it throws.
    """

    def __repr__(self) -> str:
        return 'NULL'


UNKNOWN: Ps1Fact = _Ps1Unknown()
NULL: Ps1Fact = _Ps1Null()


def null_expression() -> Ps1Variable:
    """
    The expression that spells `$null`. This is `render(NULL)`, given its own name and a precise
    return type so a caller building a node out of it does not carry render's `Expression | None`.
    """
    return Ps1Variable(name='Null')


@dataclasses.dataclass(frozen=True)
class Ps1Typed(Ps1Fact):
    """
    The value has this type and no more is known about it. A refinement — an interval, a known-bits
    mask — becomes a field here when one is built, so that narrowing what a typed value can be does
    not add an element to the lattice or a case to any caller.
    """

    type: Ps1TypeName

    def __repr__(self) -> str:
        return F'Typed({self.type})'


@dataclasses.dataclass(frozen=True)
class Ps1Constant(Ps1Fact):
    """
    The value is exactly `payload`, and its type is `type`. The payload's Python type is an
    implementation of the .NET one and never a substitute for it: `Ps1Constant(System.Char, 'A')`
    and `Ps1Constant(System.String, 'A')` hold equal payloads and are different values, which is the
    distinction this whole layer exists to keep. A caller deciding what a payload means reads
    `type`.

    An array's payload is a tuple of facts rather than of payloads, so that an `Object[]` whose
    elements are Chars is a different value from one whose elements are Strings — the fact a
    pipeline builds and the erasure that made `foreach` iterate once over a joined string.
    """

    type: Ps1TypeName
    payload: int | float | decimal.Decimal | str | bool | tuple[Ps1Fact, ...]

    def __repr__(self) -> str:
        return F'Constant({self.type}, {self.payload!r})'


class Ps1Throws(enum.Enum):
    """
    How an operation stands with respect to throwing, on one three-valued axis. `NEVER` is a claim
    this module makes that the operation *cannot* throw; `ALWAYS` a claim that it *must*, under every
    runtime state consistent with what is known; `MAYBE` is everything between, which is both an
    operation known to throw on *some* state and one this module simply declines to judge — the two
    are the same answer here because a reader of the may-throw side stops on either.

    The two are duals of one predicate rather than two axes: an over-approximation ("might it
    throw?", `not NEVER`) and an under-approximation ("must it throw?", `ALWAYS`) of the same
    question. Keeping them one field is what makes `ALWAYS ⇒ may_throw` structural — a certain throw
    can never read as safe — and what keeps the whole judgement inside `evaluate`'s single walk
    rather than a second recursion that could drift from it.
    """
    NEVER = 'never'
    MAYBE = 'maybe'
    ALWAYS = 'always'


#: The three axis values, named once at module scope so the several places that construct an outcome
#: read alike, the way `UNKNOWN` and `NULL` already do for the value side.
NEVER = Ps1Throws.NEVER
MAYBE = Ps1Throws.MAYBE
ALWAYS = Ps1Throws.ALWAYS


class Ps1Outcome(typing.NamedTuple):
    """
    What an operation does: the fact it produces, and how it stands with respect to throwing. The
    two are separate because they are not alternatives — an operation that yields an Int32 *or*
    throws is both, and a domain that had to choose could only answer `UNKNOWN` and lose the type it
    knows.

    The throw axis is a `Ps1Throws`, and the value is read in the same direction as the may-throw
    side of it: `UNKNOWN` is the value of an operation that names none, exactly as `MAYBE` is where
    this claims neither safety nor a certain throw. Not knowing anything is therefore
    `Ps1Outcome(MAYBE, UNKNOWN)` and not `Ps1Outcome(NEVER, UNKNOWN)` — the latter is a claim of
    safety made by the one answer that has no grounds for any claim. It made generalising an operand
    *remove* a throw: `1 / $x` for a divisor this module could not type answered that it cannot
    throw, where the same division over a divisor it could type answered that it can. Only `render`
    refusing to spell an `UNKNOWN` kept that out of a fold, which is a guard that holds one
    operation deep and no further.

    `may_throw` and `certainly_throws` are the two readings of the axis a caller wants, and they
    project from the one field so that the invariant `ALWAYS ⇒ may_throw` cannot be got wrong. A
    fold reads `may_throw` and stops on anything but `NEVER`; `certainly_throws` is for the
    transform that deletes or reroutes code, which acts only on `ALWAYS` — the certain-throw fold
    `refinery.lib.scripts.ps1.deobfuscation.deadcode.Ps1DeadCodeElimination._collapse_through_certain_throw`
    reads it to drop a dead tail and lift a handler, and the `no false positive` obligation on
    `ALWAYS` is what that fold rests on.
    """

    throws: Ps1Throws
    value: Ps1Fact

    @property
    def may_throw(self) -> bool:
        """
        Whether the operation might throw — `False` only where this module claims it cannot.
        """
        return self.throws is not NEVER

    @property
    def certainly_throws(self) -> bool:
        """
        Whether the operation is guaranteed to throw under every state consistent with what is
        known. A negative here is *not knowing*, never a claim of safety — that is `may_throw`.
        """
        return self.throws is ALWAYS


#: The refusal, named once so that the several places that decline read alike. It claims nothing on
#: either axis — no value, and no freedom from a throw.
NOTHING = Ps1Outcome(MAYBE, UNKNOWN)


def _throw_join(*axes: Ps1Throws) -> Ps1Throws:
    """
    The throw axis of a sequence of sub-expressions 5.1 evaluates left to right, each up to the
    first throw. It is `ALWAYS` if any one of them is — either a prior one throws, or none does and
    that one does, so the sequence throws on every state — and `NEVER` only where every one is; a
    single `MAYBE` with no `ALWAYS` beside it makes the sequence `MAYBE`.
    """
    if any(axis is ALWAYS for axis in axes):
        return ALWAYS
    if all(axis is NEVER for axis in axes):
        return NEVER
    return MAYBE


def _demoted_throw(axis: Ps1Throws) -> Ps1Throws:
    """
    The throw axis of an operand a short-circuiting operator may never evaluate. A certain throw in
    a position that can be skipped is no longer certain, so `ALWAYS` caps at `MAYBE`; the other two
    already say the operand might or might not throw and are unchanged.
    """
    return MAYBE if axis is ALWAYS else axis


def _throws_from_cell(may: bool) -> Ps1Throws:
    """
    The throw axis a measured grid cell contributes. A cell's silence about throwing is a witnessed
    lower bound rather than a bound, so a cell never grants `ALWAYS`: it says `MAYBE` where it
    recorded a throw and `NEVER` only where the value domain, not the cell, has established safety
    for the values in hand — which is why every leaf `ALWAYS` in this module comes from a
    value-precise computation and none from the grid.
    """
    return MAYBE if may else NEVER


def type_of(fact: Ps1Fact) -> Ps1TypeName | None:
    """
    The .NET type a fact carries, or `None` for `UNKNOWN` and `NULL`. `None` is *no type is named
    here* in both cases, and a caller that needs to tell them apart compares against `NULL`.
    """
    if isinstance(fact, (Ps1Typed, Ps1Constant)):
        return fact.type
    return None


def type_test(fact: Ps1Fact, target: str | Ps1TypeName) -> bool | None:
    """
    Whether `value -is target` holds for a value this fact describes: `True`, `False`, or `None`
    where the domain cannot decide. `$null` answers `False` for every target — it has no type to be
    one of — an `UNKNOWN` fact answers `None`, and everything else is the relation
    `refinery.lib.scripts.ps1.data.is_assignable_to` reads off the collected type model from the
    fact's runtime type. The result of a type test is always a `System.Boolean`, so unlike the value
    grid there is no measured cell to stamp the answer against; the only care needed is that a `None`
    stays a fold declined rather than becoming a guessed `False`.
    """
    if fact is NULL:
        return False
    runtime = type_of(fact)
    if runtime is None:
        return None
    return is_assignable_to(runtime, target)


def integer_of(fact: Ps1Fact) -> int | None:
    """
    The integer a fact names, or `None` for a fact that names anything else. This is what a caller
    holding a fact asks instead of reaching for the payload, and what it refuses is the point: a
    `Boolean` carries a Python `int` and is not one, a `$null` is an absent value rather than a
    zero, and a `Double` or a `Decimal` that happens to be whole is still not an integer here — a
    caller that wants the number one of those *converts* to is asking `convert`, which is where the
    rounding rule lives.
    """
    if not isinstance(fact, Ps1Constant) or fact.type not in _INTEGER_RANGE:
        return None
    payload = fact.payload
    return None if isinstance(payload, bool) or not isinstance(payload, int) else payload


def ordinal_of(fact: Ps1Fact) -> int | None:
    """
    The ordinal an enum value carries, or `None` for a fact that is not one. It is `integer_of` for
    the enums the domain computes, and a separate question for the reason that one refuses a
    Boolean: an ordinal is the number a member is stored as and not an integer of the domain's own
    widths, so a caller that wants the member's number asks here and one that wants an integer does
    not receive one by accident. A payload that is not an ordinal is a malformed fact and names
    nothing.
    """
    if not isinstance(fact, Ps1Constant) or fact.type not in _FOLDABLE_ENUMS:
        return None
    payload = fact.payload
    return None if isinstance(payload, bool) or not isinstance(payload, int) else payload


def integer_at(target: Ps1TypeName, value: int) -> Ps1Fact:
    """
    `value` as a value of `target`, or `UNKNOWN` where `target` names no integer width or does not
    hold it. A width that does not hold a number is a throw rather than a wrap, measured for every
    one of them, so a caller that folds refuses either way and the two are one answer here.
    """
    bounds = _INTEGER_RANGE.get(target)
    if bounds is None or not bounds[0] <= value <= bounds[1]:
        return UNKNOWN
    return Ps1Constant(target, value)


def pattern_at(target: Ps1TypeName, magnitude: int) -> Ps1Fact:
    """
    The value the bit pattern `magnitude` denotes in a register of `target`'s width, with that
    width's sign, or `UNKNOWN` where `target` names no width or the pattern is wider than it holds.

    A pattern is not a magnitude, which is the whole reason this is a separate question: measured,
    `[int]'0xFFFFFFFF'` is -1 and `[Convert]::ToInt32('FFFFFFFF', 16)` is -1, where the digits read
    as a number are four billion. Two callers with different spellings ask it, so it is stated once.
    """
    bounds = _INTEGER_RANGE.get(target)
    if bounds is None:
        return UNKNOWN
    try:
        return Ps1Constant(target, _pattern_at_width(bounds, magnitude))
    except _Throws:
        return UNKNOWN


def text_of(fact: Ps1Fact) -> str | None:
    """
    The `String` a fact names, or `None` for a fact that names anything else. This is what a caller
    holding a fact asks instead of reaching for the payload, and the reason it exists is the one
    distinction the payload cannot make: a `Char` carries a Python `str` too, and it is not a String
    — measured, the two differ in what `-is [char]` answers, in which methods they have, in what
    `[int]` makes of them and in what `+` does with them on the left. A caller that read the payload
    would get the same characters back for both.

    It is not a spelling. `refinery.lib.scripts.ps1.ast.string_value` answers what text a *node* is
    written as, which is a syntactic question the analysis layer asks about command names and paths;
    this answers what text a *value* is, which only the domain can say.
    """
    if isinstance(fact, Ps1Constant) and fact.type == _STRING and isinstance(fact.payload, str):
        return fact.payload
    return None


def coerced_text(fact: Ps1Fact) -> str | None:
    """
    The text a value contributes where PowerShell coerces it to a String, or `None` where this
    module names none. It is `convert` to a `String` and nothing else, which is what makes it a
    different question from `text_of`: that one asks what a value *is*, this asks what it *becomes*,
    and a Char answers `None` to the first and its character to the second.

    Every string operator coerces this way and uniformly, measured over `-replace`, `-split`,
    `-join`, `-f` and `-match` and over both of their operands: `'x' -replace 'x', $true` is `True`,
    `-replace 'x', 1.50d` is `1.50`, `('a','b') -join 5` is `a5b`, `-join (72, 105)` is `72105`,
    `[char]65 -replace 'A', 'B'` is `B` and `$true -replace 'T', 'X'` is `Xrue`.

    A *method* does not coerce this way and must not ask this: it converts each argument to the
    parameter's declared type, and the two disagree — `'abc'.Substring([char]1)` is `bc`, where the
    Char becomes the number one and its text would be a control character that throws.
    """
    outcome = convert(fact, _STRING)
    return None if outcome.may_throw else text_of(outcome.value)


#: The types outside the integer widths whose text carries no culture at all. The widths are not
#: listed with them because `_INTEGER_RANGE` is already the one place they are named. An enum
#: writes its member name, which no culture spells differently, and a loader's `iex` is routinely
#: `$VerbosePreference.ToString()[1, 3] + 'x'`, so the enums the domain computes are here too.
_CULTURE_FREE = frozenset({_BOOLEAN, _CHAR, _STRING}) | _FOLDABLE_ENUMS


def invariant_text(fact: Ps1Fact) -> str | None:
    """
    The text a value writes where the *current culture* renders it, or `None` where that text is not
    the one this module computes.

    It is `coerced_text` narrowed to the values no culture spells differently, and the narrowing is
    the whole of it. Measured on a host whose culture writes a decimal comma: `(1.50d).ToString()`
    is `1,50` and a collection separated by `$OFS = 1.5` reads `1,5`, where `[string]1.50d` is
    `1.50`. So a caller reading a value the *host* formats — a `ToString()` call, the separator a
    collection is joined with — computes the right characters only for a Boolean, a Char, a String
    and the integer widths, each measured to agree.
    """
    found = type_of(fact)
    if found is None or (found not in _CULTURE_FREE and found not in _INTEGER_RANGE):
        return None
    return coerced_text(fact)


_DECIMAL_DIGITS = re.compile(r'[0-9]+\Z')
_REAL_DIGITS = re.compile(r'(?:[0-9]*\.[0-9]+|[0-9]+\.?)(?:e[+-]?[0-9]+)?\Z', re.IGNORECASE)
_HEX_DIGITS = re.compile(r'[0-9a-f]+\Z', re.IGNORECASE)


def read(node: Node | None) -> Ps1Fact:
    """
    What the source pins this expression to, as a fact, or `UNKNOWN` when it pins nothing. This is
    the floor the rest of the domain stands on and it **refuses rather than invents**: an expression
    it cannot decide, a literal spelled in a way no measurement covers, and a number too wide for
    any type all answer `UNKNOWN`, never a value that happens to be close.

    Only literal structure is read — literals, the array and parenthesis forms that wrap them,
    `$true`, `$false` and `$null`, and the casts that are a *spelling* rather than a conversion, for
    which see `_cast_spelling`. An operator is not read at all, so that a caller asking what the
    *source* says never receives an answer that came from evaluating something.

    A sign is not an exception to that, because the parser has already decided it: a `-` written
    directly against a numeral is part of the numeral and reaches this inside `raw`, while
    `- 2147483648` and `-(2147483648)` are unary minus over a literal and are refused here. Reaching
    past the space or the parenthesis to the numeral would report the Int32 that only the glued
    spelling has; the other two are an operator over a value and belong to `apply`.
    """
    if node is None:
        return UNKNOWN
    if isinstance(node, Ps1ParenExpression):
        return UNKNOWN if node.expression is None else read(node.expression)
    if isinstance(node, (Ps1StringLiteral, Ps1HereString)):
        return Ps1Constant(_STRING, node.value)
    if isinstance(node, (Ps1ExpandableString, Ps1ExpandableHereString)):
        return _quoted(node.parts)
    if isinstance(node, (Ps1IntegerLiteral, Ps1RealLiteral)):
        return _numeral(node.raw)
    if is_builtin_variable(node, {'true'}):
        return Ps1Constant(_BOOLEAN, True)
    if is_builtin_variable(node, {'false'}):
        return Ps1Constant(_BOOLEAN, False)
    if is_builtin_variable(node, {'null'}):
        return NULL
    if isinstance(node, (Ps1ArrayLiteral, Ps1ArrayExpression)):
        return _array(node, _pinned).value
    if isinstance(node, Ps1SubExpression):
        return _subexpression(node, _pinned).value
    if isinstance(node, Ps1CastExpression):
        return _cast_spelling(node)
    return UNKNOWN


def read_operand(node: Node | None) -> Ps1Fact:
    """
    What an operand *written in the source* contributes to an operation, which is `read` except for
    a `Decimal` numeral whose value is a whole number: that one contributes the number without the
    places it was written with.

    5.1 folds a constant expression in its parser, and a numeral reaching that fold carries no scale
    where it has nothing to hold — measured, `'x' + 1.00d` is `x1` where `'x' + 1.100d` is `x1.100`,
    and `- 1.0d` is `-1` where `- 1.10d` is `-1.10`. It is each *operand* that loses its places and
    not the result: `1.500d + 1.500d` is `3.000`, a whole number written to three places, because
    neither addend was one.

    **Only a numeral**, which is what makes this a different question from `read`. The same value
    reached any other way keeps its scale, because then no numeral stands where the parser folds:
    `$z = 1.0d; 'x' + $z` is `x1.0` and `'x' + [decimal]'1.0'` is `x1.0`, both measured, against the
    `x1` of the numeral written in place. A bare `1.0d` is `1.0` for the same reason — there is no
    operation over it to fold.

    That is also why `refinery.lib.scripts.ps1.deobfuscation.constants` will not carry such a value:
    inlining one *writes* a numeral where the source had none, which would move the operand into the
    fold and take its places away.
    """
    numeral = _folded_numeral(node)
    return read(node) if numeral is None else numeral


def survives_being_written(fact: Ps1Fact) -> bool:
    """
    Whether a value keeps its meaning when a pass writes it down as a constant where the source had
    something else. A `Decimal` whose value is a whole number written to places does not: the source
    reached it through a variable or a cast, and the numeral standing in for one of those is a
    numeral the parser folds, which takes the places away. `read_operand` is the rule, and this is
    the same rule asked of a value rather than of a node.

    Measured: `$z = 1.0d; $z + 0d` is `1.0` while the `1.0d + 0d` an inliner writes for it is `1`.
    Nothing else in the domain answers `False` here — every other value has a spelling that reads
    back as itself wherever it is put, which is what `render` and `read` being inverses means.
    """
    if not isinstance(fact, Ps1Constant) or fact.type != _DECIMAL:
        return True
    payload = fact.payload
    if not isinstance(payload, decimal.Decimal) or payload.as_tuple().exponent == 0:
        return True
    with decimal.localcontext(_DECIMAL_ARITHMETIC):
        return payload.to_integral_value() != payload


def _folded_numeral(node: Node | None) -> Ps1Fact | None:
    """
    The value a `Decimal` numeral has where the parser folds it, or `None` for a node that is not
    one of those. See `read_operand`.

    A parenthesis does not stop the fold and so does not stop this: measured, `'x' + (1.0d)` is
    `x1`, the same as without it.
    """
    if node is not None:
        node = unwrap_parens(node)
    if not isinstance(node, (Ps1IntegerLiteral, Ps1RealLiteral)):
        return None
    fact = read(node)
    if not isinstance(fact, Ps1Constant) or fact.type != _DECIMAL:
        return None
    payload = fact.payload
    if not isinstance(payload, decimal.Decimal) or payload.as_tuple().exponent == 0:
        return None
    with decimal.localcontext(_DECIMAL_ARITHMETIC):
        whole = payload.to_integral_value()
        return None if whole != payload else Ps1Constant(_DECIMAL, whole)


def fact_of(payload: object) -> Ps1Fact:
    """
    The value a Python object denotes where nothing has narrowed it, or `UNKNOWN` for one that
    denotes none.

    This is `read`'s counterpart for a caller holding a value it *computed* rather than one it
    found written down — the emulator is that caller, and `render` is where what it computed
    becomes a tree again. A number decides the way an unsuffixed numeral decides, because the
    narrowest width that holds a magnitude is the only rule the domain has for a bare one.

    **A `str` is a String and never a Char.** That is not a gap: a payload does not carry a type
    and the two are the same Python object, which is the whole reason `Ps1Constant` carries a type
    beside its payload. A caller that means a Char has to build the fact instead of asking here,
    and one whose currency cannot tell the two apart is a caller whose Chars are already gone.

    A number no literal spells names nothing here, which is `_finite`'s rule read at this boundary
    too: `render` states that a value it is handed always has a spelling, and a fact carrying an
    infinity would be the one that does not.
    """
    if payload is None:
        return NULL
    if isinstance(payload, bool):
        return Ps1Constant(_BOOLEAN, payload)
    if isinstance(payload, int):
        return _widest_needed(payload)
    if isinstance(payload, float):
        return UNKNOWN if _finite(payload) is None else _double(payload)
    if isinstance(payload, str):
        return Ps1Constant(_STRING, payload)
    if isinstance(payload, (list, tuple)):
        return _collected(Ps1Outcome(NEVER, fact_of(one)) for one in payload).value
    return UNKNOWN


def char_fact(text: str) -> Ps1Fact:
    """
    The `System.Char` a one-character text spells, for a caller that computed the character and
    cannot ask `fact_of`: a payload names a String, and the Char differs from it in nothing but
    the type beside the payload. Any other length names nothing.
    """
    return Ps1Constant(_CHAR, text) if len(text) == 1 else UNKNOWN


def collection_fact(facts: typing.Iterable[Ps1Fact]) -> Ps1Fact:
    """
    The `Object[]` whose elements are these facts, for a caller that built the facts itself
    because its currency carries kinds the payloads do not name. One element that names no value
    names no collection: a shorter array than the script builds is a different value.
    """
    gathered = tuple(facts)
    if not all(_is_value(one) for one in gathered):
        return UNKNOWN
    return Ps1Constant(_OBJECT_ARRAY, gathered)


def _quoted(parts: list) -> Ps1Fact:
    """
    A double-quoted string all of whose parts are text, which is the one shape of it that pins a
    value: an expansion is a read of something this does not know, and one part it cannot name
    leaves the whole string unnamed rather than shortened.
    """
    text: list[str] = []
    for part in parts:
        if not isinstance(part, Ps1StringLiteral):
            return UNKNOWN
        text.append(part.value)
    return Ps1Constant(_STRING, ''.join(text))


def _pinned(node: Node | None) -> Ps1Outcome:
    """
    What the source pins an expression to, as an outcome. Reading a literal cannot throw, so this
    says that it cannot — but only where a value was read at all. A fact of `UNKNOWN` is the
    refusal, and a refusal claims nothing on either axis.
    """
    fact = read(node)
    return NOTHING if fact is UNKNOWN else Ps1Outcome(NEVER, fact)


def _array(
    node: Ps1ArrayLiteral | Ps1ArrayExpression,
    of: Callable[[Expression], Ps1Outcome],
) -> Ps1Outcome:
    """
    An array whose value's payload is the facts of its elements. `of` is how one element is
    answered, which is what lets `read` build an array out of literals and `evaluate` build one out
    of anything: the two spellings below differ in the same way whatever an element is worth, so
    they are described once. One element the caller cannot answer makes the whole array unknown —
    a caller reasoning about it would otherwise be handed a shorter array than the script builds —
    and one that may throw makes the array one that may throw, because building it is what runs it.

    The two spellings do not build the same array from the same parts, which is measured rather than
    assumed. The comma operator takes each operand whole, so `(1, 2), 3` is two elements and the
    first of them is an array. `@()` collects what a pipeline hands it and a pipeline unrolls a
    collection one level on the way, so `@(@(1, 2))` and `@((1, 2))` are each *two* elements rather
    than one holding two, while `@(@(1, 2), 3)` is two — the unrolling happens once, to the value
    the statement produced, and not again to what was inside it.
    """
    if isinstance(node, Ps1ArrayLiteral):
        return _collected(of(element) for element in node.elements)
    stream = _stream(node.body, of)
    return NOTHING if stream is None else _collected(stream)


def _subexpression(
    node: Ps1SubExpression,
    of: Callable[[Expression], Ps1Outcome],
) -> Ps1Outcome:
    """
    A `$( ... )`, which collects the same stream `@( ... )` collects and then *collapses* it. That
    last step is the whole difference between the two spellings and it is measured: `$(1)` is an
    Int32 where `@(1)` is an `Object[]` of one, and `$()` is `$null` where `@()` is the empty
    array. Everything before the collapse agrees — `$(1, 2)`, `$(@(1, 2))` and `$(1; 2)` are each
    two elements, and `$((1, 2), 3)` is two of which the first is an array — so the unrolling is
    stated once, in `_stream`, rather than described twice with a chance of drifting.
    """
    stream = _stream(node.body, of)
    if stream is None:
        return NOTHING
    if not stream:
        return Ps1Outcome(NEVER, NULL)
    if len(stream) == 1:
        return stream[0]
    return _collected(stream)


def _stream(
    body: list,
    of: Callable[[Expression], Ps1Outcome],
) -> list[Ps1Outcome] | None:
    """
    The success stream a statement list contributes, with each statement's value unrolled one level
    the way a pipeline unrolls it, or `None` where a statement is not one this can answer.
    """
    outcomes: list[Ps1Outcome] = []
    for statement in body:
        if not isinstance(statement, Ps1ExpressionStatement) or statement.expression is None:
            return None
        outcome = of(statement.expression)
        inner = outcome.value
        if (
            isinstance(inner, Ps1Constant)
            and inner.type in (_OBJECT_ARRAY, _CHAR_ARRAY)
            and isinstance(inner.payload, tuple)
        ):
            outcomes.extend(Ps1Outcome(outcome.throws, one) for one in inner.payload)
        else:
            outcomes.append(outcome)
    return outcomes


def _collected(outcomes: typing.Iterable[Ps1Outcome]) -> Ps1Outcome:
    """
    The collection its elements came to. Every one of them has to *be* a value, `$null` included:
    an element that carries only a type leaves the collection unknown rather than making a
    `Ps1Constant` whose payload is not one. `([int]'abc'), 1` is what that would be — an Int32 or a
    throw beside the number one, in a fact that says it is exactly this value.
    """
    gathered = tuple(outcomes)
    if not all(_is_value(outcome.value) for outcome in gathered):
        return NOTHING
    return Ps1Outcome(
        _throw_join(*(outcome.throws for outcome in gathered)),
        Ps1Constant(_OBJECT_ARRAY, tuple(outcome.value for outcome in gathered)),
    )


def _is_value(fact: Ps1Fact) -> bool:
    """
    Whether a fact names a value rather than a bound on one. `$null` is one: it is what an absent
    value *is*, not the absence of knowledge about it.
    """
    return fact is NULL or isinstance(fact, Ps1Constant)


def _cast_spelling(node: Ps1CastExpression) -> Ps1Fact:
    """
    The value a cast *spells*, which is a question about the source and not an evaluation of it. The
    language has no literal for a `System.Char` or for any of the six integer widths, so `render`
    writes a value of one of those as a cast of a numeral, and this reads exactly that back:
    `read(render(fact))` is `fact` for every value the domain can spell.

    One operator deep is where that matters, because one operator deep is where folding works. A
    pass standing at `[char] 72 + [char] 105` asks `read` for each operand and `apply` for the
    operator; a Char that cannot be read back is a Char that cannot be added to anything, so the
    only way to fold it would have been to spell it as a String first, which is the erasure the
    whole phase exists to end.

    It is the *target* that is restricted and not the operand. A cast to a type that does have a
    literal is a conversion rather than a spelling — `[int] '1e3'` is a question about .NET's parser
    and `[int] (1 + 2)` an operator underneath one — and neither is what the source pins. That
    restriction is also what keeps `read` from walking into an expression: the only thing it
    recurses through is another spelling.

    A `char[]` is read here though `render` spells none. It has no literal, so `read(render(fact))`
    never reaches it and the roundtrip above says nothing about it; it is read because a cast of a
    literal collection or String to it pins a value the source names — the characters — that a
    reader of a collection and a `-join` over one both need, and refusing it would leave those folds
    to the String erasure this phase ends. It stays literal-only for the reason every other target
    here does: `convert` reads its elements from `read(node.operand)`, so an operator or a variable
    underneath the cast answers `UNKNOWN` and the whole cast does too.
    """
    target = resolve_type(node.type_name)
    if target is None or (target not in _SPELLED_BY_A_CAST and target != _CHAR_ARRAY):
        return UNKNOWN
    outcome = convert(read(node.operand), target)
    return UNKNOWN if outcome.may_throw else outcome.value


def _numeral(raw: str) -> Ps1Fact:
    """
    The fact a numeric literal's spelling denotes, measured rather than derived from the digits
    alone: the same digits are an Int32, an Int64, a Decimal or a Double depending on how wide they
    are and what is written after them.

    A spelling no measurement covers is refused. `_` is one: PowerShell 5.1 has no digit separator
    and reads `1_0` as a command name, so a lexer that accepts it must not be allowed to hand the
    domain the number ten.

    A multiplier suffix is what the model already knows it is, and what it does to the *type* is
    what is measured here: it applies to whatever the numeral is and the result is then typed by
    the rule that numeral's form uses, so `1kb` is an Int32 1024, `4gb` an Int64 4294967296,
    `1lkb` an Int64 1024 and `1.5kb` a Double 1536.
    """
    if '_' in raw:
        return UNKNOWN
    text = raw
    sign = 1
    if text[:1] in ('-', '+'):
        sign = -1 if text[0] == '-' else 1
        text = text[1:]
    multiplier = 1
    lowered = text.lower()
    for suffix, factor in MULTIPLIERS.items():
        if lowered.endswith(suffix):
            multiplier = factor
            text = text[:-len(suffix)]
            break
    if text[:2].lower() == '0x':
        return _hex_numeral(text[2:], sign, multiplier)
    return _decimal_numeral(text, sign, multiplier)


def _hex_numeral(digits: str, sign: int, multiplier: int) -> Ps1Fact:
    """
    A hexadecimal literal, which names a *bit pattern* rather than a magnitude: measured, `0xFF` is
    255, `0xFFFFFFFF` is Int32 -1 because eight digits fill an Int32, `0x100000000` is Int64
    4294967296 and seventeen digits fit nothing, which 5.1 reports as a parse error.

    A `L` suffix changes the question from *which width holds this pattern* to *read these digits as
    an Int64*, so `0xFFFFFFFFL` is 4294967295 rather than -1.

    The width the pattern fills is a *floor* on the result type and not merely a step on the way to
    it. `0xFFFFFFFFFFFFFFFF` is Int64 -1: the value -1 would fit an Int32, but the sixteen digits
    said which width was being filled, and narrowing back to what the number needs would report a
    type no value in the script has.

    A multiplier over a pattern that had to be reinterpreted as negative is refused: composing the
    two rules would answer where nothing was measured, and nothing here answers from a composition.
    """
    long_suffix = digits[-1:].lower() == 'l'
    if long_suffix:
        digits = digits[:-1]
    if not _HEX_DIGITS.match(digits):
        return UNKNOWN
    magnitude = int(digits, 16)
    if long_suffix:
        if magnitude > _INT64_RANGE[1]:
            return UNKNOWN
        return _long(sign * magnitude * multiplier)
    if magnitude <= 0xFFFFFFFF:
        width = _INT32
        value = magnitude - 0x100000000 if magnitude > _INT32_RANGE[1] else magnitude
    elif magnitude <= 0xFFFFFFFFFFFFFFFF:
        width = _INT64
        value = magnitude - 0x10000000000000000 if magnitude > _INT64_RANGE[1] else magnitude
    else:
        return UNKNOWN
    if value < 0 and multiplier != 1:
        return UNKNOWN
    return _no_narrower_than(width, sign * value * multiplier)


def _decimal_numeral(text: str, sign: int, multiplier: int) -> Ps1Fact:
    """
    A decimal literal. Without a suffix it takes the narrowest of Int32, Int64, Decimal and Double
    that holds it — measured all the way up, `2147483648` being Int64, `9223372036854775808` Decimal
    and `10^32` Double. A `L` or `D` suffix names the type instead, and over a real that is a
    conversion rather than a refusal: `1.5L` is Int64 2 and `2.5L` is Int64 2, which is the
    half-to-even rounding a cast performs.

    A real `Decimal` takes its sign by `copy_negate` rather than by a multiplication, which is a
    *context* operation in Python and rounds to the ambient 28 digits where the type holds 29: the
    literal `7922816251426433759354395033.5d` was read as `7922816251426433759354395034`, a number
    the source does not spell, and every reader of the constant inherited it.
    """
    suffix = text[-1:].lower()
    if suffix in ('l', 'd'):
        text = text[:-1]
    else:
        suffix = ''
    if _DECIMAL_DIGITS.match(text):
        magnitude = int(text) * multiplier
        if suffix == 'l':
            return _long(sign * magnitude)
        if suffix == 'd':
            return Ps1Constant(_DECIMAL, decimal.Decimal(sign * magnitude))
        return _widest_needed(sign * magnitude)
    if not _REAL_DIGITS.match(text):
        return UNKNOWN
    if suffix and multiplier != 1:
        return UNKNOWN
    if suffix == 'd':
        spelled = decimal.Decimal(text)
        return Ps1Constant(_DECIMAL, spelled.copy_negate() if sign < 0 else spelled)
    if suffix == 'l':
        return _long(sign * round(decimal.Decimal(text)))
    return _double(sign * float(text) * multiplier)


def _widest_needed(value: int) -> Ps1Fact:
    """
    The narrowest type that holds `value`, which is what an unsuffixed decimal literal takes.
    """
    if _INT32_RANGE[0] <= value <= _INT32_RANGE[1]:
        return Ps1Constant(_INT32, value)
    if _INT64_RANGE[0] <= value <= _INT64_RANGE[1]:
        return Ps1Constant(_INT64, value)
    if _DECIMAL_MIN <= value <= _DECIMAL_MAX:
        return Ps1Constant(_DECIMAL, decimal.Decimal(value))
    return _double(value)


def _no_narrower_than(floor: Ps1TypeName, value: int) -> Ps1Fact:
    """
    The narrowest type that holds `value`, but never narrower than `floor`. What a hexadecimal
    literal fills is a width, so the width is what it has however small the number it denotes is.
    """
    fact = _widest_needed(value)
    if floor == _INT64 and isinstance(fact, Ps1Constant) and fact.type == _INT32:
        return Ps1Constant(_INT64, value)
    return fact


def _long(value: int) -> Ps1Fact:
    return Ps1Constant(_INT64, value) if _INT64_RANGE[0] <= value <= _INT64_RANGE[1] else UNKNOWN


def _double(value: int | float) -> Ps1Fact:
    try:
        return Ps1Constant(_DOUBLE, float(value))
    except OverflowError:
        return UNKNOWN


#: The integer types the domain computes in, narrowest first, each with the range it holds. The
#: order is what `_stamped` walks to decide which of a cell's candidate types a computed value has,
#: so it is the widening order and not merely a listing.
_INTEGER_WIDTHS: tuple[tuple[Ps1TypeName, int, int], ...] = (
    (_BYTE, 0, 0xFF),
    (_SBYTE, -0x80, 0x7F),
    (_INT16, -0x8000, 0x7FFF),
    (_UINT16, 0, 0xFFFF),
    (_INT32, *_INT32_RANGE),
    (_UINT32, 0, 0xFFFFFFFF),
    (_INT64, *_INT64_RANGE),
    (_UINT64, 0, 0xFFFFFFFFFFFFFFFF),
)

#: The range each integer type holds, which is what a cast to it is refused outside of. Built from
#: the same table the widening order is, so the two cannot come apart.
_INTEGER_RANGE: dict[Ps1TypeName, tuple[int, int]] = {
    name: (low, high) for name, low, high in _INTEGER_WIDTHS
}

#: The widths a shift masks its count by, from the *left operand's type* rather than from how large
#: its value happens to be. Only the two the mask is documented for are here; a shift over a narrower
#: left operand keeps that operand's type in the grid and is not computed, because what the count is
#: masked by there was never measured.
_SHIFT_WIDTHS = {_INT32: 32, _INT64: 64}

#: The grid's row for `$null`, which the capture collected under the one name that is not a type a
#: value can have.
_VOID = _type('System.Void')

#: Every type the grid has a row for, which is what a whole column of it is read over. A name the
#: resolver does not know is dropped rather than raised on: it would mean the capture covers a type
#: the collected tables do not, and reading one column short is a weaker answer where refusing to
#: import is no answer at all.
_GRID_TYPES = frozenset(
    resolved for resolved in map(resolve_type, operand_witnesses()) if resolved is not None
)

#: The operand types whose witnesses reach every outcome a cell over them has.
#:
#: A capture is a *lower* bound: it records what some values did. Reading a cell as *what this
#: operation produces* is an upper-bound claim, and no witness list proves one — it can only fail to
#: disprove it. So which cells may be read that way is declared, and the declaration is a
#: measurement rather than an argument. The whole grid was captured a second time with the extremes
#: the shipped witness list is missing — `[int64]::MinValue`, `[single]::MaxValue` and `::MinValue`,
#: `[double]::MinValue` and `::Epsilon`, `[decimal]::MinValue`, `[char]65535`, six more strings and
#: three more collections — and **390 of the 4096 binary cells moved**, 93 of them by gaining a
#: throw they had not recorded. Every one of the 390 carries an operand this set leaves out, which
#: is what makes it the right set rather than a hopeful one.
#:
#: What each exclusion costs is a cell, not a worry. `Byte + String` was `{Int32}` and is really
#: `{Int32, Int64, Decimal, Double}`, which is the `1 + '2147483648'` the type corpus measures as an
#: Int64 and this module used to answer `Int32` to. `Byte - Int64` was `{Int64}` and is really
#: `{Int64, Double}`. `UInt16 * Char` was `{Int32}` and is really `{Int32, Double}`. `Byte -
#: Decimal` and `Byte -band Single` were each recorded as never throwing and each throws.
#:
#: **A cell is the full cross-product of its two operands' witnesses**, which is what makes reading
#: one as an upper bound a two-way-exhaustive claim over the chosen values rather than a pairwise
#: assumption over them. `refinery/run-pwsh-operators.ps1` applies the operator to every `(l, r)`
#: with `l` from the left type's witness list and `r` from the right type's, so a cell over two
#: types in this set was measured at every combination those lists reach and not merely at each
#: value in turn. Without that the set would be claiming something the capture never tried.
#:
#: A `Double` is here although its own extremes are absent, because there is nothing for them to
#: reach: arithmetic never leaves a Double — it saturates to an infinity rather than widening or
#: throwing — and the second capture found no cell that a Double alone moves.
#:
#: The measurement is against the shipped resource, so regenerating it re-opens the question.
#: `test.lib.scripts.ps1.corpus.GRID_WITNESSES` is the ratchet that says so out loud, and
#: `GRID_WITNESS_GAPS` beside it carries the cell that convicts each type left out here.
_SPANNED = frozenset({
    _BOOLEAN,
    _BYTE,
    _DOUBLE,
    _INT16,
    _INT32,
    _SBYTE,
    _UINT16,
    _UINT32,
    _UINT64,
    _VOID,
})


#: What a kernel computes in. A `Decimal` is here because PowerShell has one and Python's is the
#: only faithful carrier for it; a `bool` because a comparison is an operation like any other; a
#: `str` because a conversion produces one and the `Ps1TypeName` the grid names is what tells a Char
#: from a one-character String.
#:
#: A `tuple` of facts is the collection a `+` or a `*` over one produces. It carries facts rather
#: than payloads for the reason `Ps1Constant` does: the elements keep the types they had, so a
#: collection of Chars stays one. `_stamped` has the arm that licenses it.
_Number = int | float | bool | decimal.Decimal | str | tuple['Ps1Fact', ...]

#: How long a collection an operator may build. A repetition's size is an operand rather than a
#: bound, so `@(1, 2) * 0xFFFFFFFF` is an allocation and not an answer; above this the operation is
#: declined and the caller keeps the expression it had. Matched to the bound the folding pass
#: already applies to a string repetition, so the two cannot disagree about what is too large.
_MAX_COLLECTION = 0x1000


class _Throws(Exception):
    """
    Raised by a kernel for an application that PowerShell answers by throwing, so that a throw is
    reported as one rather than as a refusal. The two are different answers: a throw is knowledge.

    `certain` is whether the throw was computed value-precisely — an overflow, a division by zero, a
    character out of range, a string the invariant numeric coercion cannot read — so that 5.1 is
    *guaranteed* to throw for the operands in hand. It defaults to `True` because every leaf that
    raises here is such a computation; the one exception is a string coercion the source numeral
    lexer declined, which over-rejects what 5.1 accepts (`1 + '1,000'` is 1001), so the two sites
    that raise for it pass `certain=False` unless `_coercion_rejects` confirms the reject.
    """

    def __init__(self, certain: bool = True):
        super().__init__()
        self.certain = certain


def apply(operator: str, left: Ps1Fact, right: Ps1Fact) -> Ps1Outcome:
    """
    What `left <operator> right` produces. The *type* comes from the measured grid in
    `refinery.lib.scripts.ps1.data`, never from a rule written here, and the *value* from a kernel
    that is checked against it: a computed value whose type is not one the grid recorded for that
    cell is refused rather than reported, because the grid is what a host did and the kernel is only
    what we believe.

    A cell that recorded a throw stops the kernel being consulted, unless every way that cell can
    throw is one the kernel checks for itself — see `_throws_are_modelled`. Without that exception a
    single throwing pair anywhere in a cell would cost every other pair in it its fold; with it, a
    throw the kernel cannot see is still never folded past.

    A value the kernel computed is answered without asking whether the witnesses span the operands,
    and the two halves of that survive the question the cell alone does not. The *throw*: of the
    cells the kernel computes in, the eight whose recorded silence about throwing is wrong are all a
    `Decimal` subtraction, which `_throws_are_modelled` already covers — measured against the second
    capture `_SPANNED` was found by. The *type*: an under-recorded set can only make `_stamped`
    refuse, because which promotion a pair takes is settled by their types, so the one thing their
    values decide is overflow, and an overflowed value leaves every candidate rather than landing in
    the wrong one.

    The operator is folded to lower case once, here, because PowerShell's are case-insensitive and
    a caller holding one out of a script holds whatever case was written. Doing it at the grid
    lookup alone left `-BAND` finding its cell and missing the kernel, which is a fold lost to a
    spelling.
    """
    operator = operator.lower()
    cell = binary_outcome(operator, *(_grid_type(left), _grid_type(right)))  # type: ignore[misc]
    if cell is None:
        return NOTHING
    if not cell.may_throw or _throws_are_modelled(operator, left, right):
        try:
            computed = _kernel(operator, left, right)
        except _Throws as throw:
            return Ps1Outcome(ALWAYS if throw.certain else MAYBE, UNKNOWN)
        if computed is not None:
            stamped = _typed_result(operator, computed, left, right, cell.types)
            if stamped is not UNKNOWN:
                return Ps1Outcome(NEVER, stamped)
    return _from_binary_cell(cell, _spans(left, right))


#: The operators whose result type the promotion decides rather than the grid. These are the five
#: 5.1 runs through its numeric promotion, and the only ones a cell is a worse answer for: a cell
#: over `Int32` and `UInt64` records `Decimal`, `Double` and `UInt64` together because the three are
#: what different *values* produced, and `_promotion` is what says which of them any given pair
#: takes. Every other operator keeps reading its type from the measurement.
_PROMOTED_OPERATORS = frozenset({'+', '-', '*', '/', '%'})


def _typed_result(
    operator: str,
    computed: _Number,
    left: Ps1Fact,
    right: Ps1Fact,
    candidates: frozenset[Ps1TypeName],
) -> Ps1Fact:
    """
    The fact a computed value carries. For an arithmetic application over two numbers that is the
    type the promotion answers in; for everything else it is the one the measured cell allows.

    The two are not alternatives that happen to agree. `0 - [uint64]::MaxValue` is measured a
    `Double` on the host and the cell holds `Decimal` beside it, so reading the cell answered a
    `Decimal` — a value of a type the operation never produced. A cell cannot do better, because
    what separates the two is the sign of the signed operand.

    An arithmetic pair the promotion does not cover falls back to the cell rather than being
    refused, so a String, a collection or a `Single` operand is answered exactly as before.
    """
    if operator in _PROMOTED_OPERATORS:
        promotion = _promotion(left, right)
        if promotion is not None:
            promoted = _promoted(computed, promotion)
            if promoted is not UNKNOWN:
                return promoted
    return _stamped(computed, candidates)


#: What `-bnot` complements at, keyed by the type of the operand it is given. The complement happens
#: at a width and keeps that width's type, and an operand that *has* an integer width keeps it,
#: floored at `Int32`: measured, `-bnot [byte]5` is the Int32 -6, `-bnot [uint32]7` the UInt32
#: 4294967288 and `-bnot 1L` the Int64 -2.
#:
#: **For an operand with no integer width of its own this is a floor and not the rule.** A `Char`, a
#: `Double`, a `Single`, a `Decimal`, a `String`, a `Boolean` and `$null` are converted first, and
#: 5.1 picks the width from the *value*: `-bnot 7.0` is the Int32 -8, but `-bnot 3000000000.0` is
#: the **UInt32** 1294967295 and `-bnot 5000000000.0` the Int64 -5000000001, each the narrowest
#: width that holds the number. Naming `Int32` here is safe because it is the narrowest rung: a
#: value that does not fit one makes `convert` throw and `apply_unary` refuse, so what the floor
#: costs is a fold and never an answer.
#:
#: A type absent here is one nothing measured a width for. A collection is not missing but refused:
#: `-bnot @(1, 2)` throws, and so does `-bnot 'abc'`, which is the conversion throwing rather than
#: the operator.
_BNOT_WIDTH: dict[Ps1TypeName, Ps1TypeName] = {
    _BOOLEAN: _INT32,
    _BYTE: _INT32,
    _CHAR: _INT32,
    _DECIMAL: _INT32,
    _DOUBLE: _INT32,
    _INT16: _INT32,
    _INT32: _INT32,
    _INT64: _INT64,
    _SBYTE: _INT32,
    _STRING: _INT32,
    _UINT16: _INT32,
    _UINT32: _UINT32,
    _UINT64: _UINT64,
    _VOID: _INT32,
}


def _negated(operand: Ps1Fact) -> Ps1Outcome:
    """
    What `- operand` produces, from the measured unary grid and a kernel checked against it.

    **A String is read as a numeral first, and the row the type comes out of is the numeral's own.**
    A coerced String keeps the type its spelling has — `'5L'` is an Int64 and `'1e3'` a Double, the
    same reading every arithmetic operand gets — and negating it produces that type: `- '1e3'` is
    the Double -1000, measured. The grid's `String` row names `Int32` alone because every witness
    spelled one, so reading *that* row would stamp `- '5L'` an Int32 where a host answers an Int64.
    A value stamped with a type the operation never had is what `_typed_result` keeps `apply` from
    doing; moving the lookup onto the coerced fact is the same refusal spelled for one operand.

    **A cell this cannot compute a value in is refused outright rather than answered with its
    type.** The unary capture is a witnessed lower bound like every other, and there is no spanning
    claim for the unary grid to license reading a cell as what the operation *does*.

    A collection reaches no number and `_negatable` refuses it, which is the answer its cell carries
    anyway: `- @()` raises a `MethodNotFound`, measured, and the row names no type at all.

    **The number is subtracted from zero rather than negated**, because that is what 5.1 runs: its
    compiler emits `- x` as the binary subtraction `0 - x` and has no unary arm for it at all. The
    two differ on one value and it is a value scripts hold — `0 - 0.0` is a positive zero where
    `-(0.0)` is a negative one, and a sign this domain invented travels into every quotient taken
    from it.

    A `Decimal` is subtracted like every other number, and by the same `_computed` a binary `-`
    reaches, so the one operation is computed one way. Negating through a sign flip instead would
    disagree with 5.1 on a zero: Python's `Decimal` has a signed zero, so it makes `- 0d` `-0` where
    a host writes `0`.

    The result reaches `_decimal_result` for the same reason every binary kernel result does: a
    number that has left the range a `Decimal` holds is the throw a host raises, one that has
    overflowed to an infinity is a value this domain does not carry, and one the type holds only a
    rounding of is not a value this can report.
    """
    coerced = _coerced_numeral(operand)
    if coerced is not None:
        if not isinstance(coerced, Ps1Constant):
            return Ps1Outcome(ALWAYS if _coercion_is_certain_reject(operand) else MAYBE, UNKNOWN)
        operand = coerced
    source = _grid_type(operand)
    cell = None if source is None else unary_outcome('-', source)
    if cell is None:
        return NOTHING
    number = _negatable(operand)
    if number is None:
        return NOTHING
    try:
        computed = _computed(operator_module.sub, 0, number)
    except _Throws as throw:
        return Ps1Outcome(ALWAYS if throw.certain else MAYBE, UNKNOWN)
    if computed is None:
        return NOTHING
    stamped = _stamped(computed, cell.types)
    return NOTHING if stamped is UNKNOWN else Ps1Outcome(NEVER, stamped)


def _negatable(operand: Ps1Fact) -> int | float | decimal.Decimal | None:
    """
    The number `- operand` negates, or `None` where this module computes nothing for it. `$null`
    negates as the integer zero, measured: `- $null` is the Int32 0.

    Everything else is the number a cast reads the value as, which is one reader rather than a
    second copy of it: a Boolean is its truth and a Char its code point there already, and the
    payload is checked against the type the fact carries rather than trusted.
    """
    if operand is NULL:
        return 0
    return _numeric_source(operand) if isinstance(operand, Ps1Constant) else None


def apply_unary(operator: str, operand: Ps1Fact) -> Ps1Outcome:
    """
    What `<operator> operand` produces.

    **Unary minus reads the measured grid**, exactly as `apply` reads the binary one: the *type* is
    what a host was observed to produce and the *value* comes from a kernel checked against it. The
    capture covers `-` over all sixteen operand rows, and the cells where it names two types are the
    ones the value decides between — `Int32` negates to an `Int32` or, where the result leaves that
    width, to a `Double`. Measured: `- 5` is the Int32 -5 and `- (-2147483648)` the Double
    2147483648, `- [uint32]1` the Double -1 and `- [char]65` the Int32 -65. `_stamped` is what picks
    among a cell's types by which of them holds the number, so nothing here states that rule twice.

    A String is negated by being read as a numeral first, which is where the `String` row's recorded
    throw comes from: `- '5'` is -5, `- ' 5 '` is -5, `- ''` is 0 and `- 'abc'` throws. That is the
    same coercion arithmetic performs, so the same reader sees it and the same throws are modelled.

    `-not` is absent because it is not this question: it negates a truth value, which `convert` to
    a `Boolean` already answers, and `is_truthy` is what asks.

    `-bnot` keeps a table of its own, `_BNOT_WIDTH`, because what it needs is not the result type
    but the *width the complement happens at*, and that is a different measurement. Reading the grid
    for its result type as well is recorded work, not done here.
    """
    operator = operator.lower()
    if operator == '-':
        return _negated(operand)
    if operator != '-bnot':
        return NOTHING
    source = _grid_type(operand)
    width = None if source is None else _BNOT_WIDTH.get(source)
    if width is None:
        return NOTHING
    converted = convert(operand, width)
    number = integer_of(converted.value)
    if converted.may_throw or number is None:
        return NOTHING
    low, high = _INTEGER_RANGE[width]
    complement = ~number
    return Ps1Outcome(NEVER, Ps1Constant(width, complement % (high + 1) if low == 0 else complement))


def _to_char_array(fact: Ps1Fact) -> Ps1Outcome:
    """
    What `[char[]] fact` produces: the `Char[]` whose elements are the characters of a String, or
    each element of a collection converted to a Char, or `UNKNOWN` where an element does not convert
    and the cast throws instead.

    A String is taken apart into its characters rather than converted whole — measured,
    `[char[]]'ABC'` is a `Char[]` of three, where `[char]'ABC'` throws — so it is the one operand
    read as a sequence of Chars directly. A collection is each of its elements asked of `convert` to
    a Char, so `[char[]](72, 73)` is `H`, `I` and `[char[]]@('AB')` throws where its element does.
    Any other operand is refused rather than guessed at: a scalar `Char[]` cast is a one-element
    array 5.1 builds but no measurement here covers, and `$null` and a nested collection each reach
    the tree through no fold, so a value for them would answer a question nothing asks.
    """
    if isinstance(fact, Ps1Constant) and fact.type == _STRING and isinstance(fact.payload, str):
        characters = tuple(Ps1Constant(_CHAR, one) for one in fact.payload)
        return Ps1Outcome(NEVER, Ps1Constant(_CHAR_ARRAY, characters))
    elements = _elements(fact)
    if elements is None:
        return NOTHING
    converted: list[Ps1Fact] = []
    for element in elements:
        outcome = convert(element, _CHAR)
        if outcome.may_throw or outcome.value is UNKNOWN:
            return Ps1Outcome(ALWAYS if outcome.certainly_throws else MAYBE, UNKNOWN)
        converted.append(outcome.value)
    return Ps1Outcome(NEVER, Ps1Constant(_CHAR_ARRAY, tuple(converted)))


def _enum_storage(enum: Ps1TypeName) -> Ps1TypeName | None:
    """
    The integer width an enum stores its ordinals in, read off its record's `value__` field, or
    `None` where the record names none of the domain's widths. It is what an integer is truncated
    to on its way into the enum and what an ordinal is read as on its way out.
    """
    storage = enum_storage(enum)
    width = None if storage is None else resolve_type(storage)
    return width if width in _INTEGER_RANGE else None


def _to_enum(fact: Ps1Fact, target: Ps1TypeName) -> Ps1Outcome:
    """
    What `[target] fact` produces for one of the `_FOLDABLE_ENUMS`, carried as a `Ps1Constant` of
    the enum whose payload is the ordinal.

    A String is matched against the member names, case-insensitively, and one that names no member
    is left alone rather than called a throw: 5.1 reads more spellings than that — a String of
    digits as an ordinal, a unique prefix as the member it abbreviates, surrounding whitespace
    trimmed away, and a comma-separated list as the members it combines, `'Stop,Continue'` being
    `Inquire` — and none of them is computed here, so a String that matches no name is one this
    cannot tell apart from one 5.1 accepts.

    An integer is stored at the enum's width first and checked against the members only then,
    because that is the order 5.1 does it in: `Enum.ToObject` boxes the low bits of the number and
    the defined-check reads the boxed value. Measured, `[ActionPreference]4294967297L` is `Stop`
    and `[ActionPreference]-4294967294` is `Continue`, where `6`, `300`, `-1` and `4294967295` —
    whose low word is the -1 no member holds — all throw. An ordinal no member holds after that
    truncation is a certain throw and not a value.
    """
    text = text_of(fact)
    if text is not None:
        ordinal = enum_ordinal(target, text)
        return NOTHING if ordinal is None else Ps1Outcome(NEVER, Ps1Constant(target, ordinal))
    number = integer_of(fact)
    storage = _enum_storage(target)
    if number is None or storage is None:
        return NOTHING
    ordinal = _truncated_at_width(_INTEGER_RANGE[storage], number)
    if enum_name(target, ordinal) is None:
        return Ps1Outcome(ALWAYS, UNKNOWN)
    return Ps1Outcome(NEVER, Ps1Constant(target, ordinal))


def _from_enum(fact: Ps1Constant, target: Ps1TypeName) -> Ps1Outcome:
    """
    What `[target] <enum>` produces: 5.1 reads an enum as its member name for a String and as the
    integer it is stored as for everything else, so a String is the name and every other target is
    `convert` asked of the ordinal at the enum's width — measured to agree for each: `[bool]` of
    `SilentlyContinue` is `$False`, `[byte]` of `High` is 3, `[char]` of `Continue` is the
    character 2 and `[double]` of `Stop` is 1. `_to_enum` mints no ordinal that names no member,
    so the name is always there to read; a fact whose payload is not an ordinal is malformed and
    answers nothing.
    """
    ordinal = ordinal_of(fact)
    storage = _enum_storage(fact.type)
    if ordinal is None or storage is None:
        return NOTHING
    if target == _STRING:
        name = enum_name(fact.type, ordinal)
        return NOTHING if name is None else Ps1Outcome(NEVER, Ps1Constant(_STRING, name))
    return convert(Ps1Constant(storage, ordinal), target)


def convert(fact: Ps1Fact, target: Ps1TypeName) -> Ps1Outcome:
    """
    What `[target] fact` produces, read from the measured conversion grid exactly as `apply` reads
    the binary one: the *type* is what a host was observed to produce and the *value* comes from a
    kernel checked against it.

    A cast throws where the value does not fit its target — measured, `[byte]300`, `[byte]-1`,
    `[int]2147483648`, `[char]65536` and `[char]-1` all throw rather than wrapping — and `_cast`
    raises for exactly that, so a cell that recorded a throw may still be computed where the target
    is one whose range the kernel checks. For any other target a recorded throw is one nothing here
    sees, and the cell answers alone.

    A `String` operand is read by rules of its own, in `_from_string`, and only the spellings those
    rules were measured over are computed: .NET parses a String by rules Python does not share, and
    5.1 has two of them that disagree with each other. Every other spelling reaches the grid for its
    type and stops there, which is `[int]'abc'` still being *an Int32 or a throw* — see
    `_from_conversion_cell` for why a cast may say that where an operator may not.

    A `char[]` target is answered by `_to_char_array` rather than the grid. The grid was captured
    over scalar targets, so it has no cell for an array one; but the result type of this cast is
    settled by what is written — always a `Char[]` — so the only thing the source decides is whether
    an element throws, which is `convert` to a Char asked of each. That is why it is the one target
    here whose row is composed rather than measured.

    An enum in `_FOLDABLE_ENUMS`, as the target or as the operand, is answered by `_to_enum` and
    `_from_enum` rather than the grid, which was captured over the scalar types and holds no cell
    for an enum. Those two are the deliberate exception to reading a cell: the rules they apply
    are 5.1's own for an enum without `[Flags]`, and the gate is what keeps them to the enums the
    rules were checked for.
    """
    if target == _CHAR_ARRAY:
        return _to_char_array(fact)
    if target in _FOLDABLE_ENUMS:
        return _to_enum(fact, target)
    if isinstance(fact, Ps1Constant) and fact.type in _FOLDABLE_ENUMS:
        return _from_enum(fact, target)
    source = _grid_type(fact)
    cell = None if source is None else conversion_outcome(target, source)
    if cell is None:
        return NOTHING
    if not cell.may_throw or _cast_throws_are_modelled(target):
        try:
            computed = _cast(target, fact)
        except _Throws as throw:
            return Ps1Outcome(ALWAYS if throw.certain else MAYBE, UNKNOWN)
        if computed is not None:
            stamped = _stamped(computed, cell.types)
            if stamped is not UNKNOWN:
                return Ps1Outcome(NEVER, stamped)
    outcome = _from_conversion_cell(cell, _spans(fact))
    if _string_cast_certainly_throws(fact, target):
        return Ps1Outcome(ALWAYS, outcome.value)
    return outcome


def evaluate(
    node: Node | None,
    type_of_variable: Ps1VariableTyping | None = None,
) -> Ps1Outcome:
    """
    What this expression produces. It is the module's one recursion and the only entry a caller
    holding a *tree* needs: `read`, `convert` and `apply` each answer about one step, and a consumer
    that walked the tree itself would be deciding at every node what is decided here once. A literal
    is `read`, a parenthesis is its inner, an array is its elements, a cast is `convert` over its
    operand, an operator is `apply` over both of its, and everything else carries whatever type the
    static surface names for it.

    It refuses far more than it answers, and that is the contract rather than a shortfall: for an
    expression another reader in this module can answer, this agrees with that reader or names
    nothing — never a third thing.

    A throw travels up. An operand that may throw makes the expression consuming it one that may
    throw, whatever the operation does with the value, and so does not knowing what the operand
    does, because `Ps1Outcome` reads its two fields in one direction.

    A type literal is refused rather than answered, which is the one place this deliberately says
    less than `resolve_expression_type`. That function answers `[int]` with `System.Int32` because
    what asks it is a member lookup, and the type a literal *names* is what a lookup needs; the
    value one *is* is a `System.RuntimeType`, and no measurement here covers it.

    A unary operator is `apply_unary`, which reads a grid of its own. A sign written against a
    numeral does not reach it — the parser puts that sign inside the numeral's spelling, so `-1` is
    a literal and `read` answers it; what reaches here is `- 1` with a space, and `- $x`.

    `type_of_variable` is what the caller can say about a variable occurrence, exactly as
    `resolve_expression_type` takes it. Nothing here invents a variable's value, so a variable the
    caller cannot type names nothing.

    **The answer for a node is remembered until some tree changes**, because being the one entry a
    caller with a tree needs is only affordable if it is. What asks this is a visitor descending the
    tree, and a visitor asks about a node's operand at the operand, then again at its parent, then
    again at *its* parent: the recursion below is proportional to the subtree, so the walk as a
    whole is quadratic in the depth of an expression, and a chain of two hundred operands the pass
    refuses to fold is where that stops being theoretical. What is remembered is keyed on the node's
    identity, and the whole table is dropped the moment `refinery.lib.scripts.mutation_epoch` moves
    — so an entry can only ever be read back over the same tree that produced it, and this stays a
    function of its arguments.

    **Only the query that types no variable is remembered**, which is the one that descent makes. A
    caller-supplied typing is state this module does not own: two callers that type an occurrence
    differently may not share an answer, so an entry would have to be keyed on the callable, which
    is comparable only by identity — and a bound method fails that against itself, so the table
    would be written and never read. Keeping one alive to compare against is worse than useless: a
    typing reaches the pass that wrote it and so the tree, and a table whose keys are weak so that a
    tree it answered for can be collected would then hold that tree through its own values.
    """
    if node is None:
        return NOTHING
    if type_of_variable is not None:
        return _evaluated(node, type_of_variable)
    global _EVALUATED_AT
    epoch = mutation_epoch()
    if epoch != _EVALUATED_AT:
        _EVALUATIONS.clear()
        _EVALUATED_AT = epoch
    remembered = _EVALUATIONS.get(node)
    if remembered is not None:
        return remembered
    outcome = _evaluated(node, None)
    if mutation_epoch() == epoch:
        _EVALUATIONS[node] = outcome
    return outcome


#: What `evaluate` has already answered for a node, and the mutation counter those answers stand on.
#: The counter is one number for the whole table rather than one per entry because it invalidates
#: every entry at once, and the table is emptied rather than left to be stepped over. Keys are weak
#: so that a tree nothing else holds is still collected; nothing here refers back to one.
_EVALUATIONS: WeakKeyDictionary[Node, Ps1Outcome] = WeakKeyDictionary()
_EVALUATED_AT = -1


def certainly_throws(node: Node) -> bool:
    """
    Whether evaluating `node` is guaranteed to raise a terminating error under every runtime state
    consistent with what is known — the must-throw dual of `is_fault_free`'s cannot-throw, and the
    opposite polarity from `may_throw`. `False` is *not knowing*, never a claim of safety: an
    expression this cannot prove throws answers `False` exactly as one that provably cannot does, so
    a caller must read this only where a false positive is the cost it cannot pay and a false
    negative merely declines to act.

    **The value domain is the one that knows**, and this reads its `ALWAYS`: a leaf is certain only
    where a value-precise computation on concrete operands reaches a throw 5.1 also takes — an
    overflow, a division by zero, a String the invariant coercion cannot read — never from the
    measured grid, which is a witnessed lower bound. An unknown operand makes the outcome `MAYBE`
    (the domain answers `UNKNOWN` for an unread variable rather than reading it as `$null`), so
    `[int]$x` is never certain and nothing built on this ever fires on a guessed value.

    **A `throw` statement is the one certain throw that is not a value**: reaching it transfers
    control abnormally whatever its argument is, so it answers `True` directly. Everything else is
    the expression's outcome — including a statement the value domain names nothing for, which is
    `MAYBE` and so `False`.
    """
    if isinstance(node, Ps1ThrowStatement):
        return True
    return evaluate(node).certainly_throws


def statement_certainly_throws(stmt: Node) -> bool:
    """
    Whether *stmt* is proven to raise a terminating error under every state. A `throw` is one
    whatever its argument; every other statement is read through
    `refinery.lib.scripts.ps1.ast.fault_operand`, so a `$Null =`/`[Void]` discard is judged by what
    it evaluates — `$Null = [Int]'abc'` throws in the cast before the assignment `certainly_throws`
    would otherwise read nothing certain in. The statement-level dual `deadcode` and `errorstate`
    both read, so the certain-raise judgment has one home.
    """
    if certainly_throws(stmt):
        return True
    operand = fault_operand(stmt)
    return operand is not None and certainly_throws(operand)


def _evaluated(
    node: Node,
    type_of_variable: Ps1VariableTyping | None,
) -> Ps1Outcome:
    """
    `evaluate` itself, with the remembering stripped off. Every recursive step goes back through
    `evaluate` rather than calling this directly, because an operand asked about here is the same
    operand a caller asks about on its own, and the two must share what they found.
    """
    literal = read(node)
    if literal is not UNKNOWN:
        return Ps1Outcome(NEVER, literal)
    if isinstance(node, Ps1ParenExpression):
        return evaluate(node.expression, type_of_variable)
    if isinstance(node, (Ps1ArrayLiteral, Ps1ArrayExpression)):
        return _array(node, lambda element: evaluate(element, type_of_variable))
    if isinstance(node, Ps1SubExpression):
        return _subexpression(node, lambda element: evaluate(element, type_of_variable))
    if isinstance(node, Ps1CastExpression):
        return _evaluated_cast(node, type_of_variable)
    if isinstance(node, Ps1BinaryExpression):
        return _evaluated_binary(node, type_of_variable)
    if isinstance(node, Ps1UnaryExpression):
        return _evaluated_unary(node, type_of_variable)
    if isinstance(node, Ps1TypeExpression) or not isinstance(node, Expression):
        return NOTHING
    named = resolve_expression_type(node, type_of_variable)
    return NOTHING if named is None else Ps1Outcome(MAYBE, Ps1Typed(named))


def _evaluated_cast(
    node: Ps1CastExpression,
    type_of_variable: Ps1VariableTyping | None,
) -> Ps1Outcome:
    """
    A cast, which is `convert` over whatever its operand evaluates to.

    An operand that names no type at all is the one case `convert` cannot be asked about, because
    the grid it reads is indexed by the source's type and there is no row to look in. Only there
    does the cast answer on its own, and what it answers is its target — naming one is what a cast
    does, so `[int] $s` is an Int32 or it throws whatever `$s` holds. Which targets that is true of
    is read off the grid rather than assumed; see `_cast_names`.

    Anywhere else `convert` has the last word, including where it names no value: `[byte] 300`
    throws for the value in hand, which is a stronger thing to know than *a Byte or a throw*, and
    reaching for the target there would trade it away.
    """
    target = resolve_type(node.type_name)
    if target is None:
        return NOTHING
    operand = evaluate(node.operand, type_of_variable)
    if operand.value is not UNKNOWN:
        converted = convert(operand.value, target)
        return Ps1Outcome(_throw_join(operand.throws, converted.throws), converted.value)
    named = _cast_names(target)
    return NOTHING if named is None else Ps1Outcome(_throw_join(operand.throws, MAYBE), named)


def _evaluated_unary(
    node: Ps1UnaryExpression,
    type_of_variable: Ps1VariableTyping | None,
) -> Ps1Outcome:
    operand = _operand(node.operand, type_of_variable)
    applied = apply_unary(node.operator, operand.value)
    return Ps1Outcome(_throw_join(operand.throws, applied.throws), applied.value)


#: The operators that may not evaluate their right operand at all, so a certain throw standing there
#: is not certain for the whole expression. These are the only two 5.1 short-circuits — `? :` and
#: `??` are 5.1 parse errors and never reach here.
_SHORT_CIRCUIT = frozenset({'-and', '-or'})


def _evaluated_binary(
    node: Ps1BinaryExpression,
    type_of_variable: Ps1VariableTyping | None,
) -> Ps1Outcome:
    """
    An operator, which is `apply` over both of its operands.

    A short-circuiting operator is answered here rather than excepted, and its right operand's throw
    axis is capped on purpose. `-and` and `-or` are measured, so `apply` has a cell for them; what no
    cell can carry is that the right operand may never run at all. So a right operand that is a
    *certain* throw is not one for the whole expression — `$false -and (1 / 0)` answers `$false` on
    the host and cannot throw — which is why `_demoted_throw` caps its `ALWAYS` at `MAYBE`. The
    may-throw side still over-claims there (a throw reported for a fold rather than dropped), which is
    a fold refused and never a wrong answer; reading the left operand alone where it settles the
    result is a fold this does not take. Every other operator evaluates both operands eagerly, so an
    operand's certain throw is the whole expression's.
    """
    left = _operand(node.left, type_of_variable)
    right = _operand(node.right, type_of_variable)
    applied = apply(node.operator, left.value, right.value)
    right_throws = right.throws
    if node.operator.lower() in _SHORT_CIRCUIT:
        right_throws = _demoted_throw(right_throws)
    return Ps1Outcome(
        _throw_join(left.throws, right_throws, applied.throws), applied.value)


def _operand(
    node: Node | None,
    type_of_variable: Ps1VariableTyping | None,
) -> Ps1Outcome:
    """
    What an operand of an operator produces, which is `evaluate` over it except where `read_operand`
    says a numeral standing there loses the places it was written with.
    """
    numeral = _folded_numeral(node)
    if numeral is not None:
        return Ps1Outcome(NEVER, numeral)
    return evaluate(node, type_of_variable)


@functools.cache
def _cast_names(target: Ps1TypeName) -> Ps1Fact | None:
    """
    The type a cast to `target` produces whatever it is given, or `None` where it does not always
    produce one. A cast is the one operation whose result type is settled by what was written rather
    than by what the operand held, which makes this the only thing the domain can say about a value
    it knows nothing about — and it is read off the grid's whole column rather than assumed, because
    `[array] $null` is `$null`, measured, so `[array]` is the one target a value passes through
    untouched and therefore the one that names no type.

    A source row that only ever threw contributes no type and contradicts none: `[char] @(1, 2)`
    throws, and `[char] $x` is a Char or a throw all the same.
    """
    named: set[Ps1TypeName] = set()
    for source in _GRID_TYPES:
        cell = conversion_outcome(target, source)
        if cell is None or cell.may_be_null:
            return None
        named |= cell.types
    return Ps1Typed(next(iter(named))) if len(named) == 1 else None


def _cast_throws_are_modelled(target: Ps1TypeName) -> bool:
    """
    Whether every way the grid recorded a cast to `target` throwing is one `_cast` checks for
    itself. A cast to an integer type or to a `Char` throws when the value does not fit, which is
    the range `_cast` refuses; a cell for any other target that recorded a throw threw for a reason
    nothing here models.
    """
    return target in _INTEGER_RANGE or target == _CHAR


def _collection_is_true(elements: tuple[Ps1Fact, ...]) -> bool | None:
    """
    Whether a collection counts as true, or `None` where this cannot say.

    How many elements it holds decides it, and only a collection of exactly one asks what is inside.
    Measured: `@()` is `$False`, `@(0, 0)` is `$True` although both of its elements are zero, and
    `@(0)` is `$False` because a collection of one is as true as the thing it holds.
    """
    if len(elements) != 1:
        return len(elements) > 0
    return _element_is_true(elements[0])


def _element_is_true(fact: Ps1Fact) -> bool | None:
    """
    Whether the single element of a one-element collection counts as true, or `None` where this
    cannot say.

    **This is not the same question as `[bool]` of that element**, and two measured pairs say so:
    `(,[char]0)` is `$True` where `[char]0` is `$False`, and `(,(,0))` is `$True` where `(,0)` is
    `$False`. 5.1 reaches a different function here, one with no `Char` arm at all — so every Char
    is true to it — and one that answers a collection by whether it holds anything rather than by
    asking this question again.

    Everything else is the ordinary conversion, which is why this asks `convert` for it rather than
    spelling a second copy of it out — measured, `(,$VerbosePreference)` is `$False` exactly as the
    member it holds is.

    An element that is not a value is refused rather than guessed at. A collection's payload does
    not guarantee its elements are values — `@() + (0 -shl $true)` holds a type and no value — and
    reporting such an element as true would be a guess.
    """
    if fact is NULL:
        return False
    if not isinstance(fact, Ps1Constant):
        return None
    nested = _elements(fact)
    if nested is not None:
        return len(nested) >= 1
    if fact.type == _CHAR:
        return True
    truth = convert(fact, _BOOLEAN)
    if truth.may_throw or not isinstance(truth.value, Ps1Constant):
        return None
    return truth.value.payload if isinstance(truth.value.payload, bool) else None


def _cast(target: Ps1TypeName, fact: Ps1Fact) -> _Number | None:
    """
    The value a cast produces, or `None` where this module computes nothing for it.

    A `Char` is a number to everything that reads one — `[int][char]65` is 65, measured — and it is
    a value to everything that renders one, `[string][char]65` being `A`. It is fed to `Boolean` as
    that number and to no other remaining target: `[bool][char]0` is `$False` and `[bool][char]65`
    and `[bool][char]'0'` are `$True`, all measured, which is the code point against zero and so is
    what the number already answers. The rest still have no row and are still refused.

    A real is rounded half to even on its way to an integer, which is what a host does rather than
    what a truncation would: `[int]1.5` and `[int]2.5` are both 2, `[int]1.4` is 1 and `[int]-1.5`
    is -2, all measured.

    A `Double` reaches `String` through `_double_text` but not `Decimal`: widening one to a Decimal
    through Python would carry the binary expansion of a value the host converts by its decimal digits.

    A `String` is read by `_from_string`, which is a different oracle from every other source and
    reaches only the targets whose throws this module already sees.

    `$null` converts as the zero of whatever it is cast to, which is the same thing `_kernel` makes
    of it in an arithmetic context and is measured here for every target the domain names:
    `[int]$null` and `[decimal]$null` are zero, `[char]$null` is the NUL character and `[bool]$null`
    is `$False`, each of them what the same cast of `0` produces. The one exception is `String`,
    where `[string]$null` is empty and `[string]0` is `0` — an absent value writes nothing, and the
    zero it computes as is not a zero it renders as.
    """
    if fact is NULL:
        return '' if target == _STRING else _cast(target, Ps1Constant(_INT32, 0))
    if not isinstance(fact, Ps1Constant):
        return None
    if target == _STRING:
        return _rendered(fact)
    if fact.type == _STRING and isinstance(fact.payload, str):
        return _from_string(target, fact.payload)
    if target == _BOOLEAN:
        elements = _elements(fact)
        if elements is not None:
            return _collection_is_true(elements)
    number = _numeric_source(fact)
    if number is None:
        return None
    if target == _BOOLEAN:
        return number != 0
    if target == _CHAR:
        rounded = _rounded(number)
        return None if rounded is None else _character(rounded)
    if target in _INTEGER_RANGE:
        rounded = _rounded(number)
        return None if rounded is None else _within(_INTEGER_RANGE[target], rounded)
    if fact.type == _CHAR:
        return None
    if target == _DOUBLE:
        return float(number)
    if target == _DECIMAL and not isinstance(number, float):
        return decimal.Decimal(number)
    return None


#: The whitespace a cast strips off a String before reading a number out of it. Measured: `' 5 '`,
#: a leading or trailing tab, a carriage return and a newline each convert to 5. A string of nothing
#: but whitespace is not the empty one — `[int]''` is 0 and `[int]'   '` throws — so this trims a
#: text that has something in it and never decides what an empty one is.
_CAST_TRIM = ' \t\r\n'

#: The two spellings a cast reads a number out of a String by, which are not the spellings a numeral
#: has in source. Measured: a plain decimal with an optional sign and an optional fraction converts
#: (`[int]'007'` is 7, `[int]'7.5'` is 8, `[int]'.5'` is 0, `[int]'5.'` is 5, `[int]'+7'` is 7), and
#: a hexadecimal one without a sign converts (`[byte]'0x80'` is 128).
#:
#: Everything else this module refuses rather than reads, because the two oracles 5.1 has for a
#: String disagree and neither is Python's. `[int]'1e3'` is 1000 and `[byte]'1e3'` throws, while
#: `1 + '1e3'` is the Double 1001; `[int]'1kb'` throws although `'1kb' * 1` is 1024; and
#: `[int]'1_0'`, `[int]'0b1010'` and `[int]'0o17'` throw where Python's own `int` reads all three.
_CAST_DECIMAL = re.compile(r'[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)\Z')
_CAST_HEX = re.compile(r'0[xX][0-9a-fA-F]+\Z')


def _from_string(target: Ps1TypeName, text: str) -> _Number | None:
    """
    The value a cast of the String `text` to `target` produces, or `None` where this module computes
    nothing for it.

    The targets are the ones whose every throw `convert` already sees, so that reading a String is
    not also a claim about what else the cast might do: an integer width and a `Char` throw when the
    value does not fit, which is checked here, and a `Boolean` does not throw at all. A `Double`,
    a `Single` or a `Decimal` from a String is left to the grid, which answers *that type or a
    throw* — the parse that would be needed there accepts an exponent and a thousands separator,
    and what the host does with one that overflows was not measured.

    A `Boolean` is `False` for the empty String and `True` for every other, `'0'`, `'False'` and
    `' '` included: it is the length that decides and never the text. A `Char` is the one character
    a one-character String holds and a throw for every other length, `''` included.

    A number is read at the *target's* width rather than at its own, which is what makes a
    hexadecimal String a bit pattern: measured, `[byte]'0x80'` is 128 and `[sbyte]'0x80'` is -128,
    `[uint16]'0xFFFF'` is 65535 and `[int]'0xFFFFFFFF'` is -1, and one digit more than the width
    holds throws — `[byte]'0x100'` does. A decimal String is not a pattern and keeps its sign, so
    `[byte]'-1'` throws where `[byte]'0x80'` does not.
    """
    if target == _BOOLEAN:
        return text != ''
    if target == _CHAR:
        if len(text) != 1:
            raise _Throws
        return text
    bounds = _INTEGER_RANGE.get(target)
    if bounds is None:
        return None
    if not text:
        return 0
    digits = text.strip(_CAST_TRIM)
    if _CAST_HEX.match(digits):
        return _pattern_at_width(bounds, int(digits[2:], 16))
    if not _CAST_DECIMAL.match(digits):
        return None
    rounded = _rounded(decimal.Decimal(digits))
    return None if rounded is None else _within(bounds, rounded)


def _pattern_at_width(bounds: tuple[int, int], magnitude: int) -> int:
    """
    The value a bit pattern of `magnitude` denotes in a register of the width `bounds` describes,
    with the sign that width has. A pattern too wide for the register is a throw rather than a
    truncation.
    """
    low, high = bounds
    span = high + 1 if low == 0 else (high + 1) * 2
    if magnitude >= span:
        raise _Throws
    return magnitude if magnitude <= high else magnitude - span


def _truncated_at_width(bounds: tuple[int, int], number: int) -> int:
    """
    The value the low bits of `number` denote in a register of the width `bounds` describes, with
    the sign that width has: the truncation a store into a narrower field performs, where
    `_pattern_at_width` is the reading that refuses a pattern too wide for the register.
    """
    low, high = bounds
    span = high + 1 if low == 0 else (high + 1) * 2
    return _pattern_at_width(bounds, number % span)


#: The shape of a String that 5.1's invariant numeric coercion can read a number out of, made a
#: *superset* of what 5.1 truly accepts so that a String this does NOT match is one 5.1 is certain to
#: reject. It is deliberately not the source numeral lexer `_numeral`, which rejects `'1,000'` where
#: 5.1 reads 1000, so a reject decided by that would over-claim a throw. Measured, the coercion
#: accepts a sign, thousands separators, a fraction and an exponent (`[int]'1e3'` is 1000,
#: `[int]'1,000'` is 1000, `[int]'3.9'` is 4). Being a superset is the load-bearing property: it may
#: match a String 5.1 rejects (a missed throw, sound), but it must match every String 5.1 accepts,
#: or a throw would be claimed for a value that converts.
_COERCION_NUMERIC = re.compile(r'[+-]?[0-9,]*\.?[0-9]*(?:[eE][+-]?[0-9]+)?\Z')

#: The hex spellings 5.1's integer cast reads through its .NET converter, which the decimal grammar
#: above does not carry: a `0x`, `&h` or `#` prefix on hex digits. Measured, `[int]'0xFF'`,
#: `[int]'&hFF'` and `[int]'#FF'` are each 255, so a certain throw must never be claimed for one —
#: the value path (`_from_string`) still computes only the `0x` form, which is a sound recall gap.
_COERCION_HEX = re.compile(r'(?:0[xX]|&[hH]|#)[0-9a-fA-F]+\Z')


def _coercion_rejects(text: str) -> bool:
    """
    Whether 5.1 is *certain* to throw reading a number out of the String `text` — a positive
    under-approximation used only to sharpen a throw from *may* to *must*, never to license a fold.
    `True` only where no invariant numeric coercion can read `text`; an empty or all-whitespace
    String, one that looks numeric, or a hex bit pattern answers `False` — 5.1 may accept it, so
    no throw is claimed. Measured rejects: `'abc'`, `'1_0'`, `'0b10'`, `'1kb'`, `'5L'`. Measured
    non-rejects: `'1e3'`, `'1,000'`, `'3.9'`, `'0x10'`, `'&hFF'`, `'#FF'`, `''`.

    Whitespace is stripped with `str.strip` rather than `_CAST_TRIM`, because 5.1's cast trims a
    String with the culture-aware `String.Trim` before reading it: a vertical tab, a form feed and a
    non-breaking space all convert to the number they wrap, where `_CAST_TRIM` would leave them and
    this would reject it. Stripping a *superset* of what 5.1 strips is the sound direction: it can
    only decline to claim a throw, never invent one.

    Position is not this predicate's concern and is settled before it: a String on the left of `+`
    or `*` concatenates or repeats and never coerces, so `'abc' + 1` and `'abc' * 2` reach no caller
    of this. Context is settled by which caller reaches it: a cast asks it for the spellings the
    value path declined, and arithmetic only for the ones the numeral lexer declined — which is why
    `[int]'1kb'` throws (the lexer's multiplier is not a cast's) while `1 + '1kb'` is 1025 (the lexer
    reads it, so this is never asked).
    """
    trimmed = text.strip()
    if not trimmed or _COERCION_HEX.match(trimmed):
        return False
    return _COERCION_NUMERIC.match(trimmed) is None


def _coercion_is_certain_reject(fact: Ps1Fact) -> bool:
    """
    Whether `fact` is a String an arithmetic or bitwise coercion is certain to throw on. The kernel
    already knows this operand is the one being coerced to a number, so this only has to decide the
    spelling; see `_coercion_rejects`.
    """
    return (
        isinstance(fact, Ps1Constant)
        and fact.type == _STRING
        and isinstance(fact.payload, str)
        and _coercion_rejects(fact.payload)
    )


def _string_cast_certainly_throws(fact: Ps1Fact, target: Ps1TypeName) -> bool:
    """
    Whether `[target] fact` is a String-to-integer cast 5.1 is certain to throw on. The value path
    (`_from_string`) declines such a String rather than computing it, so the cell answers *an
    integer or a throw*; this is what sharpens that *may* to a *must*. It is confined to an integer
    target because those are the ones whose reject `_coercion_rejects` was measured against — a Char
    cast throws by length, which `_from_string` already raises for, and every other target is left
    to the cell.
    """
    return target in _INTEGER_RANGE and _coercion_is_certain_reject(fact)


def _numeric_source(fact: Ps1Constant) -> int | float | decimal.Decimal | None:
    """
    The number a cast reads this value as, or `None` for a value no cast here computes from. The
    payload is checked against the type the fact carries rather than trusted, because the two are
    only ever built together here and a mismatch is a defect rather than a case.
    """
    payload = fact.payload
    if fact.type == _BOOLEAN and isinstance(payload, bool):
        return int(payload)
    if fact.type in _INTEGER_RANGE and isinstance(payload, int):
        return payload
    if fact.type == _CHAR and isinstance(payload, str) and len(payload) == 1:
        return ord(payload)
    if fact.type == _DECIMAL and isinstance(payload, decimal.Decimal):
        return payload
    if fact.type == _DOUBLE and isinstance(payload, float):
        return payload
    return None


def sort_key(fact: Ps1Fact) -> tuple | None:
    """
    The key a value sorts by under `[Array]::Sort`, or `None` for a value whose order this module
    does not settle. A value orders by the number a cast reads it as, so a Char sorts by its code
    point, a Boolean with `$false` before `$true`, and the numeric widths by magnitude — every one of
    those orderings ordinal and culture-independent, the way `Comparer.Default` compares those types.

    A String is refused, because `[Array]::Sort` compares strings by the *current culture* and the
    culture the emitted script will run under is not knowable here. Measured on 5.1:
    `[string]::Compare('aa', 'z')` is negative under en-US and positive under da-DK, where `aa`
    collates as `å` after `z`, so `@('aa', 'z')` sorts one way on one host and the other way on
    another. This is the same reason `invariant_text` refuses a current-culture rendering rather than
    guessing one; `_numeric_source` names no number for a String, so the refusal needs no branch here.

    A NaN is refused: `_numeric_source` would hand back a payload that does not compare, and .NET
    sorts a NaN before everything. The guard is a defensive floor, because no NaN reaches here —
    PowerShell has no NaN literal, so `read` builds none. An infinite Double does reach (`1e400`
    reads as `+Infinity`) and orders by magnitude like any finite one, which is what 5.1 does.
    """
    if not isinstance(fact, Ps1Constant):
        return None
    number = _numeric_source(fact)
    if number is None or number != number:
        return None
    return (number,)


def _double_text(payload: float) -> str | None:
    """
    The text 5.1 writes a `Double` as, which is the default `Double.ToString()` of the .NET Framework
    PowerShell 5.1 runs on: fifteen significant digits rounded half to even, in fixed-point notation
    while the exponent stays inside them and scientific notation outside. That is C's `%.15g` once its
    `e` is raised to an `E`, the two agreeing on the rounding, the fixed/scientific threshold and the
    two-digit-minimum exponent. Measured: `[string]0.5` is `0.5`, `[string]1E20` is `1E+20`,
    `[string]0.0000001` is `1E-07`, and `[string]` of the Double `9223372036854775808` is
    `9.22337203685478E+18` — each the value `%.15g` gives.

    A negative zero is refused rather than guessed, its `0` and `-0` spellings not being measured, so a
    withheld fold stands in. A non-finite value never reaches a Double fact — `_finite` keeps it out —
    so it is refused here only defensively.
    """
    if payload != payload or payload in (INFINITY, -INFINITY):
        return None
    if payload == 0.0 and math.copysign(1.0, payload) < 0:
        return None
    return F'{payload:.15g}'.replace('e', 'E')


def _rendered(fact: Ps1Constant) -> str | None:
    """
    The text a cast to `String` produces. Measured: `[string]5` is `5`, `[string]$true` is `True`,
    `[string]10d` is `10`, `[string]1.50d` keeps its trailing zero and `[string][char]65` is `A`.
    A String is its own text, which is the identity `[string]'foo'` is.

    It is also the text a *concatenation* contributes the value, which is one question and not two:
    measured, `'a' + $true` is `aTrue` and `'a' + 1.50d` is `a1.50`, each the same as writing
    `[string]` against the operand. See `_concatenated`.

    A `Decimal` is written in plain notation rather than by `str`, which switches to an exponent
    wherever the number is spelled with a positive one: `[string]1e3d` is `1000` on the host, where
    `str` would give `1E+3`, a text no `Decimal` .NET writes ever takes.

    A `Double` is written by `_double_text`. That the cast is culture-invariant is what lets this
    module compute it — `[string]0.5` is `0.5` on every host — where the `ToString()` a Double answers
    is not, which is why `invariant_text` refuses one. An `Object[]` is absent for the reason that
    survives: a collection is separated by `$OFS`, which lives in the session.
    """
    if fact.type == _STRING:
        return fact.payload if isinstance(fact.payload, str) else None
    if fact.type == _DECIMAL:
        return format(fact.payload, 'f') if isinstance(fact.payload, decimal.Decimal) else None
    if fact.type == _DOUBLE:
        return _double_text(fact.payload) if isinstance(fact.payload, float) else None
    if fact.type in _INTEGER_RANGE or fact.type in (_CHAR, _BOOLEAN):
        return str(fact.payload)
    return None


def _rounded(number: int | float | decimal.Decimal) -> int | None:
    """
    The integer a number converts to, half to even, or `None` for one that has no integer at all.
    """
    if isinstance(number, int):
        return number
    try:
        return round(number)
    except (OverflowError, ValueError):
        return None


def _character(code: int) -> str:
    if not 0 <= code <= 0xFFFF:
        raise _Throws
    return chr(code)


def _within(bounds: tuple[int, int], value: int) -> int:
    low, high = bounds
    if not low <= value <= high:
        raise _Throws
    return value


def _grid_type(fact: Ps1Fact) -> Ps1TypeName | None:
    """
    The type a fact is looked up under in the grid. `$null` has none, and the capture recorded its
    row under `System.Void` — the one name in the grid that is not a type any value carries.
    """
    if fact is NULL:
        return _VOID
    return type_of(fact)


def _spans(*facts: Ps1Fact) -> bool:
    """
    Whether every operand is of a type the grid's witnesses reach every outcome of, so that the cell
    they index may be read as what the operation *does* rather than as what a capture *saw*. See
    `_SPANNED` for which types those are and what it took to find out.
    """
    return all(_grid_type(fact) in _SPANNED for fact in facts)


def _cell_value(cell) -> Ps1Fact:
    """
    The fact a cell's recorded outcomes name. One type and no `$null` beside it is a typed value;
    `$null` and no type at all is `$null`, which is a value and not an absence — `$null * 5` really
    is `$null`, and reading that cell as *unknown* would leave a caller to guess where a measurement
    had already answered. Anything wider names nothing, because a caller cannot act on a value that
    might be either of two types.
    """
    if not cell.types and cell.may_be_null:
        return NULL
    if len(cell.types) == 1 and not cell.may_be_null:
        return Ps1Typed(next(iter(cell.types)))
    return UNKNOWN


def _from_binary_cell(cell, spanned: bool) -> Ps1Outcome:
    """
    What a binary cell says on its own, with nothing computed from the values.

    An operator's result type is decided by the operands' values as much as by their types — that is
    the whole reason a cell is a set — so a cell whose operands the witnesses do not span is read as
    nothing at all. Not its type, which was measured to be a lower bound and not a bound; not its
    silence about throwing, which is a lower bound in the same way and is wrong in 93 cells; and not
    its `$null`, which is a claim about a value like any other.
    """
    if not spanned:
        return NOTHING
    return Ps1Outcome(_throws_from_cell(cell.may_throw), _cell_value(cell))


def _from_conversion_cell(cell, spanned: bool) -> Ps1Outcome:
    """
    What a conversion cell says on its own, which is more than a binary cell says, because a cast's
    result type is settled by what was *written*: a cast produces a value assignable to its target
    or it throws, whatever the operand held. Measured, and not assumed from the shape of a cast:
    every target's cells carry exactly that target, and the one exception is `[array]`, whose
    accelerator names an abstract type and whose cells carry the one concrete array type it builds.

    So a source the witnesses do not span keeps the type and loses what the witnesses were the only
    evidence for — that the cast cannot throw, and that it answers `$null`.
    """
    named = _cell_value(cell)
    if spanned:
        return Ps1Outcome(_throws_from_cell(cell.may_throw), named)
    return Ps1Outcome(MAYBE, named if isinstance(named, Ps1Typed) else UNKNOWN)


#: The .NET `TypeCode` each type the domain computes in carries. The numbers are not an ordering
#: this module chose: 5.1 promotes an arithmetic pair by taking the *larger of the two type codes*
#: and running the application in the arithmetic that code selects, so the ordinals are the rule.
#: `System.Void` has no entry because `$null` never reaches the promotion: `+` answers a null left
#: operand with the right one *as it stands*, and `*` answers it with null, both decided before any
#: promotion runs. `_promotion` refuses such a pair and the measured cell answers it.
#:
#: `System.Single` is absent although it has a code of 13, because no fact carries one: `render`
#: cannot spell a Single, so nothing reaches here with that type and an entry would be a rule about
#: a value this module never holds. A Single operand is refused by the lookup below, which is the
#: same answer it gets today.
_TYPE_CODE: dict[Ps1TypeName, int] = {
    _BOOLEAN: 3,
    _CHAR: 4,
    _SBYTE: 5,
    _BYTE: 6,
    _INT16: 7,
    _UINT16: 8,
    _INT32: 9,
    _UINT32: 10,
    _INT64: 11,
    _UINT64: 12,
    _DOUBLE: 14,
    _DECIMAL: 15,
}

#: The integer types whose values can be negative, which is the question the promotion asks when a
#: signed operand meets an unsigned one wide enough to need the answer.
_SIGNED_INTEGERS = frozenset({_SBYTE, _INT16, _INT32, _INT64})

#: What each arithmetic produces, and what it produces instead when the result leaves that type.
#: An integer arithmetic widens to a `Double` — never to a `Decimal`, whatever the grid cell holds,
#: because the widening is `(double)result` in every one of the four integer kernels. A `Decimal`
#: arithmetic does not widen at all: it raises, and the domain reports that as a throw.
_PROMOTED_RESULT: dict[str, tuple[Ps1TypeName, Ps1TypeName | None]] = {
    'int': (_INT32, _DOUBLE),
    'uint': (_UINT32, _DOUBLE),
    'long': (_INT64, _DOUBLE),
    'ulong': (_UINT64, _DOUBLE),
    'decimal': (_DECIMAL, None),
    'double': (_DOUBLE, None),
}


def _promotion(left: Ps1Fact, right: Ps1Fact) -> str | None:
    """
    Which arithmetic 5.1 runs `left <op> right` in, or `None` where the pair is not one this
    promotion covers.

    The larger of the two type codes selects it, with one question left to the values: where the
    wider operand is an unsigned integer and the other is a signed one, a *negative* signed value
    cannot be represented there, so the application widens instead — to `Int64` beside a `UInt32`
    and to `Decimal` beside a `UInt64`. That is the one place the answer depends on a value rather
    than a type, and it is why the measured grid cannot carry it: the cell over `Int32` and
    `UInt64` holds `Decimal`, `Double` and `UInt64` at once, and which of them a pair takes is
    settled here.
    """
    if left is NULL or right is NULL:
        # `$null` does not reach the promotion at all: `+` answers a null left with the *right
        # operand itself*, so `$null + $true` is the Boolean `$true` and not the integer 1, and `*`
        # answers a null left with null. Those are decided before any promotion runs, and the
        # measured cell already carries them.
        return None
    codes = []
    for fact in (left, right):
        # The promotion is over what a string *coerces to*, not over `String`: measured,
        # `1 + '2147483648'` is an Int64 and `1 + '1.5L'` is an Int64 3, because the numeral the
        # string spells is the operand the type codes are compared over.
        coerced = _coerced_numeral(fact)
        name = type_of(fact if coerced is None else coerced)
        code = None if name is None else _TYPE_CODE.get(name)
        if code is None:
            return None
        codes.append(code)
    top = max(codes)
    if top <= _TYPE_CODE[_INT32]:
        return 'int'
    if top == _TYPE_CODE[_UINT32]:
        return 'long' if _is_negative(left) or _is_negative(right) else 'uint'
    if top == _TYPE_CODE[_INT64]:
        return 'long'
    if top == _TYPE_CODE[_UINT64]:
        return 'decimal' if _is_negative(left) or _is_negative(right) else 'ulong'
    if top == _TYPE_CODE[_DECIMAL]:
        return 'decimal'
    return 'double'


def _is_negative(fact: Ps1Fact) -> bool:
    """
    Whether a signed integer operand carries a negative value. Only a signed integer is asked,
    because the promotion asks this of nothing else: an unsigned operand cannot be negative, and a
    floating or `Decimal` one is already wider than the question.
    """
    if not isinstance(fact, Ps1Constant) or fact.type not in _SIGNED_INTEGERS:
        return False
    return isinstance(fact.payload, int) and fact.payload < 0


def _promoted(value: _Number, promotion: str) -> Ps1Fact:
    """
    The fact an arithmetic produced, stamped with the type that arithmetic answers in rather than
    with one read out of a grid cell. An integer that has left its own range is the widening the
    kernel performs, and a `Decimal` that has left its range is not a fact at all — the host raises
    there, and `_decimal_result` has already reported it.
    """
    natural, widened = _PROMOTED_RESULT[promotion]
    if isinstance(value, bool):
        return Ps1Constant(_BOOLEAN, value)
    if isinstance(value, int) and natural in _INTEGER_RANGE:
        low, high = _INTEGER_RANGE[natural]
        if low <= value <= high:
            return Ps1Constant(natural, value)
        return UNKNOWN if widened is None else _double(value)
    if isinstance(value, decimal.Decimal):
        return Ps1Constant(_DECIMAL, value) if natural is _DECIMAL else UNKNOWN
    if isinstance(value, float):
        if natural is not _DOUBLE and widened is not _DOUBLE:
            return UNKNOWN
        return UNKNOWN if _finite(value) is None else Ps1Constant(_DOUBLE, value)
    return UNKNOWN


def _stamped(value: _Number, candidates: frozenset[Ps1TypeName]) -> Ps1Fact:
    """
    The fact a computed value has, given the types the grid recorded for the cell it came out of.

    A `Decimal` and a `Double` are stamped with themselves, and refused where the cell did not
    record that type: a computed `Decimal` reported as a `Double` would be a value the operation
    never had.

    An integer is stamped with the one integer candidate that holds it. *One* is the whole rule:
    where two of them do — a cell such as `SByte + UInt32`, whose outcome set holds both `Int64` and
    `UInt32` because which one a pair takes depends on the signs — nothing here can say which, and
    the value is refused rather than guessed. An integer no candidate holds takes `Decimal` or
    `Double` when the cell recorded one, which is the widening a host performs on overflow and the
    reason `2147483647 + 1` is a Double.

    **The dispatch is exhaustive on purpose, and a payload of a kind not named here is refused.** A
    catch-all `Double` arm would stamp a kernel returning a collection as
    `Ps1Constant(System.Double, (1, 2))`, a value of a type it is not, by the one function whose
    whole job is to refuse exactly that. This is the guard every new kernel arm is licensed by, so
    it has to fail closed for the kinds those arms will introduce.

    The final refusal is unreachable while `_Number` names no collection, and a type checker says
    so. That is the invariant rather than dead code: widening `_Number` is what a kernel arm over
    collections has to do first, and the refusal is what that widening then lands on until an arm
    here is written for the kind it added.
    """
    if isinstance(value, bool):
        return Ps1Constant(_BOOLEAN, value) if _BOOLEAN in candidates else UNKNOWN
    if isinstance(value, int):
        holders = [
            name for name, low, high in _INTEGER_WIDTHS
            if name in candidates and low <= value <= high
        ]
        if len(holders) == 1:
            return Ps1Constant(holders[0], value)
        if holders:
            return UNKNOWN
        if _DECIMAL in candidates and _DECIMAL_MIN <= value <= _DECIMAL_MAX:
            return Ps1Constant(_DECIMAL, decimal.Decimal(value))
        return _double(value) if _DOUBLE in candidates else UNKNOWN
    if isinstance(value, decimal.Decimal):
        return Ps1Constant(_DECIMAL, value) if _DECIMAL in candidates else UNKNOWN
    if isinstance(value, str):
        holders = [name for name in (_CHAR, _STRING) if name in candidates]
        return Ps1Constant(holders[0], value) if len(holders) == 1 else UNKNOWN
    if isinstance(value, float):
        return Ps1Constant(_DOUBLE, value) if _DOUBLE in candidates else UNKNOWN
    if isinstance(value, tuple):
        return Ps1Constant(_OBJECT_ARRAY, value) if _OBJECT_ARRAY in candidates else UNKNOWN
    return UNKNOWN


def _kernel(operator: str, left: Ps1Fact, right: Ps1Fact) -> _Number | None:
    """
    The value an application produces, or `None` where this module computes nothing for it. The
    arithmetic is computed only over operands that are integers of the domain's own widths, or a
    Decimal or a Double beside one: a String or a collection reaches the grid for its type and stops
    there, so that no arithmetic here is performed in a Python type that is not what PowerShell was
    using. The one thing a String does compute is `+`, which over a String or a Char left operand is
    a concatenation and not arithmetic at all — see `_concatenated`.

    `$null` computes as the integer zero, which is what a host converts it to in an arithmetic
    context: `10 - $null` is 10, `$null - 5` is -5 and `$null -band 1` is 0, all measured. It is the
    grid that decides whether the context is arithmetic at all, so a `$null` reaching an operator
    that does something else with it never gets here.

    A shift is computed only over an `Int32` or `Int64` left operand, because the count is masked by
    the *left operand's width* and only those two widths are documented. That the width comes from
    the type and not from how large the value happens to be is the point: a small value in a wide
    variable is still shifted at the wide mask.

    A bitwise operator is computed only over integers. PowerShell will bitwise a Double by rounding
    it first, which is a conversion, and a kernel that reached for Python's operators there would be
    performing a different one.
    """
    if operator in ('-shl', '-shr'):
        if not _is_domain_integer(left) or not _is_domain_integer(right):
            return None
        left_type = type_of(left)
        width = None if left_type is None else _SHIFT_WIDTHS.get(left_type)
        if width is None:
            return None
        count = _integer_payload(right) & (width - 1)
        return _shifted(_integer_payload(left), count, width, operator == '-shl')
    if operator in _BITWISE:
        operands = [_bitwise_operand(fact) for fact in (left, right)]
        if operands[0] is None or operands[1] is None:
            return None
        return _BITWISE[operator](operands[0], operands[1])
    if operator == '+':
        if _concatenates(left):
            return _concatenated(left, right)
        if left is NULL and isinstance(right, Ps1Constant):
            # `$null` on the left of `+` is answered with the right operand *as it stands*, so
            # `$null + @(1, 2)` is that collection and not a longer one — measured two elements,
            # where `@(1, 2) + $null` is three. Nothing is added and nothing is converted.
            return right.payload
    if _elements(left) is not None and operator in ('+', '*'):
        return _collected_operand(operator, left, right)
    if operator == '*' and _replicated(left):
        # A String on the left of `*` is repeated, not multiplied: `'5' * 2` is the String `55` and
        # not the number 10. Nothing here computes that repetition, so the pair is declined before
        # it can be read as arithmetic.
        return None
    if operator in _COMPARISON_SPELLINGS:
        elements = _elements(left)
        if elements is not None:
            return _filtered(operator, elements, right)
        return _compared(operator, left, right)
    if operator not in _NUMERIC_BINARY:
        return None
    operands = _numeric_pair(left, right)
    if operands is None:
        return None
    a, b = operands
    if operator == '/':
        if b == 0:
            return _divided_by_zero(b)
        if isinstance(a, int) and isinstance(b, int) and a % b == 0:
            return a // b
        if isinstance(a, decimal.Decimal) and isinstance(b, decimal.Decimal):
            quotient = _decimal_quotient(a, b)
            return None if quotient is None else _decimal_result(quotient)
        return _decimal_result(operator_module.truediv(a, b))
    if operator == '%':
        if b == 0:
            return _divided_by_zero(b)
        if isinstance(a, int) and isinstance(b, int):
            remainder = abs(a) % abs(b)
            return -remainder if a < 0 else remainder
        if isinstance(a, decimal.Decimal) and isinstance(b, decimal.Decimal):
            return _decimal_result(_decimal_remainder(a, b))
        return _finite(math.fmod(a, b))
    arithmetic = _ARITHMETIC.get(operator)
    return None if arithmetic is None else _computed(arithmetic, a, b)


def _divided_by_zero(divisor: _Number) -> _Number | None:
    """
    What dividing by a zero produces, which is not one answer: an integer or a `Decimal` divisor of
    zero throws, and a floating one does not. Measured on both counts — the `/` and `%` cells over
    `Int32` and over `Decimal` each recorded a throw, and the ones over `Double` and `Single`
    recorded none although `0.0` is among the witnesses the capture divided by.

    So a float names no value here rather than a throw: what a host produces is an infinity or a
    `NaN`, and `_finite` is where the domain says it does not carry one. Raising instead would have
    reported `1.5 / 0.0` as an operation that may throw, which is a claim about the one axis a
    caller acts on and it is false.
    """
    if isinstance(divisor, float):
        return None
    raise _Throws


#: The types a value is a text of. A `Char` is one of them wherever an operator's *left* operand
#: decides what the operation is: `'a' + 1` is the String `a1` and `[char]65 + 1` is `A1`, measured,
#: where `1 + 'a'` throws and `1 + [char]65` is the number 66. That a Char is a text on one side of
#: an operator and a number on the other is the whole of what makes the Char erasure a wrong *value*
#: rather than only a wrong type.
_TEXTUAL = (_STRING, _CHAR)


def _is_text(fact: Ps1Fact) -> typing.TypeGuard[Ps1Constant]:
    """
    Whether a fact is a text this module holds.
    """
    return isinstance(fact, Ps1Constant) and fact.type in _TEXTUAL


def _concatenates(fact: Ps1Fact) -> typing.TypeGuard[Ps1Constant]:
    """
    Whether a left operand of `+` joins text rather than adding, which is the counterpart of
    `_replicated` for the other operator its left operand decides.

    It is a question of its own rather than a line inside `_concatenated`, because whether a `+` joins
    text or adds is decided by the *left* operand alone, not by whether the tail can be spelled. A
    tail `_concatenated` declines — an `Object[]` the session's `$OFS` separates, a right operand that
    is not a constant — is still a concatenation, and reading its refusal as *this is not one* would
    let `'a' + @(1, 2)` fall through to the arithmetic, a wrong reading where a host joins the text.
    """
    return _is_text(fact)


def _concatenated(left: Ps1Constant, right: Ps1Fact) -> str | None:
    """
    The text `+` joins when its *left* operand is a String or a Char, or `None` where this module
    computes nothing for it. Which operands those are is `_concatenates`, which the caller has
    already asked.

    The right operand contributes what a cast of it to `String` would, `$null` contributing nothing:
    `'a' + $null` is `a`, measured. A value `_rendered` refuses is refused here for its own reason —
    an `Object[]` because `$OFS` separates it and lives in the session, a right operand that is not a
    constant because there is no value to spell.
    """
    head = _rendered(left)
    if head is None:
        return None
    if right is NULL:
        return head
    if not isinstance(right, Ps1Constant):
        return None
    tail = _rendered(right)
    return None if tail is None else head + tail


def _numeric_pair(left: Ps1Fact, right: Ps1Fact):
    """
    The two payloads as Python numbers that compute in the same way PowerShell's promoted pair does,
    or `None` where they do not. An integer beside a Decimal computes as a Decimal and an integer
    beside a Double as a Double, which is what the promotion does; a Decimal beside a Double is
    refused, because Python will not mix them and choosing one to convert would be performing the
    promotion rather than reading it.
    """
    kinds = []
    values: list[int | float | decimal.Decimal] = []
    for operand in (left, right):
        coerced = _coerced_numeral(operand)
        if coerced is not None:
            if not isinstance(coerced, Ps1Constant):
                raise _Throws(_coercion_is_certain_reject(operand))
            operand = coerced
        fact = operand
        if _is_domain_integer(fact):
            kinds.append('i')
            values.append(_integer_payload(fact))
            continue
        number = _char_code(fact)
        if number is None:
            number = _truth_value(fact)
        if number is not None:
            kinds.append('i')
            values.append(number)
            continue
        if not isinstance(fact, Ps1Constant):
            return None
        if fact.type == _DECIMAL and isinstance(fact.payload, decimal.Decimal):
            kinds.append('m')
        elif fact.type == _DOUBLE and isinstance(fact.payload, float):
            kinds.append('f')
        else:
            return None
        values.append(fact.payload)
    if 'm' in kinds and 'f' in kinds:
        return None
    if 'm' in kinds:
        return decimal.Decimal(values[0]), decimal.Decimal(values[1])
    if 'f' in kinds:
        return float(values[0]), float(values[1])
    return values[0], values[1]


def _decimal_remainder(a: decimal.Decimal, b: decimal.Decimal) -> decimal.Decimal:
    """
    `a % b` over two `Decimal`s, at the precision the intermediate quotient needs rather than the one
    the result does. Python reaches a remainder through that quotient and raises `InvalidOperation`
    where it does not fit the context, so the ambient 28 digits refuse `[decimal]::MaxValue % 1.5d` —
    measured a `Decimal` 0 on the host, and raised out of `apply` and into the caller here until this
    was given room. The remainder itself is smaller than the divisor and needs no room at all.
    """
    with decimal.localcontext(_DECIMAL_ARITHMETIC):
        return a % b


#: What an operation over two `Decimal`s has to be computed at. Python's operators are *context*
#: operations and the ambient precision is 28 digits, where a `System.Decimal` is a 96-bit
#: coefficient and holds 29: at the default context `79228162514264337593543950335d + 0d` rounds to
#: `79228162514264337593543950340`, a wrong value reported as a definite one, and moving
#: `decimal.getcontext().prec` moves it again. The room here is for the
#: *exact* result, so that what the type holds is decided by `_decimal_result` and
#: `_decimal_quotient` rather than by a rounding whose rule nothing here measured. Both operands are
#: inside the `Decimal` range, so a product is at most 58 digits, a sum at most 58 places, and the
#: intermediate quotient a remainder is reached through at most the largest over the smallest.
_DECIMAL_ARITHMETIC = decimal.Context(prec=120)


def _computed(
    arithmetic: Callable[[typing.Any, typing.Any], _Number],
    a: _Number,
    b: _Number,
) -> _Number | None:
    """
    An arithmetic result, with a `Decimal` operand computed at the precision the type has rather
    than the one the process happens to be set to. See `_DECIMAL_ARITHMETIC`.
    """
    if not isinstance(a, decimal.Decimal) and not isinstance(b, decimal.Decimal):
        return _decimal_result(arithmetic(a, b))
    with decimal.localcontext(_DECIMAL_ARITHMETIC):
        return _decimal_result(arithmetic(a, b))


def _decimal_result(value: _Number) -> _Number | None:
    """
    A computed number, with a `Decimal` that has left the range of a `Decimal` reported as the throw
    it is. Python carries such a value without complaint; .NET does not have it, so neither does the
    domain, and calling it a throw is what the host does rather than a refusal.

    A `Decimal` the type cannot hold *exactly* is refused instead. .NET rounds such a result to the
    96 bits and 28 places it has, by a rule no measurement here covers, so computing it at a
    precision that carries the exact answer and then reporting whatever Python's own rounding made
    of it would be a value of our invention. See `_holds_exactly`.
    """
    if isinstance(value, decimal.Decimal):
        if not value.is_finite():
            return None
        if not _DECIMAL_MIN <= value <= _DECIMAL_MAX:
            raise _Throws
        if not _holds_exactly(value):
            return None
    return _finite(value)


def _holds_exactly(value: decimal.Decimal) -> bool:
    """
    Whether a `System.Decimal` is the number this `Decimal` is, rather than a rounding of it. The
    type is a coefficient of at most 96 bits scaled by a power of ten between zero and twenty-eight,
    and both halves of that are asked here: a result computed at `_DECIMAL_ARITHMETIC`'s precision
    can carry more places than the type has, and one inside the range the caller already tested can
    still spell more digits than the coefficient holds — `9.9999999999999999999999999999` is smaller
    than a `Decimal`'s largest value and is not a `Decimal`.
    """
    spelling = value.as_tuple()
    if not isinstance(spelling.exponent, int) or spelling.exponent < -28:
        return False
    coefficient = 0
    for digit in spelling.digits:
        coefficient = coefficient * 10 + digit
    return coefficient <= _DECIMAL_MAX


#: The smallest step a `System.Decimal` takes, which is what a quotient the type cannot hold exactly
#: has to be rounded onto.
_DECIMAL_STEP = decimal.Decimal(1).scaleb(-28)


def _decimal_quotient(a: decimal.Decimal, b: decimal.Decimal) -> decimal.Decimal | None:
    """
    `a / b` over two `Decimal`s, or `None` where this module computes nothing for it.

    A quotient the type holds exactly is that quotient — measured, `79228162514264337593543950335d /
    1d` prints in full. One it does not is rounded onto the twenty-eight places the type has, which
    is what a host does with `1d / 3d` and its `0.3333333333333333333333333333`. Both are computed
    at `_DECIMAL_ARITHMETIC` rather than at the ambient precision: dividing under
    `decimal.getcontext()` made `1d / 3d` the number `0.3` in a process that had set `prec` to one,
    a wrong constant folded into a script by a setting that has nothing to do with PowerShell.

    **A quotient that lands exactly between two of those places is refused**, because which way .NET
    breaks that tie is not something anything here measured. Asking is cheap and exact: round it both
    ways, and answer only where the two agree, which is every quotient whose discarded remainder is
    not a half.
    """
    with decimal.localcontext(_DECIMAL_ARITHMETIC):
        exact = a / b
        if not _DECIMAL_MIN <= exact <= _DECIMAL_MAX:
            raise _Throws
        if _holds_exactly(exact):
            return exact
        down = exact.quantize(_DECIMAL_STEP, rounding=decimal.ROUND_HALF_DOWN)
        up = exact.quantize(_DECIMAL_STEP, rounding=decimal.ROUND_HALF_UP)
    return down if down == up else None


def _finite(value: _Number) -> _Number | None:
    """
    A computed number, unless it is one no literal spells. An overflow to infinity is a value
    PowerShell has and this domain deliberately does not carry, because every use of it downstream
    would have to refuse anyway and a fact that cannot be spelled is worse than no fact.
    """
    if isinstance(value, float) and (value != value or value in (INFINITY, -INFINITY)):
        return None
    return value


def _is_domain_integer(fact: Ps1Fact) -> bool:
    if fact is NULL:
        return True
    return isinstance(fact, Ps1Constant) and isinstance(fact.payload, int) and not isinstance(
        fact.payload, bool) and any(name == fact.type for name, _, _ in _INTEGER_WIDTHS)


def _integer_payload(fact: Ps1Fact) -> int:
    return 0 if fact is NULL else typing.cast(int, typing.cast(Ps1Constant, fact).payload)


#: What a string is trimmed of before it is read as a number, which is what 5.1 trims: `1 + ' 7 '`
#: is the Int32 8, measured.
_COERCE_TRIM = ' \t\r\n\v\f'


def _coerced_numeral(fact: Ps1Fact) -> Ps1Fact | None:
    """
    The number a `String` operand computes as in an arithmetic context, or `None` for a fact that
    is not a String, or `UNKNOWN` for one that spells no number.

    This is not `convert` to a numeric type and the two genuinely disagree: a coerced string is
    *re-lexed as a numeric literal*, so it keeps that literal's own type and honours the suffixes
    and multipliers a literal has. Measured: `1 + '1kb'` is the Int32 1025 and `1 + '1.5L'` is the
    Int64 3, neither of which a conversion to a named type produces. It is the same reading
    `_numeral` gives a literal in the source, which is what keeps one numeral rule in the module
    rather than two.

    Two things the literal reading does not do on its own. A string is trimmed first, and one that
    is empty or all whitespace is the integer zero rather than nothing — `1 + '  '` is 1. And an
    infinite Double is refused, because a literal may spell one and the coercion may not: measured,
    `1 + '1e400'` throws where `'1e400' + 1` joins text.
    """
    if not isinstance(fact, Ps1Constant) or fact.type != _STRING:
        return None
    if not isinstance(fact.payload, str):
        return UNKNOWN
    trimmed = fact.payload.strip(_COERCE_TRIM)
    if not trimmed:
        return Ps1Constant(_INT32, 0)
    read_as = _numeral(trimmed)
    if isinstance(read_as, Ps1Constant) and isinstance(read_as.payload, float):
        if _finite(read_as.payload) is None:
            return UNKNOWN
    return read_as


def _replicated(fact: Ps1Fact) -> bool:
    """
    Whether a left operand of `*` is repeated rather than multiplied.
    """
    return isinstance(fact, Ps1Constant) and fact.type in (_STRING, _OBJECT_ARRAY)


def _elements(fact: Ps1Fact) -> tuple[Ps1Fact, ...] | None:
    """
    The facts a collection holds, or `None` for one that is not a collection or does not name its
    elements.
    """
    if not isinstance(fact, Ps1Constant) or fact.type != _OBJECT_ARRAY:
        return None
    payload = fact.payload
    if not isinstance(payload, tuple) or not all(isinstance(one, Ps1Fact) for one in payload):
        return None
    return payload


def _collected_operand(operator: str, left: Ps1Fact, right: Ps1Fact) -> _Number | None:
    """
    What a collection on the left of `+` or `*` produces, or `None` where this declines to say.

    Measured: `@(1, 2) + @(3, 4)` is the four-element collection, `@(1, 2) + 5` the three-element
    one, and `@(1, 2) + $null` is **three** elements rather than two, because appending `$null`
    appends an element. `@(1, 2) * 2` repeats and `@(1, 2) * 0` is empty. The collection has to be
    on the left: `5 + @(1, 2)` and `2 * @(1, 2)` both throw, and their cells record it.

    **The repeat count is taken as an `Int32` and throws when it does not fit one.** Measured:
    `@() * [uint64]18446744073709551615` throws an `InvalidCastIConvertible`, where `@() * 5000` is
    the empty collection. The throw is the count's conversion and not the size of anything, which is
    why an empty left operand does not escape it: nothing repeated is nothing, and 5.1 still refuses
    the count before it can say so. `_MAX_COLLECTION` bounds what this builds and is a separate
    question — it bounds the *product*, which is zero for every count when there is nothing to
    repeat, so it is no bound at all here and never was the thing standing in the way.
    """
    elements = _elements(left)
    if elements is None:
        return None
    if operator == '+':
        tail = _elements(right)
        joined = elements + (tail if tail is not None else (right,))
        return None if len(joined) > _MAX_COLLECTION else joined
    if not _is_domain_integer(right):
        return None
    count = _within(_INTEGER_RANGE[_INT32], _integer_payload(right))
    if count < 0 or len(elements) * count > _MAX_COLLECTION:
        return None
    return elements * count


def _bitwise_operand(fact: Ps1Fact) -> int | None:
    """
    The integer a bitwise operator computes over, or `None` for an operand it does not reach one
    from. A Char is its code point and a String is the numeral it spells, both measured:
    `[char]48 -band [byte]255` is 48 and `'10' -band 6` is 2.
    """
    if _is_domain_integer(fact):
        return _integer_payload(fact)
    code = _char_code(fact)
    if code is not None:
        return code
    truth = _truth_value(fact)
    if truth is not None:
        return truth
    coerced = _coerced_numeral(fact)
    if coerced is None:
        return None
    if not isinstance(coerced, Ps1Constant):
        raise _Throws(_coercion_is_certain_reject(fact))
    return _integer_payload(coerced) if _is_domain_integer(coerced) else None


def _truth_value(fact: Ps1Fact) -> int | None:
    """
    The number a `Boolean` computes as, or `None` for a fact that is not one.

    Measured, a Boolean is an ordinary number to arithmetic: `$true + 1` is the Int32 2, `$false +
    1` is 1, `$true + $true` is 2 and `$true + 1.5` is the Double 2.5. The one operator it is not a
    number to is `*` with the Boolean on its *left* — `$true * 2` throws where `2 * $true` is 2 —
    and that is the cell's throw rather than a rule here, exactly as it is for a Char.
    """
    if not isinstance(fact, Ps1Constant) or fact.type != _BOOLEAN:
        return None
    return 1 if fact.payload else 0


def _char_code(fact: Ps1Fact) -> int | None:
    """
    The number a `Char` computes as, or `None` for a fact that is not one.

    A Char is a number to every operator but two, and the two are the ones that claim it first:
    `+` reads a Char *left* operand as text — `[char]65 + 1` is the String `A1` and `1 + [char]65`
    is the Int32 66, both measured — and `_concatenated` answers that before anything here is
    asked; `*` has no operator for a Char at all and its cell records the throw. Everywhere else
    the code point is the operand, which is what makes `[char]65 -bxor 32` the Int32 97 rather than
    a fold nobody takes.
    """
    if not isinstance(fact, Ps1Constant) or fact.type != _CHAR:
        return None
    return ord(fact.payload) if isinstance(fact.payload, str) and len(fact.payload) == 1 else None


def _shifted(value: int, count: int, width: int, left: bool) -> int:
    """
    A shift performed in a `width`-bit two's complement register, which is where PowerShell performs
    it: shifting left out of the register discards the bits rather than growing the number, and
    shifting right preserves the sign.
    """
    if not left:
        return value >> count
    span = 1 << width
    result = (value << count) & (span - 1)
    return result - span if result >= span >> 1 else result


#: The value a computed Double reaches on overflow, which the domain does not carry.
INFINITY = float('inf')


def _throws_are_modelled(operator: str, left: Ps1Fact, right: Ps1Fact) -> bool:
    """
    Whether the kernel can see, for these operands, every way the operator throws — so that a cell
    which recorded a throw somewhere may still be computed here.

    Division and remainder throw for a zero divisor and nothing else, and the divisor is in hand.
    Addition, subtraction and multiplication throw only where a `Decimal` result leaves the range of
    a `Decimal`, which `_decimal_result` raises for; over the other numeric types they do not throw
    at all, and a cell of theirs that recorded one is recording something this does not model.

    A `String` operand is the other case, and it is why these cells throw at all: a string reaching
    arithmetic is read as a numeral and one that spells no number raises — `16 + 'file'` throws and
    `1 + '5'` does not, out of the same cell. `_coerced_numeral` is what sees it, so the throw is
    modelled wherever that runs, which is every operator the kernel reads a number for. Without
    this the cell's recorded throw stops the kernel being consulted and every string in arithmetic
    is refused, including the ones the host answers.

    Neither licence is given where the operator throws for what its operands *are*, which is a throw
    no reading of their numbers can see; see `_throws_for_what_the_operands_are`.
    """
    if _throws_for_what_the_operands_are(operator, left, right):
        return False
    if operator in ('/', '%'):
        return True
    if operator == '*' and _elements(left) is not None:
        # The measured throw is the count's conversion rather than any size: a repeat count is taken
        # as an `Int32`, and `@() * [uint64]18446744073709551615` throws an
        # `InvalidCastIConvertible` for one that does not fit, an empty left operand included.
        # `_collected_operand` raises for exactly that count and declines every size it will not
        # build, so the kernel never answers where the host raises, which is what this gate asks; it
        # merely answers less.
        return True
    if _STRING in (type_of(left), type_of(right)):
        return operator in _ARITHMETIC or operator in _BITWISE
    if operator in _ARITHMETIC:
        return _DECIMAL in (type_of(left), type_of(right))
    return False


def _throws_for_what_the_operands_are(operator: str, left: Ps1Fact, right: Ps1Fact) -> bool:
    """
    Whether an operation throws for what its operands *are* rather than for the values they carry.
    Such a throw is invisible to a kernel that reads numbers out of them, so a cell that recorded
    one may not be computed in however well the conversions are modelled.

    Two are measured. A Boolean or a Char on the left of `*` has no multiplication at all — `$true *
    2` and `[char]48 * 2` both raise, where `2 * $true` is 2 and `2 * [char]48` is 96. And a Boolean
    on the left of a `Decimal` raises for `+`, `-`, `/` and `%` — `$true - 1.0d` throws where
    `1.0d - $true` is 0 and `$true - 1.5` is -0.5.

    Without this guard both reach the kernel on the licence the *other* operand gives: the String
    licence would make `[char]48 * '1'` the number 48 and the `Decimal` licence would make
    `$true - 1.0d` a `Decimal` zero, each a value standing where the host aborts the script.
    """
    if operator == '*':
        return type_of(left) in (_BOOLEAN, _CHAR)
    return type_of(left) == _BOOLEAN and type_of(right) == _DECIMAL


_ARITHMETIC = {
    '+': operator_module.add,
    '-': operator_module.sub,
    '*': operator_module.mul,
}

#: The binary operators whose operands 5.1 reads as numbers, and the only ones `_kernel` consults a
#: `_numeric_pair` for. A String no number can be read out of is a throw *for these* — `1 + 'x'`
#: ends the script — but not for an operator that never coerces it (`-match`, `-split`, `-and`,
#: `-f`, …), which is why the pair, and the certain throw its reject raises, is gated to these.
_NUMERIC_BINARY = frozenset(_ARITHMETIC) | {'/', '%'}

_BITWISE: dict[str, Callable[[int, int], int]] = {
    '-band': int.__and__,
    '-bor': int.__or__,
    '-bxor': int.__xor__,
}


class _Comparison(typing.NamedTuple):
    """
    How one spelling of a comparison operator compares: what it makes of an ordering, whether it is
    an equality — the two an absent or a textual operand are answered for by a rule of their own —
    whether a matching pair is the answer or its negation, and whether the case a text was written
    in counts.
    """

    decides: Callable[[_Number, _Number], bool]
    equality: bool
    negated: bool
    cased: bool


#: Every spelling of a comparison operator, which is a closed set: 5.1 writes each of the six with a
#: `-c` prefix for the comparison the case counts in and an `-i` prefix for the one it does not, and
#: the bare spelling is the case-insensitive one.
_COMPARISON_SPELLINGS: dict[str, _Comparison] = {
    F'-{prefix}{base}': _Comparison(decides, base in ('eq', 'ne'), base == 'ne', prefix == 'c')
    for base, decides in (
        ('eq', operator_module.eq),
        ('ne', operator_module.ne),
        ('lt', operator_module.lt),
        ('le', operator_module.le),
        ('gt', operator_module.gt),
        ('ge', operator_module.ge),
    )
    for prefix in ('', 'c', 'i')
}


def _compared(operator: str, left: Ps1Fact, right: Ps1Fact) -> bool | None:
    """
    What a comparison produces, or `None` where this module computes nothing for it. Every spelling
    is decided here and none of them reaches the arithmetic on its own, because what a comparison
    compares is settled by its operands before any number is read out of them.
    """
    comparison = _COMPARISON_SPELLINGS[operator]
    if left is NULL or right is NULL:
        return _compared_to_absent(comparison, left, right)
    if _compares_as_text(comparison, left, right):
        return _compared_as_text(comparison, left, right)
    if type_of(left) == _BOOLEAN:
        return _compared_as_truth(comparison, left, right)
    try:
        operands = _numeric_pair(left, right)
    except _Throws:
        # An ordering that cannot read a number out of a text is a throw — `1 -lt 'abc'` ends the
        # script — but an equality is not: 5.1 answers `1 -eq 'abc'` with `$false`, never a throw.
        # The domain still declines to compute the equality (it over-claims a *may*-throw as before),
        # so the throw is kept but capped so nothing reads this coercion as a *certain* one.
        if comparison.equality:
            raise _Throws(False)
        raise
    return None if operands is None else comparison.decides(*operands)


def _filtered(
    operator: str,
    elements: tuple[Ps1Fact, ...],
    right: Ps1Fact,
) -> tuple[Ps1Fact, ...] | None:
    """
    The elements a comparison keeps when its left operand is a collection, or `None` where any one
    of them cannot be decided. 5.1 reads `10, 20, 30 -eq 20` as the elements the scalar comparison
    holds for — `@(20)` — and `10, 20, 30, 20, 10 -ne 20` as `10, 30, 10`, so the same predicate
    that answers the scalar case answers each element here.

    An element the scalar comparison declines withholds the whole result rather than being dropped
    from it: a collection missing the members it could not read is a different collection from the
    one 5.1 builds. Which operators reach here is `apply`'s throw gate to decide and not this — an
    ordering whose cell records a throw never does, so an element that would raise a comparison is
    refused before this filters anything.
    """
    kept: list[Ps1Fact] = []
    for element in elements:
        decided = _compared(operator, element, right)
        if decided is None:
            return None
        if decided:
            kept.append(element)
    return tuple(kept)


def _compared_to_absent(comparison: _Comparison, left: Ps1Fact, right: Ps1Fact) -> bool | None:
    """
    What a comparison with `$null` on one side produces, or `None` where this module computes
    nothing for it.

    **An absent value compares by presence and never by conversion.** `$null -eq $null` is `$True`
    while `$null -eq 0`, `$null -eq ''`, `0 -eq $null` and `'' -eq $null` are all `$False`, measured
    — 5.1 answers a null on either side before it converts anything, so the empty String is not the
    absent value and neither is the zero.

    An *ordering* is the same answer read as an order rather than as a match, and what it orders is
    presence and not the zero a conversion would put there: measured, `$null -lt 0` is `$True` where
    `0 -lt 0` is `$False`, and `$null -ge 100` is `$False`. Where the other operand sits is
    `_sorts_below_absent`.
    """
    if not _is_scalar_value(left) or not _is_scalar_value(right):
        return None
    if left is NULL and right is NULL:
        order = 0
    elif left is NULL:
        order = 1 if _sorts_below_absent(right) else -1
    else:
        order = -1 if _sorts_below_absent(left) else 1
    return comparison.decides(order, 0)


def _sorts_below_absent(fact: Ps1Fact) -> bool:
    """
    Whether a value sorts below `$null` rather than above it, which is what 5.1 asks of the operand
    an absent one is compared against. A *negative* number is below it and everything else is above
    — a zero, a positive number, a text, a truth, an unsigned integer. Measured: `$null -lt 0` is
    `$True` while `$null -lt -5` is `$False` and `$null -gt -5` is `$True`, and `$null -lt ''` is
    `$True`.
    """
    payload = fact.payload if isinstance(fact, Ps1Constant) else None
    return isinstance(payload, (int, float, decimal.Decimal)) and payload < 0


def _is_scalar_value(fact: Ps1Fact) -> bool:
    """
    Whether a fact names one value this module holds. A `Ps1Typed` names a type and no value, so
    whether it is the absent one is exactly what is not known about it; a collection is a value and
    is not one value, and an equality against it filters rather than compares — `@(1, 2) -eq $null`
    is the empty collection, measured, and not `$False`.
    """
    return fact is NULL or (isinstance(fact, Ps1Constant) and fact.type != _OBJECT_ARRAY)


def _compared_as_truth(comparison: _Comparison, left: Ps1Fact, right: Ps1Fact) -> bool | None:
    """
    What a comparison with a Boolean on the left produces, or `None` where this module computes
    nothing for it.

    A Boolean on the left converts the right operand to a Boolean and compares the two truths, which
    is neither the number a Boolean is to arithmetic nor the text it writes: measured, `$true -eq 2`
    and `$true -eq '0'` are both `$True` — every non-zero number and every non-empty text is the
    truth the left operand already is — while `$true -lt 2` is `$False`, because two operands that
    convert to the same truth are neither below nor above one another. Reading the Boolean as its
    number answered all three the other way round.
    """
    here = _truth_value(left)
    if here is None or not isinstance(right, Ps1Constant):
        return None
    try:
        there = _cast(_BOOLEAN, right)
    except _Throws:
        return None
    return None if not isinstance(there, bool) else comparison.decides(here, int(there))


def _compares_as_text(comparison: _Comparison, left: Ps1Fact, right: Ps1Fact) -> bool:
    """
    Whether a comparison joins two texts rather than two numbers, which its *left* operand decides.

    A String on the left converts the right operand to a String, so it is a text comparison whatever
    that operand is: measured, `'1.0' -eq 1` is `$False` — `1` is written `1` and does not match
    `1.0` — against `1 -eq '1.0'`, which is `$True` because there the number decides and the text is
    read as one.

    A Char on the left is a text only where the question is whether the two are equal. 5.1 answers
    that by their characters and ignores the case unless the spelling says otherwise —
    `[char]65 -eq [char]97` is `$True` and `[char]65 -ceq [char]97` is `$False`, measured — where it
    *orders* two Chars by their code points, so `[char]97 -lt [char]66` is `$False` and a collation
    of `a` against `B` would answer `$True`. What a Char converts the right operand to is a Char,
    which is the character a number spells and not the text it writes: `[char]48 -eq 48` is `$True`,
    measured, so only a Char beside another text is compared as one.
    """
    if not _is_text(left):
        return False
    if left.type == _STRING:
        return True
    return comparison.equality and _is_text(right)


def _compared_as_text(comparison: _Comparison, left: Ps1Fact, right: Ps1Fact) -> bool | None:
    """
    What a comparison of two texts produces, or `None` where this module computes nothing for it.

    An *ordering* is refused. 5.1 orders two texts by `CompareInfo.Compare`, which is a collation and
    not the arithmetic below: measured, `'10' -lt '9'` is `$True` and `'2' -lt '10'` is `$False`,
    both of which reading the numerals answers the other way.

    An equality is answered from the text each operand writes, with the case counting only where the
    spelling says it does: `[char]48 -eq '0'` and `[char]65 -eq [char]97` are both `$True` while
    `[char]65 -ceq [char]97` is `$False`, measured.

    **A pair this decides is not equal is refused where either text leaves ASCII**, because the
    comparison 5.1 makes is a collation there too and it calls texts equal that no reading of their
    code points does: `'ss' -eq [char]0x00DF` is `$True`, measured, and so is a text against the
    same text with a soft hyphen in it. Equality the other way round survives the boundary — two
    texts this reads as the same are the same text or a case variant of it, which a collation under
    `IgnoreCase` agrees with — so what the boundary costs is a refusal and never an answer.
    """
    if not comparison.equality:
        return None
    if not isinstance(left, Ps1Constant) or not isinstance(right, Ps1Constant):
        return None
    head, tail = _rendered(left), _rendered(right)
    if head is None or tail is None:
        return None
    same = head == tail if comparison.cased else head.lower() == tail.lower()
    if not same and not (head.isascii() and tail.isascii()):
        return None
    return same != comparison.negated


#: The literal suffix that pins a spelled number to its type, for the types that have one. The set
#: is the whole of what 5.1 has: `l` names an Int64 and `d` a Decimal, and the rest of the suffixes
#: a reader may expect — `y`, `uy`, `s`, `us`, `u`, `ul`, `n` — arrived in 6.2 and 7.0.
_LITERAL_SUFFIX = {_INT32: '', _INT64: 'L', _DECIMAL: 'd'}

#: The cast a value is written under where the language spells no literal of its type. Each is
#: measured: `[byte] 5` is a Byte, `[sbyte] -5` an SByte, `[uint64] 18446744073709551615` a UInt64
#: and `[char] 65` the Char `A`. A decimal numeral is the operand every one of them converts from
#: without loss, including the values above `Int64`, which reach the cast as a Decimal literal.
#:
#: `System.Single` is absent because the domain names no constant of it: no literal spells one,
#: no width row holds one and nothing stamps one, so a value that would need this entry cannot
#: be built.
_CAST_SPELLING = {
    _BYTE: 'byte',
    _SBYTE: 'sbyte',
    _INT16: 'int16',
    _UINT16: 'uint16',
    _UINT32: 'uint32',
    _UINT64: 'uint64',
}

#: The types a cast *spells* rather than converts to, which is the six widths above, the `Char`
#: `_rendered_character` writes the same way and the enums `_rendered_enum` writes as the cast of
#: a member name. One set keys both directions — `render` writes a cast for exactly these and
#: `read` reads one back for exactly these — so neither can grow without the other and
#: `read(render(fact)) == fact` cannot quietly stop holding.
_SPELLED_BY_A_CAST = frozenset(_CAST_SPELLING) | {_CHAR} | _FOLDABLE_ENUMS


def render(fact: Ps1Fact) -> Expression | None:
    """
    The expression that spells this value. **A value always has one**: a literal where the language
    has a literal of its type, and the cast of one where it does not, so that a caller holding a
    `Ps1Constant` never has to choose between leaving the source alone and spelling something else.

    `None` is therefore not a refusal to spell a value: it is the answer for a fact that *names*
    no value. `UNKNOWN` and `Ps1Typed` are the two, and beside them stand a payload that does not
    carry its own type, which is a malformed fact rather than a value, and a `Double` that is not
    finite. Infinity and NaN have no literal and no cast that reaches them, and the domain does
    not carry one either — `_finite` refuses a computed one — so that last refusal is unreachable
    rather than a gap.

    A number is spelled with its sign attached to the digits, which is the spelling that keeps its
    type: `-2147483648` is one literal that fits Int32, and a caller putting the result somewhere a
    parenthesis would separate the two has changed an Int32 into an Int64. Where a *slot* reads that
    spelling as something else — a command argument reads a leading dash as part of a word, and a
    cast written bare there is one word too — it is the slot that brackets it, in
    `refinery.lib.scripts.ps1.synth`, because only the slot knows what stands beside it.
    """
    if fact is NULL:
        return null_expression()
    if not isinstance(fact, Ps1Constant):
        return None
    payload = fact.payload
    if fact.type == _BOOLEAN:
        return Ps1Variable(name='True' if payload else 'False')
    if fact.type == _STRING:
        return make_string_literal(payload) if isinstance(payload, str) else None
    if fact.type == _CHAR:
        return _rendered_character(payload)
    if fact.type in _FOLDABLE_ENUMS:
        return _rendered_enum(fact)
    if fact.type == _OBJECT_ARRAY:
        return _rendered_array(payload) if isinstance(payload, tuple) else None
    if fact.type == _DOUBLE:
        return _rendered_double(payload)
    if isinstance(payload, bool) or not isinstance(payload, (int, decimal.Decimal)):
        return None
    suffix = _LITERAL_SUFFIX.get(fact.type)
    if suffix is not None:
        if fact.type == _DECIMAL:
            return Ps1RealLiteral(raw=F'{payload}{suffix}')
        return Ps1IntegerLiteral(raw=F'{payload}{suffix}')
    target = _CAST_SPELLING.get(fact.type)
    if target is None:
        return None
    return Ps1CastExpression(type_name=target, operand=Ps1IntegerLiteral(raw=str(payload)))


def folded_binary(left: Expression, operator: str, right: Expression) -> Expression | None:
    """
    The expression `left operator right` folds to, or `None` where the pair is not constant or the
    operation may throw.

    The operands are read exactly as `evaluate` reads the two sides of any binary expression, so a
    fold here agrees with folding the same operator written out longhand: the value a compound
    assignment `$x op= e` leaves is `$x op e`, and this is what lets the short spelling reach the
    same constant the long one does. Each operand is copied before it is read, because the throwaway
    node built to hold them adopts the children it is handed, and a fold must leave the tree it read
    from untouched whether or not a caller installs the result.
    """
    combined = Ps1BinaryExpression(
        left=_clone_node(left),
        operator=operator,
        right=_clone_node(right),
    )
    outcome = evaluate(combined)
    return None if outcome.may_throw else render(outcome.value)


def folded_increment(previous: Expression, delta: int) -> Expression | None:
    """
    The value `$x++` or `$x--` leaves in `$x`, given its previous value `previous` and a `delta` of
    `+1` or `-1`, or `None` where that value is not constant or the increment throws.

    `++` and `--` are not the binary `$x + 1` and `$x - 1`: they require a number and add the delta
    to it, where `+` and `-` would concatenate a String, coerce one, or read a Boolean as an integer
    — none of which the increment does. 5.1 answers the delta itself for `$null` and throws
    `OperatorRequiresNumber` for a String, a Char, a Boolean or a collection, so this folds only over
    `$null` and the numeric types and refuses the rest, standing no value where 5.1 raised. Over a
    number the increment *is* the binary sum, which is why `folded_binary` computes it once the
    operand is one — and `$null`, which `_is_domain_integer` reads as the zero the sum needs.
    """
    fact = read(previous)
    numeric = _is_domain_integer(fact) or (
        isinstance(fact, Ps1Constant) and fact.type in (_DECIMAL, _DOUBLE)
    )
    if not numeric:
        return None
    return folded_binary(previous, '+' if delta > 0 else '-', Ps1IntegerLiteral(raw='1'))


def _rendered_character(payload) -> Expression | None:
    """
    A `Char`, written as the cast of its code point. The one-character String that carries the same
    payload is a different value and not a shorter spelling of this one: measured, the two differ in
    the type they report, in what `-is [char]` answers, in which String methods they have and in
    what `[int]` makes of them.
    """
    if not isinstance(payload, str) or len(payload) != 1:
        return None
    return Ps1CastExpression(type_name='char', operand=Ps1IntegerLiteral(raw=str(ord(payload))))


def _rendered_enum(fact: Ps1Constant) -> Expression | None:
    """
    An enum member, written as the cast of its name to its type spelled in full, which is what
    `_cast_spelling` reads back through `_to_enum`. `_to_enum` mints no ordinal that names no
    member, so the `None` for one is the answer `render` gives every payload that carries no value.
    """
    ordinal = ordinal_of(fact)
    name = None if ordinal is None else enum_name(fact.type, ordinal)
    if name is None:
        return None
    return Ps1CastExpression(type_name=str(fact.type), operand=make_string_literal(name))


def _rendered_array(elements: tuple[Ps1Fact, ...]) -> Expression | None:
    """
    A collection, spelled by the comma operator that builds exactly it. `@()` is the empty form
    and nothing else, because it collects what a pipeline unrolls rather than what was written:
    measured, `@(@(1, 2))` is a two-element array where `,(1, 2)` is a one-element array holding
    one, and `(1, 2), 3` is the two-element array with an array in it.

    One element that names no value refuses the whole collection: a shorter array than the script
    builds is a different value, and there is no element to stand in for the one that was dropped.
    """
    if not elements:
        return Ps1ArrayExpression(body=[])
    spelled: list[Expression] = []
    for element in elements:
        one = render(element)
        if one is None:
            return None
        spelled.append(one)
    return Ps1ArrayLiteral(elements=spelled)


def _rendered_double(payload) -> Expression | None:
    if not isinstance(payload, float) or payload != payload or payload in (INFINITY, -INFINITY):
        return None
    return Ps1RealLiteral(raw=repr(payload))


def make_string_literal(value: str) -> Ps1StringLiteral | Ps1HereString:
    """
    The literal that spells `value` as a `String`, for a caller that holds a bare Python `str` and
    no fact. It is `render`'s String arm, and it is the last place in the unit where a value is
    spelled without its type having been named — a `str` reaching here becomes a String whatever it
    was. What reaches it is the emulation of a .NET method that really does produce a String, and a
    text this module computed itself.

    A here-string is chosen for multi-line text because it needs no escaping, and only where the
    text cannot close it early: a line beginning `'@` inside the value would end the string there
    and let the rest of it be read as script.
    """
    has_newline = '\n' in value
    has_nonprint = any(c in value for c in _NONPRINT_CONTROL)
    herestring_safe = not value.startswith("'@") and "\n'@" not in value
    if has_newline and not has_nonprint and herestring_safe:
        return Ps1HereString(value=value, raw=F"@'\n{value}\n'@")
    if has_nonprint or has_newline:
        escaped = value.replace('`', '``').replace('"', '`"').replace('$', '`$')
        for ch, esc in BACKTICK_ENCODE.items():
            escaped = escaped.replace(ch, esc)
        return Ps1StringLiteral(value=value, raw=F'"{escaped}"')
    if "'" not in value:
        raw = F"'{value}'"
    elif '"' not in value and '$' not in value and '`' not in value:
        raw = F'"{value}"'
    else:
        raw = "'" + value.replace("'", "''") + "'"
    return Ps1StringLiteral(value=value, raw=raw)
