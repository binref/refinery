"""
Shared utilities for PowerShell deobfuscation transforms.
"""
from __future__ import annotations

import enum
import io
import math
import re

from typing import Callable, Generator, NamedTuple, TypeGuard, TypeVar

from refinery.lib.scripts import Block, Node, Transformer
from refinery.lib.scripts.ps1.deobfuscation.data import (
    BUILTIN_VARIABLES,
    FOREACH_ALIASES,
    FORMAT_PATTERN,
    is_type,
)
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1CastExpression,
    Ps1Code,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1FunctionDefinition,
    Ps1HereString,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1RealLiteral,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.token import BACKTICK_ESCAPE

_T = TypeVar('_T')


class MutationKind(enum.Enum):
    ASSIGN = 'assign'
    MEMBER_ASSIGN = 'member_assign'
    FOREACH = 'foreach'
    INCRDECR = 'incrdecr'
    PARAM = 'param'


class BodyRole(enum.Enum):
    """
    How a statement body relates to the code that surrounds it, for the cleanup passes that descend
    into function and `&{}` bodies. A `refinery.lib.scripts.Block` or `Ps1Code` body is one of:

    - `OPAQUE`: the body's value is captured (an assignment right-hand side, `$(...)`, `@(...)`, a
      stored or argument scriptblock, a piped `&{}`); pruning any statement could destroy an
      observable value, so the body is left untouched.
    - `ROOT`: the body's output is observed but not captured into a value (the script root, a
      function body, a bare `&{}`/`.{}` in statement position); side-effect-free junk may be pruned,
      but a body that is nothing but its own output value is preserved.
    - `NESTED`: a plain nested block that runs for its side effects (a loop or `if` body in
      statement position); statements may be pruned freely.
    """
    OPAQUE = 'opaque'
    ROOT = 'root'
    NESTED = 'nested'


class VariableMutation(NamedTuple):
    variable: Ps1Variable
    kind: MutationKind
    node: Node


BACKTICK_ENCODE = {v: F'`{k}' for k, v in BACKTICK_ESCAPE.items()}
NONPRINT_CONTROL = frozenset(BACKTICK_ENCODE) - {'\n'}


def string_value(node: Node | None) -> str | None:
    if isinstance(node, Ps1StringLiteral):
        return node.value
    if isinstance(node, Ps1HereString):
        return node.value
    if isinstance(node, Ps1ExpandableString):
        out = io.StringIO()
        for p in node.parts:
            if not isinstance(p, Ps1StringLiteral):
                break
            out.write(p.value)
        else:
            return out.getvalue()
    if isinstance(node, Ps1SubExpression) and len(node.body) == 1:
        stmt = node.body[0]
        if isinstance(stmt, Ps1ExpressionStatement) and stmt.expression is not None:
            return string_value(stmt.expression)
    return None


def make_string_literal(value: str) -> Ps1StringLiteral | Ps1HereString:
    has_newline = '\n' in value
    has_nonprint = any(c in value for c in NONPRINT_CONTROL)
    # A single-quoted here-string is closed by a line that begins with `'@`; emitting a value that
    # contains such a line verbatim would terminate the string early and corrupt the script.
    herestring_safe = not value.startswith("'@") and "\n'@" not in value
    if has_newline and not has_nonprint and herestring_safe:
        raw = F"@'\n{value}\n'@"
        return Ps1HereString(value=value, raw=raw)
    if has_nonprint or has_newline:
        escaped = value.replace('`', '``').replace('"', '`"').replace('$', '`$')
        for ch, esc in BACKTICK_ENCODE.items():
            escaped = escaped.replace(ch, esc)
        raw = F'"{escaped}"'
        return Ps1StringLiteral(value=value, raw=raw)
    if "'" not in value:
        raw = F"'{value}'"
    elif '"' not in value and '$' not in value and '`' not in value:
        raw = F'"{value}"'
    else:
        raw = "'" + value.replace("'", "''") + "'"
    return Ps1StringLiteral(value=value, raw=raw)


def collect_typed_arguments(
    node: Expression, extract: Callable[[Expression], _T | None],
) -> list[_T] | None:
    if isinstance(node, Ps1ArrayLiteral):
        result: list[_T] = []
        for elem in node.elements:
            value = extract(elem)
            if value is None:
                return None
            result.append(value)
        return result
    value = extract(node)
    if value is not None:
        return [value]
    return None


def collect_string_arguments(node: Expression) -> list[str] | None:
    return collect_typed_arguments(node, string_value)


def extract_format_argument(node: Expression) -> str | int | None:
    """
    Extract a format-string argument value: integers are returned as `int` so that numeric format
    specifiers (`X`, `D`, etc.) can be applied; everything else is returned as `str`.
    """
    result = unwrap_integer(node)
    if result is not None:
        return result.value
    return string_value(node)


def collect_format_arguments(node: Expression) -> list[str | int] | None:
    return collect_typed_arguments(node, extract_format_argument)


def extract_int(node: Expression) -> int | None:
    return node.value if isinstance(node, Ps1IntegerLiteral) else None


def collect_int_arguments(node: Expression) -> list[int] | None:
    if isinstance(node, Ps1ParenExpression) and node.expression is not None:
        return collect_int_arguments(node.expression)
    return collect_typed_arguments(node, extract_int)


def collect_byte_array(node: Expression) -> bytes | None:
    """
    Extract an integer array from `node` and convert to `bytes`. Handles
    `refinery.lib.scripts.ps1.model.Ps1ArrayLiteral`,
    `refinery.lib.scripts.ps1.model.Ps1ArrayExpression`, and parenthesized wrappers.
    """
    array = unwrap_to_array_literal(node)
    if array is not None:
        node = array
    elif isinstance(node, Ps1ArrayExpression):
        items: list[int] = []
        for stmt in node.body:
            if not isinstance(stmt, Ps1ExpressionStatement) or stmt.expression is None:
                return None
            value = extract_int(stmt.expression)
            if value is None:
                return None
            items.append(value)
        try:
            return bytes(items)
        except (ValueError, OverflowError):
            return None
    values = collect_int_arguments(node)
    if values is None:
        return None
    try:
        return bytes(values)
    except (ValueError, OverflowError):
        return None


def unwrap_single_paren(node: Expression) -> Expression:
    if isinstance(node, Ps1ParenExpression) and node.expression is not None:
        return node.expression
    return node


def get_command_name(cmd: Ps1CommandInvocation) -> str | None:
    if isinstance(cmd.name, Ps1StringLiteral):
        return cmd.name.value
    return None


def extract_positional_values(
    cmd: Ps1CommandInvocation,
) -> list[Expression]:
    """
    Collect all positional argument values from a command invocation.
    """
    result: list[Expression] = []
    for arg in cmd.arguments:
        if isinstance(arg, Ps1CommandArgument):
            if arg.kind == Ps1CommandArgumentKind.POSITIONAL and arg.value is not None:
                result.append(arg.value)
        elif isinstance(arg, Expression):
            result.append(arg)
    return result


def extract_first_positional_string(
    cmd: Ps1CommandInvocation,
) -> str | None:
    values = extract_positional_values(cmd)
    if values:
        return string_value(values[0])
    return None


def get_body(node) -> list | None:
    if isinstance(node, (Ps1Code, Block, Ps1SubExpression)):
        return node.body
    return None


def inside_value_producing_context(node) -> bool:
    """
    Return `True` when `node` is or is nested inside a context whose statement bodies produce
    observable values and must not be pruned as junk or dead code: a
    `refinery.lib.scripts.ps1.model.Ps1SubExpression` (`$(...)`), a
    `refinery.lib.scripts.ps1.model.Ps1ScriptBlock`, a
    `refinery.lib.scripts.ps1.model.Ps1ArrayExpression` (`@(...)`), or the statement-valued
    right-hand side of an assignment (`$x = if (...) { ... }`).
    """
    cursor = node
    prev = None
    while cursor is not None:
        if isinstance(cursor, (Ps1SubExpression, Ps1ScriptBlock, Ps1ArrayExpression)):
            return True
        if isinstance(cursor, Ps1AssignmentExpression) and cursor.value is prev:
            return True
        prev = cursor
        cursor = cursor.parent
    return False


def _scriptblock_is_captured(block: Ps1ScriptBlock) -> bool:
    """
    Return `True` when the value of a `refinery.lib.scripts.ps1.model.Ps1ScriptBlock` is captured
    rather than run for its observable output. A bare `&{ ... }` / `.{ ... }` in statement position
    produces output that the pass may prune into; every other scriptblock (a stored closure
    `$x = { ... }`, an argument block, or an invocation whose result is assigned, passed, or piped)
    is treated as captured and left opaque.
    """
    parent = block.parent
    if isinstance(parent, Ps1FunctionDefinition):
        return False
    if not (isinstance(parent, Ps1CommandInvocation) and parent.name is block):
        return True
    invocation_parent = parent.parent
    if isinstance(invocation_parent, Ps1ExpressionStatement):
        return False
    if isinstance(invocation_parent, Ps1PipelineElement):
        pipeline = invocation_parent.parent
        if (
            isinstance(pipeline, Ps1Pipeline)
            and len(pipeline.elements) == 1
            and isinstance(pipeline.parent, Ps1ExpressionStatement)
        ):
            return False
    return True


def classify_body(node) -> BodyRole | None:
    """
    Classify the statement body owned by `node` as a
    `refinery.lib.scripts.ps1.deobfuscation.helpers.BodyRole`, or return `None` when `node` owns no
    prunable body (`get_body` is `None`). Used by the dead-code and junk passes to decide whether a
    body may be pruned and how aggressively; ambiguous capture always resolves to `OPAQUE`.
    """
    if get_body(node) is None:
        return None
    if isinstance(node, Ps1Script):
        return BodyRole.ROOT
    if isinstance(node, Ps1SubExpression):
        return BodyRole.OPAQUE
    if isinstance(node, Ps1ScriptBlock):
        if isinstance(node.parent, Ps1FunctionDefinition) and node.parent.body is node:
            return BodyRole.ROOT
        return BodyRole.OPAQUE if _scriptblock_is_captured(node) else BodyRole.ROOT
    # A plain `Block` (loop/if/try/catch/finally/trap body): walk to the nearest enclosing body
    # owner. Crossing a value-capturing boundary (`$(...)`, `@(...)`, a captured scriptblock, or the
    # right-hand side of an assignment such as `$x = if (...) {...}`) makes this block opaque; a
    # function/script/bare-`&{}` boundary resets capture, leaving it nested.
    prev = node
    cursor = node.parent
    while cursor is not None:
        if isinstance(cursor, (Ps1SubExpression, Ps1ArrayExpression)):
            return BodyRole.OPAQUE
        if isinstance(cursor, Ps1AssignmentExpression) and cursor.value is prev:
            return BodyRole.OPAQUE
        if isinstance(cursor, Ps1ScriptBlock):
            return BodyRole.OPAQUE if _scriptblock_is_captured(cursor) else BodyRole.NESTED
        if isinstance(cursor, Ps1Script):
            return BodyRole.NESTED
        prev = cursor
        cursor = cursor.parent
    return BodyRole.NESTED


def unwrap_parens(node: Node) -> Node:
    """
    Unwrap nested `refinery.lib.scripts.ps1.model.Ps1ParenExpression` wrappers and single-statement
    `refinery.lib.scripts.ps1.model.Ps1SubExpression` wrappers, stopping at an empty wrapper.
    """
    while True:
        if isinstance(node, Ps1ParenExpression) and node.expression is not None:
            node = node.expression
            continue
        if isinstance(node, Ps1SubExpression) and len(node.body) == 1:
            stmt = node.body[0]
            if isinstance(stmt, Ps1ExpressionStatement) and stmt.expression is not None:
                node = stmt.expression
                continue
        break
    return node


def unwrap_to_array_literal(node: Node) -> Ps1ArrayLiteral | None:
    """
    Unwrap parentheses and array expressions to find an inner
    `refinery.lib.scripts.ps1.model.Ps1ArrayLiteral`.
    """
    node = unwrap_parens(node)
    if isinstance(node, Ps1ArrayLiteral):
        return node
    if isinstance(node, Ps1ArrayExpression) and len(node.body) == 1:
        stmt = node.body[0]
        if isinstance(stmt, Ps1ExpressionStatement) and isinstance(stmt.expression, Ps1ArrayLiteral):
            return stmt.expression
    return None


def get_member_name(member: str | Expression) -> str | None:
    """
    Extract a plain member name string from a member that may be a string
    or a string literal expression.
    """
    if isinstance(member, str):
        return member
    if isinstance(member, Ps1StringLiteral):
        return member.value
    return None


def unwrap_integer(node: Node | None) -> Ps1IntegerLiteral | None:
    """
    Peel parentheses and unary negation to extract an integer literal, or return `None`.
    """
    node = unwrap_parens(node) if isinstance(node, Expression) else node
    if isinstance(node, Ps1IntegerLiteral):
        return node
    if is_builtin_variable(node, {'null'}):
        return Ps1IntegerLiteral(value=0, raw='0')
    if isinstance(node, Ps1UnaryExpression) and node.operator == '-':
        inner = unwrap_parens(node.operand) if isinstance(node.operand, Expression) else node.operand
        if isinstance(inner, Ps1IntegerLiteral):
            return Ps1IntegerLiteral(value=-inner.value, raw=str(-inner.value))
    return None


def is_static_type_call(node: Ps1InvokeMember, canonical: str) -> bool:
    if node.access != Ps1AccessKind.STATIC:
        return False
    if not isinstance(node.object, Ps1TypeExpression):
        return False
    return is_type(normalize_type_expression(node.object.name), canonical)


def detect_encoding_chain(node: Ps1InvokeMember) -> str | None:
    """
    If *node* is `[Text.Encoding]::X.GetString(args)`, return the encoding member name (e.g.
    `'UTF8'`).  Otherwise return `None`.
    """
    member = get_member_name(node.member)
    if member is None or member.lower() != 'getstring':
        return None
    obj = node.object
    if not isinstance(obj, Ps1MemberAccess):
        return None
    if obj.access != Ps1AccessKind.STATIC:
        return None
    if not isinstance(obj.object, Ps1TypeExpression):
        return None
    if not is_type(normalize_type_expression(obj.object.name), 'system.text.encoding'):
        return None
    enc_name = get_member_name(obj.member)
    return enc_name


def _unwrap_assignment_target(target: Node | None) -> Node | None:
    """
    Peel type-constraint casts and parentheses from an assignment target.
    """
    while isinstance(target, (Ps1ParenExpression, Ps1CastExpression)):
        target = target.expression if isinstance(target, Ps1ParenExpression) else target.operand
    return target


def assignment_target_variables(target: Node | None) -> list[Ps1Variable]:
    """
    Return the variables written by an assignment target. A plain variable target yields a single
    entry, a `refinery.lib.scripts.ps1.model.Ps1ArrayLiteral` target (the PowerShell
    multi-assignment `$a, $b = 1, 2`) yields one entry per element that unwraps to a variable, and
    any other target (index, member access, literal) yields an empty list.
    """
    target = _unwrap_assignment_target(target)
    if isinstance(target, Ps1Variable):
        return [target]
    if isinstance(target, Ps1ArrayLiteral):
        variables: list[Ps1Variable] = []
        for element in target.elements:
            unwrapped = _unwrap_assignment_target(element)
            if isinstance(unwrapped, Ps1Variable):
                variables.append(unwrapped)
        return variables
    return []


def is_assignment_write_target(var: Ps1Variable) -> bool:
    """
    Return `True` when `var` occupies the target position of an enclosing
    `refinery.lib.scripts.ps1.model.Ps1AssignmentExpression`, including as an element of a
    multi-assignment `refinery.lib.scripts.ps1.model.Ps1ArrayLiteral` target. Enclosing casts and
    parentheses are transparent.
    """
    cursor: Node = var
    parent = cursor.parent
    while isinstance(parent, (Ps1CastExpression, Ps1ParenExpression, Ps1ArrayLiteral)):
        cursor = parent
        parent = cursor.parent
    return isinstance(parent, Ps1AssignmentExpression) and parent.target is cursor


def iter_variable_mutations(
    root: Node,
) -> Generator[VariableMutation, None, None]:
    """
    Walk the AST and yield a `VariableMutation` for every node that mutates a variable.
    """
    for node in root.walk():
        if isinstance(node, Ps1AssignmentExpression):
            variables = assignment_target_variables(node.target)
            if variables:
                for variable in variables:
                    yield VariableMutation(variable, MutationKind.ASSIGN, node)
            else:
                target = _unwrap_assignment_target(node.target)
                if isinstance(target, (Ps1IndexExpression, Ps1MemberAccess)):
                    if isinstance(target.object, Ps1Variable):
                        yield VariableMutation(target.object, MutationKind.MEMBER_ASSIGN, node)
        elif isinstance(node, Ps1ForEachLoop):
            if isinstance(node.variable, Ps1Variable):
                yield VariableMutation(node.variable, MutationKind.FOREACH, node)
        elif isinstance(node, Ps1UnaryExpression):
            if node.operator in ('++', '--') and isinstance(node.operand, Ps1Variable):
                yield VariableMutation(node.operand, MutationKind.INCRDECR, node)
        elif isinstance(node, Ps1ParameterDeclaration):
            if isinstance(node.variable, Ps1Variable):
                yield VariableMutation(node.variable, MutationKind.PARAM, node)


def extract_foreach_scriptblock(expr: Expression) -> Ps1ScriptBlock | None:
    if not isinstance(expr, Ps1CommandInvocation):
        return None
    if not isinstance(expr.name, Ps1StringLiteral):
        return None
    if expr.name.value.lower() not in FOREACH_ALIASES:
        return None
    if len(expr.arguments) != 1:
        return None
    arg = expr.arguments[0]
    if isinstance(arg, Ps1CommandArgument):
        if arg.kind != Ps1CommandArgumentKind.POSITIONAL:
            return None
        arg = arg.value
    if isinstance(arg, Ps1ScriptBlock):
        return arg
    return None


def is_builtin_variable(
    node: Node | None,
    names: set[str] | frozenset[str] = BUILTIN_VARIABLES,
) -> TypeGuard[Ps1Variable]:
    """
    Return `True` when `node` is an unscoped `refinery.lib.scripts.ps1.model.Ps1Variable` whose
    lowered name is in `names` (defaults to `$Null`, `$True`, `$False`).
    """
    return (
        isinstance(node, Ps1Variable)
        and node.scope == Ps1ScopeModifier.NONE
        and node.name.lower() in names
    )


def is_pipeline_item(node: Node | None) -> TypeGuard[Ps1Variable]:
    """
    Return `True` when `node` is the current pipeline item variable, written either as `$_` or its
    full synonym `$PSItem`.
    """
    return (
        isinstance(node, Ps1Variable)
        and node.scope == Ps1ScopeModifier.NONE
        and node.name.lower() in ('_', 'psitem')
    )


def is_truthy(node: Node | None) -> bool | None:
    """
    Determine the boolean truth value of a constant expression using PowerShell semantics. Returns
    `None` for non-constant or unrecognized expressions.
    """
    node = unwrap_parens(node) if isinstance(node, Expression) else node
    if node is None:
        return None
    if is_builtin_variable(node):
        lower = node.name.lower()
        if lower == 'true':
            return True
        if lower in ('false', 'null'):
            return False
        return None
    if isinstance(node, (Ps1IntegerLiteral, Ps1RealLiteral, Ps1StringLiteral)):
        return bool(node.value)
    if isinstance(node, Ps1UnaryExpression) and node.operator == '-':
        return is_truthy(node.operand)
    return None


def is_array_reverse_call(node: Ps1ExpressionStatement) -> Ps1Variable | None:
    """
    If the statement is `[Array]::Reverse($var)`, return the variable node.
    """
    expr = node.expression
    if not isinstance(expr, Ps1InvokeMember):
        return None
    if expr.access != Ps1AccessKind.STATIC:
        return None
    if not isinstance(expr.object, Ps1TypeExpression):
        return None
    if not is_type(normalize_type_expression(expr.object.name), 'system.array'):
        return None
    member = get_member_name(expr.member)
    if member is None or member.lower() != 'reverse':
        return None
    if len(expr.arguments) != 1:
        return None
    arg = expr.arguments[0]
    if isinstance(arg, Ps1Variable):
        return arg
    return None


def extract_new_object(cmd: Ps1CommandInvocation) -> tuple[str, list[Expression]] | None:
    """
    Extract the type name and constructor arguments from a `New-Object` invocation. Returns
    `(type_name, [arg_expressions])`, or `None` when `cmd` is not a resolvable `New-Object` call.
    """
    if not isinstance(cmd.name, Ps1StringLiteral):
        return None
    if cmd.name.value.lower() != 'new-object':
        return None
    positional: list[Expression] = []
    for arg in cmd.arguments:
        if isinstance(arg, Ps1CommandArgument):
            if arg.kind != Ps1CommandArgumentKind.POSITIONAL or arg.value is None:
                return None
            positional.append(arg.value)
        elif isinstance(arg, Expression):
            positional.append(arg)
        else:
            return None
    if not positional:
        return None
    type_name_expr = positional[0]
    if not isinstance(type_name_expr, Ps1StringLiteral):
        return None
    type_name = type_name_expr.value
    ctor_args: list[Expression] = []
    if len(positional) >= 2:
        second = positional[1]
        if isinstance(second, Ps1ParenExpression) and second.expression is not None:
            inner = second.expression
            if isinstance(inner, Ps1ArrayLiteral):
                ctor_args = list(inner.elements)
            else:
                ctor_args = [inner]
        else:
            ctor_args = [second]
    return type_name, ctor_args


def ps_divide(a: int | float, b: int | float) -> int | float:
    """
    PowerShell division: integer operands yield an `int` only when the division is exact, otherwise
    a `float`; any float operand yields a `float`. Raises `ZeroDivisionError` on division by zero.
    """
    if b == 0:
        raise ZeroDivisionError
    if isinstance(a, int) and isinstance(b, int) and a % b == 0:
        return a // b
    return a / b


def ps_modulo(a: int | float, b: int | float) -> int | float:
    """
    PowerShell modulo: the result truncates toward zero and takes the sign of the dividend (unlike
    Python's floored `%`). Raises `ZeroDivisionError` when `b` is zero.
    """
    if b == 0:
        raise ZeroDivisionError
    if isinstance(a, int) and isinstance(b, int):
        r = abs(a) % abs(b)
        return -r if a < 0 else r
    return math.fmod(a, b)


def ps_shift_left(value: int, count: int) -> int:
    """
    PowerShell `-shl`: the left operand is taken as a 32-bit integer unless its magnitude needs 64
    bits, the shift count is masked to the operand width (5 bits for `Int32`, 6 for `Int64`), and the
    result wraps within the signed range of that width, matching .NET.
    """
    width = 32 if -0x80000000 <= value <= 0x7FFFFFFF else 64
    span = 1 << width
    result = (value << (count & (width - 1))) & (span - 1)
    if result >= span >> 1:
        result -= span
    return result


def ps_shift_right(value: int, count: int) -> int:
    """
    PowerShell `-shr`: an arithmetic, sign-preserving right shift of the left operand taken as a
    32-bit integer unless its magnitude needs 64 bits, with the shift count masked to the operand
    width (5 bits for `Int32`, 6 for `Int64`), matching .NET.
    """
    width = 32 if -0x80000000 <= value <= 0x7FFFFFFF else 64
    return value >> (count & (width - 1))


def switch_matches(value, condition, *, case_sensitive: bool = False) -> bool:
    """
    PowerShell `switch` clause matching for already-evaluated scalar values. String comparison is
    case-insensitive unless `case_sensitive` is set; integers and strings cross-coerce the way
    PowerShell does.
    """
    if isinstance(value, str) and isinstance(condition, str):
        return value == condition if case_sensitive else value.lower() == condition.lower()
    if isinstance(value, (int, float)) and isinstance(condition, (int, float)):
        return value == condition
    if isinstance(value, (int, float)) and isinstance(condition, str):
        try:
            return value == int(condition)
        except ValueError:
            return False
    if isinstance(value, str) and isinstance(condition, (int, float)):
        try:
            return int(value) == condition
        except ValueError:
            return False
    return value is condition


def _dotnet_replacement(template: str, text: str) -> Callable[[re.Match], str]:
    """
    Build an `re.sub` replacement function that expands .NET substitution tokens (`$1`, `${name}`,
    `$&`, `` $` ``, `$'`, `$+`, `$_`, `$$`) in `template`. Backslashes are literal, matching .NET.
    """
    def repl(m: re.Match) -> str:
        out: list[str] = []
        i = 0
        n = len(template)
        while i < n:
            c = template[i]
            if c != '$' or i + 1 >= n:
                out.append(c)
                i += 1
                continue
            tok = template[i + 1]
            if tok == '$':
                out.append('$')
                i += 2
            elif tok == '&':
                out.append(m.group(0))
                i += 2
            elif tok == '`':
                out.append(text[:m.start()])
                i += 2
            elif tok == "'":
                out.append(text[m.end():])
                i += 2
            elif tok == '_':
                out.append(text)
                i += 2
            elif tok == '+':
                last = ''
                for g in range(m.re.groups, 0, -1):
                    if m.group(g) is not None:
                        last = m.group(g)
                        break
                out.append(last)
                i += 2
            elif tok == '{':
                end = template.find('}', i + 2)
                if end < 0:
                    out.append('$')
                    i += 1
                    continue
                name = template[i + 2:end]
                try:
                    grp = m.group(int(name)) if name.isdigit() else m.group(name)
                except (IndexError, re.error):
                    grp = None
                out.append(grp or '')
                i = end + 1
            elif tok.isdigit():
                j = i + 1
                while j < n and template[j].isdigit():
                    j += 1
                digits = template[i + 1:j]
                grp = None
                while digits:
                    num = int(digits)
                    if num <= m.re.groups:
                        grp = m.group(num) or ''
                        break
                    digits = digits[:-1]
                if grp is None:
                    out.append('$')
                    i += 1
                else:
                    out.append(grp)
                    i = i + 1 + len(digits)
            else:
                out.append('$')
                i += 1
        return ''.join(out)
    return repl


def dotnet_regex_replace(pattern: str, replacement: str, text: str, *, flags: int = 0) -> str:
    """
    Replace every match of `pattern` in `text` with the .NET-style `replacement`, honoring .NET
    substitution tokens. Replace-all is direction independent, so the regex `RightToLeft` option
    does not change the result here.
    """
    return re.sub(pattern, _dotnet_replacement(replacement, text), text, flags=flags)


_BARE_COMMAND_NAME = re.compile(r'''[^\s'"`(){};|&<>@]+''')


def is_bare_command_name(name: str) -> bool:
    """
    Return `True` when `name` can be emitted as an unquoted command name, i.e. it contains no
    whitespace, quotes, or characters that would re-lex into separate tokens.
    """
    return bool(name) and _BARE_COMMAND_NAME.fullmatch(name) is not None


def set_command_name(node: Ps1CommandInvocation, name: str) -> bool:
    """
    Replace the command name of `node` with a literal for `name`, quoting it (and adding the call
    operator `&`) when the name is not a bare-safe command token. Returns `True` when the name
    actually changed, so callers should only `mark_changed()` on a `True` result; this guards
    against self-resolving rewrites that would otherwise loop forever.
    """
    if node.name is not None and string_value(node.name) == name:
        return False
    offset = node.name.offset if node.name is not None else -1
    if _BARE_COMMAND_NAME.fullmatch(name):
        literal: Ps1StringLiteral | Ps1HereString = Ps1StringLiteral(
            offset=offset, value=name, raw=name)
    else:
        literal = make_string_literal(name)
        literal.offset = offset
        if not node.invocation_operator:
            node.invocation_operator = '&'
    literal.parent = node
    node.name = literal
    return True


class StringMethodError(Exception):
    """
    Raised by apply_string_method when a method is unknown or arguments are invalid.
    """
    pass


def apply_string_method(
    s: str,
    method: str,
    args: list,
) -> str | int | bool | list[str]:
    """
    Apply a .NET System.String instance method to a Python string with already-coerced
    arguments. Raises StringMethodError for unknown methods or invalid arguments.
    """
    def _offset(k: int):
        offset = args[k]
        if not isinstance(offset, int) or offset < 0 or offset > len(s):
            raise StringMethodError
        return offset
    if (nargs := len(args)) == 0:
        if method == 'tostring':
            return s
        if method == 'tolower':
            return s.lower()
        if method == 'toupper':
            return s.upper()
        if method == 'trim':
            return s.strip()
        if method == 'trimstart':
            return s.lstrip()
        if method == 'trimend':
            return s.rstrip()
    elif nargs == 1:
        if method == 'contains':
            return args[0] in s
        if method == 'startswith':
            return s.startswith(args[0])
        if method == 'endswith':
            return s.endswith(args[0])
        if method == 'indexof':
            return s.find(args[0])
        if method == 'split':
            if not (sep := args[0]):
                return [s]
            return re.split(F'[{re.escape(sep)}]', s)
        if method == 'substring':
            return s[_offset(0):]
        if method == 'remove':
            return s[:_offset(0)]
    elif nargs == 2:
        if method == 'replace':
            return s.replace(*args)
        if method == 'substring':
            offset, length = args
            if (
                not isinstance(offset, int)
                or not isinstance(length, int)
                or offset < 0
                or offset + length > len(s)
            ):
                raise StringMethodError
            return s[offset:offset + length]
        if method == 'insert':
            offset = _offset(0)
            return s[:offset] + args[1] + s[offset:]
        if method == 'remove':
            offset, count = args
            if (
                not isinstance(offset, int)
                or not isinstance(count, int)
                or offset < 0
                or offset + count > len(s)
            ):
                raise StringMethodError
            return s[:offset] + s[offset + count:]
    raise StringMethodError


class LocalFunctionAwareTransformer(Transformer):

    def __init__(self):
        super().__init__()
        self._local_functions: set[str] = set()
        self._entry = False

    def visit(self, node: Node):
        if self._entry:
            return super().visit(node)
        self._entry = True
        try:
            self._local_functions = {
                n.name.lower()
                for n in node.walk()
                if isinstance(n, Ps1FunctionDefinition) and n.name
            }
            return super().visit(node)
        finally:
            self._entry = False


def _apply_dotnet_format(value: str | int, spec: str) -> str | None:
    """
    Apply a .NET composite format specifier to a single value. Supports `X`/`x` (hex), `D`/`d`
    (decimal), and `N`/`n` (number). Precision width is honored for zero-padding or digit count.
    Returns `None` when the specifier is not recognized or inapplicable.
    """
    if not spec:
        return str(value)
    code = spec[0]
    width_str = spec[1:]
    width = int(width_str) if width_str.isdigit() else 0
    code_upper = code.upper()
    if code_upper in ('X', 'D', 'N') and not isinstance(value, int):
        try:
            value = int(value)
        except (ValueError, TypeError):
            return None
    if code_upper == 'X':
        if value < 0:
            value &= 0xFFFFFFFF
        raw = format(value, 'X' if code.isupper() else 'x')
        return raw.zfill(width) if width else raw
    if code_upper == 'D':
        negative = value < 0
        digits = str(abs(value))
        if width:
            digits = digits.zfill(width)
        return F'-{digits}' if negative else digits
    if code_upper == 'N':
        decimal_places = width if width else 2
        return format(value, F',.{decimal_places}f')
    return None


def normalize_type_expression(name: str) -> str:
    return name.lower().replace(' ', '')


def normalize_dotnet_type_name(name: str) -> str:
    result = normalize_type_expression(name)
    if result.startswith('system.'):
        result = result[7:]
    return result


def apply_format_string(fmt: str, args: list[str | int]) -> str | None:
    """
    Apply a PowerShell-style format string to a list of arguments. Each argument can be a string
    or an integer. Format specifiers like `{0:X2}` and alignment like `{0,10}` are supported.
    Returns the formatted string, or `None` on index/value errors.
    """
    try:
        def replacer(m: re.Match) -> str:
            full = m.group(0)
            if full == '{{':
                return '{'
            if full == '}}':
                return '}'
            idx = int(m.group(1))
            value = args[idx]
            spec = m.group(3)
            if spec:
                formatted = _apply_dotnet_format(value, spec)
                if formatted is None:
                    raise ValueError(F'unsupported format specifier: {spec}')
                result = formatted
            else:
                result = str(value)
            align_str = m.group(2)
            if align_str:
                align_width = int(align_str)
                if align_width < 0:
                    result = result.ljust(-align_width)
                else:
                    result = result.rjust(align_width)
            return result
        return FORMAT_PATTERN.sub(replacer, fmt)
    except (IndexError, ValueError):
        return None
