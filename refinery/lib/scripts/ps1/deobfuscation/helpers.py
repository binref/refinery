"""
Shared utilities for PowerShell deobfuscation transforms.
"""
from __future__ import annotations

import io
import re

from collections.abc import Callable, Generator
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from typing import TypeGuard

from refinery.lib.scripts import Block, Node, Transformer
from refinery.lib.scripts.ps1.deobfuscation.names import (
    BUILTIN_VARIABLES,
    FOREACH_ALIASES,
    normalize_type_expression,
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
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1ScopeModifier,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.token import BACKTICK_ESCAPE

_T = TypeVar('_T')

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
    if has_newline and not has_nonprint:
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


def extract_int(node: Expression) -> int | None:
    return node.value if isinstance(node, Ps1IntegerLiteral) else None


def collect_int_arguments(node: Expression) -> list[int] | None:
    if isinstance(node, Ps1ParenExpression) and node.expression is not None:
        return collect_int_arguments(node.expression)
    return collect_typed_arguments(node, extract_int)


def collect_byte_array(node: Expression) -> bytes | None:
    """
    Extract an integer array from `node` and convert to `bytes`. Handles `Ps1ArrayLiteral`,
    `Ps1ArrayExpression`, and parenthesized wrappers.
    """
    array = unwrap_to_array_literal(node)
    if array is not None:
        node = array
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


def unwrap_parens(node: Node) -> Node:
    """
    Unwrap nested `Ps1ParenExpression` wrappers, stopping at an empty-parens node.
    """
    while isinstance(node, Ps1ParenExpression) and node.expression is not None:
        node = node.expression
    return node


def unwrap_to_array_literal(node: Node) -> Ps1ArrayLiteral | None:
    """
    Unwrap parentheses and array expressions to find an inner `Ps1ArrayLiteral`.
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
    from refinery.lib.scripts.ps1.deobfuscation.typenames import is_type
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
    from refinery.lib.scripts.ps1.deobfuscation.typenames import is_type
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


def iter_variable_mutations(
    root: Node,
) -> Generator[tuple[Ps1Variable, str, Node], None, None]:
    """
    Walk the AST and yield `(variable, kind, node)` for every node that mutates a variable.
    `kind` is one of 'assign', 'foreach', 'incrdecr', 'param'.
    """
    for node in root.walk():
        if isinstance(node, Ps1AssignmentExpression):
            target = node.target
            while isinstance(target, (Ps1ParenExpression, Ps1CastExpression)):
                target = target.expression if isinstance(target, Ps1ParenExpression) else target.operand
            if isinstance(target, Ps1Variable):
                yield target, 'assign', node
        elif isinstance(node, Ps1ForEachLoop):
            if isinstance(node.variable, Ps1Variable):
                yield node.variable, 'foreach', node
        elif isinstance(node, Ps1UnaryExpression):
            if node.operator in ('++', '--') and isinstance(node.operand, Ps1Variable):
                yield node.operand, 'incrdecr', node
        elif isinstance(node, Ps1ParameterDeclaration):
            if isinstance(node.variable, Ps1Variable):
                yield node.variable, 'param', node


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
    Return `True` when `node` is an unscoped `Ps1Variable` whose lowered name is in `names` (defaults
    to `$Null`, `$True`, `$False`).
    """
    return (
        isinstance(node, Ps1Variable)
        and node.scope == Ps1ScopeModifier.NONE
        and node.name.lower() in names
    )


def is_array_reverse_call(node: Ps1ExpressionStatement) -> Ps1Variable | None:
    """
    If the statement is `[Array]::Reverse($var)`, return the variable node.
    """
    from refinery.lib.scripts.ps1.deobfuscation.typenames import is_type
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
