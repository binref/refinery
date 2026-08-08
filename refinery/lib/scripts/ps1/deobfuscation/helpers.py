"""
Shared utilities for PowerShell deobfuscation transforms.
"""
from __future__ import annotations

import enum
import math
import re

from typing import Callable, Generator, NamedTuple, TypeGuard

from refinery.lib.scripts import Node, Transformer, set_value
from refinery.lib.scripts.ps1.analysis.cache import model_cache
from refinery.lib.scripts.ps1.analysis.types import TypeOracle
from refinery.lib.scripts.ps1.analysis.values import collect_typed_arguments, unwrap_integer
from refinery.lib.scripts.ps1.ast import (
    assignment_target_variables,
    get_member_name,
    normalize_type_expression,
    string_value,
    unwrap_assignment_target,
)
from refinery.lib.scripts.ps1.data import FOREACH_ALIASES, FORMAT_PATTERN, is_type
from refinery.lib.scripts.ps1.deobfuscation.substitution import substitute_field
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1AssignmentExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1HereString,
    Ps1IndexExpression,
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
from refinery.lib.scripts.ps1.token import BACKTICK_ENCODE


class MutationKind(enum.Enum):
    ASSIGN = 'assign'
    MEMBER_ASSIGN = 'member_assign'
    FOREACH = 'foreach'
    INCRDECR = 'incrdecr'
    PARAM = 'param'


class VariableMutation(NamedTuple):
    variable: Ps1Variable
    kind: MutationKind
    node: Node


NONPRINT_CONTROL = frozenset(BACKTICK_ENCODE) - {'\n'}


def store_dropped_to_value(rhs: Expression) -> Ps1ExpressionStatement:
    """
    The statement an expression becomes when it is lifted out of a position that swallowed its
    value: a discard of `rhs`, so the swallowing goes but whatever evaluating it does survives.

    The discard wrapper is not decoration. A bare expression statement *emits* its value, so
    rewriting `$unused = [ordered]@{ a = 1 }` to the hashtable alone makes the deobfuscated script
    print something the original never printed — and inside a function body, return it. The same
    holds for a `for` initializer, which PowerShell evaluates in a void context:
    `for ((Get-Date); $False; ) { }` prints nothing where the bare `(Get-Date)` prints the date.
    `$Null = ...` keeps the work and emits nothing, which is what both positions did.

    It is also `StatementEffect.DISCARD`, so a later pass removes it when the work it wraps is pure
    and keeps it when it is not — which is the whole of the recall this costs.

    Building this adopts `rhs`, which is why it may be built before the batch holding it is known
    to land: registering it with `refinery.lib.scripts.ps1.deobfuscation.removal.Ps1RemovalPlan`
    gives the adoption straight back, and no replacement holds a claim on the tree until that plan
    commits. A pass that builds one and never registers it owes the repair itself.
    """
    discard = Ps1AssignmentExpression(
        target=Ps1Variable(name='Null'), operator='=', value=rhs)
    return Ps1ExpressionStatement(expression=discard)


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


def unwrap_single_paren(node: Expression) -> Expression:
    if isinstance(node, Ps1ParenExpression) and node.expression is not None:
        return node.expression
    return node


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
                target = unwrap_assignment_target(node.target)
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

    Both edits go through the mutation API — the name through
    `refinery.lib.scripts.ps1.deobfuscation.substitution.substitute_field`, which is the one route
    by which a part of this tree takes another's place, and the operator through
    `refinery.lib.scripts.set_value` — so the rewrite advances the tree's mutation counter and every
    analysis model over it is rebuilt from the name now written rather than the one it replaced.
    Assigning the two fields directly left that counter standing, and a caller was consistent with
    the tree only for as long as it also announced the edit through
    `refinery.lib.scripts.Transformer.mark_changed`, which is a second channel the counter exists so
    as not to depend on.

    The operator is written only once the name has landed, because a substitution that would drop a
    redirection is refused and the command then runs exactly as written, call operator included.
    """
    if node.name is not None and string_value(node.name) == name:
        return False
    offset = node.name.offset if node.name is not None else -1
    bare = is_bare_command_name(name)
    if bare:
        literal: Ps1StringLiteral | Ps1HereString = Ps1StringLiteral(
            offset=offset, value=name, raw=name)
    else:
        literal = make_string_literal(name)
        literal.offset = offset
    if not substitute_field(node, 'name', literal):
        return False
    if not bare and not node.invocation_operator:
        set_value(node, 'invocation_operator', '&')
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


class OracleAwareTransformer(Transformer):
    """
    A transform whose every purity verdict is asked through the run's shared
    `refinery.lib.scripts.ps1.analysis.types.TypeOracle`, read once at entry from the model cache
    rather than reconstructed per node. One shared oracle is what keeps two transforms in a run from
    reaching opposite conclusions about the same node, and reading it before this run's own edits can
    only make the answer the more open — and so the more conservative — of the two. See
    `refinery.lib.scripts.ps1.deobfuscation.unused.Ps1DeadStoreElimination` for why the single oracle
    is load-bearing. Which command a name denotes — the other question a transform must not answer
    privately — is the command model's, read through
    `refinery.lib.scripts.ps1.analysis.commands.Ps1CommandModel`.
    """

    def __init__(self):
        super().__init__()
        self._oracle: TypeOracle | None = None
        self._entry = False

    def visit(self, node: Node):
        if self._entry:
            return super().visit(node)
        self._entry = True
        try:
            self._oracle = model_cache(self, node).oracle
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
