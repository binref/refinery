"""
Shared utilities for PowerShell deobfuscation transforms.
"""
from __future__ import annotations

import math
import re

from typing import Callable, TypeGuard

from refinery.lib.scripts import Node, set_value
from refinery.lib.scripts.ps1.analysis.values import (
    coerced_text,
    collect_facts,
    integer_of,
    make_string_literal,
)
from refinery.lib.scripts.ps1.ast import get_member_name, resolve_command_name, string_value
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
    Ps1HereString,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1ScopeModifier,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1TypeExpression,
    Ps1Variable,
)


def store_dropped_to_value(rhs: Expression) -> Ps1ExpressionStatement:
    """
    The statement an expression becomes when it is lifted out of a position that swallowed its
    value: a discard of `rhs`, so the swallowing goes but whatever evaluating it does survives.

    The discard wrapper is not decoration. A bare expression statement *emits* its value, so
    rewriting `$unused = [ordered]@{ a = 1 }` to the hashtable alone makes the deobfuscated script
    print something the original never printed — and inside a function body, return it. The same
    holds for a `for` initializer, which PowerShell evaluates in a void context:
    `for ((Get-Date); $False; ) { }` prints nothing where the bare `(Get-Date)` prints the date.
    `$Null = ...` keeps the work and emits nothing. It carries `StatementEffect.DISCARD`, so a later
    pass drops it when the work it wraps is pure.
    """
    discard = Ps1AssignmentExpression(
        target=Ps1Variable(name='Null'), operator='=', value=rhs)
    return Ps1ExpressionStatement(expression=discard)


def collect_format_arguments(node: Expression) -> list[str | int] | None:
    """
    The values a `-f` operator's right-hand side hands to the format string, each as the number it
    names or else as the text it coerces to. The number is what a numeric specifier needs — `'{0:X}'
    -f 255` is `FF` and the digits of the text would not be — and everything else contributes what
    `[string]` of it produces, which is what every other string operator does with an operand.
    """
    facts = collect_facts(node)
    if facts is None:
        return None
    arguments: list[str | int] = []
    for fact in facts:
        number = integer_of(fact)
        if number is not None:
            arguments.append(number)
            continue
        text = coerced_text(fact)
        if text is None:
            return None
        arguments.append(text)
    return arguments


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
    return is_type(node.object.name, canonical)


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
    if not is_type(obj.object.name, 'System.Text.Encoding'):
        return None
    enc_name = get_member_name(obj.member)
    return enc_name


def extract_foreach_scriptblock(
    expr: Expression,
    shadowed: frozenset[str] = frozenset(),
) -> Ps1ScriptBlock | None:
    """
    The script block a `ForEach-Object` invocation runs once per input object, or `None` when
    *expr* is not one of `%`, `foreach` or `ForEach-Object` carrying a single positional block.

    *shadowed* is the whole-run set of command names the script has taken over
    (`refinery.lib.scripts.ps1.analysis.world.Ps1TypeWorld.shadowed_names`). The three spellings
    all resolve to `foreach-object`, and a script that redefines that name runs its own body where
    the block would otherwise run: measured on 5.1, `function ForEach-Object { 'H' }` makes
    `1, 2 | % { $_ * 2 }` write `H`, not `2 4`, so a caller that folds the block as the cmdlet's
    must pass the set and this refuses where the name is in it. The default is empty, so a caller
    with no world reads the name at face value.
    """
    if not isinstance(expr, Ps1CommandInvocation):
        return None
    if not isinstance(expr.name, Ps1StringLiteral):
        return None
    if expr.name.value.lower() not in FOREACH_ALIASES:
        return None
    if resolve_command_name(expr) in shadowed:
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


def stands_where_only_a_command_may(node: Node) -> bool:
    """
    Whether *node* fills a pipeline element that only a command may fill, so replacing it with a
    value writes a script PowerShell will not parse.

    An expression is allowed as the *first* element of a pipeline and nowhere else. Measured on 5.1:
    `function zzqf { 'H' }; $r = 'x' | zzqf; Write-Host ('r=' + $r)` prints `r=H`, and the same
    script with the call replaced by its value writes `ExpressionsMustBeFirstInPipeline` and runs
    nothing at all.

    A single-element pipeline is not one of these: its only element is the first.
    """
    element = node.parent
    if not isinstance(element, Ps1PipelineElement):
        return False
    pipeline = element.parent
    if not isinstance(pipeline, Ps1Pipeline):
        return False
    return bool(pipeline.elements) and pipeline.elements[0] is not element


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


_REGEX_GROUP_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


def _character_class_end(pattern: str, start: int) -> int:
    """
    The index one past the character class that opens at `start`, where `pattern[start]` is `[`. A
    `]` at the front of a class (after an optional `^`) is a literal, a backslash carries the
    character behind it across, and a class that never closes runs to the end — where Python's own
    engine then refuses it, the same refusal an untranslated pattern already earns.
    """
    j = start + 1
    n = len(pattern)
    if j < n and pattern[j] == '^':
        j += 1
    if j < n and pattern[j] == ']':
        j += 1
    while j < n and pattern[j] != ']':
        j += 2 if pattern[j] == '\\' else 1
    return min(j + 1, n)


def dotnet_regex_pattern(pattern: str) -> str:
    """
    Rewrite a .NET regular expression into the one Python's `re` compiles, in the single place the
    two dialects name one construct differently: a *named* group. .NET writes it `(?<name>...)` or
    `(?'name'...)`, and refers back to it as `\\k<name>` or `\\k'name'`; Python writes these
    `(?P<name>...)` and `(?P=name)`. Every other piece the two spell alike, so a pattern that names
    no group is returned unchanged, and one Python already rejects is left for its own engine to
    reject.

    Three things share the `(?<` opening but are not a named group and must not be rewritten: a
    look-behind `(?<=...)`/`(?<!...)`, a `(?<` a backslash makes literal, and one inside a character
    class `[...]`, where every metacharacter is text.

    A pattern that mixes a named group with an *unnamed* one is left untranslated, because the two
    dialects disagree about what number the named one takes: .NET numbers every unnamed group first
    and the named ones after, while Python numbers strictly by position. A numeric token — a `\1`
    backreference or a `$1` in the replacement — would then resolve to a different group than 5.1
    reads, so `'ab' -replace '(?<n>a)(b)', '$1'` is `b` on the host and would fold to `a`. Returning
    the pattern unchanged leaves the `(?<name>` for Python's engine to reject. A pattern whose groups
    are all named, or all unnamed, numbers alike in both and is translated.
    """
    out: list[str] = []
    i = 0
    n = len(pattern)
    named = False
    unnamed = False
    while i < n:
        c = pattern[i]
        if c == '\\':
            if pattern.startswith((r'\k<', r"\k'"), i):
                close = '>' if pattern[i + 2] == '<' else "'"
                end = pattern.find(close, i + 3)
                name = pattern[i + 3:end] if end > 0 else ''
                if _REGEX_GROUP_NAME.fullmatch(name):
                    out.append(F'(?P={name})')
                    i = end + 1
                    continue
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if c == '[':
            end = _character_class_end(pattern, i)
            out.append(pattern[i:end])
            i = end
            continue
        if pattern.startswith('(?<', i) and i + 3 < n and pattern[i + 3] not in '=!':
            end = pattern.find('>', i + 3)
            name = pattern[i + 3:end] if end > 0 else ''
            if _REGEX_GROUP_NAME.fullmatch(name):
                out.append(F'(?P<{name}>')
                named = True
                i = end + 1
                continue
        elif pattern.startswith("(?'", i):
            end = pattern.find("'", i + 3)
            name = pattern[i + 3:end] if end > 0 else ''
            if _REGEX_GROUP_NAME.fullmatch(name):
                out.append(F'(?P<{name}>')
                named = True
                i = end + 1
                continue
        if c == '(' and not pattern.startswith('(?', i):
            unnamed = True
        out.append(c)
        i += 1
    return pattern if named and unnamed else ''.join(out)


def dotnet_regex_replace(pattern: str, replacement: str, text: str, *, flags: int = 0) -> str:
    """
    Replace every match of `pattern` in `text` with the .NET-style `replacement`, honoring .NET
    substitution tokens and .NET's spelling of a named group (see `dotnet_regex_pattern`).
    Replace-all is direction independent, so the regex `RightToLeft` option does not change the
    result here.
    """
    return re.sub(
        dotnet_regex_pattern(pattern),
        _dotnet_replacement(replacement, text),
        text,
        flags=flags,
    )


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
    `refinery.lib.scripts.ps1.deobfuscation.substitution.substitute_field` and the operator through
    `refinery.lib.scripts.set_value` — so the rewrite advances the tree's mutation counter and every
    analysis model over it is rebuilt from the name now written.

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
