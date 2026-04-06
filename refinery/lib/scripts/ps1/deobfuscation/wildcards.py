"""
Resolve wildcard-based obfuscation patterns in PowerShell scripts.

Handles three categories of wildcard obfuscation commonly used in malware:

1. Wildcard variable access via the Variable: drive (Get-Item Variable:E*t)
2. Wildcard cmdlet resolution via GetCmdlets/Invoke with wildcard patterns
3. Wildcard member/method filtering via Where-Object pipelines
"""
from __future__ import annotations

from fnmatch import fnmatch

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _KNOWN_NAMES,
    _get_command_name,
    _make_string_literal,
    _string_value,
)
from refinery.lib.scripts.ps1.deobfuscation.constants import _PS1_KNOWN_VARIABLES
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1BinaryExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1ScriptBlock,
    Ps1ScopeModifier,
    Ps1StringLiteral,
    Ps1Variable,
)

_GET_ITEM_COMMANDS = frozenset({'get-item', 'gi'})
_GET_VARIABLE_COMMANDS = frozenset({'get-variable', 'gv'})
_WHERE_OBJECT_ALIASES = frozenset({'?', 'where', 'where-object'})
_LIKE_OPERATORS = frozenset({'-like', '-ilike', '-clike'})


def _is_wildcard(pattern: str) -> bool:
    return '*' in pattern or '?' in pattern


def _wildcard_match_unique(
    pattern: str,
    candidates: dict[str, str],
) -> str | None:
    """
    Match a wildcard pattern against a dictionary of {lower_name: canonical_name}.
    Returns the canonical name if exactly one candidate matches, else None.
    """
    matches = [
        canonical
        for lower, canonical in candidates.items()
        if fnmatch(lower, pattern.lower())
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def _known_cmdlets() -> dict[str, str]:
    return {
        lower: canonical
        for lower, canonical in _KNOWN_NAMES.items()
        if '-' in canonical
    }


def _extract_first_positional_string(
    cmd: Ps1CommandInvocation,
) -> str | None:
    for arg in cmd.arguments:
        if isinstance(arg, Ps1CommandArgument):
            if arg.kind == Ps1CommandArgumentKind.POSITIONAL:
                return _string_value(arg.value) if arg.value else None
        elif isinstance(arg, Expression):
            return _string_value(arg)
    return None


def _extract_where_object_wildcard(
    cmd: Ps1CommandInvocation,
) -> str | None:
    """
    Detect Where-Object with a scriptblock body of the form:
        $_.Name -ilike 'pattern'
    Returns the pattern string, or None.
    """
    name = _get_command_name(cmd)
    if name is None or name.lower() not in _WHERE_OBJECT_ALIASES:
        return None
    if len(cmd.arguments) != 1:
        return None
    arg = cmd.arguments[0]
    if isinstance(arg, Ps1CommandArgument):
        if arg.kind != Ps1CommandArgumentKind.POSITIONAL:
            return None
        arg = arg.value
    if not isinstance(arg, Ps1ScriptBlock):
        return None
    body = arg.body
    if len(body) != 1:
        return None
    stmt = body[0]
    expr = None
    if isinstance(stmt, Ps1ExpressionStatement):
        expr = stmt.expression
    elif isinstance(stmt, Ps1Pipeline):
        if len(stmt.elements) == 1:
            elem = stmt.elements[0]
            if isinstance(elem, Ps1PipelineElement):
                expr = elem.expression
    if not isinstance(expr, Ps1BinaryExpression):
        return None
    if expr.operator.lower() not in _LIKE_OPERATORS:
        return None
    left = expr.left
    if not isinstance(left, Ps1MemberAccess):
        return None
    if not isinstance(left.object, Ps1Variable):
        return None
    if left.object.name != '_':
        return None
    member = left.member
    if isinstance(member, str):
        member_name = member
    elif isinstance(member, Ps1StringLiteral):
        member_name = member.value
    else:
        return None
    if member_name.lower() != 'name':
        return None
    if expr.right is None:
        return None
    return _string_value(expr.right)


class Ps1WildcardResolution(Transformer):

    def visit_Ps1CommandInvocation(self, node: Ps1CommandInvocation):
        self.generic_visit(node)
        replacement = self._try_resolve_variable_drive(node)
        if replacement is not None:
            return replacement
        return None

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        self.generic_visit(node)
        replacement = self._try_resolve_cmdlet_method(node)
        if replacement is not None:
            return replacement
        return None

    def visit_Ps1Pipeline(self, node: Ps1Pipeline):
        self.generic_visit(node)
        replacement = self._try_resolve_where_object_wildcard(node)
        if replacement is not None:
            return replacement
        return None

    def _try_resolve_variable_drive(
        self,
        cmd: Ps1CommandInvocation,
    ) -> Expression | None:
        name = _get_command_name(cmd)
        if name is None:
            return None
        name_lower = name.lower()
        if name_lower not in _GET_ITEM_COMMANDS and name_lower not in _GET_VARIABLE_COMMANDS:
            return None
        arg_value = _extract_first_positional_string(cmd)
        if arg_value is None:
            return None
        if name_lower in _GET_ITEM_COMMANDS:
            prefix = 'variable:'
            if not arg_value.lower().startswith(prefix):
                return None
            pattern = arg_value[len(prefix):]
        else:
            pattern = arg_value
        if not _is_wildcard(pattern):
            return None
        resolved = _wildcard_match_unique(pattern, _PS1_KNOWN_VARIABLES)
        if resolved is None:
            return None
        return Ps1Variable(
            offset=cmd.offset,
            name=resolved,
            scope=Ps1ScopeModifier.NONE,
        )

    def _try_resolve_cmdlet_method(
        self,
        node: Ps1InvokeMember,
    ) -> Expression | None:
        member = node.member
        if isinstance(member, Ps1StringLiteral):
            member_name = member.value
        elif isinstance(member, str):
            member_name = member
        else:
            return None
        member_lower = member_name.lower()
        is_getcmdlets = member_lower in ('getcmdlets', 'getcmdlet')
        is_invoke = member_lower == 'invoke'
        if not is_getcmdlets and not is_invoke:
            return None
        if len(node.arguments) != 1:
            return None
        pattern = _string_value(node.arguments[0])
        if pattern is None or not _is_wildcard(pattern):
            return None
        if is_invoke and '-' not in pattern:
            return None
        cmdlets = _known_cmdlets()
        resolved = _wildcard_match_unique(pattern, cmdlets)
        if resolved is None:
            return None
        return _make_string_literal(resolved)

    def _try_resolve_where_object_wildcard(
        self,
        node: Ps1Pipeline,
    ) -> Expression | None:
        if len(node.elements) < 2:
            return None
        last_elem = node.elements[-1]
        if not isinstance(last_elem, Ps1PipelineElement):
            return None
        if last_elem.redirections:
            return None
        cmd = last_elem.expression
        if not isinstance(cmd, Ps1CommandInvocation):
            return None
        pattern = _extract_where_object_wildcard(cmd)
        if pattern is None or not _is_wildcard(pattern):
            return None
        resolved = _wildcard_match_unique(pattern, _KNOWN_NAMES)
        if resolved is None:
            return None
        return _make_string_literal(resolved)
