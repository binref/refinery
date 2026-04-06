"""
Resolve wildcard-based obfuscation patterns in PowerShell scripts.

Handles three categories of wildcard obfuscation commonly used in malware:

1. Wildcard variable access via the Variable: drive (Get-Item Variable:E*t)
2. Wildcard cmdlet resolution via GetCmdlets/Invoke with wildcard patterns
3. Wildcard member/method filtering via Where-Object pipelines
"""
from __future__ import annotations

import re

from fnmatch import translate as fnmatch_translate
from typing import Iterable

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _KNOWN_NAMES,
    _get_command_name,
    _make_string_literal,
    _string_value,
)
from refinery.lib.scripts.ps1.deobfuscation.constants import _PS1_KNOWN_VARIABLES
from refinery.lib.scripts.ps1.deobfuscation.typenames import (
    _TYPE_MEMBERS,
    resolve_expression_type,
)
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1BinaryExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
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
    candidates: Iterable[str],
) -> str | None:
    """
    Match a wildcard pattern case-insensitively against canonical names.
    Returns the name if exactly one candidate matches, else None.
    """
    regex = re.compile(fnmatch_translate(pattern), re.IGNORECASE)
    matches = [name for name in candidates if regex.match(name)]
    if len(matches) == 1:
        return matches[0]
    return None


_GET_COMMAND_ALIASES = frozenset({'get-command', 'gcm'})
_GET_MEMBER_ALIASES = frozenset({'get-member', 'gm'})


def _known_cmdlets() -> list[str]:
    return [name for name in _KNOWN_NAMES.values() if '-' in name]


def _get_member_name(member: str | Expression) -> str | None:
    if isinstance(member, str):
        return member
    if isinstance(member, Ps1StringLiteral):
        return member.value
    return None


def _is_psobject_member_access(
    expr: Expression,
    leaf_name: str,
) -> Ps1MemberAccess | None:
    """
    Check if expr is of the form `<something>.PSObject.<leaf_name>` and return
    the inner `<something>.PSObject` member access, or None.
    """
    if not isinstance(expr, Ps1MemberAccess):
        return None
    name = _get_member_name(expr.member)
    if name is None or name.lower() != leaf_name:
        return None
    inner = expr.object
    if not isinstance(inner, Ps1MemberAccess):
        return None
    ps_name = _get_member_name(inner.member)
    if ps_name is None or ps_name.lower() != 'psobject':
        return None
    return inner


def _determine_where_object_candidates(
    elements: list,
) -> Iterable[str] | None:
    """
    Examine the pipeline elements preceding Where-Object to determine which
    candidates the wildcard should match against. Returns canonical names to
    match against, or None if the source is unrecognized.
    """
    for elem in elements:
        if not isinstance(elem, Ps1PipelineElement):
            continue
        expr = elem.expression

        if isinstance(expr, Ps1CommandInvocation):
            cmd_name = _get_command_name(expr)
            if cmd_name is not None:
                cmd_lower = cmd_name.lower()
                if cmd_lower in _GET_COMMAND_ALIASES:
                    return _known_cmdlets()
                if cmd_lower in _GET_MEMBER_ALIASES:
                    return _candidates_from_get_member(elements, elem)

        if isinstance(expr, Ps1MemberAccess):
            pso = _is_psobject_member_access(expr, 'methods')
            if pso is not None:
                return _candidates_from_type(pso.object)
            pso = _is_psobject_member_access(expr, 'properties')
            if pso is not None:
                return _candidates_from_type(pso.object)

    return None


def _candidates_from_get_member(
    elements: list,
    gm_element: Ps1PipelineElement,
) -> list[str] | None:
    """
    For a pipeline like `expr | Get-Member | Where-Object ...`, resolve
    the type of the expression piped into Get-Member.
    """
    idx = None
    for i, elem in enumerate(elements):
        if elem is gm_element:
            idx = i
            break
    if idx is None or idx == 0:
        return None
    prev = elements[idx - 1]
    if not isinstance(prev, Ps1PipelineElement):
        return None
    return _candidates_from_type(prev.expression)


def _candidates_from_type(
    expr: Expression | None,
) -> list[str] | None:
    if expr is None:
        return None
    type_name = resolve_expression_type(expr)
    if type_name is None:
        return None
    return _TYPE_MEMBERS.get(type_name)


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

    def visit_Ps1MemberAccess(self, node: Ps1MemberAccess):
        self.generic_visit(node)
        replacement = self._try_resolve_variable_value(node)
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

    def _try_resolve_variable_value(
        self,
        node: Ps1MemberAccess,
    ) -> Expression | None:
        """
        Resolve (Get-Item Variable:X).Value or (Get-Variable X).Value to $X.

        Get-Item Variable:X returns a PSVariable wrapper object. Only when
        .Value is accessed do we get the actual variable value, which is
        semantically equivalent to $X.
        """
        member_name = _get_member_name(node.member)
        if member_name is None or member_name.lower() != 'value':
            return None
        inner = node.object
        while isinstance(inner, Ps1ParenExpression) and inner.expression is not None:
            inner = inner.expression
        if not isinstance(inner, Ps1CommandInvocation):
            return None
        name = _get_command_name(inner)
        if name is None:
            return None
        name_lower = name.lower()
        if name_lower not in _GET_ITEM_COMMANDS and name_lower not in _GET_VARIABLE_COMMANDS:
            return None
        arg_value = _extract_first_positional_string(inner)
        if arg_value is None:
            return None
        if name_lower in _GET_ITEM_COMMANDS:
            prefix = 'variable:'
            if not arg_value.lower().startswith(prefix):
                return None
            pattern = arg_value[len(prefix):]
        else:
            pattern = arg_value
        if _is_wildcard(pattern):
            resolved = _wildcard_match_unique(pattern, _PS1_KNOWN_VARIABLES.values())
        else:
            pattern_lower = pattern.lower()
            resolved = next(
                (v for v in _PS1_KNOWN_VARIABLES.values() if v.lower() == pattern_lower),
                pattern,
            )
        if resolved is None:
            return None
        return Ps1Variable(
            offset=node.offset,
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
        preceding = node.elements[:-1]
        candidates = _determine_where_object_candidates(preceding)
        if candidates is None:
            return None
        resolved = _wildcard_match_unique(pattern, candidates)
        if resolved is None:
            return None
        return _make_string_literal(resolved)
