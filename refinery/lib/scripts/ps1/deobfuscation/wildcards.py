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

from refinery.lib.scripts.ps1.analysis.values import (
    Ps1VariableTyping,
    make_string_literal,
    resolve_expression_type,
)
from refinery.lib.scripts.ps1.ast import (
    argument_text,
    binds_parameter,
    bound_argument_value,
    free_positional_values,
    get_command_name,
    get_member_name,
    resolve_command_name,
    string_value,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.data import (
    GET_COMMAND_ALIASES,
    GET_MEMBER_ALIASES,
    KNOWN_CMDLETS,
    PS1_KNOWN_VARIABLES,
    member_names,
)
from refinery.lib.scripts.ps1.deobfuscation.substitution import substituted
from refinery.lib.scripts.ps1.deobfuscation.typenames import VariableTypeAwareTransformer
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AssignmentExpression,
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
    Ps1ScopeModifier,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1Variable,
)

_GET_ITEM_COMMANDS = frozenset({'get-item', 'gi', 'get-childitem', 'gci'})
_GET_VARIABLE_COMMANDS = frozenset({'get-variable', 'gv'})
_SET_ITEM_COMMANDS = frozenset({'set-item', 'si'})
_SET_VARIABLE_COMMANDS = frozenset({'set-variable', 'sv', 'set'})
_WHERE_OBJECT_ALIASES = frozenset({'?', 'where', 'where-object'})
_LIKE_OPERATORS = frozenset({'-like', '-ilike', '-clike'})


def _is_wildcard(pattern: str) -> bool:
    return '*' in pattern or '?' in pattern


def _wildcard_match_unique(
    pattern: str,
    candidates: Iterable[str],
) -> str | None:
    """
    Match a wildcard pattern case-insensitively against canonical names. Returns the name if one
    exact candidate matches, else `None`.
    """
    regex = re.compile(fnmatch_translate(pattern), re.IGNORECASE)
    matches = [name for name in candidates if regex.match(name)]
    if len(matches) == 1:
        return matches[0]
    return None


_KNOWN_CMDLET_LIST: list[str] = list(KNOWN_CMDLETS.values())


def _known_cmdlets() -> list[str]:
    return _KNOWN_CMDLET_LIST


def _is_psobject_member_access(
    expr: Expression,
    leaf_name: str,
) -> Ps1MemberAccess | None:
    """
    Check if expr is of the form `<something>.PSObject.<leaf_name>` and return the inner member
    access to `<something>.PSObject`, or `None`.
    """
    if not isinstance(expr, Ps1MemberAccess):
        return None
    name = get_member_name(expr.member)
    if name is None or name.lower() != leaf_name:
        return None
    inner = expr.object
    if not isinstance(inner, Ps1MemberAccess):
        return None
    ps_name = get_member_name(inner.member)
    if ps_name is None or ps_name.lower() != 'psobject':
        return None
    return inner


def _determine_where_object_candidates(
    elements: list,
    type_of_variable: Ps1VariableTyping | None = None,
) -> Iterable[str] | None:
    """
    Examine the pipeline elements preceding `Where-Object` to determine which candidates the
    wildcard should match against. Returns canonical names to match against, or `None` if the source
    is unrecognized.
    """
    for elem in elements:
        if not isinstance(elem, Ps1PipelineElement):
            continue
        expr = elem.expression
        while isinstance(expr, Ps1ParenExpression) and expr.expression is not None:
            inner = expr.expression
            if isinstance(inner, Ps1Pipeline):
                result = _determine_where_object_candidates(
                    inner.elements, type_of_variable,
                )
                if result is not None:
                    return result
                break
            expr = inner

        if isinstance(expr, Ps1CommandInvocation):
            cmd_name = get_command_name(expr)
            if cmd_name is not None:
                cmd_lower = cmd_name.lower()
                if cmd_lower in GET_COMMAND_ALIASES:
                    return _known_cmdlets()
                if cmd_lower in GET_MEMBER_ALIASES:
                    return _candidates_from_get_member(
                        elements, elem, type_of_variable,
                    )

        if isinstance(expr, Ps1MemberAccess):
            pso = _is_psobject_member_access(expr, 'methods')
            if pso is not None:
                return _candidates_from_type(pso.object, type_of_variable)
            pso = _is_psobject_member_access(expr, 'properties')
            if pso is not None:
                return _candidates_from_type(pso.object, type_of_variable)

    return None


def _candidates_from_get_member(
    elements: list,
    gm_element: Ps1PipelineElement,
    type_of_variable: Ps1VariableTyping | None = None,
) -> list[str] | None:
    """
    For a pipeline like `expr | Get-Member | Where-Object ...`, resolve the type of the expression
    piped into `Get-Member`.
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
    return _candidates_from_type(prev.expression, type_of_variable)


def _candidates_from_type(
    expr: Expression | None,
    type_of_variable: Ps1VariableTyping | None = None,
) -> list[str] | None:
    if expr is None:
        return None
    type_name = resolve_expression_type(expr, type_of_variable)
    if type_name is None:
        return None
    return member_names(type_name)


def _concat_expressions(exprs: list[Expression]) -> Expression:
    """
    Build a left-associative `+` chain from a list of expressions.
    """
    result = exprs[0]
    for expr in exprs[1:]:
        result = Ps1BinaryExpression(
            offset=expr.offset,
            left=result,
            operator='+',
            right=expr,
        )
    return result


def _has_valueonly_switch(cmd: Ps1CommandInvocation) -> bool:
    """
    Check if a command has a switch that is any unambiguous abbreviation of `-ValueOnly`; this is
    true even for just `-v` since no other flag starts with `v`.
    """
    for arg in cmd.arguments:
        if not isinstance(arg, Ps1CommandArgument):
            continue
        if arg.kind != Ps1CommandArgumentKind.SWITCH:
            continue
        if arg.name.lower().startswith('-v'):
            return True
    return False


#: The `-Scope` arguments a variable reference can express, mapped to the qualifier that expresses
#: them. `Local` needs none, since an unqualified reference means the scope it stands in. Every
#: other spelling — `-Scope 1`, which names the *caller's* scope, an unrecognised word, a computed
#: expression — names a scope no qualifier reaches, and the rewrite is declined rather than
#: approximated.
_EXPRESSIBLE_SCOPES: dict[str, Ps1ScopeModifier] = {
    'global': Ps1ScopeModifier.GLOBAL,
    'local': Ps1ScopeModifier.NONE,
    'private': Ps1ScopeModifier.PRIVATE,
    'script': Ps1ScopeModifier.SCRIPT,
}


#: Parameters whose effect an assignment cannot carry, so binding one declines the rewrite.
#:
#: Measured: after `New-Variable x -Option ReadOnly` a later `$x = …` raises
#: `SessionStateUnauthorizedAccessException`, where after `$x = …` it succeeds — so the option is
#: not decoration, it decides what every later store in the script does. `-PassThru` makes the
#: command emit the variable object, which an assignment does not emit, and `-Force` is what lets a
#: write land on a name an option protects.
#:
#: `-Description` is deliberately absent: it is metadata no read or write observes. Anything not
#: listed is *allowed*, which is the wrong polarity for a corruption and the right one for a
#: rewrite — see `refinery.lib.scripts.ps1.analysis.naming` on why the two tables differ.
_INEXPRESSIBLE_PARAMETERS = (
    'force',
    'option',
    'passthru',
    'visibility',
)


def _expresses_every_effect(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether an assignment carries everything *cmd* does, or drops an effect on the floor.
    """
    for argument in cmd.arguments:
        if not isinstance(argument, Ps1CommandArgument):
            continue
        if any(binds_parameter(argument.name, name) for name in _INEXPRESSIBLE_PARAMETERS):
            return False
    return True


def _subject_argument_value(
    cmd: Ps1CommandInvocation,
    command: str,
    parameter: str,
) -> str | None:
    """
    The literal name *cmd* is about, written either as `-Name x` / `-Path x` or as the first
    argument it binds by position, or `None` when it is not a literal this can read. The same
    reading `refinery.lib.scripts.ps1.analysis.naming` takes, down to
    `refinery.lib.scripts.ps1.ast.argument_text`, so the two layers agree on which argument a
    variable command names *and* on what it is called.
    """
    explicit = bound_argument_value(cmd, parameter)
    if explicit is not None:
        return argument_text(explicit)
    for value in free_positional_values(cmd, command):
        return argument_text(value)
    return None


def _expressible_scope(
    node: Ps1CommandInvocation,
    var_name: str,
) -> Ps1ScopeModifier | None:
    """
    The qualifier the variable reference replacing *node* must carry, or `None` when no reference
    can stand for the command. A name that already carries a qualifier of its own is declined
    whenever a `-Scope` argument is present too, since the two would have to be rendered one inside
    the other.
    """
    declared = bound_argument_value(node, 'scope')
    if declared is None:
        return Ps1ScopeModifier.NONE
    if ':' in var_name:
        return None
    written = string_value(declared)
    if written is None:
        return None
    return _EXPRESSIBLE_SCOPES.get(written.lower())


def _resolve_variable_name(
    pattern: str,
) -> str | None:
    """
    Resolve a variable name pattern (possibly wildcard) to a canonical name. Returns the resolved
    name, or the pattern itself for non-wildcard names.
    """
    if _is_wildcard(pattern):
        return _wildcard_match_unique(pattern, PS1_KNOWN_VARIABLES.values())
    pattern_lower = pattern.lower()
    return next(
        (v for v in PS1_KNOWN_VARIABLES.values() if v.lower() == pattern_lower),
        pattern,
    )


def _extract_where_object_wildcard(
    cmd: Ps1CommandInvocation,
) -> str | None:
    """
    Detect Where-Object with a scriptblock body of the form:

        $_.Name -ilike 'pattern'

    Returns the pattern string, or `None`.
    """
    name = get_command_name(cmd)
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
    if left.object.name.lower() not in ('_', 'psitem'):
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
    return string_value(expr.right)


class Ps1WildcardResolution(VariableTypeAwareTransformer):

    def visit_Ps1MemberAccess(self, node: Ps1MemberAccess):
        self.generic_visit(node)
        return substituted(node, self._try_resolve_variable_value(node))

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        self.generic_visit(node)
        return substituted(node, self._try_resolve_cmdlet_method(node))

    def visit_Ps1Pipeline(self, node: Ps1Pipeline):
        self.generic_visit(node)
        return substituted(node, self._try_resolve_where_object_wildcard(node))

    def visit_Ps1CommandInvocation(self, node: Ps1CommandInvocation):
        self.generic_visit(node)
        replacement = self._try_resolve_get_variable_value_only(node)
        if replacement is None:
            replacement = self._try_resolve_set_variable(node)
        return substituted(node, replacement)

    def _try_resolve_variable_value(
        self,
        node: Ps1MemberAccess,
    ) -> Expression | None:
        """
        Resolve property access on `Get-Item Variable:X` or `Get-Variable X`:

        - `.Value` resolves to `$X` (the variable's value)
        - `.Name` resolves to `'X'` as a string literal (the variable's name)

        `Get-Item Variable:X` and `Get-Variable X` return a `PSVariable` wrapper object whose
        `.Value` property gives the actual variable content and `.Name` property gives its name.
        """
        member_name = get_member_name(node.member)
        if member_name is None:
            return None
        member_lower = member_name.lower()
        if member_lower not in ('value', 'name'):
            return None
        if node.object is None:
            return None
        found = self._resolve_get_variable_pattern(node.object)
        if found is None:
            return None
        resolved, scope = found
        if member_lower == 'value':
            if scope is None:
                return None
            return Ps1Variable(
                offset=node.offset,
                name=resolved,
                scope=scope,
            )
        return make_string_literal(resolved)

    @staticmethod
    def _resolve_get_variable_pattern(
        expr: Expression,
    ) -> tuple[str, Ps1ScopeModifier | None] | None:
        """
        Given the object expression of a member access, check if it is a `Get-Item Variable:X` or
        `Get-Variable X` invocation and resolve the variable name (supporting wildcards) together
        with the qualifier a reference replacing it must carry.

        The qualifier is `None` for a `-Scope` no reference can name, which only the `.Value`
        rewrite has to decline: the name a command is about is that name whichever scope it reads.
        """
        inner = unwrap_parens(expr)
        if not isinstance(inner, Ps1CommandInvocation):
            return None
        name = get_command_name(inner)
        if name is None:
            return None
        name_lower = name.lower()
        if name_lower not in _GET_ITEM_COMMANDS and name_lower not in _GET_VARIABLE_COMMANDS:
            return None
        command = resolve_command_name(inner)
        if command is None:
            return None
        subject = 'path' if name_lower in _GET_ITEM_COMMANDS else 'name'
        arg_value = _subject_argument_value(inner, command, subject)
        if arg_value is None:
            return None
        if name_lower in _GET_ITEM_COMMANDS:
            prefix = 'variable:'
            if not arg_value.lower().startswith(prefix):
                return None
            pattern = arg_value[len(prefix):]
            pattern = pattern.lstrip('/\\')
        else:
            pattern = arg_value
        resolved = _resolve_variable_name(pattern)
        if resolved is None:
            return None
        return resolved, _expressible_scope(inner, resolved)

    def _try_resolve_get_variable_value_only(
        self,
        node: Ps1CommandInvocation,
    ) -> Expression | None:
        """
        Resolve `Get-Variable X -ValueOnly` to `$X`.
        """
        cmd_name = get_command_name(node)
        if cmd_name is None or cmd_name.lower() not in _GET_VARIABLE_COMMANDS:
            return None
        if not _has_valueonly_switch(node):
            return None
        command = resolve_command_name(node)
        if command is None:
            return None
        name_expr = bound_argument_value(node, 'name')
        if name_expr is None:
            positionals = free_positional_values(node, command)
            if not positionals:
                return None
            name_expr = positionals[0]
        arg_value = argument_text(name_expr)
        if arg_value is None:
            return None
        resolved = _resolve_variable_name(arg_value)
        if resolved is None:
            return None
        scope = _expressible_scope(node, resolved)
        if scope is None:
            return None
        return Ps1Variable(
            offset=node.offset,
            name=resolved,
            scope=scope,
        )

    def _try_resolve_cmdlet_method(
        self,
        node: Ps1InvokeMember,
    ) -> Expression | None:
        member_name = get_member_name(node.member)
        if member_name is None:
            return None
        member_lower = member_name.lower()
        is_getcmdlets = member_lower in ('getcmdlets', 'getcmdlet')
        is_getcommand = member_lower in ('getcommandname', 'getcommand')
        is_invoke = member_lower == 'invoke'
        if not is_getcmdlets and not is_getcommand and not is_invoke:
            return None
        if len(node.arguments) < 1:
            return None
        pattern = string_value(node.arguments[0])
        if pattern is None:
            return None
        if is_invoke and '-' not in pattern:
            return None
        cmdlets = _known_cmdlets()
        if _is_wildcard(pattern):
            resolved = _wildcard_match_unique(pattern, cmdlets)
        else:
            resolved = next(
                (c for c in cmdlets if c.lower() == pattern.lower()), None)
        if resolved is None:
            return None
        return make_string_literal(resolved)

    def _try_resolve_where_object_wildcard(
        self,
        node: Ps1Pipeline,
    ) -> Expression | None:
        if len(node.elements) < 2:
            return None
        last_elem = node.elements[-1]
        if not isinstance(last_elem, Ps1PipelineElement):
            return None
        cmd = last_elem.expression
        if not isinstance(cmd, Ps1CommandInvocation):
            return None
        pattern = _extract_where_object_wildcard(cmd)
        if pattern is None or not _is_wildcard(pattern):
            return None
        preceding = node.elements[:-1]
        candidates = _determine_where_object_candidates(
            preceding, self._type_of_variable,
        )
        if candidates is None:
            return None
        resolved = _wildcard_match_unique(pattern, candidates)
        if resolved is None:
            return None
        return make_string_literal(resolved)

    def _try_resolve_set_variable(
        self,
        node: Ps1CommandInvocation,
    ) -> Expression | None:
        """
        Resolve Set-Item Variable:X value or Set-Variable X value to $X = value.
        """
        cmd_name = get_command_name(node)
        if cmd_name is None:
            return None
        command = resolve_command_name(node)
        if command is None:
            return None
        cmd_lower = cmd_name.lower()
        if cmd_lower in _SET_ITEM_COMMANDS:
            return self._handle_set_item_variable(node, command)
        if cmd_lower in _SET_VARIABLE_COMMANDS:
            return self._handle_set_variable(node, command)
        return None

    def _handle_set_item_variable(
        self,
        node: Ps1CommandInvocation,
        command: str,
    ) -> Expression | None:
        """
        Set-Item Variable:/X val1 val2 → $X = val1 + val2

        `-Path` and `-Value` name the same two arguments the positional spelling does, and a command
        binding either of them by name leaves nothing free for the positional reading to find.
        """
        positionals = free_positional_values(node, command)
        path_expr = bound_argument_value(node, 'path')
        if path_expr is None:
            if not positionals:
                return None
            path_expr, positionals = positionals[0], positionals[1:]
        named_value = bound_argument_value(node, 'value')
        values = [named_value] if named_value is not None else positionals
        if not values:
            return None
        path_str = string_value(path_expr)
        if path_str is None:
            return None
        prefix = 'variable:'
        if not path_str.lower().startswith(prefix):
            return None
        var_name = path_str[len(prefix):].lstrip('/\\')
        resolved = _resolve_variable_name(var_name)
        if resolved is None:
            return None
        return self._build_assignment(node.offset, resolved, values, Ps1ScopeModifier.NONE)

    def _handle_set_variable(
        self,
        node: Ps1CommandInvocation,
        command: str,
    ) -> Expression | None:
        """
        Set-Variable X val or Set-Variable -Name X -Value val → $X = val
        """
        if not _expresses_every_effect(node):
            return None
        named_value = bound_argument_value(node, 'value')
        positionals = free_positional_values(node, command)
        name_expr = bound_argument_value(node, 'name')
        if name_expr is not None:
            var_name = argument_text(name_expr)
        elif positionals:
            var_name = argument_text(positionals[0])
            positionals = positionals[1:]
        else:
            return None
        if var_name is None:
            return None
        resolved = _resolve_variable_name(var_name)
        if resolved is None:
            return None
        scope = _expressible_scope(node, resolved)
        if scope is None:
            return None
        if named_value is not None:
            values = [named_value]
        elif positionals:
            values = positionals
        else:
            return None
        return self._build_assignment(node.offset, resolved, values, scope)

    @staticmethod
    def _build_assignment(
        offset: int,
        var_name: str,
        values: list[Expression],
        scope: Ps1ScopeModifier,
    ) -> Ps1AssignmentExpression:
        target = Ps1Variable(
            offset=offset,
            name=var_name,
            scope=scope,
        )
        if len(values) == 1:
            value = values[0]
        else:
            value = _concat_expressions(values)
        return Ps1AssignmentExpression(
            offset=offset,
            target=target,
            operator='=',
            value=value,
        )
