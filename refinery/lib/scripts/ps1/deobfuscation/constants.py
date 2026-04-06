"""
Inline constant variable references in PowerShell scripts.
"""
from __future__ import annotations

import copy

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _make_string_literal,
    _replace_in_parent,
)
from refinery.lib.scripts.ps1.model import (
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1RealLiteral,
    Ps1ScopeModifier,
    Ps1StringLiteral,
    Ps1TryCatchFinally,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)

_CONSTANT_TYPES = (Ps1StringLiteral, Ps1IntegerLiteral, Ps1RealLiteral, Ps1TypeExpression)

_PS1_DEFAULT_VARIABLES: dict[str, str] = {
    key.lower(): value for key, value in {
        'ConfirmPreference'          : r'High',
        'ConsoleFileName'            : r'',
        'DebugPreference'            : r'SilentlyContinue',
        'ErrorActionPreference'      : r'Continue',
        'InformationPreference'      : r'SilentlyContinue',
        'ProgressPreference'         : r'Continue',
        'PSCommandPath'              : r'',
        'PSCulture'                  : r'en-US',
        'PSEmailServer'              : r'',
        'PSHome'                     : r'C:\Windows\System32\WindowsPowerShell\v1.0',
        'PSScriptRoot'               : r'',
        'PSSessionApplicationName'   : r'wsman',
        'PSSessionConfigurationName' : r'http://schemas.microsoft.com/powershell/Microsoft.PowerShell',
        'PSUICulture'                : r'en-US',
        'ShellID'                    : r'Microsoft.PowerShell',
        'VerbosePreference'          : r'SilentlyContinue',
        'WarningPreference'          : r'Continue',
    }.items()
}

_PS1_ENV_CONSTANTS: dict[str, str] = {
    key.lower(): value for key, value in {
        'ComSpec': r'C:\Windows\System32\cmd.exe',
    }.items()
}

_PS1_KNOWN_VARIABLES: dict[str, str] = {
    name.lower(): name for name in [
        'ConfirmPreference',
        'ConsoleFileName',
        'DebugPreference',
        'Error',
        'ErrorActionPreference',
        'ExecutionContext',
        'ForEach',
        'FormatEnumerationLimit',
        'HOME',
        'Host',
        'InformationPreference',
        'Input',
        'Matches',
        'MaximumHistoryCount',
        'MyInvocation',
        'NestedPromptLevel',
        'OutputEncoding',
        'PID',
        'PROFILE',
        'ProgressPreference',
        'PSCommandPath',
        'PSCulture',
        'PSDefaultParameterValues',
        'PSEmailServer',
        'PSHome',
        'PSScriptRoot',
        'PSSessionApplicationName',
        'PSSessionConfigurationName',
        'PSSessionOption',
        'PSUICulture',
        'PSVersionTable',
        'PWD',
        'ShellID',
        'StackTrace',
        'This',
        'VerbosePreference',
        'WarningPreference',
        'WhatIfPreference',
    ]
}


def _candidate_key(var: Ps1Variable) -> str | None:
    """
    Return the candidate lookup key for a variable, or ``None`` if it is not
    eligible for constant inlining.
    """
    if var.scope == Ps1ScopeModifier.NONE:
        return var.name.lower()
    if var.scope == Ps1ScopeModifier.ENV:
        return F'env:{var.name.lower()}'
    return None


def _is_constant(node: Node) -> bool:
    while isinstance(node, Ps1ParenExpression) and node.expression is not None:
        node = node.expression
    if isinstance(node, _CONSTANT_TYPES):
        return True
    if isinstance(node, Ps1ArrayLiteral):
        return all(_is_constant(e) for e in node.elements)
    if isinstance(node, Ps1ArrayExpression):
        inner = _unwrap_array_expression(node)
        if inner is not None:
            return _is_constant(inner)
    return False


def _unwrap_array_expression(node: Ps1ArrayExpression) -> Ps1ArrayLiteral | None:
    """
    Unwrap ``@(e1, e2, ...)`` to its inner ``Ps1ArrayLiteral`` if possible.
    """
    if len(node.body) == 1:
        stmt = node.body[0]
        if isinstance(stmt, Ps1ExpressionStatement) and isinstance(stmt.expression, Ps1ArrayLiteral):
            return stmt.expression
    return None


def _get_array_literal(node: Node) -> Ps1ArrayLiteral | None:
    """
    Return the indexable Ps1ArrayLiteral from either a bare literal or @(...).
    """
    if isinstance(node, Ps1ArrayLiteral):
        return node
    if isinstance(node, Ps1ArrayExpression):
        return _unwrap_array_expression(node)
    return None


def _inside_try_body(node: Node) -> bool:
    cursor = node.parent
    while cursor is not None:
        parent = cursor.parent
        if isinstance(parent, Ps1TryCatchFinally) and cursor is parent.try_block:
            return True
        cursor = parent
    return False


class Ps1ConstantInlining(Transformer):

    def __init__(self, max_inline_length: int = 64, min_inlines_to_prune: int | None = 1):
        super().__init__()
        self.max_inline_length = max_inline_length
        self.min_inlines_to_prune = min_inlines_to_prune

    def visit(self, node: Node):
        # Phase 1: collect candidates, then phase 2: substitute.
        # Only the top-level call triggers the two-phase approach.
        candidates = self._collect_candidates(node)
        if not candidates:
            return None
        remaining, inlined = self._substitute(node, candidates)
        self._remove_dead_assignments(candidates, remaining, inlined)
        return None

    def _collect_candidates(self, root: Node) -> dict[str, tuple[Ps1AssignmentExpression | None, Node]]:
        """
        Returns:

            {lower_name: (assignment_node, constant_value)}

        for variables assigned exactly once via assignment to a constant expression.
        """
        assign_counts: dict[str, int] = {}
        assignments: dict[str, tuple[Ps1AssignmentExpression | None, Node]] = {}

        for node in root.walk():
            # Explicit assignment: $x = VALUE
            if isinstance(node, Ps1AssignmentExpression):
                target = node.target
                if isinstance(target, Ps1Variable):
                    key = _candidate_key(target)
                    if key is None:
                        continue
                    if node.operator == '=' and node.value is not None and _is_constant(node.value):
                        assign_counts[key] = assign_counts.get(key, 0) + 1
                        value = node.value
                        while isinstance(value, Ps1ParenExpression) and value.expression is not None:
                            value = value.expression
                        assignments[key] = (node, value)
                    else:
                        # Compound assignment or non-constant value
                        assign_counts[key] = assign_counts.get(key, 0) + 1

            # Implicit assignments
            elif isinstance(node, Ps1ForEachLoop):
                if isinstance(node.variable, Ps1Variable):
                    key = _candidate_key(node.variable)
                    if key is not None:
                        assign_counts[key] = assign_counts.get(key, 0) + 1

            elif isinstance(node, Ps1UnaryExpression):
                if node.operator in ('++', '--'):
                    operand = node.operand
                    if isinstance(operand, Ps1Variable):
                        key = _candidate_key(operand)
                        if key is not None:
                            assign_counts[key] = assign_counts.get(key, 0) + 1

            elif isinstance(node, Ps1ParameterDeclaration):
                if isinstance(node.variable, Ps1Variable):
                    key = _candidate_key(node.variable)
                    if key is not None:
                        assign_counts[key] = assign_counts.get(key, 0) + 1

        result = {
            key: val for key, val in assignments.items()
            if assign_counts.get(key, 0) == 1
            and key not in _PS1_DEFAULT_VARIABLES
        }
        for key, value in _PS1_DEFAULT_VARIABLES.items():
            if assign_counts.get(key, 0) == 0:
                result[key] = (None, _make_string_literal(value))
        for key, value in _PS1_ENV_CONSTANTS.items():
            env_key = F'env:{key}'
            if assign_counts.get(env_key, 0) == 0:
                result[env_key] = (None, _make_string_literal(value))
        return result

    def _substitute(
        self,
        root: Node,
        candidates: dict[str, tuple[Ps1AssignmentExpression | None, Node]],
    ) -> tuple[dict[str, int], dict[str, int]]:
        """
        Inline constant values. Returns:

            (remaining, inlined)

        where remaining maps lower_name to count of references that could not be substituted, and
        inlined maps lower_name to count of successful substitutions.
        """
        remaining: dict[str, int] = {}
        inlined: dict[str, int] = {}

        # Pre-count references to decide whether inlining would bloat the code.
        # Variables referenced more than once with long values are kept as-is.
        ref_counts: dict[str, int] = {}
        for node in root.walk():
            if isinstance(node, Ps1IndexExpression):
                var = node.object
                if isinstance(var, Ps1Variable):
                    key = _candidate_key(var)
                    if key is not None and key in candidates:
                        ref_counts[key] = ref_counts.get(key, 0) + 1
            elif isinstance(node, Ps1Variable):
                key = _candidate_key(node)
                if key is not None and key in candidates:
                    ref_counts[key] = ref_counts.get(key, 0) + 1
        for key, (assign_node, const_value) in candidates.items():
            use_count = ref_counts.get(key, 0)
            if assign_node is not None:
                use_count -= 1
            if use_count > 1 and isinstance(const_value, Ps1StringLiteral):
                if len(const_value.raw) > self.max_inline_length:
                    remaining[key] = use_count

        handled_vars: set[int] = set()

        for node in list(root.walk()):
            # Indexed access: $x[2]
            if isinstance(node, Ps1IndexExpression):
                var = node.object
                if isinstance(var, Ps1Variable):
                    key = _candidate_key(var)
                    if key is None:
                        continue
                    info = candidates.get(key)
                    if info is None:
                        continue
                    assign_node, const_value = info
                    if assign_node is not None and node is assign_node.target:
                        handled_vars.add(id(var))
                        continue
                    if _inside_try_body(node):
                        remaining[key] = remaining.get(key, 0) + 1
                        handled_vars.add(id(var))
                        continue
                    if not isinstance(node.index, Ps1IntegerLiteral):
                        if isinstance(const_value, Ps1StringLiteral):
                            replacement = copy.deepcopy(const_value)
                            replacement.parent = node
                            node.object = replacement
                            self.mark_changed()
                            inlined[key] = inlined.get(key, 0) + 1
                            handled_vars.add(id(var))
                        else:
                            remaining[key] = remaining.get(key, 0) + 1
                            handled_vars.add(id(var))
                        continue
                    idx = node.index.value
                    if isinstance(const_value, Ps1StringLiteral):
                        s = const_value.value
                        if idx < 0 or idx >= len(s):
                            remaining[key] = remaining.get(key, 0) + 1
                            continue
                        replacement = _make_string_literal(s[idx])
                        _replace_in_parent(node, replacement)
                        self.mark_changed()
                        inlined[key] = inlined.get(key, 0) + 1
                        handled_vars.add(id(var))
                        continue
                    array = _get_array_literal(const_value)
                    if array is None:
                        remaining[key] = remaining.get(key, 0) + 1
                        handled_vars.add(id(var))
                        continue
                    elements = array.elements
                    if idx < 0 or idx >= len(elements):
                        remaining[key] = remaining.get(key, 0) + 1
                        continue
                    replacement = copy.deepcopy(elements[idx])
                    _replace_in_parent(node, replacement)
                    self.mark_changed()
                    inlined[key] = inlined.get(key, 0) + 1
                    handled_vars.add(id(var))
                continue

            # Simple variable reference: $x
            if isinstance(node, Ps1Variable):
                if id(node) in handled_vars:
                    continue
                key = _candidate_key(node)
                if key is None:
                    continue
                info = candidates.get(key)
                if info is None:
                    continue
                if key in remaining:
                    continue
                assign_node, const_value = info
                # Don't replace the assignment target itself
                if assign_node is not None and node.parent is assign_node:
                    if node is assign_node.target:
                        continue
                if _inside_try_body(node):
                    remaining[key] = remaining.get(key, 0) + 1
                    continue
                replacement = copy.deepcopy(const_value)
                _replace_in_parent(node, replacement)
                self.mark_changed()
                inlined[key] = inlined.get(key, 0) + 1

        return remaining, inlined

    def _remove_dead_assignments(
        self,
        candidates: dict[str, tuple[Ps1AssignmentExpression | None, Node]],
        remaining: dict[str, int],
        inlined: dict[str, int],
    ):
        for key, (assign_node, _) in candidates.items():
            if assign_node is None:
                continue
            if remaining.get(key, 0) > 0:
                continue
            if self.min_inlines_to_prune is not None and inlined.get(key, 0) < self.min_inlines_to_prune:
                continue
            stmt = self._find_removable_statement(assign_node)
            if stmt is None:
                continue
            parent = stmt.parent
            if parent is None:
                continue
            for attr_name in vars(parent):
                if attr_name in ('parent', 'offset'):
                    continue
                value = getattr(parent, attr_name)
                if isinstance(value, list) and stmt in value:
                    value.remove(stmt)
                    self.mark_changed()
                    break

    @staticmethod
    def _find_removable_statement(assign_node: Ps1AssignmentExpression) -> Node | None:
        cursor = assign_node
        while cursor.parent is not None:
            parent = cursor.parent
            if isinstance(parent, Ps1ExpressionStatement):
                cursor = parent
                continue
            if isinstance(parent, Ps1PipelineElement):
                cursor = parent
                continue
            if isinstance(parent, Ps1Pipeline):
                if len(parent.elements) == 1:
                    cursor = parent
                    continue
            # cursor is the statement to remove from parent's body list
            return cursor
        return None
