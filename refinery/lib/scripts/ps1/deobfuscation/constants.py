"""
Inline constant variable references in PowerShell scripts.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import (
    Expression,
    Node,
    Transformer,
    _clone_node,
    _remove_from_parent,
    _replace_in_parent,
)
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    get_body,
    is_array_reverse_call,
    is_builtin_variable,
    iter_variable_mutations,
    make_string_literal,
    unwrap_parens,
    unwrap_to_array_literal,
)
from refinery.lib.scripts.ps1.deobfuscation.names import PS1_KNOWN_VARIABLES
from refinery.lib.scripts.ps1.model import (
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1DoLoop,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1ClassDefinition,
    Ps1EnumDefinition,
    Ps1FunctionDefinition,
    Ps1HereString,
    Ps1IfStatement,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1MemberAccess,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1RealLiteral,
    Ps1ScopeModifier,
    Ps1StringLiteral,
    Ps1SwitchStatement,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
)
from refinery.lib.scripts.win32const import DEFAULT_ENVIRONMENT_TEMPLATE

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

PS1_ENV_CONSTANTS = {
    lower_key: value
    for key, value in DEFAULT_ENVIRONMENT_TEMPLATE.items()
    if not (lower_key := key.lower()).startswith(('path', 'processor'))
    and '{u}' not in value
    and '{h}' not in value
}

_PS1_AUTOMATIC_VARIABLES = frozenset({
    '_',
    'args',
    'error',
    'event',
    'eventargs',
    'eventsubscriber',
    'executioncontext',
    'false',
    'foreach',
    'home',
    'host',
    'input',
    'lastexitcode',
    'matches',
    'myinvocation',
    'nestedpromptlevel',
    'null',
    'ofs',
    'pid',
    'profile',
    'psboundparameters',
    'pscmdlet',
    'pscommandpath',
    'psitem',
    'psscriptroot',
    'psversiontable',
    'pwd',
    'sender',
    'sourceargs',
    'sourceeventargs',
    'stacktrace',
    'switch',
    'this',
    'true',
})


def _assignment_target_variable(target) -> Ps1Variable | None:
    """
    Extract the variable from an assignment target, unwrapping any type
    constraint casts. Handles both `$x = expr` and `[Type]$x = expr`.
    """
    while isinstance(target, Ps1CastExpression):
        target = target.operand
    if isinstance(target, Ps1Variable):
        return target
    return None


def _collect_mutated_variables(root: Node) -> set[str]:
    """
    Return the set of variable keys that are written to anywhere in the AST. This includes
    assignment targets, ForEach loop variables, ++/-- operands, and parameter declarations.
    """
    mutated: set[str] = set()
    for var, _kind, _node in iter_variable_mutations(root):
        key = _candidate_key(var)
        if key is not None:
            mutated.add(key)
    for node in root.walk():
        if isinstance(node, Ps1ExpressionStatement):
            rv = is_array_reverse_call(node)
            if rv is not None:
                key = _candidate_key(rv)
                if key is not None:
                    mutated.add(key)
    return mutated


def _candidate_key(var: Ps1Variable) -> str | None:
    """
    Return the candidate lookup key for a variable, or `None` if it is not
    eligible for constant inlining.
    """
    if var.scope == Ps1ScopeModifier.NONE:
        return var.name.lower()
    if var.scope == Ps1ScopeModifier.ENV:
        return F'env:{var.name.lower()}'
    return None


def _constant_value_key(node: Node) -> tuple | None:
    """
    Return a hashable key representing the constant value of a node, or `None`
    if the node is not constant. Two constant nodes with the same key are
    guaranteed to represent the same value.
    """
    node = unwrap_parens(node)
    if isinstance(node, Ps1IntegerLiteral):
        return ('int', node.value)
    if isinstance(node, Ps1RealLiteral):
        return ('real', node.value)
    if isinstance(node, Ps1StringLiteral):
        return ('str', node.value)
    if isinstance(node, Ps1HereString):
        return ('str', node.value)
    if isinstance(node, Ps1TypeExpression):
        return ('type', node.name)
    if is_builtin_variable(node):
        return ('var', node.name.lower())
    if isinstance(node, Ps1ArrayLiteral):
        keys = []
        for e in node.elements:
            k = _constant_value_key(e)
            if k is None:
                return None
            keys.append(k)
        return ('array', tuple(keys))
    if isinstance(node, Ps1ArrayExpression):
        inner = unwrap_to_array_literal(node)
        if inner is not None:
            return _constant_value_key(inner)
    return None


def _get_array_literal(node: Node) -> Ps1ArrayLiteral | None:
    """
    Return the indexable `Ps1ArrayLiteral` from either a bare literal or `@(...)`.
    """
    if isinstance(node, Expression):
        return unwrap_to_array_literal(node)
    return None


def _clone_constant(node: Node) -> Expression:
    """
    Create a fresh copy of a constant value node without following parent references. This avoids
    the catastrophic cost of `copy.deepcopy` which traverses the entire AST through parents.
    """
    unwrapped = unwrap_parens(node)
    if isinstance(unwrapped, Ps1ArrayExpression):
        inner = unwrap_to_array_literal(unwrapped)
        if inner is None:
            raise TypeError(F'cannot clone {type(unwrapped).__name__}')
        unwrapped = inner
    if not isinstance(unwrapped, Expression):
        raise TypeError(F'cannot clone {type(unwrapped).__name__}')
    clone = _clone_node(unwrapped)
    if isinstance(clone, Ps1ArrayLiteral) and len(clone.elements) > 1:
        return Ps1ParenExpression(expression=clone)
    return clone


def _walk_outer_scope(root: Node):
    """
    Walk the AST like `root.walk()` but skip the bodies of function, class, and enum definitions.
    The definition node itself is yielded so that it can still be removed or inspected.
    """
    stack: list[Node] = [root]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (Ps1FunctionDefinition, Ps1ClassDefinition, Ps1EnumDefinition)):
            continue
        for child in node.children():
            stack.append(child)


def _find_body_entry(node: Node) -> tuple[list, int] | None:
    entries = _find_all_body_entries(node)
    return entries[0] if entries else None


def _find_all_body_entries(node: Node) -> list[tuple[list, int]]:
    """
    Walk upward from `node` and return a body-list position at every ancestor level.
    """
    result: list[tuple[list, int]] = []
    cursor = node
    while cursor.parent is not None:
        parent = cursor.parent
        body = get_body(parent)
        if body is not None:
            for idx, entry in enumerate(body):
                if entry is cursor:
                    result.append((body, idx))
                    break
        cursor = parent
    return result


def _find_dominating_entry(
    node: Node,
    entries: list[_CandidateEntry],
    seal_points: list[tuple[list, int]] | None = None,
) -> _CandidateEntry | None:
    """
    For a variable reference, find the assignment entry that dominates it. When multiple
    constant assignments exist, pick the latest one whose scope position precedes the reference
    without any later assignment of the same variable intervening.

    If `seal_points` is provided, a candidate is rejected when a non-constant assignment
    (seal point) falls between the candidate's position and the reference position.
    """
    cursor = node
    while cursor.parent is not None:
        parent = cursor.parent
        body = get_body(parent)
        if body is None:
            cursor = parent
            continue
        ref_idx: int | None = None
        for idx, entry in enumerate(body):
            if entry is cursor:
                ref_idx = idx
                break
        if ref_idx is not None:
            best: _CandidateEntry | None = None
            best_idx = -1
            for candidate_entry in entries:
                scope = candidate_entry.scope
                if scope is None:
                    continue
                assign_body, assign_idx = scope
                if assign_body is body and assign_idx < ref_idx and assign_idx > best_idx:
                    best = candidate_entry
                    best_idx = assign_idx
            if best is not None and seal_points:
                for sp_body, sp_idx in seal_points:
                    if sp_body is body and best_idx < sp_idx <= ref_idx:
                        best = None
                        break
            if best is not None:
                return best
        cursor = parent
    if not entries:
        return None
    for candidate_entry in entries:
        if candidate_entry.scope is None:
            return candidate_entry
    return None


def _is_inside_loop(node: Node) -> bool:
    """
    Check whether a node is inside the body of a loop or a switch statement. Switch is included
    because `switch ($array)` iterates over each element, making self-referential assignments
    behave like loop accumulators.
    """
    cursor = node.parent
    while cursor is not None:
        if isinstance(cursor, (Ps1WhileLoop, Ps1DoLoop, Ps1ForLoop, Ps1ForEachLoop, Ps1SwitchStatement)):
            return True
        cursor = cursor.parent
    return False


def _find_removable_statement(node: Node) -> Node | None:
    """
    Walk upward from an expression node to find the statement-level node that can be removed from
    its parent's body list.
    """
    cursor = node
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
        return cursor
    return None


class _CandidateEntry(NamedTuple):
    assign: Ps1AssignmentExpression | None
    value: Node
    scope: tuple[list, int] | None


class Ps1ConstantInlining(Transformer):

    def __init__(self, max_inline_length: int = 64, min_inlines_to_prune: int | None = 1):
        super().__init__()
        self.max_inline_length = max_inline_length
        self.min_inlines_to_prune = min_inlines_to_prune

    def visit(self, node: Node):
        candidates, seal_points = self._collect_candidates(node)
        if not candidates:
            return None
        remaining, inlined = self._substitute(node, candidates, seal_points)
        self._remove_dead_assignments(candidates, remaining, inlined)
        return None

    def _collect_candidates(
        self,
        root: Node,
    ) -> tuple[dict[str, list[_CandidateEntry]], dict[str, list[tuple[list, int]]]]:
        """
        Collect constant assignment entries per variable. Each entry is a `_CandidateEntry` of
        `(assignment_node, constant_value, scope_entry)`. A variable may have multiple entries
        when it is reassigned to different constants; each entry covers the region from its
        assignment to the next reassignment.

        Also returns a dict of seal points: body-list positions of non-constant `=` assignments
        that terminate the preceding constant region. Each seal point is expanded to all ancestor
        body levels so that nested non-constant assignments correctly block references in outer
        scopes.
        """
        rejected: set[str] = set()
        sealed: dict[str, list[tuple[list, int]]] = {}
        candidates: dict[str, list[_CandidateEntry]] = {}

        def _reject(k: str):
            rejected.add(k)
            candidates.pop(k, None)

        for node in _walk_outer_scope(root):
            if isinstance(node, Ps1AssignmentExpression):
                target = _assignment_target_variable(node.target)
                if target is not None:
                    key = _candidate_key(target)
                    if key is None or key in rejected:
                        continue
                    if node.operator == '=' and node.value is not None:
                        vk = _constant_value_key(node.value)
                        if vk is None:
                            sealed.setdefault(key, []).extend(_find_all_body_entries(node))
                        else:
                            const_value = unwrap_parens(node.value)
                            entry = _find_body_entry(node)
                            candidates.setdefault(key, []).append(_CandidateEntry(node, const_value, entry))
                    else:
                        _reject(key)
                else:
                    raw = node.target
                    while isinstance(raw, (Ps1CastExpression, Ps1ParenExpression)):
                        raw = raw.operand if isinstance(raw, Ps1CastExpression) else raw.expression
                    if isinstance(raw, (Ps1IndexExpression, Ps1MemberAccess)) and isinstance(raw.object, Ps1Variable):
                        key = _candidate_key(raw.object)
                        if key is not None:
                            _reject(key)

            elif isinstance(node, Ps1ForEachLoop):
                if isinstance(node.variable, Ps1Variable):
                    key = _candidate_key(node.variable)
                    if key is not None:
                        _reject(key)

            elif isinstance(node, Ps1UnaryExpression):
                if node.operator in ('++', '--'):
                    operand = node.operand
                    if isinstance(operand, Ps1Variable):
                        key = _candidate_key(operand)
                        if key is not None:
                            _reject(key)

            elif isinstance(node, Ps1ParameterDeclaration):
                if isinstance(node.variable, Ps1Variable):
                    key = _candidate_key(node.variable)
                    if key is not None:
                        _reject(key)

        result: dict[str, list[_CandidateEntry]] = {
            key: val for key, val in candidates.items()
            if key not in _PS1_DEFAULT_VARIABLES
        }
        for key, value in _PS1_DEFAULT_VARIABLES.items():
            if key not in rejected and key not in sealed and key not in candidates:
                result[key] = [_CandidateEntry(None, make_string_literal(value), None)]
        for key, value in PS1_ENV_CONSTANTS.items():
            env_key = F'env:{key}'
            if env_key not in rejected and env_key not in sealed and env_key not in candidates:
                result[env_key] = [_CandidateEntry(None, make_string_literal(value), None)]
        return result, sealed

    def _substitute(
        self,
        root: Node,
        candidates: dict[str, list[_CandidateEntry]],
        seal_points: dict[str, list[tuple[list, int]]],
    ) -> tuple[dict[str, int], dict[str, int]]:
        """
        Inline constant values. Returns `(remaining, inlined)` where remaining maps lower_name
        to count of references that could not be substituted, and inlined maps lower_name to
        count of successful substitutions.
        """
        remaining: dict[str, int] = {}
        inlined: dict[str, int] = {}
        bloat_blocked: set[str] = set()

        ref_counts: dict[str, int] = {}
        for node in _walk_outer_scope(root):
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
        for key, entries in candidates.items():
            assign_count = sum(1 for a, _, _ in entries if a is not None)
            use_count = ref_counts.get(key, 0) - assign_count
            if use_count > 1 and len(entries) == 1:
                const_value = entries[0].value
                if isinstance(const_value, (Ps1StringLiteral, Ps1HereString)):
                    if len(const_value.raw) > self.max_inline_length:
                        remaining[key] = use_count
                        bloat_blocked.add(key)
                else:
                    array = _get_array_literal(const_value)
                    if array is not None and len(array.elements) > self.max_inline_length:
                        remaining[key] = use_count
                        bloat_blocked.add(key)

        assign_nodes: set[Ps1AssignmentExpression] = set()
        for entries in candidates.values():
            for assign_node, _, _ in entries:
                if assign_node is not None:
                    assign_nodes.add(assign_node)

        handled_vars: set[Ps1Variable] = set()

        for node in list(_walk_outer_scope(root)):
            if isinstance(node, Ps1IndexExpression):
                var = node.object
                if isinstance(var, Ps1Variable):
                    key = _candidate_key(var)
                    if key is not None and key in candidates and key not in bloat_blocked:
                        self._substitute_index_reference(
                            node,
                            var,
                            key,
                            candidates,
                            seal_points,
                            assign_nodes,
                            remaining,
                            inlined,
                            handled_vars,
                        )
                continue
            if isinstance(node, Ps1Variable):
                if node not in handled_vars:
                    key = _candidate_key(node)
                    if key is not None and key in candidates and key not in bloat_blocked:
                        self._substitute_variable_reference(
                            node,
                            key,
                            candidates,
                            seal_points,
                            remaining,
                            inlined,
                        )

        return remaining, inlined

    def _substitute_index_reference(
        self,
        node: Ps1IndexExpression,
        var: Ps1Variable,
        key: str,
        candidates: dict[str, list[_CandidateEntry]],
        seal_points: dict[str, list[tuple[list, int]]],
        assign_nodes: set[Ps1AssignmentExpression],
        remaining: dict[str, int],
        inlined: dict[str, int],
        handled_vars: set[Ps1Variable],
    ) -> None:
        if node.parent in assign_nodes:
            handled_vars.add(var)
            return
        if sp := seal_points.get(key):
            sp = self._exclude_own_seal_points(var, key, sp)
        entry = _find_dominating_entry(node, candidates[key], sp)
        if entry is None:
            remaining[key] = remaining.get(key, 0) + 1
            handled_vars.add(var)
            return
        const_value = entry.value
        if not isinstance(node.index, Ps1IntegerLiteral):
            if isinstance(const_value, Ps1StringLiteral):
                replacement = _clone_constant(const_value)
                replacement.parent = node
                node.object = replacement
                self.mark_changed()
                inlined[key] = inlined.get(key, 0) + 1
                handled_vars.add(var)
            else:
                remaining[key] = remaining.get(key, 0) + 1
                handled_vars.add(var)
            return
        idx = node.index.value
        if isinstance(const_value, Ps1StringLiteral):
            s = const_value.value
            if idx < 0 or idx >= len(s):
                remaining[key] = remaining.get(key, 0) + 1
                return
            replacement = make_string_literal(s[idx])
            _replace_in_parent(node, replacement)
            self.mark_changed()
            inlined[key] = inlined.get(key, 0) + 1
            handled_vars.add(var)
            return
        array = _get_array_literal(const_value)
        if array is None:
            remaining[key] = remaining.get(key, 0) + 1
            handled_vars.add(var)
            return
        elements = array.elements
        if idx < 0 or idx >= len(elements):
            remaining[key] = remaining.get(key, 0) + 1
            return
        replacement = _clone_constant(elements[idx])
        _replace_in_parent(node, replacement)
        self.mark_changed()
        inlined[key] = inlined.get(key, 0) + 1
        handled_vars.add(var)

    def _substitute_variable_reference(
        self,
        node: Ps1Variable,
        key: str,
        candidates: dict[str, list[_CandidateEntry]],
        seal_points: dict[str, list[tuple[list, int]]],
        remaining: dict[str, int],
        inlined: dict[str, int],
    ) -> None:
        parent = node.parent
        while isinstance(parent, Ps1CastExpression):
            parent = parent.parent
        if (
            isinstance(parent, Ps1AssignmentExpression)
            and _assignment_target_variable(parent.target) is node
        ):
            return
        if sp := seal_points.get(key):
            sp = self._exclude_own_seal_points(node, key, sp)
        entry = _find_dominating_entry(node, candidates[key], sp)
        if entry is None:
            remaining[key] = remaining.get(key, 0) + 1
            return
        replacement = _clone_constant(entry.value)
        _replace_in_parent(node, replacement)
        self.mark_changed()
        inlined[key] = inlined.get(key, 0) + 1

    @staticmethod
    def _exclude_own_seal_points(
        node: Node,
        key: str,
        seal_points: list[tuple[list, int]],
    ) -> list[tuple[list, int]]:
        """
        When a variable reference sits on the RHS of an assignment to the same variable
        (e.g. `$x = [char]($x)`), the seal points generated by that assignment must not
        block this reference. The RHS is evaluated before the assignment takes effect, so
        the reference still sees the previous constant value.

        This exclusion is suppressed when the assignment is inside a loop body, because
        the variable may have been modified in a previous iteration and no longer holds
        the pre-loop constant.
        """
        cursor = node
        while cursor.parent is not None:
            if isinstance(parent := cursor.parent, Ps1AssignmentExpression) and cursor is parent.value:
                target = _assignment_target_variable(parent.target)
                if target is not None and _candidate_key(target) == key:
                    if _is_inside_loop(parent):
                        break
                    own = set()
                    for body, idx in _find_all_body_entries(parent):
                        own.add((id(body), idx))
                    return [
                        sp for sp in seal_points if (id(sp[0]), sp[1]) not in own
                    ]
            cursor = parent
        return seal_points

    def _remove_dead_assignments(
        self,
        candidates: dict[str, list[_CandidateEntry]],
        remaining: dict[str, int],
        inlined: dict[str, int],
    ):
        for key, entries in candidates.items():
            if remaining.get(key, 0) > 0:
                continue
            if self.min_inlines_to_prune is not None and inlined.get(key, 0) < self.min_inlines_to_prune:
                continue
            for assign_node, _, _ in entries:
                if assign_node is None:
                    continue
                stmt = self._find_removable_statement(assign_node)
                if stmt is None:
                    continue
                if _remove_from_parent(stmt):
                    self.mark_changed()

    _find_removable_statement = staticmethod(_find_removable_statement)


class Ps1NullVariableInlining(Transformer):
    """
    Replace references to never-assigned variables with `$Null`. Only operates on variables that
    appear in expression contexts where null coercion enables further simplification (arithmetic,
    comparison, cast, assignment value).
    """

    @staticmethod
    def _is_null_eligible(ref: Ps1Variable) -> bool:
        cursor = ref
        while cursor.parent is not None:
            parent = cursor.parent
            if isinstance(parent, Ps1BinaryExpression):
                return True
            if isinstance(parent, Ps1UnaryExpression):
                return True
            if isinstance(parent, Ps1CastExpression):
                return True
            if isinstance(parent, Ps1AssignmentExpression) and cursor is parent.value:
                return True
            if isinstance(parent, (Ps1ParenExpression, Ps1ArrayLiteral)):
                cursor = parent
                continue
            if isinstance(parent, (Ps1WhileLoop, Ps1DoLoop, Ps1ForLoop)) and cursor is parent.condition:
                return True
            if isinstance(parent, (Ps1IfStatement, Ps1SwitchStatement)):
                return any(cursor is cond for cond, _ in parent.clauses)
            return False
        return False

    def visit(self, node: Node):
        mutated = _collect_mutated_variables(node)
        for ref in list(node.walk()):
            if not isinstance(ref, Ps1Variable):
                continue
            key = _candidate_key(ref)
            if key is None:
                continue
            if key in mutated:
                continue
            if key in PS1_KNOWN_VARIABLES:
                continue
            if key in _PS1_DEFAULT_VARIABLES:
                continue
            if key in _PS1_AUTOMATIC_VARIABLES:
                continue
            if key.startswith('env:'):
                continue
            parent = ref.parent
            while isinstance(parent, Ps1CastExpression):
                parent = parent.parent
            if isinstance(parent, Ps1AssignmentExpression) and _assignment_target_variable(parent.target) is ref:
                continue
            if not self._is_null_eligible(ref):
                continue
            _replace_in_parent(ref, Ps1Variable(name='Null'))
            self.mark_changed()
