"""
Inline constant variable references in PowerShell scripts.
"""
from __future__ import annotations

from refinery.lib.scripts import (
    Expression,
    Node,
    Transformer,
    _clone_node,
    _remove_from_parent,
    _replace_in_parent,
)
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _PS1_KNOWN_VARIABLES,
    _get_body,
    _is_array_reverse_call,
    _is_builtin_variable,
    _iter_variable_mutations,
    _make_string_literal,
    _unwrap_parens,
    _unwrap_to_array_literal,
)
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
    Ps1HereString,
    Ps1IfStatement,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1RealLiteral,
    Ps1ScopeModifier,
    Ps1StringLiteral,
    Ps1SwitchStatement,
    Ps1TryCatchFinally,
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

_PS1_ENV_CONSTANTS = {
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
    for var, _kind, _node in _iter_variable_mutations(root):
        key = _candidate_key(var)
        if key is not None:
            mutated.add(key)
    for node in root.walk():
        if isinstance(node, Ps1ExpressionStatement):
            rv = _is_array_reverse_call(node)
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
    node = _unwrap_parens(node)
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
    if _is_builtin_variable(node):
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
        inner = _unwrap_to_array_literal(node)
        if inner is not None:
            return _constant_value_key(inner)
    return None


def _get_array_literal(node: Node) -> Ps1ArrayLiteral | None:
    """
    Return the indexable `Ps1ArrayLiteral` from either a bare literal or
    `@(...)`.
    """
    if isinstance(node, Expression):
        return _unwrap_to_array_literal(node)
    return None


def _clone_constant(node: Node) -> Expression:
    """
    Create a fresh copy of a constant value node without following parent references. This avoids
    the catastrophic cost of `copy.deepcopy` which traverses the entire AST through parents.
    """
    unwrapped = _unwrap_parens(node)
    if isinstance(unwrapped, Ps1ArrayExpression):
        inner = _unwrap_to_array_literal(unwrapped)
        if inner is None:
            raise TypeError(F'cannot clone {type(unwrapped).__name__}')
        unwrapped = inner
    if not isinstance(unwrapped, Expression):
        raise TypeError(F'cannot clone {type(unwrapped).__name__}')
    clone = _clone_node(unwrapped)
    if isinstance(clone, Ps1ArrayLiteral) and len(clone.elements) > 1:
        return Ps1ParenExpression(expression=clone)
    return clone


def _inside_try_body(node: Node) -> bool:
    cursor = node.parent
    while cursor is not None:
        parent = cursor.parent
        if isinstance(parent, Ps1TryCatchFinally) and cursor is parent.try_block:
            return True
        cursor = parent
    return False


def _find_body_entry(node: Node) -> tuple[list, int] | None:
    cursor = node
    while cursor.parent is not None:
        parent = cursor.parent
        body = _get_body(parent)
        if body is not None:
            for idx, entry in enumerate(body):
                if entry is cursor:
                    return (body, idx)
        cursor = parent
    return None


def _is_dominated_by(node: Node, scope_entries: list[tuple[list, int]]) -> bool:
    cursor = node
    reached_root = False
    while cursor.parent is not None:
        parent = cursor.parent
        body = _get_body(parent)
        if body is not None:
            reached_root = True
            for idx, entry in enumerate(body):
                if entry is cursor:
                    for assign_body, assign_idx in scope_entries:
                        if assign_body is body and assign_idx <= idx:
                            return True
                    break
            cursor = parent
            continue
        cursor = parent
    return not reached_root


class Ps1ConstantInlining(Transformer):

    def __init__(self, max_inline_length: int = 64, min_inlines_to_prune: int | None = 1):
        super().__init__()
        self.max_inline_length = max_inline_length
        self.min_inlines_to_prune = min_inlines_to_prune

    def visit(self, node: Node):
        candidates, scope_entries = self._collect_candidates(node)
        if not candidates:
            return None
        remaining, inlined = self._substitute(node, candidates, scope_entries)
        self._remove_dead_assignments(candidates, remaining, inlined)
        return None

    def _collect_candidates(
        self,
        root: Node,
    ) -> tuple[dict[str, tuple[list[Ps1AssignmentExpression], Node]], dict[str, list[tuple[list, int]]]]:
        """
        Returns:

            (candidates, scope_entries)

        where candidates maps lower_name to ([assignment_nodes], constant_value) for variables whose
        every assignment is to the same constant value, and scope_entries maps lower_name to a list
        of (body_list, index) tuples locating each assignment in its enclosing body.
        """
        rejected: set[str] = set()
        candidates: dict[str, tuple[list[Ps1AssignmentExpression], Node]] = {}
        value_keys: dict[str, tuple] = {}
        scope_entries: dict[str, list[tuple[list, int]]] = {}

        def _reject(k: str):
            rejected.add(k)
            candidates.pop(k, None)
            value_keys.pop(k, None)
            scope_entries.pop(k, None)

        for node in root.walk():
            if isinstance(node, Ps1AssignmentExpression):
                target = _assignment_target_variable(node.target)
                if target is not None:
                    key = _candidate_key(target)
                    if key is None or key in rejected:
                        continue
                    if node.operator == '=' and node.value is not None:
                        vk = _constant_value_key(node.value)
                        if vk is None:
                            _reject(key)
                        else:
                            prev = value_keys.get(key)
                            if prev is not None and prev != vk:
                                _reject(key)
                            else:
                                value_keys[key] = vk
                                const_value = _unwrap_parens(node.value)
                                existing = candidates.get(key)
                                if existing is not None:
                                    existing[0].append(node)
                                else:
                                    candidates[key] = ([node], const_value)
                                entry = _find_body_entry(node)
                                if entry is not None:
                                    scope_entries.setdefault(key, []).append(entry)
                    else:
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

        result = {
            key: val for key, val in candidates.items()
            if key not in _PS1_DEFAULT_VARIABLES
        }
        result_scope = {
            key: entries for key, entries in scope_entries.items()
            if key in result
        }
        for key, value in _PS1_DEFAULT_VARIABLES.items():
            if key not in rejected and key not in candidates:
                result[key] = ([], _make_string_literal(value))
        for key, value in _PS1_ENV_CONSTANTS.items():
            env_key = F'env:{key}'
            if env_key not in rejected and env_key not in candidates:
                result[env_key] = ([], _make_string_literal(value))
        return result, result_scope

    def _substitute(
        self,
        root: Node,
        candidates: dict[str, tuple[list[Ps1AssignmentExpression], Node]],
        scope_entries: dict[str, list[tuple[list, int]]],
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
        for key, (assign_nodes, const_value) in candidates.items():
            use_count = ref_counts.get(key, 0)
            use_count -= len(assign_nodes)
            if use_count > 1 and isinstance(const_value, (Ps1StringLiteral, Ps1HereString)):
                if len(const_value.raw) > self.max_inline_length:
                    remaining[key] = use_count
            elif use_count > 1:
                array = _get_array_literal(const_value)
                if array is not None and len(array.elements) > self.max_inline_length:
                    remaining[key] = use_count

        assign_node_ids: set[int] = set()
        for assign_nodes, _ in candidates.values():
            for an in assign_nodes:
                assign_node_ids.add(id(an))

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
                    assign_nodes, const_value = info
                    if id(node.parent) in assign_node_ids:
                        handled_vars.add(id(var))
                        continue
                    if _inside_try_body(node):
                        remaining[key] = remaining.get(key, 0) + 1
                        handled_vars.add(id(var))
                        continue
                    entries = scope_entries.get(key)
                    if entries is not None and not _is_dominated_by(node, entries):
                        remaining[key] = remaining.get(key, 0) + 1
                        handled_vars.add(id(var))
                        continue
                    if not isinstance(node.index, Ps1IntegerLiteral):
                        if isinstance(const_value, Ps1StringLiteral):
                            replacement = _clone_constant(const_value)
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
                    replacement = _clone_constant(elements[idx])
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
                assign_nodes, const_value = info
                parent = node.parent
                while isinstance(parent, Ps1CastExpression):
                    parent = parent.parent
                if (
                    id(parent) in assign_node_ids
                    and isinstance(parent, Ps1AssignmentExpression)
                    and _assignment_target_variable(parent.target) is node
                ):
                    continue
                if _inside_try_body(node):
                    remaining[key] = remaining.get(key, 0) + 1
                    continue
                entries = scope_entries.get(key)
                if entries is not None and not _is_dominated_by(node, entries):
                    remaining[key] = remaining.get(key, 0) + 1
                    continue
                replacement = _clone_constant(const_value)
                _replace_in_parent(node, replacement)
                self.mark_changed()
                inlined[key] = inlined.get(key, 0) + 1

        return remaining, inlined

    def _remove_dead_assignments(
        self,
        candidates: dict[str, tuple[list[Ps1AssignmentExpression], Node]],
        remaining: dict[str, int],
        inlined: dict[str, int],
    ):
        for key, (assign_nodes, _) in candidates.items():
            if not assign_nodes:
                continue
            if remaining.get(key, 0) > 0:
                continue
            if self.min_inlines_to_prune is not None and inlined.get(key, 0) < self.min_inlines_to_prune:
                continue
            for assign_node in assign_nodes:
                stmt = self._find_removable_statement(assign_node)
                if stmt is None:
                    continue
                if _remove_from_parent(stmt):
                    self.mark_changed()

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
                for cond, _body in parent.clauses:
                    if cursor is cond:
                        return True
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
            if key in _PS1_KNOWN_VARIABLES:
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
