"""
.NET type system utilities for PowerShell deobfuscation.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.ps1.deobfuscation.data import (
    CANONICAL_TYPE_NAMES,
    GET_MEMBER_ALIASES,
    MEMBER_LOOKUP,
    OBJ_COMMANDS,
    PROPERTY_TYPES,
    TYPE_MEMBERS,
    VARIABLE_TYPES,
    WMI_CLASS_NAMES,
    WMI_COMMANDS,
    _resolve_type_name,
)
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    extract_first_positional_string,
    get_command_name,
    get_member_name,
    iter_variable_mutations,
    make_string_literal,
    MutationKind,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1CastExpression,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1HereString,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1ScopeModifier,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1Variable,
)


def canonical_type_name(name: str) -> str | None:
    """
    Return the canonical PascalCase display name for a .NET type, preserving an explicit `System.`
    prefix if the caller used one. Returns `None` if the type is not in the database.
    """
    resolved = _resolve_type_name(name)
    lower = resolved if resolved is not None else name.lower()
    display = CANONICAL_TYPE_NAMES.get(lower)
    if display is None:
        bare = lower.removeprefix('system.')
        if bare != lower:
            display = CANONICAL_TYPE_NAMES.get(bare)
    if display is None:
        return None
    has_system = name.lower().startswith('system.')
    display_has_system = display.lower().startswith('system.')
    if has_system and not display_has_system:
        display = F'System.{display}'
    return display


def canonical_member_name(type_name_lower: str, member: str) -> str | None:
    """
    Return the canonical PascalCase member name for a known .NET type.
    """
    lookup = MEMBER_LOOKUP.get(type_name_lower)
    if lookup is None:
        return None
    return lookup.get(member.lower())


def resolve_expression_type(
    expr: Expression,
    variable_types: dict[str, str] | None = None,
) -> str | None:
    """
    Trace the .NET type of a PowerShell expression by walking member access chains. Returns the
    lowercase full .NET type name, or `None` if the type cannot be determined.
    """
    unwrapped = unwrap_parens(expr)
    if not isinstance(unwrapped, Expression):
        return None
    expr = unwrapped
    if isinstance(expr, (Ps1StringLiteral, Ps1HereString)):
        return 'system.string'
    if isinstance(expr, Ps1IntegerLiteral):
        return 'system.int32'
    if isinstance(expr, Ps1ArrayLiteral):
        return 'system.array'
    if isinstance(expr, Ps1ArrayExpression):
        if (
            len(expr.body) == 1
            and isinstance(expr.body[0], Ps1ExpressionStatement)
            and isinstance(expr.body[0].expression, Ps1ArrayLiteral)
        ):
            return 'system.array'
    if isinstance(expr, Ps1Variable):
        key = expr.name.lower()
        if variable_types and key in variable_types:
            return variable_types[key]
        return VARIABLE_TYPES.get(key)
    if isinstance(expr, Ps1TypeExpression):
        return _resolve_type_name(expr.name)
    if isinstance(expr, Ps1CastExpression):
        return _resolve_type_name(expr.type_name)
    if isinstance(expr, Ps1CommandInvocation):
        cmd_name = get_command_name(expr)
        if cmd_name is not None:
            cmd_lower = cmd_name.lower()
            if cmd_lower in OBJ_COMMANDS:
                type_str = extract_first_positional_string(expr)
                if type_str is not None:
                    return _resolve_type_name(type_str)
            elif cmd_lower in WMI_COMMANDS:
                class_str = extract_first_positional_string(expr)
                if class_str is not None:
                    wmi_lower = class_str.lower()
                    if wmi_lower in WMI_CLASS_NAMES:
                        return wmi_lower
    if isinstance(expr, Ps1MemberAccess):
        if expr.object is None:
            return None
        obj_type = resolve_expression_type(expr.object, variable_types)
        if obj_type is None:
            return None
        member_name = get_member_name(expr.member)
        if member_name is None:
            return None
        return PROPERTY_TYPES.get((obj_type, member_name.lower()))
    return None


def resolve_member_type(
    obj: Expression,
    member: str,
    variable_types: dict[str, str] | None = None,
) -> str | None:
    """
    Resolve the .NET result type of accessing member on obj. Returns the lowercase full .NET type
    name (e.g. `'system.int32'`), or `None` if the object type or the member cannot be resolved.
    """
    obj_type = resolve_expression_type(obj, variable_types)
    if obj_type is None:
        return None
    return PROPERTY_TYPES.get((obj_type, member.lower()))


def is_known_member(
    obj: Expression,
    member: str,
    variable_types: dict[str, str] | None = None,
) -> bool:
    """
    Return `True` if *member* is a known member (property or method) of the resolved type of obj.
    """
    obj_type = resolve_expression_type(obj, variable_types)
    if obj_type is None:
        return False
    lookup = MEMBER_LOOKUP.get(obj_type)
    if lookup is None:
        return False
    return member.lower() in lookup


def get_member_order(type_name: str) -> list[str] | None:
    """
    Return the members of a .NET type in PowerShell Get-Member display order: Methods sorted
    alphabetically, then properties sorted alphabetically.
    """
    members = TYPE_MEMBERS.get(type_name)
    if members is None:
        return None
    methods = sorted(
        (m for m in members if (type_name, m.lower()) not in PROPERTY_TYPES),
        key=str.lower,
    )
    properties = sorted(
        (m for m in members if (type_name, m.lower()) in PROPERTY_TYPES),
        key=str.lower,
    )
    return methods + properties


def _pipeline_pipes_to_get_member(pipeline: Ps1Pipeline) -> bool:
    """
    Check if the last element in a pipeline is a `Get-Member` command.
    """
    if not pipeline.elements:
        return False
    last = pipeline.elements[-1]
    if not isinstance(last, Ps1PipelineElement):
        return False
    cmd = last.expression
    if not isinstance(cmd, Ps1CommandInvocation):
        return False
    name = get_command_name(cmd)
    return name is not None and name.lower() in GET_MEMBER_ALIASES


def _pipeline_source_type(
    pipeline: Ps1Pipeline,
    variable_types: dict[str, str] | None = None,
) -> str | None:
    """
    Determine the .NET type of the expression piped into `Get-Member`. Assumes `Get-Member` is the
    last pipeline element.
    """
    if len(pipeline.elements) < 2:
        return None
    source = pipeline.elements[-2]
    if not isinstance(source, Ps1PipelineElement):
        return None
    if source.expression is None:
        return None
    return resolve_expression_type(source.expression, variable_types)


def _resolve_foreach_element_type(iterable: Expression | None) -> str | None:
    """
    Determine the .NET type of elements produced by a foreach iterable. For a string, PowerShell
    yields the string itself (not individual chars). For an array literal, if all elements share
    the same resolved type, that type is returned.
    """
    if iterable is None:
        return None
    if isinstance(iterable, (Ps1StringLiteral, Ps1HereString)):
        return 'system.string'
    if isinstance(iterable, Ps1ArrayLiteral) and iterable.elements:
        types = set()
        for elem in iterable.elements:
            if isinstance(elem, Expression):
                t = resolve_expression_type(elem)
                if t is None:
                    return None
                types.add(t)
            else:
                return None
        if len(types) == 1:
            return types.pop()
    return None


def collect_variable_types(root: Node) -> dict[str, str]:
    """
    Scan the AST for single-assignment variables whose RHS has a resolvable .NET type; e.g.

        $x = New-Object Net.WebClient

    Returns a mapping from lowercase variable name to canonical .NET type string. Mutations that do
    not change the variable's type (member/index assignments, ++/--) are not reassignments.
    """
    assign_counts: dict[str, int] = {}
    typed_assigns: dict[str, str] = {}
    for var, kind, node in iter_variable_mutations(root):
        if var.scope != Ps1ScopeModifier.NONE:
            continue
        key = var.name.lower()
        if kind in (MutationKind.MEMBER_ASSIGN, MutationKind.INCRDECR):
            continue
        assign_counts[key] = assign_counts.get(key, 0) + 1
        if kind is MutationKind.ASSIGN and isinstance(node, Ps1AssignmentExpression):
            if node.operator == '=' and isinstance(node.value, Expression):
                resolved = resolve_expression_type(node.value)
                if resolved is not None:
                    typed_assigns[key] = resolved
        elif kind is MutationKind.FOREACH and isinstance(node, Ps1ForEachLoop):
            element_type = _resolve_foreach_element_type(node.iterable)
            if element_type is not None:
                typed_assigns[key] = element_type
    return {
        key: type_name
        for key, type_name in typed_assigns.items()
        if assign_counts.get(key, 0) == 1
    }


class VariableTypeAwareTransformer(Transformer):

    def __init__(self):
        super().__init__()
        self._variable_types: dict[str, str] | None = None

    def visit(self, node: Node):
        if self._variable_types is None:
            self._variable_types = collect_variable_types(node)
        return super().visit(node)


class Ps1TypeSystemSimplifications(VariableTypeAwareTransformer):
    """
    Resolve type-aware patterns. For example, the following resolves to the Nth member name string:

        ($X | Get-Member)[N].Name
    """

    def visit_Ps1MemberAccess(self, node: Ps1MemberAccess):
        self.generic_visit(node)
        result = self._try_resolve_get_member_index_name(node)
        if result is not None:
            return result
        result = self._try_strip_name_on_string(node)
        if result is not None:
            return result
        self._try_normalize_member_case(node)
        return None

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        self.generic_visit(node)
        self._try_normalize_member_case(node)
        return None

    def _try_normalize_member_case(self, node: Ps1MemberAccess | Ps1InvokeMember):
        if node.object is None:
            return
        obj_type = resolve_expression_type(node.object, self._variable_types)
        if obj_type is None:
            return
        member_name = get_member_name(node.member)
        if member_name is None:
            return
        canonical = canonical_member_name(obj_type, member_name)
        if canonical is not None and canonical != member_name:
            node.member = canonical
            self.mark_changed()

    def _try_strip_name_on_string(
        self,
        node: Ps1MemberAccess,
    ) -> Expression | None:
        """
        Strip `.Name` access on a string literal: After `Where-Object` wildcard resolution or
        `Get-Member` index resolution, a MemberInfo `.Name` access can be left dangling on the
        resolved string: `'GetCmdlets'.Name` -> `'GetCmdlets'`.
        """
        member_name = get_member_name(node.member)
        if member_name is None or member_name.lower() != 'name':
            return None
        if not isinstance(node.object, Ps1StringLiteral):
            return None
        return node.object

    def _try_resolve_get_member_index_name(
        self,
        node: Ps1MemberAccess,
    ) -> Expression | None:
        """
        Resolve ($X | Get-Member)[N].Name to the Nth member name string.
        """
        member_name = get_member_name(node.member)
        if member_name is None or member_name.lower() != 'name':
            return None
        obj = node.object
        if not isinstance(obj, Ps1IndexExpression):
            return None
        if not isinstance(obj.index, Ps1IntegerLiteral):
            return None
        index = obj.index.value
        inner = unwrap_parens(obj.object) if obj.object is not None else None
        if not isinstance(inner, Ps1Pipeline):
            return None
        if not _pipeline_pipes_to_get_member(inner):
            return None
        type_name = _pipeline_source_type(inner, self._variable_types)
        if type_name is None:
            return None
        ordered = get_member_order(type_name)
        if ordered is None or index < 0 or index >= len(ordered):
            return None
        return make_string_literal(ordered[index])
