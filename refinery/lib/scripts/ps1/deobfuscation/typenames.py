"""
.NET type system utilities for PowerShell deobfuscation.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer, set_value
from refinery.lib.scripts.ps1.analysis.cache import model_cache
from refinery.lib.scripts.ps1.analysis.dataflow import Ps1VariableFlow
from refinery.lib.scripts.ps1.analysis.values import (
    Ps1VariableTyping,
    make_string_literal,
    resolve_expression_type,
)
from refinery.lib.scripts.ps1.analysis.variable_types import type_at
from refinery.lib.scripts.ps1.ast import get_command_name, get_member_name, unwrap_parens
from refinery.lib.scripts.ps1.data import (
    CANONICAL_TYPE_NAMES,
    GET_MEMBER_ALIASES,
    TYPE_ACCELERATORS,
    canonical_member,
)
from refinery.lib.scripts.ps1.data import resolve_member_type as data_member_type
from refinery.lib.scripts.ps1.data import (
    resolve_type,
    view_members,
)
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName, parse_type_name
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1CommandInvocation,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1Script,
    Ps1StringLiteral,
    Ps1Variable,
)


def _accelerator_spelling(name: str) -> bool:
    """
    Whether `name` is written as a type accelerator, with or without array, pointer or reference
    suffixes. A name the type-name grammar does not understand is judged as written.
    """
    parsed = parse_type_name(name)
    if parsed is None:
        return name.lower() in TYPE_ACCELERATORS
    return parsed.name.lower() in TYPE_ACCELERATORS


def canonical_type_name(name: str) -> str | None:
    """
    Return the canonical PascalCase display name for a .NET type, preserving an explicit `System.`
    prefix if the caller used one. Returns `None` if the type is not in the database, or if the name
    is already a type accelerator: `[ref]`, `[int]` and `[string]` are the readable forms and are
    left untouched, where a verbose `[System.Int32]` still folds to `[Int32]`.

    The array suffixes are carried through rather than looked up, because the display table is keyed
    by the element type: rendering `byte[]` off its definition alone would answer `Byte`, a
    different type, turning `New-Object Byte[] $n` into `New-Object Byte $n`.

    An accelerator keeps its spelling through a suffix too. `[byte[]]` is the readable form for the
    same reason `[byte]` is, and it reached the display table only because the name it was looked up
    under carried the suffix and the table is keyed without one.
    """
    if _accelerator_spelling(name):
        return None
    resolved = resolve_type(name)
    lower = resolved.definition.lower() if resolved is not None else name.lower()
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
    if resolved is not None and (resolved.ranks or resolved.pointers or resolved.byref):
        return str(resolved._replace(name=display, arity=0, arguments=()))
    return display


def canonical_member_name(type_name: str | Ps1TypeName, member: str) -> str | None:
    """
    Return the canonical PascalCase member name for a known .NET type.
    """
    return canonical_member(type_name, member)


def resolve_member_type(
    obj: Expression,
    member: str,
    type_of_variable: Ps1VariableTyping | None = None,
) -> Ps1TypeName | None:
    """
    Resolve the .NET result type of accessing `member` on `obj`, or `None` if the object type or the
    member cannot be resolved.
    """
    obj_type = resolve_expression_type(obj, type_of_variable)
    if obj_type is None:
        return None
    return data_member_type(obj_type, member)


def get_member_order(type_name: str | Ps1TypeName) -> list[str] | None:
    """
    Return the members of a .NET type in PowerShell Get-Member display order: Methods sorted
    alphabetically, then properties sorted alphabetically.
    """
    members = view_members(type_name)
    if members is None:
        return None
    methods = sorted(
        (name for name, m in members.items() if m['kind'] != 'property'),
        key=str.lower,
    )
    properties = sorted(
        (name for name, m in members.items() if m['kind'] == 'property'),
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
    type_of_variable: Ps1VariableTyping | None = None,
) -> Ps1TypeName | None:
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
    return resolve_expression_type(source.expression, type_of_variable)


class VariableTypeAwareTransformer(Transformer):
    """
    A pass that asks `refinery.lib.scripts.ps1.analysis.variable_types.type_at` what a variable
    holds where it is read, rather than carrying a table of names it built itself.

    The flow model is captured once at the root and dropped when the walk ends, for the reason
    `refinery.lib.scripts.ps1.deobfuscation.typecast.Ps1TypeCasts.visit` gives. The answers are held
    for as long as the model is, keyed on the occurrence they were asked about: `type_at` walks
    every write of a binding, and a member chain, two passes and every iteration of the normalize
    group ask about the same occurrences again. The occurrence is kept beside its answer because
    `id` alone identifies a node only while that node is alive, and this walk frees the ones it
    replaces.
    """

    def __init__(self):
        super().__init__()
        self._flow: Ps1VariableFlow | None = None
        self._typed: dict[int, tuple[Ps1Variable, Ps1TypeName | None]] = {}
        self._entry = False

    def visit(self, node: Node):
        if self._entry or not isinstance(node, Ps1Script):
            return super().visit(node)
        self._entry = True
        try:
            self._flow = model_cache(self, node).variable_flow
            return super().visit(node)
        finally:
            self._entry = False
            self._flow = None
            self._typed.clear()

    def _type_of_variable(self, var: Ps1Variable) -> Ps1TypeName | None:
        if self._flow is None:
            return None
        found = self._typed.get(id(var))
        if found is None or found[0] is not var:
            found = self._typed[id(var)] = (var, type_at(var, self._flow))
        return found[1]


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
        obj_type = resolve_expression_type(node.object, self._type_of_variable)
        if obj_type is None:
            return
        member_name = get_member_name(node.member)
        if member_name is None:
            return
        canonical = canonical_member_name(obj_type, member_name)
        if canonical is not None and canonical != member_name:
            set_value(node, 'member', canonical)
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
        type_name = _pipeline_source_type(inner, self._type_of_variable)
        if type_name is None:
            return None
        ordered = get_member_order(type_name)
        if ordered is None or index < 0 or index >= len(ordered):
            return None
        return make_string_literal(ordered[index])
