"""
Purity analysis for PowerShell expressions: decide whether evaluating a node produces observable
side effects. Shared by the dead-code, trap-removal, and junk/unused-variable passes so that a
single conservative allow-list governs every "is it safe to delete this?" decision.
"""
from __future__ import annotations

import enum

from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    extract_new_object,
    get_command_name,
    is_builtin_variable,
    normalize_dotnet_type_name,
)
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandArgument,
    Ps1CommandInvocation,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1HashLiteral,
    Ps1HereString,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1RangeExpression,
    Ps1RealLiteral,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)

_PURE_STATIC_TYPES = frozenset({
    'array',
    'bitconverter',
    'char',
    'collections.arraylist',
    'collections.generic.dictionary',
    'collections.generic.hashset',
    'collections.generic.list',
    'collections.hashtable',
    'convert',
    'datetime',
    'decimal',
    'double',
    'environment',
    'guid',
    'int',
    'int32',
    'int64',
    'io.path',
    'ipaddress',
    'math',
    'object',
    'security.securestring',
    'securestring',
    'string',
    'text.stringbuilder',
    'timespan',
    'version',
})

_PURE_STATIC_METHODS = frozenset({
    ('diagnostics.process', 'getcurrentprocess'),
    ('threading.tasks.task', 'delay'),
    ('collections.hashtable', 'synchronized'),
})


def _pure_type_name(name: str) -> str:
    """
    Normalize a .NET type name for purity lookup: lower-cased, `System.` prefix removed, and any
    generic-argument suffix (`[byte]` or the arity marker before it) stripped, so `System.Collections.Generic.List`
    and `List[byte]` reduce to the same `collections.generic.list` key.
    """
    name = normalize_dotnet_type_name(name)
    for separator in ('[', '`'):
        name = name.split(separator, 1)[0]
    return name


_PURE_INSTANCE_METHODS = frozenset({
    'adddays',
    'addhours',
    'addminutes',
    'addmonths',
    'addseconds',
    'addyears',
    'compareto',
    'contains',
    'endswith',
    'equals',
    'gethashcode',
    'gettype',
    'indexof',
    'lastindexof',
    'length',
    'padleft',
    'padright',
    'split',
    'startswith',
    'substring',
    'tochar',
    'tochararray',
    'tolower',
    'tostring',
    'touniversaltime',
    'toupper',
    'trim',
    'trimend',
    'trimstart',
})

_PURE_CMDLETS = frozenset({
    'get-childitem',
    'get-command',
    'get-content',
    'get-date',
    'get-item',
    'get-location',
    'get-process',
    'get-random',
    'get-variable',
    'measure-object',
    'out-null',
    'out-string',
    'select-object',
    'sort-object',
    'where-object',
})

_PURE_PIPELINE_CMDLETS = frozenset({
    'foreach-object',
    'select-object',
    'sort-object',
    'where-object',
})


def _command_body_is_pure(cmd: Ps1CommandInvocation) -> bool:
    """
    Check whether all script block arguments of a pipeline cmdlet (ForEach-Object, Where-Object,
    etc.) have side-effect-free bodies. These cmdlets are pure transforms: they evaluate a script
    block per input item without mutating state themselves. Note: the `$Null = <pure>` discard
    idiom is NOT currently recognized here because `is_side_effect_free` has no case for
    `Ps1AssignmentExpression`; such bodies are caught at statement level by
    `pipeline_ends_with_void_foreach` instead.
    """
    # TODO: teach `is_side_effect_free` to recognize `$Null = <pure>` assignments as pure so that
    # this function correctly handles ForEach bodies containing the discard idiom without relying
    # on the separate `pipeline_ends_with_void_foreach` path.
    for arg in cmd.arguments:
        block = arg.value if isinstance(arg, Ps1CommandArgument) else arg
        if not isinstance(block, Ps1ScriptBlock):
            continue
        for stmt in block.body:
            if not isinstance(stmt, Ps1ExpressionStatement):
                return False
            if stmt.expression is not None and not is_side_effect_free(stmt.expression):
                return False
    return True


def is_side_effect_free(node) -> bool:
    """
    Conservative check: return `True` only when evaluating `node` is guaranteed to produce no
    observable side effects beyond yielding a value.
    """
    if isinstance(node, (Ps1StringLiteral, Ps1HereString, Ps1IntegerLiteral, Ps1RealLiteral)):
        return True
    if isinstance(node, Ps1TypeExpression):
        return True
    if isinstance(node, Ps1Variable):
        return True
    if isinstance(node, Ps1ParenExpression):
        return node.expression is None or is_side_effect_free(node.expression)
    if isinstance(node, Ps1CastExpression):
        return is_side_effect_free(node.operand)
    if isinstance(node, Ps1UnaryExpression):
        if node.operator in ('++', '--'):
            return False
        return is_side_effect_free(node.operand)
    if isinstance(node, Ps1BinaryExpression):
        return is_side_effect_free(node.left) and is_side_effect_free(node.right)
    if isinstance(node, Ps1RangeExpression):
        return is_side_effect_free(node.start) and is_side_effect_free(node.end)
    if isinstance(node, Ps1ArrayLiteral):
        return all(is_side_effect_free(e) for e in node.elements)
    if isinstance(node, Ps1HashLiteral):
        return all(is_side_effect_free(value) for _key, value in node.pairs)
    if isinstance(node, Ps1ArrayExpression):
        if len(node.body) == 1:
            stmt = node.body[0]
            if isinstance(stmt, Ps1ExpressionStatement) and stmt.expression is not None:
                return is_side_effect_free(stmt.expression)
        return len(node.body) == 0
    if isinstance(node, Ps1IndexExpression):
        return is_side_effect_free(node.object) and is_side_effect_free(node.index)
    if isinstance(node, Ps1MemberAccess):
        return is_side_effect_free(node.object)
    if isinstance(node, Ps1InvokeMember):
        if not all(is_side_effect_free(a) for a in node.arguments):
            return False
        if node.access == Ps1AccessKind.STATIC:
            obj = node.object
            if isinstance(obj, Ps1TypeExpression):
                type_name = _pure_type_name(obj.name)
                if type_name in _PURE_STATIC_TYPES:
                    return True
                member = node.member
                if (
                    isinstance(member, str)
                    and (type_name, member.lower()) in _PURE_STATIC_METHODS
                ):
                    return True
        elif is_side_effect_free(node.object):
            member = node.member
            if isinstance(member, str) and member.lower() in _PURE_INSTANCE_METHODS:
                return True
        return False
    if isinstance(node, Ps1CommandInvocation):
        new_object = extract_new_object(node)
        if new_object is not None:
            type_name, ctor_args = new_object
            if _pure_type_name(type_name) in _PURE_STATIC_TYPES:
                return all(is_side_effect_free(a) for a in ctor_args)
            return False
        name = get_command_name(node)
        if name is None:
            return False
        if name.lower() in _PURE_CMDLETS:
            return True
        if name.lower() in _PURE_PIPELINE_CMDLETS:
            return _command_body_is_pure(node)
        return False
    if isinstance(node, Ps1Pipeline):
        return all(
            isinstance(el, Ps1PipelineElement) and is_side_effect_free(el.expression)
            for el in node.elements
        )
    if isinstance(node, Ps1ExpandableString):
        return all(is_side_effect_free(p) for p in node.parts)
    return False


class StatementEffect(enum.Enum):
    """
    The observable effect of evaluating a standalone statement, used by every pass that decides
    whether a statement can be pruned from a body:

    - `EFFECT`: the statement performs a side effect (a command call, a store to a real variable, an
      increment); it must be preserved.
    - `OUTPUT`: the statement is side-effect-free but yields a value to the enclosing pipeline (a
      bare constant, a pure expression); it is junk at a discarding position, but in a captured body
      it may be the return value, so removing it needs an emit-safety check.
    - `DISCARD`: the statement is a syntactic no-op that yields nothing and does nothing observable
      (an empty statement, the `$Null = <pure>` discard idiom, a `[Void]` cast, a `... | Out-Null`
      pipeline, a discarding `ForEach`); it is always safe to remove, even when it empties the body.
    """
    EFFECT = 'effect'
    OUTPUT = 'output'
    DISCARD = 'discard'


def classify_statement_effect(stmt) -> StatementEffect:
    """
    Classify the observable effect of a standalone statement as a `StatementEffect`. This is the one
    shared authority the dead-code and junk-removal passes consult so they never disagree about
    whether a statement carries a body's output: a `DISCARD` emits nothing and can always be dropped,
    an `OUTPUT` yields a value that emit-safety must protect in a captured body, and an `EFFECT` must
    always be kept.
    """
    if not isinstance(stmt, Ps1ExpressionStatement):
        return StatementEffect.EFFECT
    expr = stmt.expression
    if expr is None:
        return StatementEffect.DISCARD
    if isinstance(expr, Ps1CastExpression) and expr.type_name.lower() == 'void':
        return StatementEffect.DISCARD
    if isinstance(expr, Ps1Pipeline):
        if pipeline_ends_with_out_null(expr) and pipeline_prefix_is_pure(expr):
            return StatementEffect.DISCARD
        if pipeline_ends_with_void_foreach(expr) and pipeline_prefix_is_pure(expr):
            return StatementEffect.DISCARD
        if pipeline_ends_with_cmdlet(expr, _PURE_PIPELINE_CMDLETS):
            # A pure pipeline cmdlet (`... | Where-Object {...}`) yields a filtered value a caller
            # may consume, so it is kept even though it performs no side effect of its own.
            return StatementEffect.EFFECT
    if (
        isinstance(expr, Ps1AssignmentExpression)
        and expr.operator == '='
        and is_builtin_variable(expr.target, {'null'})
    ):
        if expr.value is not None and is_side_effect_free(expr.value):
            return StatementEffect.DISCARD
        return StatementEffect.EFFECT
    if is_side_effect_free(expr):
        return StatementEffect.OUTPUT
    return StatementEffect.EFFECT


def pipeline_ends_with_out_null(pipeline: Ps1Pipeline) -> bool:
    if len(pipeline.elements) < 2:
        return False
    last = pipeline.elements[-1]
    if not isinstance(last, Ps1PipelineElement):
        return False
    expr = last.expression
    if isinstance(expr, Ps1CommandInvocation):
        name = get_command_name(expr)
        return name is not None and name.lower() == 'out-null'
    return False


def pipeline_prefix_is_pure(pipeline: Ps1Pipeline) -> bool:
    for el in pipeline.elements[:-1]:
        if not isinstance(el, Ps1PipelineElement):
            return False
        if not is_side_effect_free(el.expression):
            return False
    return True


def pipeline_ends_with_void_foreach(pipeline: Ps1Pipeline) -> bool:
    """
    Detect junk pipelines like `... | ForEach-Object { [Void]$_ }` or
    `... | ForEach-Object { $Null = $_ }` where the ForEach body explicitly discards all output.
    These are anti-analysis noise injected into malware scripts.
    """
    if len(pipeline.elements) < 2:
        return False
    last = pipeline.elements[-1]
    if not isinstance(last, Ps1PipelineElement):
        return False
    expr = last.expression
    if not isinstance(expr, Ps1CommandInvocation):
        return False
    name = get_command_name(expr)
    if name is None or name.lower() != 'foreach-object':
        return False
    for arg in expr.arguments:
        block = arg.value if isinstance(arg, Ps1CommandArgument) else arg
        if not isinstance(block, Ps1ScriptBlock):
            continue
        for stmt in block.body:
            if not isinstance(stmt, Ps1ExpressionStatement) or stmt.expression is None:
                return False
            ex = stmt.expression
            if isinstance(ex, Ps1CastExpression) and ex.type_name.lower() == 'void':
                continue
            if (
                isinstance(ex, Ps1AssignmentExpression)
                and ex.operator == '='
                and is_builtin_variable(ex.target, {'null'})
                and (ex.value is None or is_side_effect_free(ex.value))
            ):
                continue
            return False
    return True


def pipeline_ends_with_cmdlet(pipeline: Ps1Pipeline, names: frozenset) -> bool:
    if len(pipeline.elements) < 2:
        return False
    last = pipeline.elements[-1]
    if not isinstance(last, Ps1PipelineElement):
        return False
    expr = last.expression
    if not isinstance(expr, Ps1CommandInvocation):
        return False
    name = get_command_name(expr)
    return name is not None and name.lower() in names


def statement_performs_side_effect(stmt) -> bool:
    """
    Return `True` only when a statement is known to perform a genuine observable side effect
    beyond yielding a value. This is stricter than `classify_statement_effect` returning `EFFECT`:
    pipelines ending with a pure pipeline cmdlet (`Where-Object`, `Select-Object`, etc.) are
    classified as `EFFECT` to prevent their deletion, but they have no side effect of their own —
    only a value yield. Such statements must NOT count as anchors that permit removing surrounding
    pure-output statements from a ROOT body.

    Control-flow statements (`if`, `for`, `while`, etc.) are treated as non-anchors even when their
    bodies contain side effects, because they execute conditionally — they cannot guarantee that the
    function's output is already covered when their condition is unknown at compile time.
    """
    if not isinstance(stmt, Ps1ExpressionStatement):
        return False
    expr = stmt.expression
    if expr is None:
        return False
    if isinstance(expr, Ps1Pipeline) and pipeline_ends_with_cmdlet(expr, _PURE_PIPELINE_CMDLETS):
        return False
    return classify_statement_effect(stmt) is StatementEffect.EFFECT
