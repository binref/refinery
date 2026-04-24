"""
Remove unused variable assignments and junk expression statements.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.ps1.deobfuscation.constants import (
    _PS1_AUTOMATIC_VARIABLES,
    _PS1_DEFAULT_VARIABLES,
    _assignment_target_variable,
    _candidate_key,
    _find_removable_statement,
    _walk_outer_scope,
)
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    get_body,
    get_command_name,
    inside_value_producing_context,
)
from refinery.lib.scripts.ps1.deobfuscation.data import PS1_KNOWN_VARIABLES
from refinery.lib.scripts.ps1.model import (
    Expression,
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
    Ps1ForEachLoop,
    Ps1FunctionDefinition,
    Ps1HereString,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParameterDeclaration,
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

_SKIP_VARIABLES = _PS1_AUTOMATIC_VARIABLES | frozenset(PS1_KNOWN_VARIABLES) | frozenset(_PS1_DEFAULT_VARIABLES)

_PURE_STATIC_TYPES = frozenset({
    'array',
    'bitconverter',
    'char',
    'convert',
    'datetime',
    'decimal',
    'double',
    'environment',
    'guid',
    'int',
    'int32',
    'int64',
    'math',
    'string',
    'system.array',
    'system.bitconverter',
    'system.char',
    'system.convert',
    'system.datetime',
    'system.decimal',
    'system.double',
    'system.environment',
    'system.guid',
    'system.int32',
    'system.int64',
    'system.math',
    'system.string',
    'system.timespan',
    'timespan',
})

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
    'insert',
    'lastindexof',
    'length',
    'padleft',
    'padright',
    'remove',
    'replace',
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
    block per input item without mutating state themselves.
    """
    for arg in cmd.arguments:
        block = arg.value if isinstance(arg, Ps1CommandArgument) else arg
        if not isinstance(block, Ps1ScriptBlock):
            continue
        for stmt in block.body:
            if isinstance(stmt, Ps1ExpressionStatement) and stmt.expression is not None:
                if not _is_side_effect_free(stmt.expression):
                    return False
            elif not isinstance(stmt, Ps1ExpressionStatement):
                return False
    return True


def _is_side_effect_free(node) -> bool:
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
        return node.expression is None or _is_side_effect_free(node.expression)
    if isinstance(node, Ps1CastExpression):
        return _is_side_effect_free(node.operand)
    if isinstance(node, Ps1UnaryExpression):
        if node.operator in ('++', '--'):
            return False
        return _is_side_effect_free(node.operand)
    if isinstance(node, Ps1BinaryExpression):
        return _is_side_effect_free(node.left) and _is_side_effect_free(node.right)
    if isinstance(node, Ps1RangeExpression):
        return _is_side_effect_free(node.start) and _is_side_effect_free(node.end)
    if isinstance(node, Ps1ArrayLiteral):
        return all(_is_side_effect_free(e) for e in node.elements)
    if isinstance(node, Ps1ArrayExpression):
        if len(node.body) == 1:
            stmt = node.body[0]
            if isinstance(stmt, Ps1ExpressionStatement) and stmt.expression is not None:
                return _is_side_effect_free(stmt.expression)
        return len(node.body) == 0
    if isinstance(node, Ps1IndexExpression):
        return _is_side_effect_free(node.object) and _is_side_effect_free(node.index)
    if isinstance(node, Ps1MemberAccess):
        return _is_side_effect_free(node.object)
    if isinstance(node, Ps1InvokeMember):
        if not all(_is_side_effect_free(a) for a in node.arguments):
            return False
        if node.access == Ps1AccessKind.STATIC:
            obj = node.object
            if isinstance(obj, Ps1TypeExpression) and obj.name.lower() in _PURE_STATIC_TYPES:
                return True
        elif _is_side_effect_free(node.object):
            member = node.member
            if isinstance(member, str) and member.lower() in _PURE_INSTANCE_METHODS:
                return True
        return False
    if isinstance(node, Ps1CommandInvocation):
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
            isinstance(el, Ps1PipelineElement) and _is_side_effect_free(el.expression)
            for el in node.elements
        )
    if isinstance(node, Ps1ExpandableString):
        return all(_is_side_effect_free(p) for p in node.parts)
    return False


class Ps1UnusedVariableRemoval(Transformer):
    """
    Remove assignments to variables that are never read anywhere in the outer scope. When the
    right-hand side of an assignment has side effects, the assignment wrapper is stripped but the
    expression is preserved as a standalone statement.
    """

    def visit(self, node: Node):
        write_nodes: dict[str, list[Node]] = {}
        write_targets: set[Ps1Variable] = set()
        read_in_assign: dict[str, set[str]] = {}
        has_free_read: set[str] = set()
        for n in _walk_outer_scope(node):
            if isinstance(n, Ps1AssignmentExpression):
                var = _assignment_target_variable(n.target)
                if var is not None:
                    write_targets.add(var)
                    key = _candidate_key(var)
                    if key is not None:
                        write_nodes.setdefault(key, []).append(n)
            elif isinstance(n, Ps1ForEachLoop):
                if isinstance(n.variable, Ps1Variable):
                    write_targets.add(n.variable)
            elif isinstance(n, Ps1UnaryExpression) and n.operator in ('++', '--'):
                if isinstance(n.operand, Ps1Variable):
                    write_targets.add(n.operand)
                    key = _candidate_key(n.operand)
                    if key is not None:
                        write_nodes.setdefault(key, []).append(n)
            elif isinstance(n, Ps1ParameterDeclaration):
                if isinstance(n.variable, Ps1Variable):
                    write_targets.add(n.variable)
        for n in _walk_outer_scope(node):
            if not isinstance(n, Ps1Variable) or n in write_targets:
                continue
            key = _candidate_key(n)
            if key is None:
                continue
            enclosing = self._enclosing_assignment_target(n)
            if enclosing is not None:
                read_in_assign.setdefault(key, set()).add(enclosing)
            else:
                has_free_read.add(key)
        dead: set[str] = set()
        for key in write_nodes:
            if key in has_free_read or key in _SKIP_VARIABLES:
                continue
            if key not in read_in_assign:
                dead.add(key)
        changed = True
        while changed:
            changed = False
            for key, assignees in read_in_assign.items():
                if key in dead or key in has_free_read or key in _SKIP_VARIABLES:
                    continue
                if key not in write_nodes:
                    continue
                if assignees.issubset(dead):
                    dead.add(key)
                    changed = True
        if not dead:
            return None
        body = get_body(node)
        if body is not None:
            dead_stmts: set[Node] = set()
            for key in dead:
                for mutation in write_nodes[key]:
                    stmt = _find_removable_statement(mutation)
                    if stmt is not None:
                        dead_stmts.add(stmt)
            surviving = [
                s for s in body
                if s not in dead_stmts
                and not isinstance(s, Ps1FunctionDefinition)
            ]
            if not surviving:
                return None
        for key in dead:
            for mutation in write_nodes[key]:
                self._remove_mutation(mutation)

    @staticmethod
    def _enclosing_assignment_target(var: Ps1Variable) -> str | None:
        """
        If `var` is read inside an assignment's RHS, return the assignment target's variable key.
        """
        cursor: Node = var
        while cursor.parent is not None:
            parent = cursor.parent
            if isinstance(parent, Ps1AssignmentExpression) and cursor is not parent.target:
                target = _assignment_target_variable(parent.target)
                if target is not None:
                    return _candidate_key(target)
                return None
            cursor = parent
        return None

    def _remove_mutation(self, mutation: Node):
        if isinstance(mutation, Ps1AssignmentExpression):
            rhs = mutation.value
            if rhs is not None and not _is_side_effect_free(rhs) and isinstance(rhs, Expression):
                stmt = _find_removable_statement(mutation)
                if stmt is None:
                    return
                replacement = Ps1ExpressionStatement(expression=rhs)
                _replace_in_parent(stmt, replacement)
                self.mark_changed()
            else:
                stmt = _find_removable_statement(mutation)
                if stmt is not None and _remove_from_parent(stmt):
                    self.mark_changed()
        elif isinstance(mutation, Ps1UnaryExpression):
            stmt = _find_removable_statement(mutation)
            if stmt is not None and _remove_from_parent(stmt):
                self.mark_changed()


class Ps1JunkStatementRemoval(Transformer):
    """
    Remove standalone expression statements that produce no observable side effects (junk/noise
    injected for anti-analysis) and function definitions that are never called.
    """

    def visit(self, node: Node):
        called = self._reachable_functions(node)
        for parent in list(_walk_outer_scope(node)):
            if inside_value_producing_context(parent):
                continue
            body = get_body(parent)
            if body is None:
                continue
            self._prune_body(body, parent is node, called)

    @staticmethod
    def _reachable_functions(node: Node) -> set[str]:
        """
        Collect all function names transitively reachable from top-level call sites. First gather
        direct calls from the outer scope, then expand through function bodies until stable.
        """
        directly_called: set[str] = set()
        functions: dict[str, Ps1FunctionDefinition] = {}
        for n in _walk_outer_scope(node):
            if isinstance(n, Ps1CommandInvocation):
                name = get_command_name(n)
                if name is not None:
                    directly_called.add(name.lower())
            elif isinstance(n, Ps1FunctionDefinition):
                functions[n.name.lower()] = n
        reachable = set(directly_called)
        frontier = list(reachable & functions.keys())
        while frontier:
            fname = frontier.pop()
            fdef = functions[fname]
            if fdef.body is None:
                continue
            for n in fdef.body.walk():
                if isinstance(n, Ps1CommandInvocation):
                    name = get_command_name(n)
                    if name is not None:
                        key = name.lower()
                        if key not in reachable:
                            reachable.add(key)
                            if key in functions:
                                frontier.append(key)
        return reachable

    def _prune_body(self, body: list, is_root: bool, called: set[str]):
        removable: set[Node] = set()
        for stmt in body:
            if self._is_removable_statement(stmt):
                removable.add(stmt)
            elif is_root and isinstance(stmt, Ps1FunctionDefinition):
                if stmt.name.lower() not in called:
                    removable.add(stmt)
        if not removable:
            return
        if is_root:
            surviving = [
                s for s in body
                if s not in removable
                and not isinstance(s, Ps1FunctionDefinition)
            ]
            if not surviving:
                return
        for stmt in list(body):
            if stmt in removable:
                if _remove_from_parent(stmt):
                    self.mark_changed()

    @staticmethod
    def _is_removable_statement(stmt) -> bool:
        if not isinstance(stmt, Ps1ExpressionStatement):
            return False
        expr = stmt.expression
        if expr is None:
            return False
        if isinstance(expr, Ps1CastExpression) and expr.type_name.lower() == 'void':
            return True
        if isinstance(expr, Ps1Pipeline):
            if _pipeline_ends_with_out_null(expr) and _pipeline_prefix_is_pure(expr):
                return True
            if _pipeline_ends_with_void_foreach(expr) and _pipeline_prefix_is_pure(expr):
                return True
            if _pipeline_ends_with_cmdlet(expr, _PURE_PIPELINE_CMDLETS):
                return False
        return _is_side_effect_free(expr)


def _pipeline_ends_with_out_null(pipeline: Ps1Pipeline) -> bool:
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


def _pipeline_prefix_is_pure(pipeline: Ps1Pipeline) -> bool:
    for el in pipeline.elements[:-1]:
        if not isinstance(el, Ps1PipelineElement):
            return False
        if not _is_side_effect_free(el.expression):
            return False
    return True


def _pipeline_ends_with_void_foreach(pipeline: Ps1Pipeline) -> bool:
    """
    Detect junk pipelines like ``... | ForEach-Object { [Void]$_ }`` where the ForEach body
    explicitly discards all output via ``[Void]`` casts. These are anti-analysis noise injected
    into malware scripts.
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
            if not (isinstance(stmt.expression, Ps1CastExpression)
                    and stmt.expression.type_name.lower() == 'void'):
                return False
    return True


def _pipeline_ends_with_cmdlet(pipeline: Ps1Pipeline, names: frozenset) -> bool:
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
