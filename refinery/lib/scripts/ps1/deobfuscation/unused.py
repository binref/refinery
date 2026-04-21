"""
Remove assignments to variables that are never read.
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
from refinery.lib.scripts.ps1.deobfuscation.helpers import get_body
from refinery.lib.scripts.ps1.deobfuscation.names import PS1_KNOWN_VARIABLES
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1FunctionDefinition,
    Ps1HereString,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1MemberAccess,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1RangeExpression,
    Ps1RealLiteral,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)

_SKIP_VARIABLES = _PS1_AUTOMATIC_VARIABLES | frozenset(PS1_KNOWN_VARIABLES) | frozenset(_PS1_DEFAULT_VARIABLES)


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
    return False


class Ps1UnusedVariableRemoval(Transformer):
    """
    Remove assignments to variables that are never read anywhere in the outer scope. When the
    right-hand side of an assignment has side effects, the assignment wrapper is stripped but the
    expression is preserved as a standalone statement.
    """

    def visit(self, node: Node):
        write_nodes: dict[str, list[Node]] = {}
        write_targets: set[int] = set()
        read_in_assign: dict[str, set[str]] = {}
        has_free_read: set[str] = set()
        for n in _walk_outer_scope(node):
            if isinstance(n, Ps1AssignmentExpression):
                var = _assignment_target_variable(n.target)
                if var is not None:
                    write_targets.add(id(var))
                    key = _candidate_key(var)
                    if key is not None:
                        write_nodes.setdefault(key, []).append(n)
            elif isinstance(n, Ps1ForEachLoop):
                if isinstance(n.variable, Ps1Variable):
                    write_targets.add(id(n.variable))
            elif isinstance(n, Ps1UnaryExpression) and n.operator in ('++', '--'):
                if isinstance(n.operand, Ps1Variable):
                    write_targets.add(id(n.operand))
                    key = _candidate_key(n.operand)
                    if key is not None:
                        write_nodes.setdefault(key, []).append(n)
            elif isinstance(n, Ps1ParameterDeclaration):
                if isinstance(n.variable, Ps1Variable):
                    write_targets.add(id(n.variable))
        for n in _walk_outer_scope(node):
            if not isinstance(n, Ps1Variable) or id(n) in write_targets:
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
            dead_stmts: set[int] = set()
            for key in dead:
                for mutation in write_nodes[key]:
                    stmt = _find_removable_statement(mutation)
                    if stmt is not None:
                        dead_stmts.add(id(stmt))
            surviving = [
                s for s in body
                if id(s) not in dead_stmts
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
