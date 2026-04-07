"""
Eliminate dead code from PowerShell scripts after constant folding.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Statement, Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import _get_body
from refinery.lib.scripts.ps1.model import (
    Ps1DoUntilLoop,
    Ps1DoWhileLoop,
    Ps1ExpressionStatement,
    Ps1ForLoop,
    Ps1IfStatement,
    Ps1IntegerLiteral,
    Ps1ParenExpression,
    Ps1RealLiteral,
    Ps1StringLiteral,
    Ps1SwitchStatement,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
)


def _is_truthy(node) -> bool | None:
    """
    Determine the boolean truth value of a constant expression using PowerShellsemantics. Returns
    None for non-constant or unrecognized expressions.
    """
    while isinstance(node, Ps1ParenExpression):
        node = node.expression
    if node is None:
        return None
    if isinstance(node, Ps1Variable) and node.scope == node.scope.NONE:
        lower = node.name.lower()
        if lower == 'true':
            return True
        if lower in ('false', 'null'):
            return False
        return None
    if isinstance(node, Ps1IntegerLiteral):
        return node.value != 0
    if isinstance(node, Ps1RealLiteral):
        return node.value != 0.0
    if isinstance(node, Ps1StringLiteral):
        return len(node.value) > 0
    if isinstance(node, Ps1UnaryExpression) and node.operator == '-':
        return _is_truthy(node.operand)
    return None


class Ps1DeadCodeElimination(Transformer):
    """
    Remove unreachable code guarded by constant boolean conditions and resolve switch statements
    on constant values.
    """

    def visit(self, node: Node):
        for parent in list(node.walk()):
            body = _get_body(parent)
            if body is None:
                continue
            new_body = self._prune_body(body)
            if new_body is not body:
                body.clear()
                body.extend(new_body)
                for stmt in new_body:
                    stmt.parent = parent
                self.mark_changed()

    def _prune_body(self, body: list[Statement]) -> list[Statement]:
        result: list[Statement] = []
        changed = False
        for stmt in body:
            replacement = self._try_prune(stmt)
            if replacement is not None:
                result.extend(replacement)
                changed = True
            else:
                result.append(stmt)
        return result if changed else body

    def _try_prune(self, stmt: Statement) -> list[Statement] | None:
        if isinstance(stmt, Ps1WhileLoop):
            return self._prune_while(stmt)
        if isinstance(stmt, Ps1DoWhileLoop):
            return self._prune_do_while(stmt)
        if isinstance(stmt, Ps1DoUntilLoop):
            return self._prune_do_until(stmt)
        if isinstance(stmt, Ps1ForLoop):
            return self._prune_for(stmt)
        if isinstance(stmt, Ps1IfStatement):
            return self._prune_if(stmt)
        if isinstance(stmt, Ps1SwitchStatement):
            return self._prune_switch(stmt)
        return None

    @staticmethod
    def _prune_while(node: Ps1WhileLoop) -> list[Statement] | None:
        if _is_truthy(node.condition) is False:
            return []
        return None

    @staticmethod
    def _prune_do_while(node: Ps1DoWhileLoop) -> list[Statement] | None:
        if _is_truthy(node.condition) is False and node.body is not None:
            return list(node.body.body)
        return None

    @staticmethod
    def _prune_do_until(node: Ps1DoUntilLoop) -> list[Statement] | None:
        if _is_truthy(node.condition) is True and node.body is not None:
            return list(node.body.body)
        return None

    @staticmethod
    def _prune_for(node: Ps1ForLoop) -> list[Statement] | None:
        if _is_truthy(node.condition) is not False:
            return None
        result: list[Statement] = []
        if node.initializer is not None:
            result.append(Ps1ExpressionStatement(expression=node.initializer))
        return result

    @staticmethod
    def _prune_if(node: Ps1IfStatement) -> list[Statement] | None:
        kept_clauses: list[tuple] = []
        for condition, block in node.clauses:
            truth = _is_truthy(condition)
            if truth is True:
                return list(block.body)
            if truth is False:
                continue
            kept_clauses.append((condition, block))
            kept_clauses.extend(node.clauses[node.clauses.index((condition, block)) + 1:])
            break
        else:
            if node.else_block is not None:
                return list(node.else_block.body)
            return []
        if len(kept_clauses) == len(node.clauses):
            return None
        node.clauses[:] = kept_clauses
        return None

    @staticmethod
    def _prune_switch(node: Ps1SwitchStatement) -> list[Statement] | None:
        if node.regex or node.wildcard or node.exact or node.file:
            return None
        value = node.value
        if isinstance(value, Ps1IntegerLiteral):
            target_int = value.value
            target_str = None
        elif isinstance(value, Ps1StringLiteral):
            target_str = value.value.lower()
            target_int = None
        else:
            return None
        default_body: list[Statement] | None = None
        for condition, block in node.clauses:
            if condition is None:
                default_body = list(block.body)
                continue
            if target_int is not None and isinstance(condition, Ps1IntegerLiteral):
                if condition.value == target_int:
                    return list(block.body)
            elif target_str is not None and isinstance(condition, Ps1StringLiteral):
                if condition.value.lower() == target_str:
                    return list(block.body)
            elif target_int is not None and isinstance(condition, Ps1StringLiteral):
                try:
                    if int(condition.value) == target_int:
                        return list(block.body)
                except ValueError:
                    pass
            elif target_str is not None and isinstance(condition, Ps1IntegerLiteral):
                try:
                    if int(target_str) == condition.value:
                        return list(block.body)
                except ValueError:
                    pass
        if default_body is not None:
            return default_body
        return []
