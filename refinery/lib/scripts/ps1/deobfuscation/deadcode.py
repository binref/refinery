"""
Eliminate dead code from PowerShell scripts after constant folding.
"""
from __future__ import annotations

from refinery.lib.scripts import Block, Node, Statement, Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import _get_body
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1BreakStatement,
    Ps1ContinueStatement,
    Ps1DoUntilLoop,
    Ps1DoWhileLoop,
    Ps1ExpressionStatement,
    Ps1ForLoop,
    Ps1IfStatement,
    Ps1IntegerLiteral,
    Ps1ParenExpression,
    Ps1RealLiteral,
    Ps1ScopeModifier,
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


def _unwrap_integer(node) -> int | None:
    """
    Extract a plain integer value from a constant expression, or return None.
    """
    while isinstance(node, Ps1ParenExpression):
        node = node.expression
    if isinstance(node, Ps1IntegerLiteral):
        return node.value
    if (
        isinstance(node, Ps1Variable)
        and node.scope == Ps1ScopeModifier.NONE
        and node.name.lower() == 'null'
    ):
        return 0
    if isinstance(node, Ps1UnaryExpression) and node.operator == '-':
        inner = node.operand
        while isinstance(inner, Ps1ParenExpression):
            inner = inner.expression
        if isinstance(inner, Ps1IntegerLiteral):
            return -inner.value
    return None


_COMPARISON_OPS = {
    '-eq': int.__eq__,
    '-ne': int.__ne__,
    '-lt': int.__lt__,
    '-le': int.__le__,
    '-gt': int.__gt__,
    '-ge': int.__ge__,
}


def _evaluate_for_condition(node: Ps1ForLoop) -> bool | None:
    """
    Try to evaluate a for-loop condition at loop entry by substituting the initial value of the
    loop variable into the comparison. Returns the boolean result, or None if the pattern does not
    match.
    """
    init = node.initializer
    cond = node.condition
    if not isinstance(init, Ps1AssignmentExpression) or init.operator != '=':
        return None
    if not isinstance(init.target, Ps1Variable):
        return None
    init_val = _unwrap_integer(init.value)
    if init_val is None:
        return None
    if not isinstance(cond, Ps1BinaryExpression):
        return None
    op_fn = _COMPARISON_OPS.get(cond.operator.lower())
    if op_fn is None:
        return None
    var_name = init.target.name.lower()
    var_scope = init.target.scope
    left_val = _resolve_side(cond.left, var_name, var_scope, init_val)
    right_val = _resolve_side(cond.right, var_name, var_scope, init_val)
    if left_val is None or right_val is None:
        return None
    return bool(op_fn(left_val, right_val))


def _resolve_side(
    node, var_name: str, var_scope: Ps1ScopeModifier, init_val: int,
) -> int | None:
    """
    Resolve one side of a for-loop condition to an integer: if the node is the loop variable,
    return the initial value; if it is a constant integer, return that; otherwise return None.
    """
    while isinstance(node, Ps1ParenExpression):
        node = node.expression
    if (
        isinstance(node, Ps1Variable)
        and node.name.lower() == var_name
        and node.scope == var_scope
    ):
        return init_val
    return _unwrap_integer(node)


def _body_breaks_unconditionally(body: list[Statement]) -> bool:
    """
    Return True if the last statement in the body is an unlabeled break and the body contains no
    continue statements at any nesting depth. Such a loop body executes exactly once.
    """
    if not body:
        return False
    last = body[-1]
    if not isinstance(last, Ps1BreakStatement) or last.label is not None:
        return False
    for stmt in body[:-1]:
        for node in stmt.walk():
            if isinstance(node, Ps1ContinueStatement):
                return False
    return True


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
        truth = _is_truthy(node.condition)
        if truth is False:
            return []
        if node.body is not None and _body_breaks_unconditionally(node.body.body):
            body = list(node.body.body[:-1])
            if truth is True or node.condition is None:
                return body
            return [Ps1IfStatement(clauses=[(node.condition, Block(body=body))])]
        return None

    @staticmethod
    def _prune_do_while(node: Ps1DoWhileLoop) -> list[Statement] | None:
        if node.body is not None:
            if _is_truthy(node.condition) is False:
                return list(node.body.body)
            if _body_breaks_unconditionally(node.body.body):
                return list(node.body.body[:-1])
        return None

    @staticmethod
    def _prune_do_until(node: Ps1DoUntilLoop) -> list[Statement] | None:
        if node.body is not None:
            if _is_truthy(node.condition) is True:
                return list(node.body.body)
            if _body_breaks_unconditionally(node.body.body):
                return list(node.body.body[:-1])
        return None

    @staticmethod
    def _prune_for(node: Ps1ForLoop) -> list[Statement] | None:
        truth = _evaluate_for_condition(node)
        if truth is None:
            truth = _is_truthy(node.condition)
        if truth is False:
            result: list[Statement] = []
            if node.initializer is not None:
                result.append(Ps1ExpressionStatement(expression=node.initializer))
            return result
        if node.body is not None and _body_breaks_unconditionally(node.body.body):
            result = []
            if node.initializer is not None:
                result.append(Ps1ExpressionStatement(expression=node.initializer))
            body = list(node.body.body[:-1])
            if truth is True or node.condition is None:
                result.extend(body)
            else:
                result.append(Ps1IfStatement(clauses=[(node.condition, Block(body=body))]))
            return result
        return None

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
