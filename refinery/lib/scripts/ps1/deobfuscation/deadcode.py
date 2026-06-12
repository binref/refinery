"""
Eliminate dead code from PowerShell scripts after constant folding.
"""
from __future__ import annotations

from refinery.lib.scripts import Block, Expression, Node, Statement, Transformer
from refinery.lib.scripts.ps1.deobfuscation.data import COMPARISON_OPS
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    get_body,
    inside_value_producing_context,
    is_builtin_variable,
    is_truthy,
    switch_matches,
    unwrap_integer,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1BreakStatement,
    Ps1ContinueStatement,
    Ps1DoLoop,
    Ps1ExpressionStatement,
    Ps1ForLoop,
    Ps1IfStatement,
    Ps1IntegerLiteral,
    Ps1ParenExpression,
    Ps1RealLiteral,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1StringLiteral,
    Ps1SwitchStatement,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
)


def _evaluate_for_condition(node: Ps1ForLoop) -> bool | None:
    """
    Try to evaluate a for-loop condition at loop entry by substituting the initial value of the
    loop variable into the comparison. Returns the boolean result, or `None` if the pattern does not
    match.
    """
    init = node.initializer
    cond = node.condition
    if not isinstance(init, Ps1AssignmentExpression) or init.operator != '=':
        return None
    if not isinstance(init.target, Ps1Variable):
        return None
    init_val = unwrap_integer(init.value)
    if init_val is None:
        return None
    if not isinstance(cond, Ps1BinaryExpression):
        return None
    op_fn = COMPARISON_OPS.get(cond.operator.lower())
    if op_fn is None:
        return None
    var_name = init.target.name.lower()
    var_scope = init.target.scope
    left_val = _resolve_side(cond.left, var_name, var_scope, init_val.value)
    right_val = _resolve_side(cond.right, var_name, var_scope, init_val.value)
    if left_val is None or right_val is None:
        return None
    return bool(op_fn(left_val, right_val))


def _resolve_side(
    node, var_name: str, var_scope: Ps1ScopeModifier, init_val: int,
) -> int | None:
    """
    Resolve one side of a for-loop condition to an integer: if the node is the loop variable,
    return the initial value; if it is a constant integer, return that; otherwise return `None`.
    """
    node = unwrap_parens(node) if isinstance(node, Expression) else node
    if (
        isinstance(node, Ps1Variable)
        and node.name.lower() == var_name
        and node.scope == var_scope
    ):
        return init_val
    result = unwrap_integer(node)
    return result.value if result is not None else None


def _body_breaks_unconditionally(body: list[Statement]) -> bool:
    """
    Return `True` if the last statement in the body is an unlabeled break and the body contains no
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


_NO_LITERAL = object()


def _switch_literal(node):
    """
    Extract the constant `int`/`str`/`bool` value a switch value or clause condition compares with,
    or `_NO_LITERAL` when it is not a compile-time constant.
    """
    node = unwrap_parens(node)
    if isinstance(node, (Ps1IntegerLiteral, Ps1RealLiteral, Ps1StringLiteral)):
        return node.value
    if is_builtin_variable(node, {'true'}):
        return True
    if is_builtin_variable(node, {'false'}):
        return False
    return _NO_LITERAL


def _switch_clause_body(body: list[Statement]) -> tuple[list[Statement], bool] | None:
    """
    Return the statements of a matched switch clause together with a flag indicating whether the
    clause terminates the switch (a trailing `break`). Returns `None` when the body contains a
    top-level `break`/`continue` that is not a single trailing `break`, since inlining it would
    retarget the jump to an enclosing loop.
    """
    stmts = list(body)
    stop = False
    if stmts and isinstance(stmts[-1], Ps1BreakStatement):
        stmts = stmts[:-1]
        stop = True
    for stmt in stmts:
        if isinstance(stmt, (Ps1BreakStatement, Ps1ContinueStatement)):
            return None
    return stmts, stop


def _is_pure_constant(node) -> bool:
    """
    Return `True` when an expression is a side-effect-free constant that can be removed as a
    standalone statement. Only matches numeric literals and the built-in constants `$Null`,
    `$True`, and `$False` — string literals are excluded because they may represent intentional
    pipeline output.
    """
    if isinstance(node, (Ps1IntegerLiteral, Ps1RealLiteral)):
        return True
    if is_builtin_variable(node):
        return True
    if isinstance(node, Ps1ParenExpression):
        return _is_pure_constant(node.expression)
    if isinstance(node, Ps1UnaryExpression) and node.operator in ('+', '-'):
        return _is_pure_constant(node.operand)
    return False


class Ps1DeadCodeElimination(Transformer):
    """
    Remove unreachable code guarded by constant boolean conditions and resolve switch statements
    on constant values.
    """

    def visit(self, node: Node):
        for parent in list(node.walk()):
            if inside_value_producing_context(parent):
                continue
            body = get_body(parent)
            if body is None:
                continue
            new_body = self._prune_body(body, isinstance(parent, Ps1Script))
            if new_body is not body:
                body.clear()
                body.extend(new_body)
                for stmt in new_body:
                    stmt.parent = parent
                self.mark_changed()

    def _prune_body(
        self, body: list[Statement], is_script_level: bool = False,
    ) -> list[Statement]:
        result: list[Statement] = []
        changed = False
        prune_constants = not is_script_level or any(
            not (isinstance(s, Ps1ExpressionStatement) and _is_pure_constant(s.expression))
            for s in body
        )
        for stmt in body:
            if (
                prune_constants
                and isinstance(stmt, Ps1ExpressionStatement)
                and _is_pure_constant(stmt.expression)
            ):
                changed = True
                continue
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
        if isinstance(stmt, Ps1DoLoop):
            return self._prune_do_loop(stmt)
        if isinstance(stmt, Ps1ForLoop):
            return self._prune_for(stmt)
        if isinstance(stmt, Ps1IfStatement):
            return self._prune_if(stmt)
        if isinstance(stmt, Ps1SwitchStatement):
            return self._prune_switch(stmt)
        return None

    @staticmethod
    def _prune_while(node: Ps1WhileLoop) -> list[Statement] | None:
        truth = is_truthy(node.condition)
        if truth is False:
            return []
        if node.body is not None and _body_breaks_unconditionally(node.body.body):
            body = list(node.body.body[:-1])
            if truth is True or node.condition is None:
                return body
            return [Ps1IfStatement(clauses=[(node.condition, Block(body=body))])]
        return None

    @staticmethod
    def _prune_do_loop(node: Ps1DoLoop) -> list[Statement] | None:
        if node.body is not None:
            trivially_exits = (
                is_truthy(node.condition) is True if node.is_until
                else is_truthy(node.condition) is False
            )
            if trivially_exits:
                return list(node.body.body)
            if _body_breaks_unconditionally(node.body.body):
                return list(node.body.body[:-1])
        return None

    @staticmethod
    def _prune_for(node: Ps1ForLoop) -> list[Statement] | None:
        truth = _evaluate_for_condition(node)
        if truth is None:
            truth = is_truthy(node.condition)
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
            truth = is_truthy(condition)
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
        return [node]

    @staticmethod
    def _prune_switch(node: Ps1SwitchStatement) -> list[Statement] | None:
        if node.regex or node.wildcard or node.file:
            return None
        value = _switch_literal(node.value)
        if value is _NO_LITERAL:
            return None
        default_body: list[Statement] | None = None
        result: list[Statement] = []
        matched = False
        for condition, block in node.clauses:
            if condition is None:
                default_body = block.body
                continue
            cond_val = _switch_literal(condition)
            if cond_val is _NO_LITERAL:
                # A non-constant clause condition might match at runtime; cannot resolve statically.
                return None
            if switch_matches(value, cond_val, case_sensitive=node.case_sensitive):
                body = _switch_clause_body(block.body)
                if body is None:
                    return None
                stmts, stop = body
                result.extend(stmts)
                matched = True
                if stop:
                    return result
        if matched:
            return result
        if default_body is not None:
            body = _switch_clause_body(default_body)
            if body is None:
                return None
            return body[0]
        return []
