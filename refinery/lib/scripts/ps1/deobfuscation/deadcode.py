"""
Eliminate dead code from PowerShell scripts after constant folding.
"""
from __future__ import annotations

from refinery.lib.scripts import Block, Expression, Node, Statement, Transformer
from refinery.lib.scripts.ps1.deobfuscation.data import COMPARISON_OPS, KNOWN_CMDLETS
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    BodyRole,
    classify_body,
    get_body,
    is_builtin_variable,
    is_truthy,
    switch_matches,
    unwrap_integer,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.deobfuscation.purity import (
    StatementEffect,
    classify_statement_effect,
    is_side_effect_free,
    statement_performs_side_effect,
)
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1BreakStatement,
    Ps1CommandArgument,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1DoLoop,
    Ps1ExpressionStatement,
    Ps1ForLoop,
    Ps1IfStatement,
    Ps1IntegerLiteral,
    Ps1ParenExpression,
    Ps1RealLiteral,
    Ps1ScopeModifier,
    Ps1StringLiteral,
    Ps1SwitchStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
)

_PATH_EXTENSIONS = frozenset({'.exe', '.ps1', '.cmd', '.bat', '.com', '.vbs', '.msi'})


def _is_unresolvable_command(expr: Expression) -> bool:
    """
    Return `True` when `expr` is a command invocation of an unknown bareword whose arguments are all
    side-effect-free. Such an invocation will throw `CommandNotFoundException` at runtime — no side
    effect precedes the throw, and if it somehow resolved, the discarded result is harmless. This
    predicate is intentionally narrow: only bareword string-literal names that do not match any
    known cmdlet or alias and do not look like a filesystem path.
    """
    if not isinstance(expr, Ps1CommandInvocation):
        return False
    if not isinstance(expr.name, Ps1StringLiteral):
        return False
    name = expr.name.value
    name_lower = name.lower()
    if name_lower in KNOWN_CMDLETS:
        return False
    if any(sep in name for sep in ('\\', '/', ':')):
        return False
    if any(name_lower.endswith(ext) for ext in _PATH_EXTENSIONS):
        return False
    if name.startswith('.') or name.startswith('~'):
        return False
    for arg in expr.arguments:
        value = arg.value if isinstance(arg, Ps1CommandArgument) else arg
        if value is not None and not is_side_effect_free(value):
            return False
    return True


def _try_body_is_harmless(body: list[Statement]) -> bool:
    """
    Return `True` when every statement in a try body is guaranteed to produce no observable side
    effects whether it succeeds or throws. This covers pure expressions (value discarded) and
    unresolvable bareword commands (throw `CommandNotFoundException` with no preceding side effect).
    """
    for stmt in body:
        if not isinstance(stmt, Ps1ExpressionStatement):
            return False
        if stmt.expression is None:
            continue
        if is_side_effect_free(stmt.expression):
            continue
        if _is_unresolvable_command(stmt.expression):
            continue
        return False
    return True


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


def _make_int_literal(value: int) -> Ps1IntegerLiteral:
    return Ps1IntegerLiteral(value=value, raw=str(value))


def _is_counter_variable(node, var_name: str, var_scope: Ps1ScopeModifier) -> bool:
    node = unwrap_parens(node) if isinstance(node, Expression) else node
    return (
        isinstance(node, Ps1Variable)
        and node.name.lower() == var_name
        and node.scope == var_scope
    )


def _counter_delta(iterator, var_name: str, var_scope: Ps1ScopeModifier) -> int | None:
    """
    Return the constant per-iteration change a for-loop iterator applies to the loop variable, or
    `None` when the iterator is not a nonzero constant step on that single variable (`$i++`, `$i--`,
    `$i += k`, `$i -= k`).
    """
    if isinstance(iterator, Ps1UnaryExpression) and iterator.operator in ('++', '--'):
        if _is_counter_variable(iterator.operand, var_name, var_scope):
            return 1 if iterator.operator == '++' else -1
        return None
    if isinstance(iterator, Ps1AssignmentExpression) and iterator.operator in ('+=', '-='):
        if not _is_counter_variable(iterator.target, var_name, var_scope):
            return None
        step = unwrap_integer(iterator.value)
        if step is None:
            return None
        delta = step.value if iterator.operator == '+=' else -step.value
        return delta or None
    return None


def _counter_condition(cond, var_name: str, var_scope: Ps1ScopeModifier):
    """
    Return `(predicate, bound)` where `predicate` maps an integer loop-variable value to the truth
    of the for-loop condition and `bound` is the constant it is compared against, or `None` when the
    condition is not a comparison between the loop variable and a constant integer (`$i <cmp> C` or
    `C <cmp> $i`). The bound lets the caller size a simulation cap to the loop's real trip count.
    """
    if not isinstance(cond, Ps1BinaryExpression):
        return None
    op_fn = COMPARISON_OPS.get(cond.operator.lower())
    if op_fn is None:
        return None
    left_int = unwrap_integer(cond.left)
    right_int = unwrap_integer(cond.right)
    if _is_counter_variable(cond.left, var_name, var_scope) and right_int is not None:
        bound = right_int.value
        return (lambda value: bool(op_fn(value, bound))), bound
    if _is_counter_variable(cond.right, var_name, var_scope) and left_int is not None:
        bound = left_int.value
        return (lambda value: bool(op_fn(bound, value))), bound
    return None


def _simulate_empty_for_terminal(node: Ps1ForLoop) -> tuple[Ps1Variable, int] | None:
    """
    For an empty-bodied `for` loop driven by a single integer counter, return `(variable, terminal)`
    giving the value the counter holds once the loop exits, or `None` when the loop is not a
    provably-terminating linear counter (non-constant initializer/bound, `for (;;)`, a
    non-constant-step iterator, or a condition that never turns false). The counter is stepped
    exactly as PowerShell evaluates the loop — check the condition, then apply the iterator — so the
    terminal value is exact, including the zero-iteration case where the counter keeps its initial
    value.
    """
    init = node.initializer
    if not isinstance(init, Ps1AssignmentExpression) or init.operator != '=':
        return None
    if not isinstance(init.target, Ps1Variable):
        return None
    init_int = unwrap_integer(init.value)
    if init_int is None:
        return None
    variable = init.target
    var_name = variable.name.lower()
    var_scope = variable.scope
    delta = _counter_delta(node.iterator, var_name, var_scope)
    if delta is None:
        return None
    condition = _counter_condition(node.condition, var_name, var_scope)
    if condition is None:
        return None
    predicate, bound = condition
    # A terminating linear counter reaches the bound within `distance / |step|` iterations; a couple
    # extra guard against off-by-one and the exact-hit (`-ne`/`-eq`) cases. Exceeding this proves the
    # condition never turns false (a wrong-direction step), so the loop is infinite and left intact.
    cap = abs(bound - init_int.value) // abs(delta) + 2
    value = init_int.value
    iterations = 0
    while predicate(value):
        value += delta
        iterations += 1
        if iterations > cap:
            return None
    return variable, value


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
            if isinstance(node, (Ps1BreakStatement, Ps1ContinueStatement)):
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
            role = classify_body(parent)
            if role is None or role is BodyRole.OPAQUE:
                continue
            body = get_body(parent)
            new_body = self._prune_body(body, role)
            if new_body is not body:
                body.clear()
                body.extend(new_body)
                for stmt in new_body:
                    stmt.parent = parent
                self.mark_changed()

    def _prune_body(
        self, body: list[Statement], role: BodyRole = BodyRole.NESTED,
    ) -> list[Statement]:
        # First pass: apply control-flow pruning (dead branches, empty loops, try/trap removal).
        # prune_output must be computed from what actually survives this pass: a branch like
        # `if ($false) {}` is a non-expression statement that looks like a side effect before
        # pruning but produces nothing afterwards. Computing prune_output from the original body
        # would cause the flag to stay True even after the apparent anchor is eliminated,
        # incorrectly silencing the body's observable return value.
        intermediate: list[Statement] = []
        changed = False
        for stmt in body:
            replacement = self._try_prune(stmt)
            if replacement is not None:
                intermediate.extend(replacement)
                changed = True
            else:
                intermediate.append(stmt)
        # Second pass: drop bare output statements (pure constants) that carry no side effect.
        # A ROOT body must preserve a pure output when no side-effecting statement survives to
        # carry the body's observable value. DISCARD statements emit nothing and never count.
        # A NESTED body has no observable return value — all output statements are prunable.
        if role is BodyRole.NESTED:
            prune_output = True
        else:
            prune_output = any(statement_performs_side_effect(s) for s in intermediate)
        result: list[Statement] = []
        for stmt in intermediate:
            if isinstance(stmt, Ps1ExpressionStatement) and _is_pure_constant(stmt.expression):
                if prune_output:
                    changed = True
                    continue
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
        if isinstance(stmt, Ps1TryCatchFinally):
            return self._prune_try(stmt)
        if isinstance(stmt, Ps1TrapStatement):
            return self._prune_trap(stmt)
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
                body = node.body.body
                if _body_breaks_unconditionally(body):
                    return list(body[:-1])
                for stmt in body:
                    for node in stmt.walk():
                        if isinstance(node, (Ps1BreakStatement, Ps1ContinueStatement)):
                            return None
                return list(body)
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
        if node.body is None or not node.body.body:
            terminal = _simulate_empty_for_terminal(node)
            if terminal is not None:
                variable, value = terminal
                target = Ps1Variable(name=variable.name, scope=variable.scope)
                assignment = Ps1AssignmentExpression(
                    target=target, operator='=', value=_make_int_literal(value))
                return [Ps1ExpressionStatement(expression=assignment)]
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

    @staticmethod
    def _prune_try(node: Ps1TryCatchFinally) -> list[Statement] | None:
        """
        Resolve a `try`/`catch`/`finally` whose `try` body cannot produce observable side effects.
        An empty (or absent) `try` block raises nothing, so every `catch` clause is unreachable and
        drops away; the `finally` block always runs, so its statements are hoisted in place of the
        whole construct. A non-empty `try` body that is "harmless" (all statements are either pure
        expressions or unresolvable bareword commands that would throw without side effects) combined
        with all-empty `catch` clauses is likewise a no-op — the entire construct is removed (or
        reduced to the `finally` body when present).
        """
        try_body = node.try_block.body if node.try_block is not None else []
        if not try_body:
            finally_body = node.finally_block.body if node.finally_block is not None else []
            return list(finally_body)
        if not _try_body_is_harmless(try_body):
            return None
        for clause in node.catch_clauses:
            if clause.body is not None and clause.body.body:
                return None
        finally_body = node.finally_block.body if node.finally_block is not None else []
        return list(finally_body)

    @staticmethod
    def _prune_trap(node: Ps1TrapStatement) -> list[Statement] | None:
        """
        Remove a `trap` handler whose body produces no observable output. A trap only runs when the
        code it guards throws a terminating error; injected-noise traps (`trap { continue }`, an
        empty `trap {}`, `trap { break }`) merely swallow or re-raise without emitting anything, so
        deleting them is invisible unless an error actually propagates. A body that emits output (a
        real logging handler such as `trap { Write-Host 'err' }`) is not side-effect-free and keeps
        the trap intact. This is the one removal not provable under strict semantics — it relies on
        the guarded code never throwing — and is deliberately gated on a strict no-output body.
        """
        body = node.body.body if node.body is not None else []
        for stmt in body:
            if isinstance(stmt, (Ps1BreakStatement, Ps1ContinueStatement)):
                if stmt.label is not None:
                    return None
                continue
            if isinstance(stmt, Ps1ExpressionStatement):
                if stmt.expression is None or is_side_effect_free(stmt.expression):
                    continue
            return None
        return []
