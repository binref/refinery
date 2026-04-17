"""
Recover original control flow from control-flow-flattened PowerShell scripts.

Control flow flattening replaces sequential and branching code with a dispatcher loop: a while loop
containing a single switch on a state variable, where each case sets the state variable to
determine the next case to execute. This transformer identifies the dispatcher pattern, extracts
the state machine, and recovers the original structure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Generator

from refinery.lib.scripts import Block, Expression, Node, Statement, Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import _get_body, _unwrap_parens
from refinery.lib.scripts.ps1.deobfuscation.emulator import evaluate_truthy
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1BreakStatement,
    Ps1ExpressionStatement,
    Ps1IfStatement,
    Ps1IntegerLiteral,
    Ps1ParenExpression,
    Ps1RealLiteral,
    Ps1ScopeModifier,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1SwitchStatement,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
    Expression,
)

_MAX_STATES = 500
_MAX_UNROLL_ITERATIONS = 500

_VarKey = tuple[str, Ps1ScopeModifier]
_StateKey = int | float | str


def _is_bool_literal(node: Expression) -> bool | None:
    """
    Check if a node is a $True or $False variable literal. Returns the boolean value,
    or None if the node is not a boolean literal.
    """
    if isinstance(node, Ps1Variable) and node.scope == Ps1ScopeModifier.NONE:
        lower = node.name.lower()
        if lower == 'true':
            return True
        if lower == 'false':
            return False
    return None


def _unwrap_constant(node) -> _StateKey | None:
    """
    Extract a constant value (int, float, or string) from an AST node.
    """
    node = _unwrap_parens(node) if isinstance(node, Expression) else node
    if isinstance(node, Ps1IntegerLiteral):
        return node.value
    if isinstance(node, Ps1RealLiteral):
        return node.value
    if isinstance(node, Ps1StringLiteral):
        return node.value
    if isinstance(node, Ps1UnaryExpression) and node.operator == '-':
        inner = _unwrap_parens(node.operand) if isinstance(node.operand, Expression) else node.operand
        if isinstance(inner, Ps1IntegerLiteral):
            return -inner.value
        if isinstance(inner, Ps1RealLiteral):
            return -inner.value
    if (
        isinstance(node, Ps1Variable)
        and node.scope == Ps1ScopeModifier.NONE
        and node.name.lower() == 'null'
    ):
        return 0
    return None


@dataclass
class _LinearTransition:
    target: _StateKey


@dataclass
class _ConditionalTransition:
    condition: Expression
    true_target: _StateKey
    false_target: _StateKey
    true_prefix: list[Statement] = field(default_factory=list)
    false_prefix: list[Statement] = field(default_factory=list)


@dataclass
class _ExitTransition:
    pass


_Transition = _LinearTransition | _ConditionalTransition | _ExitTransition


@dataclass
class _StateBlock:
    state_id: _StateKey
    statements: list[Statement]
    transition: _Transition


@dataclass
class _DispatcherMatch:
    state_var_name: str
    state_var_scope: Ps1ScopeModifier
    condition: Expression
    switch: Ps1SwitchStatement


def _same_variable(node: Ps1Variable, name: str, scope: Ps1ScopeModifier) -> bool:
    return node.name.lower() == name and node.scope == scope


def _var_key(node: Ps1Variable) -> _VarKey:
    return (node.name.lower(), node.scope)


def _collect_variables(node: Node) -> set[_VarKey]:
    """
    Collect all distinct variable keys referenced in an expression tree.
    """
    result: set[_VarKey] = set()
    for child in node.walk():
        if isinstance(child, Ps1Variable) and child.scope != Ps1ScopeModifier.NONE:
            continue
        if isinstance(child, Ps1Variable):
            lower = child.name.lower()
            if lower in ('true', 'false', 'null'):
                continue
            result.add(_var_key(child))
    return result


def _make_exit_check(
    condition: Expression,
    var_name: str,
) -> Callable[[_StateKey], bool]:
    """
    Return a predicate that checks whether assigning a given state value to the state variable
    would make the while condition falsy (the loop would exit). Uses the emulator to evaluate the
    condition with the state variable bound.
    """
    def is_exit(state_value: _StateKey) -> bool:
        bindings = {var_name: state_value}
        result = evaluate_truthy(condition, bindings)
        if result is None:
            return False
        return not result
    return is_exit


def _is_state_assignment(
    stmt: Statement,
    var_name: str,
    var_scope: Ps1ScopeModifier,
) -> _StateKey | None:
    """
    If the statement is an assignment to the state variable with a constant value, return that
    value. Otherwise return None.
    """
    if not isinstance(stmt, Ps1ExpressionStatement):
        return None
    expr = stmt.expression
    if not isinstance(expr, Ps1AssignmentExpression):
        return None
    if expr.operator != '=':
        return None
    target = expr.target
    if not isinstance(target, Ps1Variable):
        return None
    if not _same_variable(target, var_name, var_scope):
        return None
    return _unwrap_constant(expr.value)


def _get_simple_assignment(
    stmt: Statement,
) -> tuple[_VarKey, Node] | None:
    """
    If the statement is a simple assignment ($var = <value>), return the variable key
    and the value node. Returns None for non-assignments or compound operators.
    """
    if not isinstance(stmt, Ps1ExpressionStatement):
        return None
    expr = stmt.expression
    if not isinstance(expr, Ps1AssignmentExpression):
        return None
    if expr.operator != '=':
        return None
    target = expr.target
    if not isinstance(target, Ps1Variable):
        return None
    if expr.value is None:
        return None
    return (_var_key(target), expr.value)


def _resolve_value(
    node: Node,
    env: dict[_VarKey, _StateKey | bool],
) -> _StateKey | None:
    """
    Try to resolve a node to a constant value given a variable environment.
    """
    if not isinstance(node, Expression):
        return None
    expr = _unwrap_parens(node)
    value = _unwrap_constant(expr)
    if value is not None:
        return value
    if isinstance(expr, Ps1Variable):
        key = _var_key(expr)
        val = env.get(key)
        if isinstance(val, (int, float, str)):
            return val
    return None


def _resolve_bool(
    node: Node,
    env: dict[_VarKey, _StateKey | bool],
) -> bool | None:
    """
    Try to resolve a node to a boolean given a variable environment.
    """
    if not isinstance(node, Expression):
        return None
    expr = _unwrap_parens(node)
    literal = _is_bool_literal(expr)
    if literal is not None:
        return literal
    if isinstance(expr, Ps1Variable):
        key = _var_key(expr)
        val = env.get(key)
        if isinstance(val, bool):
            return val
    if isinstance(expr, Ps1BinaryExpression) and expr.left is not None and expr.right is not None:
        op = expr.operator.lower()
        if op in ('-eq', '-ne', '-lt', '-le', '-gt', '-ge'):
            left_val = _resolve_value(expr.left, env)
            right_val = _resolve_value(expr.right, env)
            if left_val is not None and right_val is not None:
                if type(left_val) is not type(right_val):
                    return None
                if op == '-eq':
                    return left_val == right_val
                if op == '-ne':
                    return left_val != right_val
                if isinstance(left_val, str):
                    assert isinstance(right_val, str)
                    a_s, b_s = left_val, right_val
                    if op == '-lt':
                        return a_s < b_s
                    if op == '-le':
                        return a_s <= b_s
                    if op == '-gt':
                        return a_s > b_s
                    if op == '-ge':
                        return a_s >= b_s
                else:
                    a_n = float(left_val)
                    b_n = float(right_val)
                    if op == '-lt':
                        return a_n < b_n
                    if op == '-le':
                        return a_n <= b_n
                    if op == '-gt':
                        return a_n > b_n
                    if op == '-ge':
                        return a_n >= b_n
        elif op == '-and':
            left_bool = _resolve_bool(expr.left, env)
            right_bool = _resolve_bool(expr.right, env)
            if left_bool is not None and right_bool is not None:
                return left_bool and right_bool
            if left_bool is False or right_bool is False:
                return False
        elif op == '-or':
            left_bool = _resolve_bool(expr.left, env)
            right_bool = _resolve_bool(expr.right, env)
            if left_bool is not None and right_bool is not None:
                return left_bool or right_bool
            if left_bool is True or right_bool is True:
                return True
    if isinstance(expr, Ps1UnaryExpression) and expr.operand is not None:
        op = expr.operator.lower()
        if op in ('-not', '!'):
            inner = _resolve_bool(expr.operand, env)
            if inner is not None:
                return not inner
    return None


def _match_dispatcher(loop: Ps1WhileLoop) -> _DispatcherMatch | None:
    """
    Check whether a while loop matches the CFF dispatcher pattern: a while loop whose condition
    involves a single variable, and whose body is a single switch on that variable.
    """
    cond = loop.condition
    if cond is None:
        return None
    body = loop.body
    if body is None or len(body.body) != 1:
        return None
    switch = body.body[0]
    if not isinstance(switch, Ps1SwitchStatement):
        return None
    if switch.file:
        return None
    switch_val = switch.value
    if not isinstance(switch_val, Ps1Variable):
        return None
    var_name = switch_val.name.lower()
    var_scope = switch_val.scope
    cond_vars = _collect_variables(cond)
    if not cond_vars:
        return None
    state_key = (var_name, var_scope)
    if state_key not in cond_vars:
        return None
    if len(cond_vars) > 1:
        return None
    return _DispatcherMatch(
        state_var_name=var_name,
        state_var_scope=var_scope,
        condition=cond,
        switch=switch,
    )


def _find_state_init(
    body: list[Statement],
    loop_index: int,
    var_name: str,
    var_scope: Ps1ScopeModifier,
) -> tuple[int, _StateKey] | None:
    """
    Scan backwards from the while loop to find the state variable initialization. Returns
    (index_in_body, initial_state_value) or None.
    """
    for i in range(loop_index - 1, -1, -1):
        value = _is_state_assignment(body[i], var_name, var_scope)
        if value is not None:
            return (i, value)
    return None


def _strip_trailing_break(stmts: list[Statement]) -> list[Statement]:
    """
    Remove a trailing break statement (part of the switch dispatch, not the original code).
    """
    if stmts and isinstance(stmts[-1], Ps1BreakStatement) and stmts[-1].label is None:
        return stmts[:-1]
    return stmts


def _extract_transition(
    stmts: list[Statement],
    var_name: str,
    var_scope: Ps1ScopeModifier,
    is_exit: Callable[[_StateKey], bool],
) -> tuple[list[Statement], _Transition] | None:
    """
    Separate a switch case body into side-effect statements and a state transition. Returns
    (side_effects, transition) or None if the pattern is not recognized.
    """
    if not stmts:
        return None
    last = stmts[-1]
    state_val = _is_state_assignment(last, var_name, var_scope)
    if state_val is not None:
        side_effects = list(stmts[:-1])
        if is_exit(state_val):
            return (side_effects, _ExitTransition())
        return (side_effects, _LinearTransition(target=state_val))
    if isinstance(last, Ps1IfStatement) and last.else_block is not None and len(last.clauses) == 1:
        condition, true_block = last.clauses[0]
        false_block = last.else_block
        true_body = _strip_trailing_break(list(true_block.body))
        false_body = _strip_trailing_break(list(false_block.body))
        if not true_body or not false_body:
            return None
        true_state = _is_state_assignment(true_body[-1], var_name, var_scope)
        false_state = _is_state_assignment(false_body[-1], var_name, var_scope)
        if true_state is None or false_state is None:
            return None
        true_prefix = true_body[:-1]
        false_prefix = false_body[:-1]
        side_effects = list(stmts[:-1])
        return (side_effects, _ConditionalTransition(
            condition=condition,
            true_target=true_state,
            false_target=false_state,
            true_prefix=true_prefix,
            false_prefix=false_prefix,
        ))
    return None


def _extract_state_machine(
    match: _DispatcherMatch,
    is_exit: Callable[[_StateKey], bool],
) -> dict[_StateKey, _StateBlock] | None:
    """
    Parse all switch cases into a state machine dictionary. Returns None on failure.
    """
    states: dict[_StateKey, _StateBlock] = {}
    var_name = match.state_var_name
    var_scope = match.state_var_scope
    for condition, block in match.switch.clauses:
        if condition is None:
            continue
        state_id = _unwrap_constant(condition)
        if state_id is None:
            return None
        body = _strip_trailing_break(list(block.body))
        result = _extract_transition(body, var_name, var_scope, is_exit)
        if result is None:
            return None
        side_effects, transition = result
        states[state_id] = _StateBlock(
            state_id=state_id,
            statements=side_effects,
            transition=transition,
        )
    if len(states) > _MAX_STATES:
        return None
    return states


def _negate_condition(cond: Expression) -> Expression:
    """
    Return the logical negation of a condition expression. Tries to simplify where possible (e.g.,
    flipping -eq to -ne) rather than wrapping in -Not.
    """
    cond = _unwrap_parens(cond)
    if isinstance(cond, Ps1BinaryExpression):
        flipped = {
            '-eq': '-NE',
            '-ne': '-EQ',
            '-lt': '-GE',
            '-ge': '-LT',
            '-gt': '-LE',
            '-le': '-GT',
        }.get(cond.operator.lower())
        if flipped is not None:
            return Ps1BinaryExpression(
                left=cond.left,
                operator=flipped,
                right=cond.right,
            )
    if (
        isinstance(cond, Ps1UnaryExpression)
        and cond.operator.lower() in ('-not', '!')
        and cond.operand is not None
    ):
        return cond.operand
    return Ps1UnaryExpression(operator='-Not', operand=Ps1ParenExpression(expression=cond))


def _build_if(
    condition: Expression,
    true_body: list[Statement],
    false_body: list[Statement],
) -> Ps1IfStatement | None:
    """
    Build an if/else statement. Returns None if both bodies are empty. Omits the else block if the
    false body is empty; negates the condition if only the true body is empty.
    """
    if not true_body and not false_body:
        return None
    if not true_body:
        return Ps1IfStatement(
            clauses=[(_negate_condition(condition), Block(body=false_body))],
        )
    if not false_body:
        return Ps1IfStatement(
            clauses=[(condition, Block(body=true_body))],
        )
    return Ps1IfStatement(
        clauses=[(condition, Block(body=true_body))],
        else_block=Block(body=false_body),
    )


def _find_back_edges(
    states: dict[_StateKey, _StateBlock],
    entry: _StateKey,
    is_exit: Callable[[_StateKey], bool],
) -> dict[_StateKey, _StateKey]:
    """
    Walk the state graph from the entry and find back-edges using DFS. Returns a mapping from back-
    edge source state to back-edge target state (the loop header).
    """
    back_edges: dict[_StateKey, _StateKey] = {}
    visiting: set[_StateKey] = set()
    visited: set[_StateKey] = set()

    def _targets(block: _StateBlock) -> Generator[_StateKey, None, None]:
        t = block.transition
        if isinstance(t, _LinearTransition):
            yield t.target
        elif isinstance(t, _ConditionalTransition):
            yield t.true_target
            yield t.false_target

    def _dfs(state: _StateKey):
        if is_exit(state) or state not in states:
            return
        if state in visited:
            return
        visiting.add(state)
        block = states[state]
        for target in _targets(block):
            if is_exit(target) or target not in states:
                continue
            if target in visiting:
                back_edges[state] = target
            elif target not in visited:
                _dfs(target)
        visiting.discard(state)
        visited.add(state)

    _dfs(entry)
    return back_edges


def _find_join_point(
    states: dict[_StateKey, _StateBlock],
    true_start: _StateKey,
    false_start: _StateKey,
    is_exit: Callable[[_StateKey], bool],
    back_edge_targets: set[_StateKey],
) -> _StateKey | None:
    """
    Find the first state reachable from both arms of a conditional (the join point). Returns None
    if no common state is found (one or both arms exit).
    """
    true_reach: list[_StateKey] = []
    false_reach: list[_StateKey] = []
    true_queue: list[_StateKey] = [true_start]
    false_queue: list[_StateKey] = [false_start]
    true_seen: set[_StateKey] = set()
    false_seen: set[_StateKey] = set()

    def _successors(s: _StateKey) -> list[_StateKey]:
        if s not in states:
            return []
        block = states[s]
        t = block.transition
        if isinstance(t, _LinearTransition):
            return [t.target]
        if isinstance(t, _ConditionalTransition):
            return [t.true_target, t.false_target]
        return []

    def _expand(
        queue: list[_StateKey],
        seen: set[_StateKey],
        reach: list[_StateKey],
    ):
        while queue:
            s = queue.pop(0)
            if is_exit(s) or s not in states:
                continue
            if s in seen:
                continue
            if s in back_edge_targets:
                reach.append(s)
                continue
            seen.add(s)
            reach.append(s)
            for succ in _successors(s):
                queue.append(succ)

    _expand(true_queue, true_seen, true_reach)
    _expand(false_queue, false_seen, false_reach)
    true_set = set(true_reach)
    for s in false_reach:
        if s in true_set:
            return s
    return None


def _collect_loop_states(
    states: dict[_StateKey, _StateBlock],
    header: _StateKey,
    is_exit: Callable[[_StateKey], bool],
    latches: set[_StateKey],
) -> set[_StateKey]:
    """
    Collect all state IDs that belong to a loop (reachable from header without leaving through
    latches).
    """
    loop_states: set[_StateKey] = set()
    queue: list[_StateKey] = [header]
    while queue:
        s = queue.pop(0)
        if is_exit(s) or s not in states or s in loop_states:
            continue
        loop_states.add(s)
        if s in latches and s != header:
            continue
        block = states[s]
        t = block.transition
        if isinstance(t, _LinearTransition):
            queue.append(t.target)
        elif isinstance(t, _ConditionalTransition):
            queue.append(t.true_target)
            queue.append(t.false_target)
    return loop_states


def _collect_internal_vars(
    states: dict[_StateKey, _StateBlock],
    loop_states: set[_StateKey],
    state_var_key: _VarKey,
) -> set[_VarKey]:
    """
    Identify internal dispatch variables within the loop. These are variables that are only
    assigned constant values (integers, floats, strings, or booleans) or copies of other internal
    variables. They are artifacts of the flattening and should be suppressed in output.
    """
    candidates: set[_VarKey] = {state_var_key}
    changed = True
    while changed:
        changed = False
        for sid in loop_states:
            block = states[sid]
            for stmts in _all_statement_lists(block):
                for stmt in stmts:
                    result = _get_simple_assignment(stmt)
                    if result is None:
                        continue
                    key, value = result
                    if key in candidates:
                        continue
                    if isinstance(value, Expression):
                        value = _unwrap_parens(value)
                    if _unwrap_constant(value) is not None:
                        candidates.add(key)
                        changed = True
                    elif isinstance(value, Ps1Variable):
                        if _is_bool_literal(value) is not None:
                            candidates.add(key)
                            changed = True
                        elif _var_key(value) in candidates:
                            candidates.add(key)
                            changed = True
    return candidates


def _all_statement_lists(block: _StateBlock) -> Generator[list[Statement], None, None]:
    """
    Yield all statement lists within a state block (main statements plus conditional transition
    prefixes).
    """
    yield block.statements
    t = block.transition
    if isinstance(t, _ConditionalTransition):
        yield t.true_prefix
        yield t.false_prefix


def _update_env(
    env: dict[_VarKey, _StateKey | bool],
    key: _VarKey,
    value: Node,
):
    """
    Update the variable environment for an internal assignment.
    """
    if isinstance(value, Expression):
        value = _unwrap_parens(value)
    const_val = _unwrap_constant(value)
    if const_val is not None:
        env[key] = const_val
        return
    if isinstance(value, Ps1Variable):
        bool_val = _is_bool_literal(value)
        if bool_val is not None:
            env[key] = bool_val
            return
        src_key = _var_key(value)
        if src_key in env:
            env[key] = env[src_key]
            return
    env.pop(key, None)


def _simulate_statements(
    stmts: list[Statement],
    env: dict[_VarKey, _StateKey | bool],
    internal_vars: set[_VarKey],
    output: list[Statement],
):
    """
    Process a list of statements during simulation. Updates env for internal assignments, and
    appends non-internal statements to output.
    """
    for stmt in stmts:
        result = _get_simple_assignment(stmt)
        if result is not None:
            key, value = result
            if key in internal_vars:
                _update_env(env, key, value)
                continue
        output.append(stmt)


def _simulate_arm(
    states: dict[_StateKey, _StateBlock],
    start: _StateKey,
    header: _StateKey,
    is_exit: Callable[[_StateKey], bool],
    latches: set[_StateKey],
    env: dict[_VarKey, _StateKey | bool],
    internal_vars: set[_VarKey],
    output: list[Statement],
) -> tuple[list[Statement], _StateKey | None] | None:
    """
    Simulate execution of a single arm (branch) during loop unrolling. Follows the state graph
    linearly, resolving conditions where possible. Returns (statements, next_state) or None if a
    condition cannot be resolved.
    """
    current: _StateKey | None = start
    step_count = 0
    while current is not None and step_count < _MAX_STATES * 2:
        step_count += 1
        if is_exit(current):
            return (output, None)
        if current not in states:
            return None
        if current == header:
            return (output, header)
        if current in latches:
            cur_block = states[current]
            _simulate_statements(cur_block.statements, env, internal_vars, output)
            t = cur_block.transition
            if isinstance(t, _LinearTransition) and t.target == header:
                return (output, header)
            return None

        cur_block = states[current]
        _simulate_statements(cur_block.statements, env, internal_vars, output)
        t = cur_block.transition

        if isinstance(t, _ExitTransition):
            return (output, None)
        if isinstance(t, _LinearTransition):
            current = t.target
            continue
        if isinstance(t, _ConditionalTransition):
            branch = _resolve_bool(t.condition, env)
            if branch is True:
                _simulate_statements(t.true_prefix, env, internal_vars, output)
                current = t.true_target
            elif branch is False:
                _simulate_statements(t.false_prefix, env, internal_vars, output)
                current = t.false_target
            else:
                return None
            continue
        return None
    return None


def _seed_env_from_preamble(
    states: dict[_StateKey, _StateBlock],
    entry: _StateKey,
    header: _StateKey,
    is_exit: Callable[[_StateKey], bool],
    internal_vars: set[_VarKey],
) -> dict[_VarKey, _StateKey | bool] | None:
    """
    Walk the linear chain from entry to header, simulating assignments to build the initial
    variable environment. Returns the env or None if the path from entry to header is not a
    simple linear chain.
    """
    env: dict[_VarKey, _StateKey | bool] = {}
    discard: list[Statement] = []
    current = entry
    visited: set[_StateKey] = set()
    while current != header:
        if is_exit(current) or current not in states or current in visited:
            return None
        visited.add(current)
        block = states[current]
        _simulate_statements(block.statements, env, internal_vars, discard)
        if isinstance(block.transition, _LinearTransition):
            current = block.transition.target
        else:
            return None
    return env


def _try_unroll_loop(
    states: dict[_StateKey, _StateBlock],
    entry: _StateKey,
    header: _StateKey,
    is_exit: Callable[[_StateKey], bool],
    back_edges: dict[_StateKey, _StateKey],
    loop_headers: set[_StateKey],
) -> tuple[list[Statement], set[_VarKey]] | None:
    """
    Attempt to unroll a loop by symbolically executing it. Returns

        (unrolled_statements, internal_vars)

    if successful, or None if the loop cannot be fully resolved.
    """
    block = states[header]
    if not isinstance(block.transition, _ConditionalTransition):
        return None
    cond_trans = block.transition

    latches: set[_StateKey] = set()
    for latch, target in back_edges.items():
        if target == header:
            latches.add(latch)

    loop_states = _collect_loop_states(states, header, is_exit, latches)

    cond = cond_trans.condition
    loop_var_key: _VarKey | None = None
    cond_unwrapped = _unwrap_parens(cond)
    if isinstance(cond_unwrapped, Ps1BinaryExpression):
        left = _unwrap_parens(cond_unwrapped.left) if cond_unwrapped.left is not None else None
        right = (
            _unwrap_parens(cond_unwrapped.right) if cond_unwrapped.right is not None else None
        )
        if isinstance(left, Ps1Variable):
            loop_var_key = _var_key(left)
        elif isinstance(right, Ps1Variable):
            loop_var_key = _var_key(right)

    if loop_var_key is None:
        return None

    internal_vars = _collect_internal_vars(states, loop_states, loop_var_key)

    true_target = cond_trans.true_target
    false_target = cond_trans.false_target
    true_is_exit = is_exit(true_target) or true_target not in states
    false_is_exit = is_exit(false_target) or false_target not in states

    true_reaches_header = _state_reaches(
        states, true_target, header, is_exit, loop_headers - {header},
    )
    false_reaches_header = _state_reaches(
        states, false_target, header, is_exit, loop_headers - {header},
    )

    if true_reaches_header and (not false_reaches_header or false_is_exit):
        body_entry = true_target
        body_prefix_stmts = list(cond_trans.true_prefix)
    elif false_reaches_header and (not true_reaches_header or true_is_exit):
        body_entry = false_target
        body_prefix_stmts = list(cond_trans.false_prefix)
    elif false_is_exit:
        body_entry = true_target
        body_prefix_stmts = list(cond_trans.true_prefix)
    elif true_is_exit:
        body_entry = false_target
        body_prefix_stmts = list(cond_trans.false_prefix)
    else:
        return None

    seed = _seed_env_from_preamble(states, entry, header, is_exit, internal_vars)
    env: dict[_VarKey, _StateKey | bool] = seed if seed is not None else {}
    result: list[Statement] = []

    for iteration in range(_MAX_UNROLL_ITERATIONS):
        cond_result = _resolve_bool(cond, env)
        if cond_result is False:
            return (result, internal_vars)
        if cond_result is None and iteration > 0:
            return None

        iteration_stmts: list[Statement] = []
        _simulate_statements(block.statements, env, internal_vars, iteration_stmts)
        _simulate_statements(body_prefix_stmts, env, internal_vars, iteration_stmts)

        current: _StateKey | None = body_entry
        step_count = 0
        while current is not None and step_count < _MAX_STATES * 2:
            step_count += 1
            if is_exit(current):
                result.extend(iteration_stmts)
                return (result, internal_vars)
            if current not in states:
                return None
            if current == header:
                break
            if current in latches:
                cur_block = states[current]
                _simulate_statements(
                    cur_block.statements, env, internal_vars, iteration_stmts,
                )
                t = cur_block.transition
                if isinstance(t, _LinearTransition) and t.target == header:
                    break
                return None

            cur_block = states[current]
            _simulate_statements(cur_block.statements, env, internal_vars, iteration_stmts)
            t = cur_block.transition

            if isinstance(t, _ExitTransition):
                result.extend(iteration_stmts)
                return (result, internal_vars)

            if isinstance(t, _LinearTransition):
                current = t.target
                continue

            if isinstance(t, _ConditionalTransition):
                branch = _resolve_bool(t.condition, env)
                if branch is True:
                    _simulate_statements(
                        t.true_prefix, env, internal_vars, iteration_stmts,
                    )
                    current = t.true_target
                    continue
                if branch is False:
                    _simulate_statements(
                        t.false_prefix, env, internal_vars, iteration_stmts,
                    )
                    current = t.false_target
                    continue
                true_stmts: list[Statement] = []
                false_stmts: list[Statement] = []
                true_env = dict(env)
                false_env = dict(env)
                _simulate_statements(
                    t.true_prefix, true_env, internal_vars, true_stmts,
                )
                _simulate_statements(
                    t.false_prefix, false_env, internal_vars, false_stmts,
                )
                true_arm_result = _simulate_arm(
                    states, t.true_target, header, is_exit, latches,
                    true_env, internal_vars, true_stmts,
                )
                false_arm_result = _simulate_arm(
                    states, t.false_target, header, is_exit, latches,
                    false_env, internal_vars, false_stmts,
                )
                if true_arm_result is None or false_arm_result is None:
                    return None
                true_arm_body, true_next = true_arm_result
                false_arm_body, false_next = false_arm_result
                if_stmt = _build_if(t.condition, true_arm_body, false_arm_body)
                if if_stmt is not None:
                    iteration_stmts.append(if_stmt)
                for key in set(env.keys()) | set(true_env.keys()) | set(false_env.keys()):
                    tv = true_env.get(key)
                    fv = false_env.get(key)
                    if tv == fv and tv is not None:
                        env[key] = tv
                    else:
                        env.pop(key, None)
                if true_next == false_next:
                    current = true_next
                elif true_next is None:
                    current = false_next
                elif false_next is None:
                    current = true_next
                else:
                    current = true_next
                continue
            return None

        result.extend(iteration_stmts)

    return None


def _recover_structure(
    states: dict[_StateKey, _StateBlock],
    entry: _StateKey,
    is_exit: Callable[[_StateKey], bool],
) -> list[Statement] | None:
    """
    Walk the state graph from the entry state and emit the recovered AST. Returns None if the
    structure cannot be recovered (e.g., irreducible control flow).
    """
    back_edges = _find_back_edges(states, entry, is_exit)
    loop_headers: set[_StateKey] = set(back_edges.values())

    def _emit_arm(
        start: _StateKey,
        stop: _StateKey | None,
        claimed: set[_StateKey],
    ) -> tuple[list[Statement], _StateKey | None] | None:
        """
        Emit statements from start, stopping before the stop state (if given). Returns

            (statements, next_state)

        where next_state is the stop state or None.
        """
        result: list[Statement] = []
        current: _StateKey | None = start

        while current is not None:
            if is_exit(current):
                return (result, None)
            if current not in states:
                return None
            if stop is not None and current == stop:
                return (result, current)
            if current in claimed:
                return (result, current)
            if current in loop_headers:
                loop_result = _emit_loop(current, claimed)
                if loop_result is None:
                    return None
                loop_stmts, loop_next, loop_internals = loop_result
                if loop_internals is not None:
                    filtered: list[Statement] = []
                    for s in result:
                        assignment = _get_simple_assignment(s)
                        if assignment is None or assignment[0] not in loop_internals:
                            filtered.append(s)
                    result = filtered
                result.extend(loop_stmts)
                current = loop_next
                continue
            claimed.add(current)
            block = states[current]
            result.extend(block.statements)
            transition = block.transition

            if isinstance(transition, _ExitTransition):
                return (result, None)

            if isinstance(transition, _LinearTransition):
                current = transition.target
                continue

            if isinstance(transition, _ConditionalTransition):
                true_target = transition.true_target
                false_target = transition.false_target
                join = _find_join_point(
                    states, true_target, false_target, is_exit, loop_headers,
                )
                effective_stop = join if join is not None else stop
                true_result = _emit_arm(true_target, effective_stop, claimed)
                false_result = _emit_arm(false_target, effective_stop, claimed)
                if true_result is None or false_result is None:
                    return None
                true_stmts, true_next = true_result
                false_stmts, false_next = false_result
                true_stmts = list(transition.true_prefix) + true_stmts
                false_stmts = list(transition.false_prefix) + false_stmts
                if_stmt = _build_if(transition.condition, true_stmts, false_stmts)
                if if_stmt is not None:
                    result.append(if_stmt)
                if true_next == false_next:
                    current = true_next
                elif true_next is None:
                    current = false_next
                elif false_next is None:
                    current = true_next
                else:
                    current = true_next
                continue
        return (result, None)

    def _emit_loop(
        header: _StateKey,
        outer_claimed: set[_StateKey],
    ) -> tuple[list[Statement], _StateKey | None, set[_VarKey] | None] | None:
        """
        Emit a while loop rooted at the given header state. First attempts to fully unroll the loop
        via symbolic execution. Falls back to structural recovery if unrolling fails. Returns:

            (statements, next_state, internal_vars_or_None)
        """
        unrolled = _try_unroll_loop(
            states, entry, header, is_exit, back_edges, loop_headers,
        )
        if unrolled is not None:
            unrolled_stmts, unrolled_internals = unrolled
            for sid in _collect_loop_states(
                states, header, is_exit,
                {latch for latch, target in back_edges.items() if target == header},
            ):
                outer_claimed.add(sid)
            return (unrolled_stmts, None, unrolled_internals)

        block = states[header]
        loop_cond: Expression
        body_start: _StateKey
        exit_target: _StateKey | None = None

        if isinstance(block.transition, _ConditionalTransition):
            cond_trans = block.transition
            true_target = cond_trans.true_target
            false_target = cond_trans.false_target
            true_is_exit = is_exit(true_target) or true_target not in states
            false_is_exit = is_exit(false_target) or false_target not in states

            true_reaches_header = _state_reaches(
                states, true_target, header, is_exit, loop_headers - {header},
            )
            false_reaches_header = _state_reaches(
                states, false_target, header, is_exit, loop_headers - {header},
            )

            if true_reaches_header and not false_reaches_header:
                loop_cond = cond_trans.condition
                body_start_stmts = list(block.statements) + list(cond_trans.true_prefix)
                body_start = true_target
                exit_target = false_target
            elif false_reaches_header and not true_reaches_header:
                loop_cond = _negate_condition(cond_trans.condition)
                body_start_stmts = list(block.statements) + list(cond_trans.false_prefix)
                body_start = false_target
                exit_target = true_target
            elif true_is_exit:
                loop_cond = _negate_condition(cond_trans.condition)
                body_start_stmts = list(block.statements) + list(cond_trans.false_prefix)
                body_start = false_target
                exit_target = true_target
            elif false_is_exit:
                loop_cond = cond_trans.condition
                body_start_stmts = list(block.statements) + list(cond_trans.true_prefix)
                body_start = true_target
                exit_target = false_target
            else:
                loop_cond = Ps1Variable(name='True', scope=Ps1ScopeModifier.NONE)
                body_start_stmts = list(block.statements)
                body_start = header
                outer_claimed.add(header)
                inner_claimed: set[_StateKey] = set()
                inner_claimed.add(header)
                body_result = _emit_arm(true_target, header, inner_claimed)
                if body_result is None:
                    return None
                body_stmts = body_start_stmts
                if_true, _ = body_result
                if_false_result = _emit_arm(false_target, header, inner_claimed)
                if if_false_result is None:
                    return None
                if_false, _ = if_false_result
                true_body = list(cond_trans.true_prefix) + if_true
                false_body = list(cond_trans.false_prefix) + if_false
                if_stmt = _build_if(cond_trans.condition, true_body, false_body)
                if if_stmt is not None:
                    body_stmts.append(if_stmt)
                while_stmt = Ps1WhileLoop(
                    condition=loop_cond,
                    body=Block(body=body_stmts),
                )
                outer_claimed.update(inner_claimed)
                return ([while_stmt], exit_target, None)
        else:
            loop_cond = Ps1Variable(name='True', scope=Ps1ScopeModifier.NONE)
            body_start_stmts = list(block.statements)
            if isinstance(block.transition, _LinearTransition):
                body_start = block.transition.target
            else:
                return None
            exit_target = None

        outer_claimed.add(header)
        inner_claimed = set()
        inner_claimed.add(header)
        body_result = _emit_arm(body_start, header, inner_claimed)
        if body_result is None:
            return None
        body_stmts, _ = body_result
        all_body = body_start_stmts + body_stmts
        while_stmt = Ps1WhileLoop(
            condition=loop_cond,
            body=Block(body=all_body),
        )
        outer_claimed.update(inner_claimed)
        next_state: _StateKey | None = None
        if exit_target is not None and not is_exit(exit_target):
            next_state = exit_target
        return ([while_stmt], next_state, None)

    claimed: set[_StateKey] = set()
    result = _emit_arm(entry, None, claimed)
    if result is None:
        return None
    stmts, _ = result
    return stmts


def _state_reaches(
    states: dict[_StateKey, _StateBlock],
    start: _StateKey,
    target: _StateKey,
    is_exit: Callable[[_StateKey], bool],
    barriers: set[_StateKey],
) -> bool:
    """
    Check if the state graph can reach target from start without crossing barriers.
    """
    visited: set[_StateKey] = set()
    queue: list[_StateKey] = [start]
    while queue:
        s = queue.pop(0)
        if s == target:
            return True
        if is_exit(s) or s not in states or s in visited or s in barriers:
            continue
        visited.add(s)
        block = states[s]
        t = block.transition
        if isinstance(t, _LinearTransition):
            queue.append(t.target)
        elif isinstance(t, _ConditionalTransition):
            queue.append(t.true_target)
            queue.append(t.false_target)
    return False


class Ps1ControlFlowDeflattening(Transformer):
    """
    Recover original control flow from control-flow-flattened scripts.
    """

    def visit(self, node: Node):
        for parent in list(node.walk()):
            if isinstance(parent, Ps1SubExpression):
                continue
            body = _get_body(parent)
            if body is None:
                continue
            self._try_deflatten_body(body, parent)

    def _try_deflatten_body(self, body: list[Statement], parent: Node):
        i = 0
        while i < len(body):
            stmt = body[i]
            if not isinstance(stmt, Ps1WhileLoop):
                i += 1
                continue
            match = _match_dispatcher(stmt)
            if match is None:
                i += 1
                continue
            init = _find_state_init(body, i, match.state_var_name, match.state_var_scope)
            if init is None:
                i += 1
                continue
            init_index, entry_state = init
            is_exit = _make_exit_check(match.condition, match.state_var_name)
            machine = _extract_state_machine(match, is_exit)
            if machine is None:
                i += 1
                continue
            if entry_state not in machine:
                i += 1
                continue
            recovered = _recover_structure(machine, entry_state, is_exit)
            if recovered is None:
                i += 1
                continue
            recovered = [
                s for s in recovered
                if _is_state_assignment(s, match.state_var_name, match.state_var_scope) is None
            ]
            for s in recovered:
                s.parent = parent
            body[init_index:i + 1] = recovered
            self.mark_changed()
            i += len(recovered)
