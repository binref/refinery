"""
Remove unused variable assignments and junk expression statements.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.ps1.deobfuscation.constants import (
    _PS1_SKIP_VARIABLES,
    _assignment_target_variable,
    _candidate_key,
    _find_removable_statement,
    _walk_outer_scope,
)
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    BodyRole,
    assignment_target_variables,
    classify_body,
    get_body,
    get_command_name,
    is_assignment_write_target,
)
from refinery.lib.scripts.ps1.deobfuscation.purity import (
    StatementEffect,
    classify_statement_effect,
    is_side_effect_free,
)
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AssignmentExpression,
    Ps1ClassDefinition,
    Ps1CommandInvocation,
    Ps1EnumDefinition,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1FunctionDefinition,
    Ps1ParameterDeclaration,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1UnaryExpression,
    Ps1Variable,
)


def _inside_definition(node: Node) -> bool:
    """
    Return `True` when `node` is nested inside a function, class, or enum definition body.
    """
    cursor = node.parent
    while cursor is not None:
        if isinstance(cursor, (Ps1FunctionDefinition, Ps1ClassDefinition, Ps1EnumDefinition)):
            return True
        cursor = cursor.parent
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
                for var in assignment_target_variables(n.target):
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
        # An outer-scope assignment can still be read through PowerShell's dynamic scoping (from
        # inside a function body) or through a scope qualifier (`$script:x`, `$global:x`). The
        # outer-scope walk above misses both, so collect those reads from the full tree by bare name
        # and treat them as free reads — keeping the assignment alive rather than deleting live code.
        for n in node.walk():
            if not isinstance(n, Ps1Variable) or n in write_targets:
                continue
            scoped = n.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.ENV)
            if not scoped and not _inside_definition(n):
                continue
            has_free_read.add(n.name.lower())
            if n.scope == Ps1ScopeModifier.ENV:
                has_free_read.add(F'env:{n.name.lower()}')
        dead: set[str] = set()
        for key in write_nodes:
            if key in has_free_read or key in _PS1_SKIP_VARIABLES:
                continue
            if key not in read_in_assign:
                dead.add(key)
        changed = True
        while changed:
            changed = False
            for key, assignees in read_in_assign.items():
                if key in dead or key in has_free_read or key in _PS1_SKIP_VARIABLES:
                    continue
                if key not in write_nodes:
                    continue
                if assignees.issubset(dead):
                    dead.add(key)
                    changed = True
        if not dead:
            return None
        removable: list[Node] = []
        seen: set[Node] = set()
        for key in dead:
            for mutation in write_nodes[key]:
                if mutation in seen:
                    continue
                if (
                    isinstance(mutation, Ps1AssignmentExpression)
                    and not self._all_targets_dead(mutation, dead)
                ):
                    continue
                seen.add(mutation)
                removable.append(mutation)
        body = get_body(node)
        if body is not None:
            dead_stmts: set[Node] = set()
            for mutation in removable:
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
        for mutation in removable:
            self._remove_mutation(mutation)

    @staticmethod
    def _all_targets_dead(assign: Ps1AssignmentExpression, dead: set[str]) -> bool:
        """
        Return `True` when every variable written by `assign` is dead. A multi-assignment such as
        `$a, $b = 1, 2` is only removable when all of its targets are dead; removing it while a
        co-target is still live would destroy that live write.
        """
        keys = [_candidate_key(var) for var in assignment_target_variables(assign.target)]
        if not keys:
            return False
        return all(key is not None and key in dead for key in keys)

    @staticmethod
    def _enclosing_assignment_target(var: Ps1Variable) -> str | None:
        """
        If `var` is read inside an assignment's RHS, return the assignment target's variable key.
        """
        if is_assignment_write_target(var):
            return None
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
            if rhs is not None and not is_side_effect_free(rhs) and isinstance(rhs, Expression):
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
        for parent in list(node.walk()):
            role = classify_body(parent)
            if role is None or role is BodyRole.OPAQUE:
                continue
            body = get_body(parent)
            self._prune_body(body, role, isinstance(parent, Ps1Script), called)
        self._remove_inert_functions(node)

    @staticmethod
    def _is_dynamic_dispatch(cmd: Ps1CommandInvocation) -> bool:
        """
        Return `True` when an invocation may resolve to an arbitrary function name at runtime. A
        literal command name resolves statically, and a literal scriptblock body (`&{ ... }`) runs
        inline; any other command expression (a variable like `& $f`, an expandable string, or a
        subexpression) could dispatch to any defined function.
        """
        return not isinstance(cmd.name, (Ps1StringLiteral, Ps1ScriptBlock))

    @staticmethod
    def _reachable_functions(node: Node) -> set[str]:
        """
        Collect all function names transitively reachable from top-level call sites. First gather
        direct calls from the outer scope, then expand through function bodies until stable. When an
        invocation may dispatch dynamically (see `_is_dynamic_dispatch`), every defined function is
        treated as reachable so that a function called only through `& $f` is never removed.
        """
        directly_called: set[str] = set()
        functions: dict[str, Ps1FunctionDefinition] = {}
        dynamic_call = False
        for n in _walk_outer_scope(node):
            if isinstance(n, Ps1CommandInvocation):
                name = get_command_name(n)
                if name is not None:
                    directly_called.add(name.lower())
                elif Ps1JunkStatementRemoval._is_dynamic_dispatch(n):
                    dynamic_call = True
            elif isinstance(n, Ps1FunctionDefinition):
                functions[n.name.lower()] = n
        if dynamic_call:
            return set(functions.keys()) | directly_called
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
                    if name is None:
                        if Ps1JunkStatementRemoval._is_dynamic_dispatch(n):
                            return set(functions.keys()) | reachable
                        continue
                    key = name.lower()
                    if key not in reachable:
                        reachable.add(key)
                        if key in functions:
                            frontier.append(key)
        return reachable

    def _remove_inert_functions(self, node: Node):
        """
        Remove top-level functions whose body carries no observable output or side effect together
        with the bare call statements that invoke them. After body pruning, an injected junk function
        such as `function j { $Null = 915 }` has an empty body; calling it is a no-op, so the
        definition and its call sites drop out as a unit. Only whole-statement, argument-free
        invocations of the function count as call sites — if the name is referenced any other way, or
        anything in the script dispatches dynamically (`& $f`), the function is kept, because its
        result might then be observed or its identity might not be provable.
        """
        if self._any_dynamic_dispatch(node):
            return
        inert: dict[str, Ps1FunctionDefinition] = {}
        for stmt in node.body:
            if isinstance(stmt, Ps1FunctionDefinition) and self._body_is_inert(stmt):
                inert[stmt.name.lower()] = stmt
        if not inert:
            return
        call_sites: dict[str, list[Node]] = {name: [] for name in inert}
        other_reference: set[str] = set()
        for ref in node.walk():
            if not isinstance(ref, Ps1CommandInvocation):
                continue
            name = get_command_name(ref)
            if name is None:
                continue
            key = name.lower()
            if key not in inert:
                continue
            statement = self._bare_call_statement(ref)
            if statement is not None and not ref.arguments:
                call_sites[key].append(statement)
            else:
                other_reference.add(key)
        for key, definition in inert.items():
            if key in other_reference:
                continue
            for statement in call_sites[key]:
                if _remove_from_parent(statement):
                    self.mark_changed()
            if _remove_from_parent(definition):
                self.mark_changed()

    @staticmethod
    def _body_is_inert(function: Ps1FunctionDefinition) -> bool:
        """
        Return `True` when a function body neither emits output nor performs a side effect: it is
        empty, or every statement is a no-output discard (`$Null = <pure>`, `[Void]`, `Out-Null`).
        A statement that yields a value or has any effect makes the function observable and non-inert.
        """
        if function.body is None:
            return True
        for stmt in function.body.body:
            if classify_statement_effect(stmt) is not StatementEffect.DISCARD:
                return False
        return True

    @staticmethod
    def _bare_call_statement(cmd: Ps1CommandInvocation) -> Node | None:
        """
        Return the enclosing statement when `cmd` is invoked as a whole expression statement (`f`
        alone, or `f` as the sole element of a statement-level pipeline), or `None` when its result
        flows into a larger expression where the call's value could be observed.
        """
        parent = cmd.parent
        if isinstance(parent, Ps1ExpressionStatement):
            return parent
        if isinstance(parent, Ps1PipelineElement):
            pipeline = parent.parent
            if (
                isinstance(pipeline, Ps1Pipeline)
                and len(pipeline.elements) == 1
                and isinstance(pipeline.parent, Ps1ExpressionStatement)
            ):
                return pipeline.parent
        return None

    @staticmethod
    def _any_dynamic_dispatch(node: Node) -> bool:
        for n in node.walk():
            if isinstance(n, Ps1CommandInvocation):
                if get_command_name(n) is None and Ps1JunkStatementRemoval._is_dynamic_dispatch(n):
                    return True
        return False

    def _prune_body(self, body: list, role: BodyRole, is_script_root: bool, called: set[str]):
        is_root = role is BodyRole.ROOT
        discard: set[Node] = set()
        output: set[Node] = set()
        dead_functions: set[Node] = set()
        for stmt in body:
            if isinstance(stmt, Ps1FunctionDefinition):
                if is_root and stmt.name.lower() not in called:
                    dead_functions.add(stmt)
                continue
            effect = classify_statement_effect(stmt)
            if effect is StatementEffect.DISCARD:
                discard.add(stmt)
            elif effect is StatementEffect.OUTPUT:
                output.add(stmt)
        # Emit-safety for a captured `ROOT` body (a function body or bare `&{}`): a side-effect-free
        # value may be the body's whole point (its return value), so a pure output statement is only
        # pruned when a non-removable statement survives to carry the body's output. A `DISCARD`
        # emits nothing and is always safe to drop, even when it empties the body — that is what
        # turns a junk function inert. The true script root has no return value, so this guard does
        # not apply there. A `NESTED` body likewise has no observable value: prune freely.
        if is_root and not is_script_root and output:
            if not self._output_survives(body, discard, output, dead_functions):
                output.clear()
        removable = discard | output | dead_functions
        if not removable:
            return
        # Never strip the script root down to nothing: a script that is only function definitions is
        # a module whose functions may be dot-sourced, so leaving it empty would erase real code.
        if is_script_root:
            surviving = [s for s in body if s not in removable]
            if not surviving:
                return
        for stmt in list(body):
            if stmt in removable:
                if _remove_from_parent(stmt):
                    self.mark_changed()

    @staticmethod
    def _output_survives(
        body: list, discard: set[Node], output: set[Node], dead_functions: set[Node],
    ) -> bool:
        """
        Return `True` when a statement that carries observable output would remain after pruning, so
        that removing the pure-output statements does not silence a captured body's return value.
        """
        for stmt in body:
            if stmt in discard or stmt in output or stmt in dead_functions:
                continue
            if isinstance(stmt, Ps1FunctionDefinition):
                continue
            return True
        return False
