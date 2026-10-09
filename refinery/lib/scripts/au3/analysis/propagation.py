"""
The constant-binding walk: which variable holds which value at every read, and which globals
every script function may write. The propagate transform reads the read values; Phase 3's
interpreter reads both.

The walk is one abstract pass per scope — the script body and every function body, each
starting from nothing: a global constant is not seeded into a function walk, because a local of
the same name in the function shadows it and an unseen `#include` cannot be told apart from one
that does not. A name binds only where `refinery.lib.scripts.au3.analysis.scopes` proves which
storage a write targets; a bare assignment or `Dim` inside a function proves nothing, so it binds
nothing and kills the name in every interpretation.

Bindings survive only as long as the program agrees on them: an `If` keeps the value only where
every branch agrees, a loop kills every name its body may change before the loop and after it,
and a call kills what its callee may write. `Const` and `Enum` names are never killed — AutoIt
refuses to run a script that reassigns one. A `Static` never binds at all: its value survives
the call that wrote it, so no single pass can know it.

A binding is taken only from a shape the fold leaves behind — a literal, a run-time-constant
macro, a unary minus over a number, an array literal of such, a `Binary("0x…")` call — plus the
compound assignments, which combine their operands through the operator table. Everything else
is a kill.
"""
from __future__ import annotations

from dataclasses import dataclass

from collections.abc import Mapping

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.builtins import BUILTIN_NAMES
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel, Binding
from refinery.lib.scripts.au3.analysis.values import (
    Au3Value,
    apply_binary,
    literal_value,
    of_int,
)
from refinery.lib.scripts.au3.model import (
    Au3ArrayAccess,
    Au3Assignment,
    Au3Call,
    Au3CaseRange,
    Au3DoUntilStatement,
    Au3EnumDeclaration,
    Au3ForInStatement,
    Au3ForStatement,
    Au3FunctionDeclaration,
    Au3IfStatement,
    Au3MemberAccess,
    Au3ReDimStatement,
    Au3Script,
    Au3SelectStatement,
    Au3StringLiteral,
    Au3SwitchStatement,
    Au3Variable,
    Au3VariableDeclaration,
    Au3WhileStatement,
    Au3WithStatement,
    Expression,
)
from refinery.lib.scripts.au3.parser import Au3Parser


@dataclass(frozen=True)
class Au3PropagationModel:
    """
    What the walk learned about one tree version: the value at every variable read a
    substitution may replace — a read in a target or `ByRef` position is never recorded — the
    may-write summary of every script function, and the globals proven at every script-level call
    to a function that writes none. Built once per tree version by `build_propagation_model`.
    """
    values: dict[Au3Variable, Au3Value]
    summaries: dict[str, frozenset[str] | None]
    entries: dict[Au3Call, dict[str, Au3Value]]

    def value_at(self, node: Au3Variable) -> Au3Value | None:
        """
        The value *node* provably holds where it is read, or `None` when the walk does not know.
        """
        return self.values.get(node)

    def may_write(self, function: str) -> frozenset[str] | None:
        """
        The globals *function* may write, or `None` when it may write any.
        """
        return self.summaries.get(function)

    def entry_globals(self, call: Au3Call) -> Mapping[str, Au3Value]:
        """
        The globals the walk proves a value for where *call* stands — a call at script level to a
        function whose summary is empty, so nothing it does can change them and the values hold
        for the whole call. Inside a function body the walk knows no globals, so the answer there
        is empty.
        """
        return self.entries.get(call, {})


@dataclass
class _State:
    constants: dict[str, Au3Value]
    variables: dict[str, tuple[Binding, Au3Value]]

    @classmethod
    def empty(cls) -> _State:
        return cls({}, {})

    def copy(self) -> _State:
        return _State(dict(self.constants), dict(self.variables))

    def lookup(self, name: str) -> Au3Value | None:
        value = self.constants.get(name)
        if value is not None:
            return value
        entry = self.variables.get(name)
        if entry is None:
            return None
        return entry[1]

    def bind(self, name: str, binding: Binding, value: Au3Value | None) -> None:
        self.constants.pop(name, None)
        if value is None:
            self.variables.pop(name, None)
        else:
            self.variables[name] = (binding, value)

    def kill(self, name: str) -> None:
        self.constants.pop(name, None)
        self.variables.pop(name, None)

    def kill_all(self) -> None:
        self.variables.clear()

    def replace_with(self, other: _State) -> None:
        self.constants = other.constants
        self.variables = other.variables


def _join_states(one: _State, two: _State) -> _State:
    """
    The state both *one* and *two* agree on: a name survives only with the same binding in both.
    """
    constants = {
        name: value
        for name, value in one.constants.items()
        if two.constants.get(name) == value
    }
    variables = {
        name: entry
        for name, entry in one.variables.items()
        if two.variables.get(name) == entry
    }
    return _State(constants, variables)


def _argument_variables(call: Au3Call) -> set[str]:
    """
    The names of a call's arguments that are nothing but a variable: the positions an unseen
    callee may hold by reference.
    """
    names = set()
    for argument in call.arguments:
        node = ast.unwrap_parens(argument)
        if isinstance(node, Au3Variable):
            names.add(node.name)
    return names


def _byref_variables(call: Au3Call, function: Au3FunctionDeclaration) -> set[str]:
    """
    The names a call passes into the `ByRef` parameters of *function*.
    """
    names = set()
    for index, parameter in enumerate(function.params):
        if not parameter.by_ref or index >= len(call.arguments):
            continue
        node = ast.unwrap_parens(call.arguments[index])
        if isinstance(node, Au3Variable):
            names.add(node.name)
    return names


def execute_kills(call: Au3Call) -> set[str] | None:
    """
    The names an `Execute` call may write: a constant argument spells one expression, so only a
    call inside it can write anything; a parse failure answers `""` and writes nothing. Any other
    argument can execute arbitrary code.
    """
    if len(call.arguments) != 1:
        return None
    literal = ast.unwrap_parens(call.arguments[0])
    if not isinstance(literal, Au3StringLiteral):
        return None
    expression = Au3Parser(literal.value).parse_expression()
    if expression is None:
        return set()
    if ast.contains_a_call(expression):
        return None
    return set()


def assign_kills(call: Au3Call) -> set[str] | None:
    """
    The names an `Assign` call may write: a constant first argument names one variable, anything
    else may name any.
    """
    if not call.arguments:
        return set()
    literal = ast.unwrap_parens(call.arguments[0])
    if not isinstance(literal, Au3StringLiteral):
        return None
    return {literal.value.lstrip('$').lower()}


def _call_kills(
    call: Au3Call,
    scope_model: Au3ScopeModel,
    summaries: dict[str, frozenset[str] | None],
) -> tuple[set[str] | None, set[str]]:
    """
    The names a call may write — `None` for every non-constant — and the argument names it may
    hold by reference. A script function kills its may-write summary; a call to any name the
    script and the table do not know may run anything.
    """
    callee = ast.direct_callee(call)
    if callee is None:
        return None, _argument_variables(call)
    if callee.name in scope_model.functions:
        summary = summaries.get(callee.name)
        byref = _byref_variables(call, scope_model.functions[callee.name])
        if summary is None:
            return None, byref
        return set(summary), byref
    if callee.name not in BUILTIN_NAMES:
        return None, _argument_variables(call)
    if callee.name == 'execute':
        return execute_kills(call), set()
    if callee.name == 'assign':
        return assign_kills(call), set()
    return set(), set()


def _written_names(
    body: list[Statement],
    scope_model: Au3ScopeModel,
    summaries: dict[str, frozenset[str] | None],
) -> set[str] | None:
    """
    The names one pass over *body* may change — written, killed, or rebound — or `None` when it
    may change any. A loop drops these at its entry and its exit, so a read inside the body sees
    a value only where every iteration agrees on it, and a read after the loop sees one only when
    no iteration can have changed it.
    """
    names: set[str] = set()
    for node in ast.scope_nodes(body):
        if isinstance(node, Au3Variable):
            if ast.is_write_occurrence(node):
                names.add(node.name)
            continue
        if not isinstance(node, Au3Call):
            continue
        kills, byref = _call_kills(node, scope_model, summaries)
        if kills is None:
            return None
        names |= kills
        names |= byref
    return names


def _function_scan(
    function: Au3FunctionDeclaration,
    scope_model: Au3ScopeModel,
) -> tuple[set[str], bool, set[str]]:
    """
    What one function may write by itself, ignoring its calls: the global names its provable
    writes target, whether it may write any global at all, and the script functions it calls.
    A variable handed to the `ByRef` parameter of a script function is written by that call, so
    it counts as a write of this function. A write to a `ByRef` parameter of this function is a
    write of its local: the variable behind it belongs to the caller, which counts it there.
    """
    names: set[str] = set()
    everything = False
    callees: set[str] = set()
    for node in ast.scope_nodes(function.body):
        if isinstance(node, Au3Variable):
            if not ast.is_write_occurrence(node):
                continue
            statement = ast.owning_statement(node)
            if statement is None:
                continue
            if scope_model.binding(function, statement, node.name) is not Binding.LOCAL:
                names.add(node.name)
            continue
        if not isinstance(node, Au3Call):
            continue
        callee = ast.direct_callee(node)
        if callee is None:
            everything = True
            continue
        if callee.name in scope_model.functions:
            callees.add(callee.name)
            statement = ast.owning_statement(node)
            if statement is None:
                continue
            for name in _byref_variables(node, scope_model.functions[callee.name]):
                if scope_model.binding(function, statement, name) is not Binding.LOCAL:
                    names.add(name)
            continue
        if callee.name not in BUILTIN_NAMES:
            everything = True
            continue
        if callee.name == 'execute':
            kills = execute_kills(node)
        elif callee.name == 'assign':
            kills = assign_kills(node)
        else:
            continue
        if kills is None:
            everything = True
        else:
            names |= kills
    return names, everything, callees


def _build_summaries(scope_model: Au3ScopeModel) -> dict[str, frozenset[str] | None]:
    """
    The may-write summary of every script function: its own global writes plus those of every
    script function it reaches, transitively, merged by worklist fixpoint. `None` is the summary
    of a function that may write any global.
    """
    scanned = {
        name: _function_scan(function, scope_model)
        for name, function in scope_model.functions.items()
    }
    summaries = {
        name: None if everything else frozenset(names)
        for name, (names, everything, callees) in scanned.items()
    }
    changed = True
    while changed:
        changed = False
        for name, (names, everything, callees) in scanned.items():
            if everything:
                continue
            merged = set(names)
            for callee in callees:
                summary = summaries[callee]
                if summary is None:
                    merged = None
                    break
                merged |= summary
            updated = None if merged is None else frozenset(merged)
            if updated != summaries[name]:
                summaries[name] = updated
                changed = True
    return summaries


class _Walker:
    """
    One abstract pass over every scope, recording the value at each variable read.
    """

    def __init__(self, scope_model: Au3ScopeModel, summaries: dict[str, frozenset[str] | None]):
        self.scope_model = scope_model
        self.summaries = summaries
        self.functions = scope_model.function_names
        self.values: dict[Au3Variable, Au3Value] = {}
        self.entries: dict[Au3Call, dict[str, Au3Value]] = {}

    def walk_scope(self, scope: Au3FunctionDeclaration | None, body: list[Statement]) -> None:
        state = _State.empty()
        for stmt in body:
            self.visit_statement(scope, stmt, state)

    def visit_statement(
        self,
        scope: Au3FunctionDeclaration | None,
        stmt: Statement,
        state: _State,
    ) -> None:
        if isinstance(stmt, Au3FunctionDeclaration):
            return
        if isinstance(stmt, Au3VariableDeclaration):
            self.visit_declaration(scope, stmt, state)
            return
        if isinstance(stmt, Au3EnumDeclaration):
            self.visit_enum(scope, stmt, state)
            return
        if isinstance(stmt, Au3ReDimStatement):
            self.visit_redim(scope, stmt, state)
            return
        if isinstance(stmt, Au3IfStatement):
            self.visit_if(scope, stmt, state)
            return
        if isinstance(stmt, Au3WhileStatement):
            self.visit_loop(scope, stmt.test, stmt.body, state)
            return
        if isinstance(stmt, Au3DoUntilStatement):
            self.visit_loop(scope, stmt.test, stmt.body, state)
            return
        if isinstance(stmt, Au3ForStatement):
            self.visit_for(scope, stmt, state)
            return
        if isinstance(stmt, Au3ForInStatement):
            self.visit_forin(scope, stmt, state)
            return
        if isinstance(stmt, Au3SwitchStatement):
            self.visit_switch(scope, stmt, state)
            return
        if isinstance(stmt, Au3SelectStatement):
            self.visit_select(scope, stmt, state)
            return
        if isinstance(stmt, Au3WithStatement):
            self.visit_expression(scope, stmt.object, state)
            for inner in stmt.body:
                self.visit_statement(scope, inner, state)
            return
        for child in stmt.children():
            if isinstance(child, Expression):
                self.visit_expression(scope, child, state)

    def visit_declaration(
        self,
        scope: Au3FunctionDeclaration | None,
        stmt: Au3VariableDeclaration,
        state: _State,
    ) -> None:
        for declarator in stmt.declarations:
            for dimension in declarator.dimensions:
                self.visit_expression(scope, dimension, state)
            self.visit_expression(scope, declarator.initializer, state)
            variable = declarator.variable
            if variable is None:
                continue
            if stmt.is_const:
                value = literal_value(declarator.initializer, self.functions)
                if value is None:
                    state.kill(variable.name)
                else:
                    state.constants[variable.name] = value
                continue
            if stmt.is_static:
                state.kill(variable.name)
                continue
            state.bind(
                variable.name,
                self.scope_model.binding(scope, stmt, variable.name),
                literal_value(declarator.initializer, self.functions))

    def visit_enum(
        self,
        scope: Au3FunctionDeclaration | None,
        stmt: Au3EnumDeclaration,
        state: _State,
    ) -> None:
        """
        The enum count: an entry with an initializer resets it, one without takes the count and
        advances it by the step. The count starts at 0 and falls to unknown past an entry whose
        initializer is not a literal.
        """
        counter: Au3Value | None = of_int(0)
        step = of_int(stmt.step_value)
        for declarator in stmt.declarations:
            variable = declarator.variable
            if declarator.initializer is not None:
                self.visit_expression(scope, declarator.initializer, state)
                value = literal_value(declarator.initializer, self.functions)
                if value is None or variable is None:
                    counter = None
                    if variable is not None:
                        state.kill(variable.name)
                else:
                    state.constants[variable.name] = value
                    counter = apply_binary(stmt.step_operator, value, step)
                continue
            if variable is None:
                continue
            if counter is None:
                state.kill(variable.name)
                continue
            state.constants[variable.name] = counter
            counter = apply_binary(stmt.step_operator, counter, step)

    def visit_redim(
        self,
        scope: Au3FunctionDeclaration | None,
        stmt: Au3ReDimStatement,
        state: _State,
    ) -> None:
        for target in stmt.targets:
            for dimension in target.dimensions:
                self.visit_expression(scope, dimension, state)
            if target.variable is not None:
                state.kill(target.variable.name)

    def visit_assignment(
        self,
        scope: Au3FunctionDeclaration | None,
        assignment: Au3Assignment,
        state: _State,
    ) -> None:
        self.visit_expression(scope, assignment.value, state)
        self.visit_target(scope, assignment.target, state)
        variable = ast.store_target_variable(assignment.target)
        if variable is None:
            return
        if not isinstance(ast.unwrap_parens(assignment.target), Au3Variable):
            state.kill(variable.name)
            return
        statement = ast.owning_statement(assignment)
        if statement is None:
            return
        binding = self.scope_model.binding(scope, statement, variable.name)
        if binding is Binding.NONE:
            state.kill(variable.name)
            return
        if assignment.operator == '=':
            state.bind(variable.name, binding, literal_value(assignment.value, self.functions))
            return
        current = state.lookup(variable.name)
        operand = literal_value(assignment.value, self.functions)
        if current is None or operand is None:
            state.bind(variable.name, binding, None)
            return
        operator = assignment.operator.rstrip('=')
        state.bind(variable.name, binding, apply_binary(operator, current, operand))

    def visit_target(
        self,
        scope: Au3FunctionDeclaration | None,
        target: Expression | None,
        state: _State,
    ) -> None:
        """
        The reads a store target holds — an index, a member's object — with the stored variable
        itself left unrecorded: a read in target position is never one a substitution may
        replace, and the value the compound operators need comes from the state directly.
        """
        node = ast.unwrap_parens(target)
        if isinstance(node, Au3ArrayAccess):
            self.visit_expression(scope, node.index, state)
            self.visit_target(scope, node.array, state)
            return
        if isinstance(node, Au3MemberAccess):
            self.visit_target(scope, node.object, state)

    def visit_expression(
        self,
        scope: Au3FunctionDeclaration | None,
        node: Expression | None,
        state: _State,
    ) -> None:
        if node is None:
            return
        if isinstance(node, Au3Variable):
            value = state.lookup(node.name)
            if value is not None:
                self.values[node] = value
            return
        if isinstance(node, Au3Assignment):
            self.visit_assignment(scope, node, state)
            return
        if isinstance(node, Au3Call):
            self.visit_call(scope, node, state)
            return
        for child in node.children():
            if isinstance(child, Expression):
                self.visit_expression(scope, child, state)

    def visit_call(
        self,
        scope: Au3FunctionDeclaration | None,
        call: Au3Call,
        state: _State,
    ) -> None:
        """
        A `ByRef` argument of a declared script function is a target position — the callee
        receives the variable itself, not its value — so its read is never recorded and a
        substitution may never replace it, and the same holds for a bare variable in the callee
        position: the call runs what the variable names, not what it holds. An argument of a call
        to a name the script does not declare is still recorded and replaced — an unseen callee
        may hold it by reference, which would divert what the callee receives; telling the two
        apart needs the builtin name universe, which no module owns yet.
        """
        kills, byref = _call_kills(call, self.scope_model, self.summaries)
        if not isinstance(ast.unwrap_parens(call.callee), Au3Variable):
            self.visit_expression(scope, call.callee, state)
        callee = ast.direct_callee(call)
        function = self.scope_model.functions.get(callee.name) if callee is not None else None
        for index, argument in enumerate(call.arguments):
            node = ast.unwrap_parens(argument)
            if (
                isinstance(node, Au3Variable)
                and function is not None
                and index < len(function.params)
                and function.params[index].by_ref
            ):
                continue
            self.visit_expression(scope, argument, state)
        if (
            scope is None
            and function is not None
            and callee is not None
            and self.summaries.get(callee.name) == frozenset()
        ):
            self.entries[call] = {
                **state.constants,
                **{name: entry[1] for name, entry in state.variables.items()},
            }
        for name in byref:
            state.kill(name)
        if kills is None:
            state.kill_all()
        else:
            for name in kills:
                state.kill(name)

    def visit_if(
        self,
        scope: Au3FunctionDeclaration | None,
        stmt: Au3IfStatement,
        state: _State,
    ) -> None:
        """
        One branch runs, reached only after every earlier test evaluated false: each branch sees
        the state after the kills of the tests up to its own, and the branches join.
        """
        self.visit_expression(scope, stmt.test, state)
        outcomes = [self.visit_branch(scope, stmt.body, state)]
        for elseif in stmt.elseifs:
            self.visit_expression(scope, elseif.test, state)
            outcomes.append(self.visit_branch(scope, elseif.body, state))
        if stmt.else_body is None:
            outcomes.append(state.copy())
        else:
            outcomes.append(self.visit_branch(scope, stmt.else_body, state))
        self.join_into(state, outcomes)

    def visit_switch(
        self,
        scope: Au3FunctionDeclaration | None,
        stmt: Au3SwitchStatement,
        state: _State,
    ) -> None:
        self.visit_expression(scope, stmt.discriminant, state)
        outcomes = []
        has_else = False
        for case in stmt.cases:
            if case.values is None:
                has_else = True
            else:
                for value in case.values:
                    self.visit_case_value(scope, value, state)
            outcomes.append(self.visit_branch(scope, case.body, state))
        if not has_else:
            outcomes.append(state.copy())
        self.join_into(state, outcomes)

    def visit_select(
        self,
        scope: Au3FunctionDeclaration | None,
        stmt: Au3SelectStatement,
        state: _State,
    ) -> None:
        outcomes = []
        has_else = False
        for case in stmt.cases:
            if case.test is None:
                has_else = True
            else:
                self.visit_expression(scope, case.test, state)
            outcomes.append(self.visit_branch(scope, case.body, state))
        if not has_else:
            outcomes.append(state.copy())
        self.join_into(state, outcomes)

    def visit_case_value(
        self,
        scope: Au3FunctionDeclaration | None,
        value: Node,
        state: _State,
    ) -> None:
        if isinstance(value, Au3CaseRange):
            self.visit_expression(scope, value.start, state)
            self.visit_expression(scope, value.end, state)
        elif isinstance(value, Expression):
            self.visit_expression(scope, value, state)

    def visit_branch(
        self,
        scope: Au3FunctionDeclaration | None,
        body: list[Statement],
        state: _State,
    ) -> _State:
        branch = state.copy()
        for stmt in body:
            self.visit_statement(scope, stmt, branch)
        return branch

    def visit_for(
        self,
        scope: Au3FunctionDeclaration | None,
        stmt: Au3ForStatement,
        state: _State,
    ) -> None:
        self.visit_expression(scope, stmt.start, state)
        self.visit_expression(scope, stmt.limit, state)
        self.visit_expression(scope, stmt.step, state)
        if stmt.variable is not None:
            state.kill(stmt.variable.name)
        self.visit_loop(scope, None, stmt.body, state)

    def visit_forin(
        self,
        scope: Au3FunctionDeclaration | None,
        stmt: Au3ForInStatement,
        state: _State,
    ) -> None:
        self.visit_expression(scope, stmt.iterable, state)
        if stmt.variable is not None:
            state.kill(stmt.variable.name)
        self.visit_loop(scope, None, stmt.body, state)

    def visit_loop(
        self,
        scope: Au3FunctionDeclaration | None,
        test: Expression | None,
        body: list[Statement],
        state: _State,
    ) -> None:
        written = _written_names(body, self.scope_model, self.summaries)
        if written is None:
            state.kill_all()
        else:
            for name in written:
                state.kill(name)
        self.visit_expression(scope, test, state)
        branch = state.copy()
        for stmt in body:
            self.visit_statement(scope, stmt, branch)

    def join_into(self, state: _State, outcomes: list[_State]) -> None:
        result = outcomes[0]
        for outcome in outcomes[1:]:
            result = _join_states(result, outcome)
        state.replace_with(result)


def build_propagation_model(root: Au3Script, scope_model: Au3ScopeModel) -> Au3PropagationModel:
    """
    Walk every scope of *root* — the script body and every function body — and record the value
    at each variable read the walk reaches, along with the may-write summaries the calls rest on.
    """
    summaries = _build_summaries(scope_model)
    walker = _Walker(scope_model, summaries)
    for scope, body in ast.scope_bodies(root):
        walker.walk_scope(scope, body)
    return Au3PropagationModel(walker.values, summaries, walker.entries)
