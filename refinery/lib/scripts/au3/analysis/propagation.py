"""
The constant-binding walk: which variable holds which value at every read, and which globals
every script function may write. The propagate transform reads the read values; Phase 3's
interpreter reads both.

The may-write summary is refined by the existence census — see
`refinery.lib.scripts.au3.analysis.existence`: a bare write inside a function creates a local
of that function, so it counts as a global write only where the census proves a global of the
name may exist when the tree runs. A `ReDim` creates no storage, so the refinement leaves it
counted.

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

A binding is taken from the value the constant evaluator proves — see
`refinery.lib.scripts.au3.analysis.constants`, asked over the state's own lookups, so an
arithmetic over proven reads binds what it computes and one pass collapses a chain of derived
constants. The compound assignments take the same evaluator's bounded combination. A value past
the payload bound is data, not a constant: its reads are never recorded, and a combination that
would leave the bound binds nothing, so no accumulator grows a state past what the script itself
spells. Everything the evaluator refuses is a kill.

A binding the bound refuses is asked once more without it, but only where reads stand behind
it: an answer past the bound is an accumulator the walk can never fold into one legal
statement, so every read the run recorded is retracted and the run passes through as written
instead of half-folded. The reads behind a binding are its lineage — the reads the value
flowed from, carried through assignments, declarations, and compound operators, joined where
branches agree — and a binding with no reads behind it is refused as before.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.builtins import call_is_bounded
from refinery.lib.scripts.au3.analysis.constants import (
    Policy,
    combine,
    constant_value,
    within_limit,
)
from refinery.lib.scripts.au3.analysis.existence import (
    Au3ExistenceModel,
    assign_kills,
    execute_kills,
)
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel, Binding
from refinery.lib.scripts.au3.analysis.values import (
    Au3Value,
    apply_binary,
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
    Au3SwitchStatement,
    Au3Variable,
    Au3VariableDeclaration,
    Au3WhileStatement,
    Au3WithStatement,
    Expression,
)

#: The payload beyond which a value the walk proves is data, not a constant: a read of such a
#: value is never recorded, and a combination that would leave the bound binds nothing, so no
#: state grows past what the script itself spells.
_MAX_PROPAGATED_PAYLOAD = 4096

#: One recorded read behind a binding: the read site itself, the lineage of the name the site
#: read, or two lineages joined. A growing accumulator run shares its earlier lineage with
#: every later binding, so the structure is walked by identity and a shared subtree once.
_Lineage = None | Au3Variable | tuple['_Lineage', '_Lineage']


def _lineage_reads(lineage: _Lineage) -> Iterator[Au3Variable]:
    stack: list[_Lineage] = [lineage]
    seen: set[int] = set()
    while stack:
        item = stack.pop()
        if item is None or id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, tuple):
            stack.extend(item)
        else:
            yield item


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
    lineage: dict[str, _Lineage]
    version: int = 0

    @classmethod
    def empty(cls) -> _State:
        return cls({}, {}, {})

    def copy(self) -> _State:
        return _State(
            dict(self.constants), dict(self.variables), dict(self.lineage), self.version)

    def lookup(self, name: str) -> Au3Value | None:
        value = self.constants.get(name)
        if value is not None:
            return value
        entry = self.variables.get(name)
        if entry is None:
            return None
        return entry[1]

    def bind(self, name: str, binding: Binding, value: Au3Value | None, lineage: _Lineage) -> None:
        changed = self.constants.pop(name, None) is not None
        if value is None:
            changed = self.variables.pop(name, None) is not None or changed
            changed = self.lineage.pop(name, None) is not None or changed
        else:
            if not changed and self.variables.get(name) != (binding, value):
                changed = True
            self.variables[name] = (binding, value)
            self.lineage[name] = lineage
        if changed:
            self.version += 1

    def bind_constant(self, name: str, value: Au3Value, lineage: _Lineage) -> None:
        if self.constants.get(name) != value:
            self.version += 1
        self.constants[name] = value
        self.lineage[name] = lineage

    def kill(self, name: str) -> None:
        if (
            self.constants.pop(name, None) is not None
            or self.variables.pop(name, None) is not None
            or self.lineage.pop(name, None) is not None
        ):
            self.version += 1

    def kill_all(self) -> None:
        if self.variables:
            self.version += 1
            for name in self.variables:
                self.lineage.pop(name, None)
            self.variables.clear()

    def replace_with(self, other: _State) -> None:
        if self.constants != other.constants or self.variables != other.variables:
            self.version += 1
        self.constants = other.constants
        self.variables = other.variables
        self.lineage = other.lineage


def _join_states(one: _State, two: _State) -> _State:
    """
    The state both *one* and *two* agree on: a name survives only with the same binding in both,
    and the lineage of a surviving name is the union of theirs — the reads either branch's value
    flowed from.
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
    lineage = {
        name: (one.lineage.get(name), two.lineage.get(name))
        for name in constants.keys() | variables.keys()
    }
    return _State(constants, variables, lineage)


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


def _builtin_kills(call: Au3Call) -> tuple[set[str] | None, set[str]]:
    """
    The names a call to a builtin may write — `None` for may-write-anything — and the argument
    names it may hold by reference. `Execute` and `Assign` answer through their own payload
    readers, and neither holds an argument by reference: their arguments are a payload and a
    name. A bounded builtin writes and captures nothing; a computed callee, `Call`, a
    registration builtin, or a name neither the script nor the builtin table knows may run
    anything, over every variable the call passes.
    """
    callee = ast.direct_callee(call)
    if callee is None:
        return None, _argument_variables(call)
    if callee.name == 'execute':
        return execute_kills(call), set()
    if callee.name == 'assign':
        return assign_kills(call), set()
    if call_is_bounded(callee.name):
        return set(), set()
    return None, _argument_variables(call)


def _call_kills(
    call: Au3Call,
    scope_model: Au3ScopeModel,
    summaries: dict[str, frozenset[str] | None],
) -> tuple[set[str] | None, set[str]]:
    """
    The names a call may write — `None` for every non-constant — and the argument names it may
    hold by reference. A script function kills its may-write summary; every other callee answers
    through `_builtin_kills`.
    """
    callee = ast.direct_callee(call)
    if callee is not None and callee.name in scope_model.functions:
        summary = summaries.get(callee.name)
        function = scope_model.functions[callee.name]
        byref = {variable.name for variable in ast.byref_arguments(function, call.arguments)}
        if summary is None:
            return None, byref
        return set(summary), byref
    return _builtin_kills(call)


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
    existence: Au3ExistenceModel,
) -> tuple[set[str], bool, set[str]]:
    """
    What one function may write by itself, ignoring its calls: the global names its provable
    writes target, whether it may write any global at all, and the script functions it calls.
    A variable handed to the `ByRef` parameter of a script function is written by that call, so
    it counts as a write of this function — a bare write the call performs where it stands, not
    one of the declaration or the loop header that may hold the call. A write to a `ByRef`
    parameter of this function is a write of its local: the variable behind it belongs to the
    caller, which counts it there. Whether any other write counts is the existence model's
    `write_may_target_global`.
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
            binding = scope_model.binding(function, statement, node.name)
            creates_storage = not isinstance(statement, Au3ReDimStatement)
            if existence.write_may_target_global(binding, node.name, creates_storage):
                names.add(node.name)
            continue
        if not isinstance(node, Au3Call):
            continue
        callee = ast.direct_callee(node)
        if callee is not None and callee.name in scope_model.functions:
            callees.add(callee.name)
            target = scope_model.functions[callee.name]
            for variable in ast.byref_arguments(target, node.arguments):
                binding = scope_model.binding(function, node, variable.name)
                if existence.write_may_target_global(binding, variable.name, True):
                    names.add(variable.name)
            continue
        kills, _held = _builtin_kills(node)
        if kills is None:
            everything = True
        else:
            names |= kills
    return names, everything, callees


def _build_summaries(
    scope_model: Au3ScopeModel,
    existence: Au3ExistenceModel,
) -> dict[str, frozenset[str] | None]:
    """
    The may-write summary of every script function: its own global writes plus those of every
    script function it reaches, transitively, merged by worklist fixpoint. `None` is the summary
    of a function that may write any global.
    """
    scanned = {
        name: _function_scan(function, scope_model, existence)
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
        self._literals: dict[Expression, Au3Value | None] = {}
        self._reads: list[_Lineage] = []
        self._snapshot_state: _State | None = None
        self._snapshot_version = 0
        self._snapshot: dict[str, Au3Value] = {}

    def _proven(self, expression: Expression | None, state: _State) -> Au3Value | None:
        """
        The value the constant evaluator proves for *expression* over the state the walk has
        reached, within the payload bound. One memo of literal attempts serves the whole walk:
        the tree stands still while the walk reads it.
        """
        return constant_value(
            expression,
            Policy(
                self.functions,
                lookup=state.lookup,
                limit=_MAX_PROPAGATED_PAYLOAD,
                literals=self._literals,
            ),
        )

    def _unproven(self, expression: Expression | None, state: _State) -> Au3Value | None:
        """
        The value the constant evaluator proves for *expression* over the same state with the
        payload bound lifted — the second question an overflow decision asks, whose answer never
        enters the state.
        """
        return constant_value(
            expression,
            Policy(
                self.functions,
                lookup=state.lookup,
                limit=None,
                literals=self._literals,
            ),
        )

    def _reads_of(
        self,
        scope: Au3FunctionDeclaration | None,
        expression: Expression | None,
        state: _State,
    ) -> _Lineage:
        """
        Visit *expression* and collect the reads a binding consumes: the lineage the binding
        retracts when the run behind it overflows. A nested assignment collects its own, so its
        reads belong to its binding alone.
        """
        self._reads.append(None)
        self.visit_expression(scope, expression, state)
        return self._reads.pop()

    def _bind_proven(
        self,
        expression: Expression | None,
        state: _State,
        lineage: _Lineage,
    ) -> Au3Value | None:
        """
        The value a binding takes from the bounded evaluator, with the overflow decision a
        lineage behind it needs. A proof that fails with no reads behind it is refused as
        before. One with reads asks the evaluator once more without the payload bound: an
        answer past it is an accumulator the walk cannot finish folding, so every read the run
        recorded is retracted and the run passes through as written; an answer within it binds.
        """
        value = self._proven(expression, state)
        if value is None and lineage is not None:
            value = self._unproven(expression, state)
            if value is not None and not within_limit(value, _MAX_PROPAGATED_PAYLOAD):
                self._retract(lineage)
                return None
        return value

    def _bind_combined(
        self,
        operator: str,
        current: Au3Value,
        operand: Au3Value,
        lineage: _Lineage,
    ) -> Au3Value | None:
        """
        The same decision for a compound assignment, whose bounded combination is refused where
        the accumulated result would leave the payload bound.
        """
        value = combine(operator, current, operand, _MAX_PROPAGATED_PAYLOAD)
        if value is None and lineage is not None:
            value = combine(operator, current, operand, None)
            if value is not None and not within_limit(value, _MAX_PROPAGATED_PAYLOAD):
                self._retract(lineage)
                return None
        return value

    def _retract(self, lineage: _Lineage) -> None:
        for node in _lineage_reads(lineage):
            self.values.pop(node, None)

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
            lineage = self._reads_of(scope, declarator.initializer, state)
            variable = declarator.variable
            if variable is None:
                continue
            if stmt.is_const:
                value = self._bind_proven(declarator.initializer, state, lineage)
                if value is None:
                    state.kill(variable.name)
                else:
                    state.bind_constant(variable.name, value, lineage)
                continue
            if stmt.is_static:
                state.kill(variable.name)
                continue
            state.bind(
                variable.name,
                self.scope_model.binding(scope, stmt, variable.name),
                self._bind_proven(declarator.initializer, state, lineage),
                lineage)

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
        counter_lineage: _Lineage = None
        step = of_int(stmt.step_value)
        for declarator in stmt.declarations:
            variable = declarator.variable
            if declarator.initializer is not None:
                lineage = self._reads_of(scope, declarator.initializer, state)
                value = self._bind_proven(declarator.initializer, state, lineage)
                if value is None or variable is None:
                    counter = None
                    counter_lineage = None
                    if variable is not None:
                        state.kill(variable.name)
                else:
                    state.bind_constant(variable.name, value, lineage)
                    counter = apply_binary(stmt.step_operator, value, step)
                    counter_lineage = lineage
                continue
            if variable is None:
                continue
            if counter is None:
                state.kill(variable.name)
                continue
            state.bind_constant(variable.name, counter, counter_lineage)
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
        lineage = self._reads_of(scope, assignment.value, state)
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
            state.bind(
                variable.name,
                binding,
                self._bind_proven(assignment.value, state, lineage),
                lineage)
            return
        current = state.lookup(variable.name)
        operand = self._proven(assignment.value, state)
        if operand is None and lineage is not None:
            operand = self._unproven(assignment.value, state)
        combined = (state.lineage.get(variable.name), lineage)
        if current is None or operand is None:
            state.bind(variable.name, binding, None, None)
            return
        operator = assignment.operator.rstrip('=')
        state.bind(
            variable.name,
            binding,
            self._bind_combined(operator, current, operand, combined),
            combined)

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
            if value is not None and within_limit(value, _MAX_PROPAGATED_PAYLOAD):
                self.values[node] = value
                if self._reads:
                    self._reads[-1] = ((node, state.lineage.get(node.name)), self._reads[-1])
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
        position: the call runs what the variable names, not what it holds. A call with no
        declared function behind it — `Call`, a registration builtin, or a name neither the
        script nor the builtin table knows — carries the same risk for every bare-variable
        argument, since the unseen callee may bind any of them by reference; `_call_kills`'s
        `byref` is exactly that set. An argument of a call to a bounded builtin is still
        recorded and replaced: `call_is_bounded` is the fact that rules the reference out.
        """
        kills, byref = _call_kills(call, self.scope_model, self.summaries)
        if not isinstance(ast.unwrap_parens(call.callee), Au3Variable):
            self.visit_expression(scope, call.callee, state)
        callee = ast.direct_callee(call)
        function = self.scope_model.functions.get(callee.name) if callee is not None else None
        for index, argument in enumerate(call.arguments):
            node = ast.unwrap_parens(argument)
            if isinstance(node, Au3Variable):
                if function is not None:
                    if index < len(function.params) and function.params[index].by_ref:
                        continue
                elif node.name in byref:
                    continue
            self.visit_expression(scope, argument, state)
        if (
            scope is None
            and function is not None
            and callee is not None
            and self.summaries.get(callee.name) == frozenset()
        ):
            self.entries[call] = self._entry_snapshot(state)
        for name in byref:
            state.kill(name)
        if kills is None:
            state.kill_all()
        else:
            for name in kills:
                state.kill(name)

    def _entry_snapshot(self, state: _State) -> dict[str, Au3Value]:
        """
        The globals the walk proves where a call stands, built once per state the calls share:
        a state's version rises only where its content changes, so calls no change separates
        hold one snapshot in common and a tree of many calls over many constants costs one copy
        rather than one per call.
        """
        if self._snapshot_state is not state or self._snapshot_version != state.version:
            self._snapshot = {
                **state.constants,
                **{name: entry[1] for name, entry in state.variables.items()},
            }
            self._snapshot_state = state
            self._snapshot_version = state.version
        return self._snapshot

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


def build_propagation_model(
    root: Au3Script,
    scope_model: Au3ScopeModel,
    existence: Au3ExistenceModel,
) -> Au3PropagationModel:
    """
    Walk every scope of *root* — the script body and every function body — and record the value
    at each variable read the walk reaches, along with the may-write summaries the calls rest on,
    over the global-existence answer of *existence*.
    """
    summaries = _build_summaries(scope_model, existence)
    walker = _Walker(scope_model, summaries)
    for scope, body in ast.scope_bodies(root):
        walker.walk_scope(scope, body)
    return Au3PropagationModel(walker.values, summaries, walker.entries)
