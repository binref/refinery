"""
One script function of an AutoIt3 tree, run over the value domain. The Phase 3 transform calls
it on a call whose every argument is a literal, and replaces the call with the spelled result —
which is what resolves a script-defined decoder function, the shape the obfuscator hides its
payload behind.

The interpreter owns no semantics of its own: the operators and coercions are
`refinery.lib.scripts.au3.analysis.values`, the builtins its table, the functions the scope
model, and the expression evaluation is the constant evaluator
`refinery.lib.scripts.au3.analysis.constants`, asked with a frame-backed lookup and a call hook
that reaches the script functions the interpreter runs. What it owns is the run: the storage
rules a function body follows (a read finds the local first and a global second, and a write
stores a local of the run — the storage AutoIt writes wherever the gate below lets a function
run), the control flow, and the budget that keeps a runaway loop from running forever. Every
refusal and every budget overrun answers `None` from `call` — the call site stands unchanged. A
loop or case signal that reaches a function boundary is one of those refusals: no construct
consumed it, which is a shape AutoIt refuses to load.

The gate is the may-write summary: only a function whose summary is the empty set runs, because
only then does nothing it reaches change a global, and only then do the values the walk proved
at the call site hold for the whole run. The globals the run may read are exactly what
`Au3PropagationModel.entry_globals` hands over.

`probe` is the second entry point, and it replaces nothing: it runs one function body over an
empty world to learn a value — the payload of an `Execute`, the name a computed `Call` spells —
so it needs no summary and no entry globals. Its soundness is the one frame it runs: a read of
a name the run never wrote refuses, and a read after a write sees the value the run itself
stored either way, whatever storage an implicit write targets in the script. A nested call
into a script function refuses there — a callee's implicit write lands in the callee's frame
under the probe but in a global in the script, so the caller's later read of that name diverges.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.builtins import evaluate_builtin
from refinery.lib.scripts.au3.analysis.constants import Policy, constant_value, within_limit
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel
from refinery.lib.scripts.au3.analysis.values import (
    Au3Value,
    Kind,
    apply_binary,
    compare,
    literal_value,
    of_array,
    of_int,
    of_number,
    of_string,
    to_number,
    truthy,
)
from refinery.lib.scripts.au3.model import (
    Au3ArrayAccess,
    Au3ArrayLiteral,
    Au3Assignment,
    Au3CaseRange,
    Au3ContinueCaseStatement,
    Au3ContinueLoopStatement,
    Au3DoUntilStatement,
    Au3EnumDeclaration,
    Au3ErrorNode,
    Au3ExitLoopStatement,
    Au3ExitStatement,
    Au3ForInStatement,
    Au3ForStatement,
    Au3FunctionDeclaration,
    Au3IfStatement,
    Au3ReDimStatement,
    Au3ReturnStatement,
    Au3ScopeKind,
    Au3SelectStatement,
    Au3SwitchCase,
    Au3SwitchStatement,
    Au3Variable,
    Au3VariableDeclaration,
    Au3VariableDeclarator,
    Au3WhileStatement,
    Au3WithStatement,
    Expression,
)

_MAX_INTERPRETER_ITERATIONS = 100_000
_MAX_INTERPRETER_PAYLOAD_LEN = 1_000_000
_MAX_INTERPRETER_ARRAY_LEN = 1_000_000
_MAX_INTERPRETER_DEPTH = 64


def _nested_array(value: Au3Value) -> bool:
    """
    Whether *value* is an array holding an array — the one array shape the run refuses wherever
    it reaches one: an argument, a ternary branch, or a result the evaluator's literal path
    hands in, exactly as the array literal the run builds itself is refused.
    """
    return (
        value.kind is Kind.ARRAY
        and any(
            element.kind is Kind.ARRAY
            for element in cast(tuple[Au3Value, ...], value.payload)
        )
    )


class _Refusal(Exception):
    """
    The one way out of a run the interpreter cannot finish: an unpinned semantics, a shape the
    domain does not model, or a budget overrun.
    """


class _Return(Exception):
    def __init__(self, value: Au3Value):
        self.value = value


class _ExitLoop(Exception):
    def __init__(self, level: int):
        self.level = level


class _ContinueLoop(Exception):
    def __init__(self, level: int):
        self.level = level


class _ContinueCase(Exception):
    pass


@dataclass
class _Array:
    """
    One array a run holds mutable, converted to the domain's value — a fresh copy — wherever a
    read, an argument, or a result carries it out.
    """
    elements: list[Au3Value]


@dataclass
class _Budget:
    """
    What one top-level call may spend: loop iterations and calls together, and recursion depth.
    """
    steps: int = 0
    depth: int = 0

    def spend(self) -> None:
        self.steps += 1
        if self.steps > _MAX_INTERPRETER_ITERATIONS:
            raise _Refusal


class _Frame:
    """
    The storage one running function sees: its locals and the globals the call site proved, and
    the evaluation policy over them, its hooks bound to this frame alone. A write to a name the
    run never declared declares it — the local AutoIt itself creates — and a read of a name no
    storage holds refuses.
    """

    def __init__(
        self,
        globals: Mapping[str, Au3Value],
        budget: _Budget,
        probing: bool = False,
    ):
        self.globals = globals
        self.budget = budget
        self.probing = probing
        self.locals: dict[str, Au3Value | _Array] = {}
        self.policy: Policy = Policy(frozenset())

    def read(self, name: str) -> Au3Value:
        local = self.locals.get(name)
        if local is not None:
            if isinstance(local, Au3Value):
                return local
            return of_array(tuple(local.elements))
        value = self.globals.get(name)
        if value is None:
            raise _Refusal
        return value

    def write(self, name: str, value: Au3Value) -> None:
        self.locals[name] = _stored(value)

    def array(self, name: str) -> _Array:
        local = self.locals.get(name)
        if not isinstance(local, _Array):
            raise _Refusal
        return local


def _stored(value: Au3Value) -> Au3Value | _Array:
    if value.kind is Kind.ARRAY:
        return _Array(list(cast(tuple[Au3Value, ...], value.payload)))
    return value


@dataclass(frozen=True)
class Au3Probe:
    """
    What one probe learned: the value its run answered — `None` where the run refused — and the
    steps the run spent, which a caller that owns many probes bounds in total.
    """
    value: Au3Value | None
    steps: int


class Au3Interpreter:
    """
    Runs one script function of a tree over the value domain. Constructed once per tree version
    from the scope model and the may-write summaries the propagation walk built.
    """

    def __init__(
        self,
        scope_model: Au3ScopeModel,
        summaries: Mapping[str, frozenset[str] | None],
    ):
        self.functions = scope_model.functions
        self.function_names = scope_model.function_names
        self.summaries = summaries

    def call(
        self,
        function: Au3FunctionDeclaration,
        arguments: Sequence[Au3Value],
        globals: Mapping[str, Au3Value],
    ) -> Au3Value | None:
        try:
            return self._call(function, list(arguments), globals, _Budget())
        except _Refusal:
            return None

    def probe(
        self,
        function: Au3FunctionDeclaration,
        arguments: Sequence[Au3Value],
    ) -> Au3Probe:
        """
        One ungated run of *function*'s body over an empty world: no summary gate, no globals,
        and a nested script-function call refusing. The run computes a value — it replaces
        nothing — so it needs no effect soundness: a read of a name the run never wrote refuses,
        and a read after a write sees the value the run itself stored, whatever storage an
        implicit write targets in the script.
        """
        budget = _Budget()
        try:
            value = self._call(function, list(arguments), {}, budget, probing=True)
        except _Refusal:
            value = None
        return Au3Probe(value, budget.steps)

    def _call(
        self,
        function: Au3FunctionDeclaration,
        arguments: list[Au3Value],
        globals: Mapping[str, Au3Value],
        budget: _Budget,
        probing: bool = False,
    ) -> Au3Value:
        name = function.name.name if function.name is not None else None
        if name is None or (
            not probing
            and self.summaries.get(name) != frozenset()
        ):
            raise _Refusal
        if len(arguments) > len(function.params):
            raise _Refusal
        budget.spend()
        budget.depth += 1
        frame = _Frame(globals, budget, probing)
        frame.policy = self._policy(frame)
        try:
            if budget.depth > _MAX_INTERPRETER_DEPTH:
                raise _Refusal
            for index, parameter in enumerate(function.params):
                variable = parameter.variable
                if variable is None or parameter.by_ref:
                    raise _Refusal
                if index < len(arguments):
                    value = arguments[index]
                else:
                    if parameter.default is None:
                        raise _Refusal
                    value = literal_value(parameter.default, self.function_names)
                    if value is None:
                        raise _Refusal
                frame.write(variable.name, value)
            self._run_body(function.body, frame)
            return of_int(0)
        except _Return as returned:
            return returned.value
        except (_ExitLoop, _ContinueLoop, _ContinueCase):
            raise _Refusal
        finally:
            budget.depth -= 1

    def _run_body(self, body: Sequence[Statement], frame: _Frame) -> None:
        for statement in body:
            self._run_statement(statement, frame)

    def _run_statement(self, statement: Statement, frame: _Frame) -> None:
        if isinstance(statement, Au3VariableDeclaration):
            self._run_declaration(statement, frame)
            return
        if isinstance(statement, Au3EnumDeclaration):
            self._run_enum(statement, frame)
            return
        if isinstance(statement, Au3ReDimStatement):
            self._run_redim(statement, frame)
            return
        if isinstance(statement, Au3IfStatement):
            self._run_if(statement, frame)
            return
        if isinstance(statement, Au3WhileStatement):
            self._run_while(statement, frame)
            return
        if isinstance(statement, Au3DoUntilStatement):
            self._run_do_until(statement, frame)
            return
        if isinstance(statement, Au3ForStatement):
            self._run_for(statement, frame)
            return
        if isinstance(statement, Au3ForInStatement):
            self._run_for_in(statement, frame)
            return
        if isinstance(statement, Au3SwitchStatement):
            self._run_switch(statement, frame)
            return
        if isinstance(statement, Au3SelectStatement):
            self._run_select(statement, frame)
            return
        if isinstance(statement, Au3ReturnStatement):
            raise _Return(
                of_int(0) if statement.value is None else self._eval(statement.value, frame))
        if isinstance(statement, Au3ExitLoopStatement):
            raise _ExitLoop(self._loop_level(statement.level, frame))
        if isinstance(statement, Au3ContinueLoopStatement):
            raise _ContinueLoop(self._loop_level(statement.level, frame))
        if isinstance(statement, Au3ContinueCaseStatement):
            raise _ContinueCase
        if isinstance(
            statement,
            (
                Au3ExitStatement,
                Au3WithStatement,
                Au3ErrorNode,
            ),
        ):
            raise _Refusal
        for child in statement.children():
            if isinstance(child, Expression):
                self._eval(child, frame)

    def _run_declaration(self, statement: Au3VariableDeclaration, frame: _Frame) -> None:
        if not _declares_into_local(statement.is_static, statement.scope, statement.is_const):
            raise _Refusal
        for declarator in statement.declarations:
            self._run_declarator(declarator, frame)

    def _run_declarator(self, declarator: Au3VariableDeclarator, frame: _Frame) -> None:
        variable = declarator.variable
        if variable is None:
            raise _Refusal
        if not declarator.dimensions:
            value = of_string('')
            if declarator.initializer is not None:
                value = self._eval(declarator.initializer, frame)
            frame.write(variable.name, value)
            return
        if len(declarator.dimensions) != 1:
            raise _Refusal
        dimension = declarator.dimensions[0]
        if dimension is None:
            initializer = self._eval(declarator.initializer, frame)
            if initializer.kind is not Kind.ARRAY:
                raise _Refusal
            frame.write(variable.name, initializer)
            return
        size = self._subscript(self._eval(dimension, frame))
        if not 1 <= size <= _MAX_INTERPRETER_ARRAY_LEN:
            raise _Refusal
        elements = [of_string('') for _ in range(size)]
        if declarator.initializer is not None:
            initializer = self._eval(declarator.initializer, frame)
            if initializer.kind is not Kind.ARRAY:
                raise _Refusal
            for index, element in enumerate(cast(tuple[Au3Value, ...], initializer.payload)):
                if index >= size:
                    break
                elements[index] = element
        frame.write(variable.name, of_array(tuple(elements)))

    def _run_enum(self, statement: Au3EnumDeclaration, frame: _Frame) -> None:
        if statement.scope is Au3ScopeKind.GLOBAL:
            raise _Refusal
        counter: Au3Value | None = of_int(0)
        step = of_int(statement.step_value)
        for declarator in statement.declarations:
            variable = declarator.variable
            if variable is None:
                raise _Refusal
            if declarator.initializer is not None:
                value = self._eval(declarator.initializer, frame)
                frame.write(variable.name, value)
                counter = apply_binary(statement.step_operator, value, step)
                continue
            if counter is None:
                raise _Refusal
            frame.write(variable.name, counter)
            counter = apply_binary(statement.step_operator, counter, step)

    def _run_redim(self, statement: Au3ReDimStatement, frame: _Frame) -> None:
        for target in statement.targets:
            variable = target.variable
            if variable is None or len(target.dimensions) != 1:
                raise _Refusal
            array = frame.array(variable.name)
            size = self._subscript(self._eval(target.dimensions[0], frame))
            if not 1 <= size <= _MAX_INTERPRETER_ARRAY_LEN:
                raise _Refusal
            while len(array.elements) < size:
                array.elements.append(of_string(''))
            del array.elements[size:]

    def _run_if(self, statement: Au3IfStatement, frame: _Frame) -> None:
        if self._decides(statement.test, frame):
            self._run_body(statement.body, frame)
            return
        for elseif in statement.elseifs:
            if self._decides(elseif.test, frame):
                self._run_body(elseif.body, frame)
                return
        if statement.else_body is not None:
            self._run_body(statement.else_body, frame)

    def _run_while(self, statement: Au3WhileStatement, frame: _Frame) -> None:
        while self._decides(statement.test, frame):
            frame.budget.spend()
            if not self._run_loop_body(statement.body, frame):
                return

    def _run_do_until(self, statement: Au3DoUntilStatement, frame: _Frame) -> None:
        while True:
            frame.budget.spend()
            if not self._run_loop_body(statement.body, frame):
                return
            if self._decides(statement.test, frame):
                return

    def _run_for(self, statement: Au3ForStatement, frame: _Frame) -> None:
        variable = statement.variable
        if variable is None:
            raise _Refusal
        start = self._number(statement.start, frame)
        limit = self._number(statement.limit, frame)
        step = (
            of_int(1)
            if statement.step is None
            else of_number(self._number(statement.step, frame))
        )
        number = to_number(step)
        if number is None or number == 0:
            raise _Refusal
        frame.write(variable.name, of_number(start))
        while True:
            relation = '<=' if number > 0 else '>='
            within = compare(relation, frame.read(variable.name), of_number(limit))
            if within is None or not truthy(within):
                return
            frame.budget.spend()
            if not self._run_loop_body(statement.body, frame):
                return
            advanced = apply_binary('+', frame.read(variable.name), step)
            if advanced is None:
                raise _Refusal
            frame.write(variable.name, advanced)

    def _run_for_in(self, statement: Au3ForInStatement, frame: _Frame) -> None:
        variable = statement.variable
        if variable is None:
            raise _Refusal
        iterable = self._eval(statement.iterable, frame)
        if iterable.kind is not Kind.ARRAY:
            raise _Refusal
        for element in cast(tuple[Au3Value, ...], iterable.payload):
            frame.budget.spend()
            frame.write(variable.name, element)
            if not self._run_loop_body(statement.body, frame):
                return

    def _run_switch(self, statement: Au3SwitchStatement, frame: _Frame) -> None:
        discriminant = self._eval(statement.discriminant, frame)
        index = self._matching_case(statement.cases, discriminant, frame)
        if index is None:
            return
        while index < len(statement.cases):
            try:
                self._run_body(statement.cases[index].body, frame)
                return
            except _ContinueCase:
                index += 1
                if index >= len(statement.cases):
                    raise _Refusal

    def _run_select(self, statement: Au3SelectStatement, frame: _Frame) -> None:
        for case in statement.cases:
            if case.test is None or self._decides(case.test, frame):
                self._run_body(case.body, frame)
                return

    def _matching_case(
        self,
        cases: Sequence[Au3SwitchCase],
        discriminant: Au3Value,
        frame: _Frame,
    ) -> int | None:
        for index, case in enumerate(cases):
            if case.values is None:
                return index
            for value in case.values:
                if self._matches(discriminant, value, frame):
                    return index
        return None

    def _matches(self, discriminant: Au3Value, value: Node, frame: _Frame) -> bool:
        if isinstance(value, Au3CaseRange):
            low = self._eval(value.start, frame)
            high = self._eval(value.end, frame)
            within = compare('<=', low, discriminant)
            ending = compare('<=', discriminant, high)
            if within is None or ending is None:
                raise _Refusal
            return truthy(within) is True and truthy(ending) is True
        equal = compare('=', discriminant, self._eval(cast(Expression, value), frame))
        if equal is None:
            raise _Refusal
        return truthy(equal) is True

    def _run_loop_body(self, body: Sequence[Statement], frame: _Frame) -> bool:
        """
        One iteration of a loop body: `False` when an `ExitLoop` ended the loop, `True` when the
        loop continues — a `ContinueLoop` of this level among them. A signal of a deeper level
        travels on, one level cheaper.
        """
        try:
            self._run_body(body, frame)
        except _ExitLoop as signal:
            if signal.level > 1:
                raise _ExitLoop(signal.level - 1)
            return False
        except _ContinueLoop as signal:
            if signal.level > 1:
                raise _ContinueLoop(signal.level - 1)
        return True

    def _policy(self, frame: _Frame) -> Policy:
        """
        The evaluation over one frame: its lookup reads the frame, its call hook runs the script
        functions the callee names, and its fallback answers the shapes only the run holds.
        """
        return Policy(
            self.function_names,
            lookup=lambda name: self._frame_value(name, frame),
            limit=_MAX_INTERPRETER_PAYLOAD_LEN,
            call=lambda name, arguments: self._run_call(name, arguments, frame),
            fallback=lambda expression: self._eval_special(expression, frame),
        )

    def _eval(self, node: Expression | None, frame: _Frame) -> Au3Value:
        value = self._eval_expression(node, frame)
        if not within_limit(value, _MAX_INTERPRETER_PAYLOAD_LEN) or _nested_array(value):
            raise _Refusal
        return value

    def _eval_expression(self, node: Expression | None, frame: _Frame) -> Au3Value:
        if node is None:
            raise _Refusal
        if isinstance(node, (Au3Assignment, Au3ArrayAccess, Au3ArrayLiteral)):
            special = self._eval_special(node, frame)
            if special is None:
                raise _Refusal
            return special
        value = constant_value(node, frame.policy)
        if value is None:
            raise _Refusal
        return value

    def _eval_special(self, node: Expression, frame: _Frame) -> Au3Value | None:
        """
        The value of an expression only the run can hold — an assignment, an array access, an
        array literal — asked where it stands inside an expression the constant evaluator walks,
        or `None` where the run refuses it.
        """
        try:
            if isinstance(node, Au3Assignment):
                return self._eval_assignment(node, frame)
            if isinstance(node, Au3ArrayAccess):
                return self._element(self._eval(node.array, frame), self._eval(node.index, frame))
            if isinstance(node, Au3ArrayLiteral):
                elements = [self._eval(element, frame) for element in node.elements]
                if any(element.kind is Kind.ARRAY for element in elements):
                    return None
                return of_array(tuple(elements))
        except _Refusal:
            return None
        return None

    def _frame_value(self, name: str, frame: _Frame) -> Au3Value | None:
        """
        The value a variable read holds in *frame*, or `None` where the run stored none.
        """
        try:
            return frame.read(name)
        except _Refusal:
            return None

    def _run_call(
        self,
        name: str,
        arguments: tuple[Au3Value, ...],
        frame: _Frame,
    ) -> Au3Value | None:
        """
        The value of one call inside a run: a script function the interpreter runs — the
        precedence a call site has over the builtin of the same name — then the builtin table.
        Every argument answers the bounds first: the payload bound the run holds over every
        value it evaluates, and the refusal of an array holding an array.
        """
        if any(
            not within_limit(argument, _MAX_INTERPRETER_PAYLOAD_LEN)
            or _nested_array(argument)
            for argument in arguments
        ):
            return None
        function = self.functions.get(name)
        if function is not None:
            if frame.probing:
                return None
            try:
                return self._call(function, list(arguments), frame.globals, frame.budget)
            except _Refusal:
                return None
        return evaluate_builtin(name, tuple(arguments))

    def _eval_assignment(self, node: Au3Assignment, frame: _Frame) -> Au3Value:
        variable = ast.store_target_variable(node.target)
        if variable is None:
            raise _Refusal
        target = ast.unwrap_parens(node.target)
        if isinstance(target, Au3ArrayAccess):
            return self._eval_element_assignment(node, target, variable, frame)
        if not isinstance(target, Au3Variable):
            raise _Refusal
        if node.operator == '=':
            value = self._eval(node.value, frame)
        else:
            current = frame.read(variable.name)
            operand = self._eval(node.value, frame)
            value = apply_binary(node.operator.rstrip('='), current, operand)
            if value is None:
                raise _Refusal
        frame.write(variable.name, value)
        return value

    def _eval_element_assignment(
        self,
        node: Au3Assignment,
        target: Au3ArrayAccess,
        variable: Au3Variable,
        frame: _Frame,
    ) -> Au3Value:
        if not isinstance(ast.unwrap_parens(target.array), Au3Variable):
            raise _Refusal
        array = frame.array(variable.name)
        subscript = self._subscript(self._eval(target.index, frame))
        if not 0 <= subscript < len(array.elements):
            raise _Refusal
        if node.operator == '=':
            value = self._eval(node.value, frame)
        else:
            operand = self._eval(node.value, frame)
            value = apply_binary(
                node.operator.rstrip('='), array.elements[subscript], operand)
            if value is None:
                raise _Refusal
        if value.kind is Kind.ARRAY:
            raise _Refusal
        array.elements[subscript] = value
        return value

    def _element(self, array: Au3Value, index: Au3Value) -> Au3Value:
        if array.kind is not Kind.ARRAY:
            raise _Refusal
        elements = cast(tuple[Au3Value, ...], array.payload)
        subscript = self._subscript(index)
        if not 0 <= subscript < len(elements):
            raise _Refusal
        return elements[subscript]

    def _subscript(self, index: Au3Value) -> int:
        number = to_number(index)
        if number is None:
            raise _Refusal
        return int(number)

    def _number(self, node: Expression | None, frame: _Frame) -> int | float:
        number = to_number(self._eval(node, frame))
        if number is None:
            raise _Refusal
        return number

    def _decides(self, node: Expression | None, frame: _Frame) -> bool:
        verdict = truthy(self._eval(node, frame))
        if verdict is None:
            raise _Refusal
        return verdict

    def _loop_level(self, node: Expression | None, frame: _Frame) -> int:
        if node is None:
            return 1
        number = to_number(self._eval(node, frame))
        if number is None or not isinstance(number, int):
            raise _Refusal
        return max(1, number)


def _declares_into_local(is_static: bool, scope: Au3ScopeKind | None, is_const: bool) -> bool:
    """
    Whether a variable declaration of this shape creates a local of the running function:
    `Local`, and a `Const` of function scope. `Static` keeps its value across calls, `Global`
    writes the whole script, and a `Dim` forces nothing, so each refuses.
    """
    if is_static or scope is Au3ScopeKind.GLOBAL:
        return False
    return scope is Au3ScopeKind.LOCAL or is_const
