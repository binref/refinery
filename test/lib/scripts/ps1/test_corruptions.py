from __future__ import annotations

import inspect

from typing import NamedTuple

from test import backlog, opportunity, todo, wontfix
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts import Expression, Node
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ErrorNode,
    Ps1Exit,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1FileRedirection,
    Ps1ForEachLoop,
    Ps1HashLiteral,
    Ps1IndexExpression,
    Ps1InputRedirection,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1Jump,
    Ps1MemberAccess,
    Ps1MergingRedirection,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1RealLiteral,
    Ps1RedirectionStream,
    Ps1Script,
    Ps1ScopeModifier,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1SwitchStatement,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser

_WRITE_HOST = frozenset({'write-host'})
_WRITE_OUTPUT = frozenset({'write-output', 'echo', 'write'})
_REMOVE_VARIABLE = frozenset({'remove-variable', 'rv'})
_NEW_VARIABLE = frozenset({'new-variable', 'nv'})
_SET_VARIABLE = frozenset({'set-variable', 'sv', 'set'})
_GET_VARIABLE = frozenset({'get-variable', 'gv'})
_GET_PROCESS = frozenset({'get-process', 'gps', 'ps'})
_INVOKE_COMMAND = frozenset({'invoke-command', 'icm'})
_FOREACH_OBJECT = frozenset({'foreach-object', '%'})
_SHORT_CIRCUIT = frozenset({'-and', '-or'})
_REFERENCE_TYPES = frozenset({'ref', 'psreference'})


def _unwrap(node: Node | None) -> Node | None:
    while True:
        if isinstance(node, Ps1ParenExpression):
            node = node.expression
            continue
        if isinstance(node, Ps1SubExpression) and len(node.body) == 1:
            statement = node.body[0]
            if isinstance(statement, Ps1ExpressionStatement):
                node = statement.expression
                continue
        if isinstance(node, Ps1Pipeline) and len(node.elements) == 1:
            node = node.elements[0].expression
            continue
        return node


def _literal_value(node: Node | None):
    node = _unwrap(node)
    if isinstance(node, (Ps1StringLiteral, Ps1IntegerLiteral, Ps1RealLiteral)):
        return node.value
    if isinstance(node, Ps1ExpandableString):
        parts = []
        for part in node.parts:
            if not isinstance(part, Ps1StringLiteral):
                return None
            parts.append(part.value)
        return ''.join(parts)
    return None


def _binding_key(variable: Ps1Variable) -> str:
    if variable.scope is Ps1ScopeModifier.ENV:
        return F'env:{variable.name.lower()}'
    return variable.name.lower()


def _target_variables(target: Node | None) -> list[Ps1Variable]:
    while isinstance(target, (Ps1ParenExpression, Ps1CastExpression)):
        target = target.expression if isinstance(target, Ps1ParenExpression) else target.operand
    if isinstance(target, Ps1Variable):
        return [target]
    if isinstance(target, Ps1ArrayLiteral):
        return [inner for element in target.elements for inner in _target_variables(element)]
    return []


def _reads_variable(node: Node | None, key: str) -> bool:
    node = _unwrap(node)
    if isinstance(node, Ps1IndexExpression):
        return _reads_variable(node.object, key)
    return isinstance(node, Ps1Variable) and _binding_key(node) == key


def _emitted_constants(node: Node | None) -> list | None:
    node = _unwrap(node)
    if isinstance(node, Ps1ArrayLiteral):
        emitted: list = []
        for element in node.elements:
            values = _emitted_constants(element)
            if values is None:
                return None
            emitted.extend(values)
        return emitted
    if isinstance(node, Ps1Variable):
        return [None] if _binding_key(node) == 'null' else None
    value = _literal_value(node)
    return None if value is None else [value]


def _stores(root: Node, key: str) -> list[Ps1AssignmentExpression]:
    return [
        node for node in root.walk()
        if isinstance(node, Ps1AssignmentExpression)
        and any(_binding_key(target) == key for target in _target_variables(node.target))
    ]


def _value_handed_to(store: Ps1AssignmentExpression, key: str) -> Node | None:
    slots = _unwrap(store.target)
    if not isinstance(slots, Ps1ArrayLiteral):
        return store.value
    values = _unwrap(store.value)
    if not isinstance(values, Ps1ArrayLiteral):
        return None
    last = len(slots.elements) - 1
    for index, slot in enumerate(slots.elements):
        if not isinstance(slot, Ps1Variable) or _binding_key(slot) != key:
            continue
        if index < last or len(values.elements) == len(slots.elements):
            return values.elements[index] if index < len(values.elements) else None
    return None


def _stores_value(root: Node, key: str, value) -> bool:
    return any(_literal_value(store.value) == value for store in _stores(root, key))


def _element_stores(root: Node, key: str) -> list[Ps1AssignmentExpression]:
    return [
        node for node in root.walk()
        if isinstance(node, Ps1AssignmentExpression)
        and isinstance(target := _unwrap(node.target), Ps1IndexExpression)
        and _reads_variable(target.object, key)
    ]


def _fetches_from(node: Node | None, key: str) -> bool:
    node = _unwrap(node)
    if isinstance(node, (Ps1IndexExpression, Ps1MemberAccess)):
        return _fetches_from(node.object, key)
    return isinstance(node, Ps1Variable) and _binding_key(node) == key


def _container_stores(root: Node, key: str) -> list[Ps1AssignmentExpression]:
    return [
        node for node in root.walk()
        if isinstance(node, Ps1AssignmentExpression)
        and not isinstance(_unwrap(node.target), Ps1Variable)
        and _fetches_from(node.target, key)
    ]


def _hash_values(node: Node | None) -> list[Node]:
    node = _unwrap(node)
    if not isinstance(node, Ps1HashLiteral):
        return []
    return [value for _, value in node.pairs]


def _occurrences(root: Node, key: str) -> list[Ps1Variable]:
    return [
        node for node in root.walk()
        if isinstance(node, Ps1Variable) and _binding_key(node) == key
    ]


def _occurrences_ahead_of_the_read(root: Ps1Script, key: str) -> int:
    return sum(len(_occurrences(statement, key)) for statement in root.body[:-1])


def _dot_sourced_blocks(root: Node) -> list[Ps1ScriptBlock]:
    return [
        node.name for node in root.walk()
        if isinstance(node, Ps1CommandInvocation)
        and node.invocation_operator == '.'
        and isinstance(node.name, Ps1ScriptBlock)
    ]


def _constrained_stores(root: Node, key: str, type_name: str) -> list[Ps1AssignmentExpression]:
    return [
        store for store in _stores(root, key)
        if isinstance(target := _unwrap(store.target), Ps1CastExpression)
        and target.type_name.lower().rpartition('.')[2] == type_name
    ]


def _piped_into(
    root: Node,
    names: frozenset[str],
) -> list[tuple[Node | None, Ps1CommandInvocation]]:
    found: list[tuple[Node | None, Ps1CommandInvocation]] = []
    for node in root.walk():
        if not isinstance(node, Ps1Pipeline):
            continue
        for source, sink in zip(node.elements, node.elements[1:]):
            command = _unwrap(sink.expression)
            if (
                isinstance(command, Ps1CommandInvocation)
                and isinstance(command.name, Ps1StringLiteral)
                and command.name.value.lower() in names
            ):
                found.append((source.expression, command))
    return found


def _pipeline_pairs(
    root: Node,
    writing: frozenset[str],
    binding: frozenset[str],
) -> list[tuple[Ps1CommandInvocation, Ps1CommandInvocation]]:
    found: list[tuple[Ps1CommandInvocation, Ps1CommandInvocation]] = []
    for node in root.walk():
        if not isinstance(node, Ps1Pipeline):
            continue
        for source, sink in zip(node.elements, node.elements[1:]):
            writer = _unwrap(source.expression)
            binder = _unwrap(sink.expression)
            if (
                isinstance(writer, Ps1CommandInvocation)
                and isinstance(writer.name, Ps1StringLiteral)
                and writer.name.value.lower() in writing
                and isinstance(binder, Ps1CommandInvocation)
                and isinstance(binder.name, Ps1StringLiteral)
                and binder.name.value.lower() in binding
            ):
                found.append((writer, binder))
    return found


def _wraps_as_one_record(node: Node | None, key: str) -> bool:
    node = _unwrap(node)
    return (
        isinstance(node, Ps1ArrayLiteral)
        and len(node.elements) == 1
        and _reads_variable(node.elements[0], key)
    )


def _supplies_array(root: Node, node: Node | None, values: list) -> bool:
    if _emitted_constants(node) == values:
        return True
    operand = _unwrap(node)
    if not isinstance(operand, Ps1Variable):
        return False
    return any(
        _emitted_constants(store.value) == values
        for store in _stores(root, _binding_key(operand))
    )


def _commands(root: Node) -> list[Ps1CommandInvocation]:
    return [node for node in root.walk_in_order() if isinstance(node, Ps1CommandInvocation)]


def _invocations(root: Node, names: frozenset[str]) -> list[Ps1CommandInvocation]:
    return [
        command for command in _commands(root)
        if isinstance(command.name, Ps1StringLiteral)
        and command.name.value.lower() in names
    ]


def _catch_clause_counts(root: Node) -> list[int]:
    return [
        len(node.catch_clauses) for node in root.walk()
        if isinstance(node, Ps1TryCatchFinally)
    ]


def _static_calls(root: Node, type_name: str, member: str) -> list[Ps1InvokeMember]:
    return [
        node for node in root.walk()
        if isinstance(node, Ps1InvokeMember)
        and node.access is Ps1AccessKind.STATIC
        and isinstance(node.object, Ps1TypeExpression)
        and node.object.name.lower().rpartition('.')[2] == type_name
        and isinstance(node.member, str)
        and node.member.lower() == member
    ]


def _mutates_through_argument(root: Node, type_name: str, member: str, key: str) -> bool:
    return any(
        _reads_variable(argument, key)
        for call in _static_calls(root, type_name, member)
        for argument in call.arguments
    )


def _instance_calls(root: Node, member: str) -> list[Ps1InvokeMember]:
    return [
        node for node in root.walk()
        if isinstance(node, Ps1InvokeMember)
        and node.access is Ps1AccessKind.INSTANCE
        and isinstance(node.member, str)
        and node.member.lower() == member
    ]


class _Redirection(NamedTuple):
    operator: type
    streams: tuple[Ps1RedirectionStream, ...]
    append: bool
    file: object


def _redirections(root: Node) -> list[_Redirection]:
    found: list[_Redirection] = []
    for node in root.walk_in_order():
        if isinstance(node, Ps1FileRedirection):
            target = _literal_value(node.target)
            found.append(_Redirection(Ps1FileRedirection, (node.stream,), node.append, target))
        elif isinstance(node, Ps1MergingRedirection):
            streams = (node.from_stream, node.to_stream)
            found.append(_Redirection(Ps1MergingRedirection, streams, False, None))
        elif isinstance(node, Ps1InputRedirection):
            source = _literal_value(node.source)
            found.append(_Redirection(Ps1InputRedirection, (), False, source))
    return found


def _file_writes(root: Node) -> list[_Redirection]:
    return [entry for entry in _redirections(root) if entry.operator is Ps1FileRedirection]


def _argument_values(command: Ps1CommandInvocation) -> list[Node]:
    values: list[Node] = []
    for argument in command.arguments:
        if isinstance(argument, Ps1CommandArgument):
            if argument.value is not None:
                values.append(argument.value)
        elif isinstance(argument, Expression):
            values.append(argument)
    return values


def _positional_values(command: Ps1CommandInvocation) -> list[Node]:
    values: list[Node] = []
    for argument in command.arguments:
        if isinstance(argument, Ps1CommandArgument):
            if argument.kind is Ps1CommandArgumentKind.POSITIONAL and argument.value is not None:
                values.append(argument.value)
        elif isinstance(argument, Expression):
            values.append(argument)
    return values


def _switch_spellings(command: Ps1CommandInvocation) -> list[str]:
    return [
        argument.name for argument in command.arguments
        if isinstance(argument, Ps1CommandArgument) and argument.name
    ]


def _binds(command: Ps1CommandInvocation, parameter: str) -> bool:
    return any(
        parameter.startswith(written)
        for name in _switch_spellings(command)
        if (written := name.lstrip('-').lower())
    )


def _binds_the_name(command: Ps1CommandInvocation, name: str) -> bool:
    return name in [_literal_value(value) for value in _positional_values(command)]


def _passes_variable(root: Node, key: str) -> bool:
    for node in root.walk():
        if not isinstance(node, Ps1CommandInvocation):
            continue
        for value in _argument_values(node):
            operand = _unwrap(value)
            if isinstance(operand, Ps1Variable) and _binding_key(operand) == key:
                return True
    return False


def _inside_script_block(node: Node) -> bool:
    cursor = node.parent
    while cursor is not None:
        if isinstance(cursor, Ps1ScriptBlock):
            return True
        cursor = cursor.parent
    return False


def _printed_expressions(root: Node, nested: bool | None = None) -> list[Node | None]:
    found: list[Node | None] = []
    for command in _invocations(root, _WRITE_HOST):
        if nested is not None and _inside_script_block(command) is not nested:
            continue
        found.extend(_unwrap(value) for value in _argument_values(command))
    return found


def _printed_values(root: Node, nested: bool | None = None) -> set:
    return {
        value
        for expression in _printed_expressions(root, nested)
        if (value := _literal_value(expression)) is not None
    }


def _output_writes(root: Node) -> list[list | None]:
    writes: list[list | None] = []
    for command in _invocations(root, _WRITE_OUTPUT):
        emitted: list = []
        for value in _argument_values(command):
            values = _emitted_constants(value)
            if values is None:
                writes.append(None)
                break
            emitted.extend(values)
        else:
            writes.append(emitted)
    return writes


def _writes_true(root: Node) -> bool:
    commands = _invocations(root, _WRITE_OUTPUT)
    if len(commands) != 1:
        return False
    values = [_unwrap(value) for value in _argument_values(commands[0])]
    return (
        len(values) == 1
        and isinstance(values[0], Ps1Variable)
        and _binding_key(values[0]) == 'true'
    )


def _inside_short_circuit(node: Node) -> bool:
    cursor = node
    while cursor.parent is not None:
        parent = cursor.parent
        if (
            isinstance(parent, Ps1BinaryExpression)
            and parent.operator.lower() in _SHORT_CIRCUIT
            and parent.right is cursor
        ):
            return True
        cursor = parent
    return False


def _increments(root: Node, key: str) -> bool:
    for node in root.walk():
        if isinstance(node, Ps1CommandInvocation) and isinstance(node.name, Ps1StringLiteral):
            text = node.name.value
            if text.startswith('$') and text.endswith(('++', '--')):
                reread = Ps1Parser(text).parse()
                if any(
                    isinstance(inner, Ps1UnaryExpression)
                    and isinstance(operand := _unwrap(inner.operand), Ps1Variable)
                    and _binding_key(operand) == key
                    for inner in reread.walk()
                ):
                    return True
        if isinstance(node, Ps1UnaryExpression) and node.operator in ('++', '--'):
            operand = _unwrap(node.operand)
            if isinstance(operand, Ps1Variable) and _binding_key(operand) == key:
                return True
        if not isinstance(node, Ps1AssignmentExpression):
            continue
        if not any(_binding_key(target) == key for target in _target_variables(node.target)):
            continue
        if node.operator != '=':
            return True
        if node.value is not None and any(
            isinstance(inner, Ps1Variable) and _binding_key(inner) == key
            for inner in node.value.walk()
        ):
            return True
    return False


def _is_reference_to(node: Node | None, key: str) -> bool:
    if not isinstance(node, Ps1CastExpression):
        return False
    if node.type_name.lower().rpartition('.')[2] not in _REFERENCE_TYPES:
        return False
    operand = _unwrap(node.operand)
    return isinstance(operand, Ps1Variable) and _binding_key(operand) == key


class _Ps1Ledger(TestPs1):

    def _deobfuscated_tree(self, source: str) -> Ps1Script:
        return Ps1Parser(self._deobfuscate_iterative(source)).parse()

    def _assertPrints(self, tree: Ps1Script, key: str, printed: str, never: str) -> None:
        values = _printed_values(tree)
        self.assertNotIn(
            never, values, F'${key} was folded to {never!r}, which is not the value it holds')
        self.assertTrue(
            printed in values or _stores_value(tree, key, printed),
            F'nothing left in the output can give ${key} the value {printed!r}',
        )

    def _assertWrites(self, tree: Ps1Script, written: list, corrupt: list, mutated: bool) -> None:
        writes = _output_writes(tree)
        for position, (value, wrong, right) in enumerate(zip(writes, corrupt, written)):
            if wrong == right:
                continue
            self.assertNotEqual(
                value, wrong,
                F'output {position} writes {wrong}, which the script never writes there')
        self.assertTrue(
            writes == written or mutated,
            F'nothing left in the output can write {written}',
        )

    def _assertTheStoreReachesTheName(
        self, source: str, key: str, written: list, corrupt: list,
    ) -> None:
        tree = self._deobfuscated_tree(source)
        kept = _occurrences_ahead_of_the_read(tree, key) >= _occurrences_ahead_of_the_read(
            Ps1Parser(source).parse(), key)
        self._assertWrites(tree, written, corrupt, kept)

    def _assertTheIdentityIsKept(self, source: str, key: str) -> None:
        tree = self._deobfuscated_tree(source)
        self.assertTrue(
            _writes_true(tree)
            or len(_occurrences(tree, key)) >= len(_occurrences(Ps1Parser(source).parse(), key)),
            F'an occurrence of ${key} was replaced by a copy of the array it holds',
        )


class TestPs1Corruptions(_Ps1Ledger):

    def test_dot_sourced_remove_variable_unsets_the_callers_variable(self):
        tree = self._deobfuscated_tree("$x = 'a'; . { Remove-Variable x }; Write-Host $x")
        self.assertTrue(
            _invocations(tree, _REMOVE_VARIABLE),
            'the call that unsets the caller variable was dropped',
        )
        self.assertNotIn(
            'a', _printed_values(tree), 'the read was folded to the value the removal discarded')

    def test_dot_sourced_new_variable_replaces_the_callers_value(self):
        tree = self._deobfuscated_tree("$x = 'a'; . { New-Variable x 'b' -Force }; Write-Host $x")
        self.assertTrue(
            _invocations(tree, _NEW_VARIABLE) or 'b' in _printed_values(tree),
            'the call that redefines the caller variable was dropped and nothing prints its value',
        )
        self.assertNotIn(
            'a', _printed_values(tree), 'the read was folded to the value that was overwritten')

    def test_dot_sourced_out_variable_overwrites_the_callers_variable(self):
        tree = self._deobfuscated_tree("$x = 'a'; . { Get-Process -OutVariable x }; Write-Host $x")
        self.assertTrue(
            [call for call in _invocations(tree, _GET_PROCESS) if _binds(call, 'outvariable')],
            'the call whose -OutVariable writes the caller variable was dropped',
        )
        self.assertNotIn(
            'a', _printed_values(tree), 'the read was folded past a write it cannot see')

    @backlog
    def test_function_running_invoke_expression_may_write_the_callers_variable(self):
        tree = self._deobfuscated_tree("$x = 'a'; function f { iex $c }; f; Write-Host $x")
        self.assertTrue(
            _passes_variable(tree, 'c'), 'the call that may write any variable was dropped')
        self.assertNotIn(
            'a', _printed_values(tree), 'the read was folded across a call that may rewrite it')

    def test_computed_invoke_expression_name_may_write_the_callers_variable(self):
        tree = self._deobfuscated_tree("$x = 'a'; &('i' + 'ex') $c; Write-Host $x")
        self.assertTrue(
            _passes_variable(tree, 'c'), 'the call that may write any variable was dropped')
        self.assertNotIn(
            'a', _printed_values(tree), 'the read was folded across a call that may rewrite it')

    def test_set_variable_global_supplies_the_value_that_is_read_back(self):
        tree = self._deobfuscated_tree("Set-Variable global:y 'b'; Write-Host $global:y")
        self.assertTrue(
            _invocations(tree, _SET_VARIABLE) or 'b' in _printed_values(tree),
            'the store was deleted and nothing left in the output supplies the value it wrote',
        )

    def test_short_circuited_and_operand_never_stores(self):
        tree = self._deobfuscated_tree("$x = 'a'; $false -and ($x = 'b'); Write-Host $x")
        self._assertPrints(tree, 'x', 'a', 'b')
        for store in _stores(tree, 'x'):
            if _literal_value(store.value) == 'b':
                self.assertTrue(
                    _inside_short_circuit(store),
                    'the store from the unevaluated operand is now reached unconditionally',
                )

    def test_short_circuited_or_operand_never_stores(self):
        tree = self._deobfuscated_tree("$x = 'a'; $true -or ($x = 'b'); Write-Host $x")
        self._assertPrints(tree, 'x', 'a', 'b')
        for store in _stores(tree, 'x'):
            if _literal_value(store.value) == 'b':
                self.assertTrue(
                    _inside_short_circuit(store),
                    'the store from the unevaluated operand is now reached unconditionally',
                )

    def test_array_sort_sorts_the_variable_in_place(self):
        tree = self._deobfuscated_tree("$x = @('b', 'a'); [Array]::Sort($x); Write-Host $x[0]")
        sorts_the_variable = False
        for call in _static_calls(tree, 'array', 'sort'):
            for argument in call.arguments:
                operand = _unwrap(argument)
                if isinstance(operand, Ps1Variable) and _binding_key(operand) == 'x':
                    sorts_the_variable = True
        printed = _printed_values(tree)
        self.assertNotIn('b', printed, 'the read was folded to the order from before the sort')
        self.assertTrue(
            'a' in printed or sorts_the_variable,
            'the sort no longer reaches the array the read observes',
        )

    def test_trap_with_continue_resumes_after_the_throw(self):
        tree = self._deobfuscated_tree("trap { continue }; throw 'e'; Write-Host 'after'")
        self.assertTrue(
            [node for node in tree.walk() if isinstance(node, Ps1TrapStatement)]
            or not [node for node in tree.walk() if isinstance(node, Ps1ThrowStatement)],
            'the handler that makes execution resume was removed while the throw stayed',
        )
        self.assertIn(
            'after', _printed_values(tree), 'the statement the trap resumes into was removed')

    def test_a_parameter_default_of_a_function_nobody_calls_never_runs(self):
        tree = self._deobfuscated_tree(
            "function g($p = (Set-Variable $n 'v')) { }; $x = 'a'; Write-Host $x")
        self.assertIn(
            'a', _printed_values(tree), 'the read was not folded past a default that never runs'
        )

    @backlog
    def test_a_parameter_default_run_by_a_call_writes_a_script_variable_named_at_run_time(self):
        tree = self._deobfuscated_tree(
            "$n = 'script:x'; function g($p = (Set-Variable $n 'v')) { }; "
            "$x = 'a'; g; Write-Host $x"
        )
        self.assertTrue(
            _invocations(tree, _SET_VARIABLE) or 'v' in _printed_values(tree),
            'the write the default makes was dropped and nothing prints the value it wrote',
        )
        self.assertNotIn(
            'a', _printed_values(tree), 'the read was folded past a default the call runs'
        )

    @backlog
    def test_a_child_scope_writing_a_runtime_named_script_variable_reaches_the_caller(self):
        source = "$n = 'script:x'; $x = 'a'; & { Set-Variable $n 'v' }; Write-Host $x"
        printing_v = (
            self._apply(source),
            inspect.cleandoc("""
                $x = 'a'
                & {
                  $script:x = 'v'
                }
                Write-Host $x
            """),
            inspect.cleandoc("""
                & {
                  $script:x = 'v'
                }
                Write-Host $x
            """),
            "Write-Host 'v'",
        )
        self.assertIn(self._deobfuscate_iterative(source), printing_v)

    @backlog
    def test_child_scope_may_change_the_process_environment(self):
        tree = self._deobfuscated_tree('& { iex $c }; Write-Host $env:ComSpec')
        self.assertTrue(
            _passes_variable(tree, 'c'), 'the call that may change the environment was dropped')
        self.assertTrue(
            any(
                isinstance(printed, Ps1Variable) and _binding_key(printed) == 'env:comspec'
                for printed in _printed_expressions(tree)
            ),
            'the environment read was replaced by a value the deobfuscator cannot know',
        )

    def test_invoke_command_with_computername_runs_on_another_machine(self):
        tree = self._deobfuscated_tree('Invoke-Command -Comp $h -ScriptBlock { 1 }')
        self.assertTrue(
            [
                call for call in _invocations(tree, _INVOKE_COMMAND)
                if _binds(call, 'computername')
                and any(isinstance(v, Ps1ScriptBlock) for v in _argument_values(call))
            ],
            'the block was taken out of the remote invocation and now runs on this machine',
        )

    def test_native_openssl_argument_spelling_survives(self):
        tree = self._deobfuscated_tree('openssl enc -d -a -in x')
        commands = _invocations(tree, frozenset({'openssl'}))
        self.assertEqual(len(commands), 1, 'the native command did not survive as one invocation')
        self.assertListEqual(
            _switch_spellings(commands[0]),
            ['-d', '-a', '-in'],
            'an argument of a native program was rewritten to a PowerShell parameter name',
        )
        self.assertListEqual(
            [_literal_value(value) for value in _positional_values(commands[0])],
            ['enc', 'x'],
            'the operands of the native program did not survive unchanged',
        )

    def test_native_executable_switch_spelling_survives(self):
        tree = self._deobfuscated_tree('foo.exe -noprofile -file x')
        commands = _invocations(tree, frozenset({'foo.exe'}))
        self.assertEqual(len(commands), 1, 'the native command did not survive as one invocation')
        self.assertListEqual(
            _switch_spellings(commands[0]),
            ['-noprofile', '-file'],
            'an argument of a native program was rewritten to a PowerShell parameter name',
        )

    def test_bare_script_path_is_a_call_and_not_a_dot_source(self):
        script = frozenset({R'.\a.ps1'})
        called = _invocations(self._deobfuscated_tree(R'.\a.ps1'), script)
        dot_sourced = _invocations(self._deobfuscated_tree(R'. .\a.ps1'), script)
        self.assertEqual(len(called), 1, 'the call did not survive as one invocation of the script')
        self.assertEqual(len(dot_sourced), 1, 'the dot-source did not survive as one invocation')
        self.assertNotEqual(
            called[0].invocation_operator,
            '.',
            'running a script was read as a dot-source, inventing a write into the caller',
        )
        self.assertEqual(
            dot_sourced[0].invocation_operator,
            '.',
            'a dot-source was read as an ordinary call, losing the write it makes into the caller',
        )

    def test_dot_in_argument_position_is_a_path_and_not_a_dot_source(self):
        for source, paths in [
            ('Copy-Item . dest', ['.', 'dest']),
            ('Test-Path .', ['.']),
            ('Get-ChildItem . -Recurse', ['.']),
            ('Copy-Item .. dest', ['..', 'dest']),
        ]:
            commands = _commands(self._deobfuscated_tree(source))
            self.assertFalse(
                [command for command in commands if command.invocation_operator == '.'],
                F'{source} grew a dot-source, inventing a write into the caller scope',
            )
            self.assertEqual(len(commands), 1, F'{source} was split into several commands')
            self.assertEqual(
                [_literal_value(value) for value in _positional_values(commands[0])],
                paths,
                F'{source} lost the path from the command that takes it',
            )

    def test_absolute_executable_path_is_one_command_name(self):
        commands = _commands(self._deobfuscated_tree(R'C:\x\y.exe'))
        self.assertEqual(len(commands), 1, 'the path was read as more than one command')
        self.assertEqual(
            _literal_value(commands[0].name),
            R'C:\x\y.exe',
            'the command name is not the whole path',
        )
        self.assertEqual(
            _argument_values(commands[0]), [], 'part of the path was read as an argument')

    def test_reserved_input_operator_is_not_a_file_write(self):
        writes = _file_writes(self._deobfuscated_tree('Get-Content < in.txt > out.txt'))
        self.assertEqual(
            writes,
            [_Redirection(Ps1FileRedirection, (Ps1RedirectionStream.OUTPUT,), False, 'out.txt')],
            'the reserved operator reads as a write to the file behind it',
        )

    def test_reserved_input_operator_neither_gains_nor_loses_a_redirection(self):
        for source in (
            'Get-Content < in.txt > out.txt',
            'Get-Content < in.txt',
            'echo a < b',
        ):
            self.assertEqual(
                _redirections(self._deobfuscated_tree(source)),
                _redirections(Ps1Parser(source).parse()),
                F'{source} does not redirect what it redirected before it was written back out',
            )

    def test_percent_invokes_foreach_object_with_a_script_block(self):
        tree = self._deobfuscated_tree('% { Write-Host 1 }')
        self.assertFalse(
            [node for node in tree.walk() if isinstance(node, Ps1ForEachLoop)],
            'the alias became the loop keyword its expansion begins with',
        )
        commands = _invocations(tree, _FOREACH_OBJECT)
        self.assertEqual(len(commands), 1, 'the alias and its block were read as several commands')
        arguments = _argument_values(commands[0])
        self.assertEqual(len(arguments), 1, 'the command was left with more than the block')
        self.assertIsInstance(
            arguments[0], Ps1ScriptBlock, 'the block is not an argument of the command')
        self.assertEqual(
            _printed_values(tree), {1}, 'the block no longer prints what it was given to print')

    def test_command_name_beginning_with_a_keyword_stays_a_command(self):
        for source in ('Exit-PSSession', 'Break-Glass', 'Return-Value'):
            tree = self._deobfuscated_tree(source)
            self.assertFalse(
                [node for node in tree.walk() if isinstance(node, (Ps1Exit, Ps1Jump))],
                F'{source} was read as the keyword statement its name begins with',
            )
            self.assertEqual(
                len(_invocations(tree, frozenset({source.lower()}))),
                1,
                F'{source} did not survive as one command invocation',
            )

    def test_foreach_object_beginning_a_statement_stays_a_command(self):
        tree = self._deobfuscated_tree('ForEach-Object { Write-Host 1 }')
        self.assertFalse(
            [node for node in tree.walk() if isinstance(node, Ps1ForEachLoop)],
            'the cmdlet was read as the loop keyword its name begins with',
        )
        self.assertEqual(
            len(_invocations(tree, _FOREACH_OBJECT)),
            1,
            'the cmdlet did not survive as one command invocation',
        )

    def test_catch_joined_to_its_type_filter_is_not_a_handler(self):
        tree = self._deobfuscated_tree('try{foo}catch[System.Exception]{bar}')
        self.assertEqual(
            _catch_clause_counts(tree),
            [],
            'a handler was invented where 5.1 reads a command name and refuses the script',
        )
        self.assertEqual(
            [node.text for node in tree.walk() if isinstance(node, Ps1ErrorNode)],
            ['try{foo}'],
            'the source 5.1 refuses was dropped instead of being kept verbatim',
        )
        self.assertEqual(
            _catch_clause_counts(self._deobfuscated_tree('try{foo}catch [System.Exception]{bar}')),
            [1],
            'a typed handler 5.1 runs was lost',
        )
        self.assertEqual(
            _catch_clause_counts(self._deobfuscated_tree('try{foo}catch{bar}')),
            [1],
            'an untyped handler 5.1 runs was lost',
        )

    def test_function_body_reads_the_callers_variable(self):
        tree = self._deobfuscated_tree("$x = 'a'; function f { Write-Host $x }; f; $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_child_scope_block_reads_the_callers_variable(self):
        tree = self._deobfuscated_tree("$v = 'a'; & { Write-Host $v }; $v = 'c'")
        self._assertPrints(tree, 'v', 'a', 'c')

    def test_child_scope_block_reads_the_script_scoped_variable(self):
        tree = self._deobfuscated_tree("$x = 'a'; & { Write-Host $script:x }; $x = 'b'")
        self._assertPrints(tree, 'x', 'a', 'b')

    def test_function_body_reads_the_script_scoped_variable(self):
        tree = self._deobfuscated_tree("$x = 'a'; function f { Write-Host $script:x }; f; $x = 'b'")
        self._assertPrints(tree, 'x', 'a', 'b')

    def test_script_block_invoked_before_the_second_store_reads_the_first(self):
        tree = self._deobfuscated_tree("$x = 'a'; $sb = { Write-Host $x }; & $sb; $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_script_block_invoked_after_the_second_store_reads_the_second(self):
        tree = self._deobfuscated_tree("$x = 'a'; $sb = { Write-Host $x }; $x = 'c'; & $sb")
        self._assertPrints(tree, 'x', 'c', 'a')

    def test_script_block_invoke_method_reads_the_callers_variable(self):
        tree = self._deobfuscated_tree("$x = 'a'; $sb = { Write-Host $x }; $sb.Invoke(); $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_local_invoke_command_script_block_reads_the_callers_variable(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; Invoke-Command -ScriptBlock { Write-Host $x }; $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_foreach_object_block_reads_the_callers_variable(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; 1..2 | ForEach-Object { Write-Host $x }; $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_invoke_script_string_reads_the_callers_variable(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; $ExecutionContext.InvokeCommand.InvokeScript('Write-Host $x'); $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_invoke_expression_string_reads_the_callers_variable(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; $c = 'Write-Host $x'; function f { iex $c }; f; $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_get_variable_reads_the_caller_by_name(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; function f { Write-Host (Get-Variable x -ValueOnly) }; f; $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_get_variable_wildcard_reads_without_naming_the_variable(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; Write-Host (Get-Variable x* | ForEach-Object Value); $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_get_variable_call_is_a_read_of_the_preceding_store(self):
        tree = self._deobfuscated_tree("$x = 'a'; Get-Variable x; $x = 'c'")
        self.assertTrue(
            [
                call for call in _invocations(tree, _GET_VARIABLE)
                if 'x' in [_literal_value(value) for value in _positional_values(call)]
            ],
            'the call that reads the variable by name was dropped',
        )
        self.assertTrue(
            _stores_value(tree, 'x', 'a'), 'the store that call reads was deleted as dead')

    def test_invoke_expression_may_read_the_preceding_store(self):
        tree = self._deobfuscated_tree("$x = 'a'; iex $c; $x = 'c'")
        self.assertTrue(
            _passes_variable(tree, 'c'), 'the call that may read any variable was dropped')
        self.assertTrue(
            _stores_value(tree, 'x', 'a'), 'the store that call may read was deleted as dead')

    def test_increment_in_child_scope_creates_a_local_copy(self):
        tree = self._deobfuscated_tree('$v = 41; & { $v++; Write-Host $v }; Write-Host $v')
        inner = _printed_values(tree, nested=True)
        outer = _printed_values(tree, nested=False)
        self.assertNotIn(
            41, inner, 'the print inside the child scope was folded past the increment')
        self.assertNotIn(
            42, outer, 'the increment made in the child scope was folded into the caller')
        self.assertTrue(
            42 in inner or _increments(tree, 'v'),
            'the increment the child scope performs was lost',
        )
        self.assertTrue(
            41 in outer or _stores_value(tree, 'v', 41),
            'nothing left in the output gives the caller the value it keeps',
        )

    def test_reference_to_a_scoped_variable_is_written_by_the_callee(self):
        tree = self._deobfuscated_tree(
            "$i = 0; $null = [int]::TryParse('42', [ref]$script:i); Write-Host $i")
        self.assertTrue(
            42 in _printed_values(tree) or [
                call for call in _static_calls(tree, 'int', 'tryparse')
                if any(_is_reference_to(argument, 'i') for argument in call.arguments)
            ],
            'the call writing through the reference was dropped and nothing prints what it wrote',
        )
        self.assertNotIn(
            0, _printed_values(tree), 'the read was folded past a write made through [ref]')

    def test_reference_to_an_environment_variable_is_never_written_back(self):
        tree = self._deobfuscated_tree(
            "$env:z = '7'; $ok = [int]::TryParse('42', [ref]$env:z); Write-Host $env:z")
        self._assertPrints(tree, 'env:z', '7', '42')

    def test_two_names_for_one_array_both_see_it_reversed(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $y = $x; Write-Output $y[0]; [Array]::Reverse($x); Write-Output $y[0]')
        aliased = any(_reads_variable(store.value, 'x') for store in _stores(tree, 'y'))
        self._assertWrites(
            tree,
            [[1], [3]],
            [[3], [3]],
            aliased and _mutates_through_argument(tree, 'array', 'reverse', 'x'),
        )

    def test_invoke_expression_rebinds_the_array_that_is_reversed_after_it(self):
        tree = self._deobfuscated_tree(
            "$x = 1, 2, 3; $c = '$x = 7, 8, 9'; iex $c; [Array]::Reverse($x); Write-Output $x")
        self._assertWrites(
            tree,
            [[9, 8, 7]],
            [[7, 8, 9]],
            _mutates_through_argument(tree, 'array', 'reverse', 'x'),
        )

    def test_function_body_reverses_the_callers_array_in_place(self):
        tree = self._deobfuscated_tree(
            'function f { [Array]::Reverse($x) }; $x = 1, 2, 3; f; Write-Output $x')
        stores_the_array = any(
            _emitted_constants(store.value) == [1, 2, 3] for store in _stores(tree, 'x'))
        self._assertWrites(
            tree,
            [[3, 2, 1]],
            [[1, 2, 3]],
            stores_the_array and _mutates_through_argument(tree, 'array', 'reverse', 'x'),
        )

    def test_reversal_does_not_reorder_the_effects_that_build_the_array(self):
        tree = self._deobfuscated_tree(
            "$x = $(Write-Host 'a'; 1), $(Write-Host 'b'; 2); [Array]::Reverse($x); Write-Output $x")
        self.assertEqual(
            [_literal_value(expression) for expression in _printed_expressions(tree)],
            ['a', 'b'],
            'the reversal was applied to the effects building the array instead of to the array',
        )
        self.assertNotEqual(
            _output_writes(tree),
            [[1, 2]],
            'the array was written in the order it held before the reversal',
        )

    def test_reverse_mutates_its_argument_even_when_its_result_is_stored(self):
        tree = self._deobfuscated_tree('$x = 1, 2, 3; $r = [Array]::Reverse($x); Write-Output $x')
        self._assertWrites(
            tree,
            [[3, 2, 1]],
            [[1, 2, 3]],
            _mutates_through_argument(tree, 'array', 'reverse', 'x'),
        )

    def test_clear_blanks_the_range_of_the_array_the_variable_holds(self):
        tree = self._deobfuscated_tree('$x = 1, 2, 3; [Array]::Clear($x, 0, 1); Write-Output $x')
        self._assertWrites(
            tree,
            [[None, 2, 3]],
            [[1, 2, 3]],
            _mutates_through_argument(tree, 'array', 'clear', 'x'),
        )

    def test_copy_writes_through_its_destination_argument(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $y = 0, 0, 0; [Array]::Copy($x, $y, 3); Write-Output $y')
        holds_the_destination = any(
            _emitted_constants(store.value) == [0, 0, 0] for store in _stores(tree, 'y'))
        copies_into_the_variable = any(
            len(call.arguments) == 3
            and _supplies_array(tree, call.arguments[0], [1, 2, 3])
            and _reads_variable(call.arguments[1], 'y')
            and _literal_value(call.arguments[2]) == 3
            for call in _static_calls(tree, 'array', 'copy')
        )
        self._assertWrites(
            tree, [[1, 2, 3]], [[0, 0, 0]], holds_the_destination and copies_into_the_variable)

    def test_reverse_with_a_range_turns_around_only_that_part(self):
        tree = self._deobfuscated_tree('$x = 1, 2, 3; [Array]::Reverse($x, 0, 2); Write-Output $x')
        reverses_the_range = any(
            _reads_variable(call.arguments[0], 'x')
            and [_literal_value(argument) for argument in call.arguments[1:]] == [0, 2]
            for call in _static_calls(tree, 'array', 'reverse')
            if call.arguments
        )
        self._assertWrites(tree, [[2, 1, 3]], [[1, 2, 3]], reverses_the_range)

    def test_set_value_writes_through_the_receiver(self):
        tree = self._deobfuscated_tree('$x = 1, 2, 3; $x.SetValue(9, 0); Write-Output $x')
        writes_into_the_variable = any(
            _reads_variable(call.object, 'x') for call in _instance_calls(tree, 'setvalue'))
        self._assertWrites(tree, [[9, 2, 3]], [[1, 2, 3]], writes_into_the_variable)

    def test_copy_to_writes_through_its_destination_argument(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $y = 0, 0, 0; $x.CopyTo($y, 0); Write-Output $y')
        holds_the_destination = any(
            _emitted_constants(store.value) == [0, 0, 0] for store in _stores(tree, 'y'))
        copies_into_the_variable = any(
            _supplies_array(tree, call.object, [1, 2, 3])
            and len(call.arguments) == 2
            and _reads_variable(call.arguments[0], 'y')
            and _literal_value(call.arguments[1]) == 0
            for call in _instance_calls(tree, 'copyto')
        )
        self._assertWrites(
            tree, [[1, 2, 3]], [[0, 0, 0]], holds_the_destination and copies_into_the_variable)

    def test_element_store_through_one_name_is_seen_through_the_other(self):
        tree = self._deobfuscated_tree('$x = 1, 2, 3; $y = $x; $y[0] = 9; Write-Output $x[0]')
        aliased = any(_reads_variable(store.value, 'x') for store in _stores(tree, 'y'))
        self._assertWrites(tree, [[9]], [[1]], aliased and bool(_element_stores(tree, 'y')))

    def test_a_multi_assignment_slot_is_handed_the_array_standing_against_it(self):
        tree = self._deobfuscated_tree('$x = 1, 2, 3; $a, $b = $x, 9; $a[0] = 7; Write-Output $x[0]')
        aliased = any(
            _reads_variable(_value_handed_to(store, 'a'), 'x') for store in _stores(tree, 'a'))
        self._assertWrites(tree, [[7]], [[1]], aliased and bool(_element_stores(tree, 'a')))

    def test_an_array_a_container_holds_is_the_one_the_call_reverses(self):
        tree = self._deobfuscated_tree(
            "$x = 1, 2, 3; $h = @{}; $h['k'] = $x; [Array]::Reverse($h['k']); Write-Output $x")
        stored = any(_reads_variable(store.value, 'x') for store in _element_stores(tree, 'h'))
        self._assertWrites(tree, [[3, 2, 1]], [[1, 2, 3]], stored)

    def test_a_foreach_variable_is_bound_to_the_element_and_not_to_a_copy(self):
        tree = self._deobfuscated_tree(
            '$p = @(@(1, 2), @(3, 4)); foreach ($e in $p) { [Array]::Reverse($e) }; '
            'Write-Output $p[0]')
        reverses_the_element = any(
            _reads_variable(call.arguments[0], 'e')
            for call in _static_calls(tree, 'array', 'reverse') if call.arguments
        )
        self._assertWrites(tree, [[2, 1]], [[1, 2]], reverses_the_element)

    def test_a_called_body_that_keeps_its_argument_keeps_the_callers_array(self):
        tree = self._deobfuscated_tree(
            'function f($a) { $script:k = $a }; $x = 1, 2, 3; f $x; $x[0] = 9; Write-Output $k[0]')
        hands_the_variable_on = any(
            any(_reads_variable(value, 'x') for value in _positional_values(invocation))
            for invocation in _invocations(tree, frozenset({'f'}))
        )
        self._assertWrites(tree, [[9]], [[1]], hands_the_variable_on)

    @todo
    def test_a_subexpression_between_two_names_gives_each_its_own_array(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $y = $($x); [Array]::Reverse($x); Write-Output $y')
        copies_the_array = any(
            isinstance(store.value, Ps1SubExpression) for store in _stores(tree, 'y'))
        self._assertWrites(tree, [[1, 2, 3]], [[3, 2, 1]], copies_the_array)

    def test_loop_reads_the_array_the_previous_iteration_reversed(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; for ($i = 0; $i -lt 2; $i++) { Write-Output $x[0]; [Array]::Reverse($x) }')
        self.assertEqual(
            _output_writes(tree),
            [None],
            'a read whose value differs between the iterations was folded to one constant',
        )
        self.assertTrue(
            _mutates_through_argument(tree, 'array', 'reverse', 'x'),
            'the reversal that makes the two iterations differ no longer reaches the array',
        )

    def test_parentheses_around_the_argument_do_not_stop_the_reversal(self):
        tree = self._deobfuscated_tree('$x = 1, 2, 3; [Array]::Reverse(($x)); Write-Output $x')
        self._assertWrites(
            tree,
            [[3, 2, 1]],
            [[1, 2, 3]],
            _mutates_through_argument(tree, 'array', 'reverse', 'x'),
        )

    def test_reversing_an_element_of_an_array_of_arrays_mutates_that_element(self):
        tree = self._deobfuscated_tree(
            '$p = @(@(1, 2), @(3, 4)); [Array]::Reverse($p[0]); Write-Output $p[0]')
        self._assertWrites(
            tree, [[2, 1]], [[1, 2]], _mutates_through_argument(tree, 'array', 'reverse', 'p'))


class TestPs1AStoreThroughAContainerReachesTheArrayTheContainerWasHanded(_Ps1Ledger):

    _UNREACHED = (
        inspect.cleandoc("""
            $x = 1, 2, 3
            $h = @{}
            $h['k'] = $x
            Write-Output $h['k']
        """),
        inspect.cleandoc("""
            $x = 1, 2, 3
            $o = [pscustomobject]@{ P = 0 }
            $o.P = $x
            Write-Output $o.P
        """),
        inspect.cleandoc("""
            $x = 1, 2, 3
            $a = 0, 0
            $a[0] = $x
            Write-Output $a[0]
        """),
        inspect.cleandoc("""
            $x = 1, 2, 3
            $h = @{ k = $x }
            Write-Output $h.k
        """),
        inspect.cleandoc("""
            $x = 1, 2, 3
            $a, $b = $x, 9
            Write-Output $a
        """),
    )

    def _assertKeepsTheArray(
        self,
        tree: Ps1Script,
        key: str,
        stored: int,
        holds_the_array: bool,
    ) -> None:
        takes_the_store = any(
            _emitted_constants(store.value) == [stored]
            for store in _container_stores(tree, key)
        )
        self._assertWrites(
            tree, [[stored, 2, 3]], [[1, 2, 3]], holds_the_array and takes_the_store)

    def test_a_store_through_a_hashtable_key_reaches_the_array_the_key_was_given(self):
        tree = self._deobfuscated_tree(
            "$x = 1, 2, 3; $h = @{}; $h['k'] = $x; $h['k'][0] = 9; Write-Output $h['k']")
        holds_the_array = any(
            _reads_variable(store.value, 'x')
            for store in _container_stores(tree, 'h')
        )
        self._assertKeepsTheArray(tree, 'h', 9, holds_the_array)

    def test_a_store_through_a_property_reaches_the_array_the_property_was_given(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $o = [pscustomobject]@{ P = 0 }; $o.P = $x; $o.P[0] = 9; '
            'Write-Output $o.P')
        holds_the_array = any(
            _reads_variable(store.value, 'x')
            for store in _container_stores(tree, 'o')
        )
        self._assertKeepsTheArray(tree, 'o', 9, holds_the_array)

    def test_a_store_through_an_element_reaches_the_array_that_element_was_given(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $a = 0, 0; $a[0] = $x; $a[0][0] = 9; Write-Output $a[0]')
        holds_the_array = any(
            _reads_variable(store.value, 'x')
            for store in _container_stores(tree, 'a')
        )
        self._assertKeepsTheArray(tree, 'a', 9, holds_the_array)

    def test_a_store_through_a_key_written_into_a_literal_reaches_the_array_it_was_given(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $h = @{ k = $x }; $h.k[0] = 9; Write-Output $h.k')
        holds_the_array = any(
            _reads_variable(value, 'x')
            for store in _stores(tree, 'h')
            for value in _hash_values(store.value)
        )
        self._assertKeepsTheArray(tree, 'h', 9, holds_the_array)

    def test_a_store_through_one_target_of_a_multi_assignment_reaches_the_array_it_took(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $a, $b = $x, 9; $a[0] = 7; Write-Output $a')
        holds_the_array = any(
            _reads_variable(element, 'x')
            for store in _stores(tree, 'a')
            if isinstance(value := _unwrap(store.value), Ps1ArrayLiteral)
            for element in value.elements
        )
        self._assertKeepsTheArray(tree, 'a', 7, holds_the_array)

    def test_the_same_shapes_take_the_value_where_no_store_reaches_the_container(self):
        for container in self._UNREACHED:
            with self.subTest(container):
                tree = self._deobfuscated_tree(container)
                self.assertEqual(_occurrences(tree, 'x'), [])


class TestPs1ADotSourcedBlockRebindsTheCallersNameAndAChildScopeDoesNot(_Ps1Ledger):

    def test_a_name_a_dot_sourced_block_rebinds_is_off_the_array_the_reversal_turns(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $y = $x; . { $y = 9, 9, 9 }; [Array]::Reverse($x); Write-Output $y')
        rebound = any(
            _emitted_constants(store.value) == [9, 9, 9]
            for block in _dot_sourced_blocks(tree)
            for store in _stores(block, 'y')
        )
        self._assertWrites(tree, [[9, 9, 9]], [[3, 2, 1]], rebound)

    def test_a_name_a_child_scope_writes_is_still_on_the_array_the_reversal_turns(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $y = $x; & { $y = 9, 9, 9 }; [Array]::Reverse($x); Write-Output $y')
        aliased = any(_reads_variable(store.value, 'x') for store in _stores(tree, 'y'))
        self._assertWrites(
            tree,
            [[3, 2, 1]],
            [[9, 9, 9]],
            aliased and _mutates_through_argument(tree, 'array', 'reverse', 'x'),
        )


class TestPs1AConstrainedNameNeverHoldsTheArrayThatWasAssignedToIt(_Ps1Ledger):

    def test_a_reversal_does_not_reach_a_name_a_constraint_converted_its_value_for(self):
        tree = self._deobfuscated_tree(
            '[string]$y = 0; $x = 1, 2, 3; $y = $x; [Array]::Reverse($x); Write-Output $y')
        constrained = bool(_constrained_stores(tree, 'y', 'string'))
        takes_the_array = any(
            _supplies_array(tree, store.value, [1, 2, 3]) for store in _stores(tree, 'y'))
        self._assertWrites(tree, [['1 2 3']], [[3, 2, 1]], constrained and takes_the_array)

    def test_the_same_script_without_the_constraint_is_answered_with_the_reversal(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $y = $x; [Array]::Reverse($x); Write-Output $y')
        self.assertEqual(_output_writes(tree), [[3, 2, 1]])


class TestPs1AValuePipedIntoANameBindingCommandIsBoundToWhatThePipelineWrote(_Ps1Ledger):

    def test_a_name_bound_from_an_enumerating_pipeline_is_not_on_the_array_piped_into_it(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $y = $x; $x | Set-Variable z; $y[0] = 9; Write-Output $z')
        bound = any(
            _supplies_array(tree, source, [1, 2, 3])
            and any(_literal_value(value) == 'z' for value in _positional_values(command))
            for source, command in _piped_into(tree, _SET_VARIABLE)
        )
        self._assertWrites(tree, [[1, 2, 3]], [[9, 2, 3]], bound)


class TestPs1AValueReachingANameBindingCommandThroughACommandStillReachesIt(_Ps1Ledger):

    def _assertBoundToTheArray(self, tree: Ps1Script, bound: bool) -> None:
        stored = any(_emitted_constants(store.value) == [9] for store in _element_stores(tree, 'x'))
        self._assertWrites(tree, [[9, 2, 3]], [[1, 2, 3]], bound and stored)

    def test_a_name_bound_behind_a_command_told_not_to_enumerate_is_on_the_array_it_wrote(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; Write-Output -NoEnumerate $x | Set-Variable z; $x[0] = 9; '
            'Write-Output $z')
        bound = any(
            _binds(writer, 'noenumerate')
            and any(_reads_variable(value, 'x') for value in _argument_values(writer))
            and _binds_the_name(binder, 'z')
            for writer, binder in _pipeline_pairs(tree, _WRITE_OUTPUT, _SET_VARIABLE)
        )
        self._assertBoundToTheArray(tree, bound)

    def test_a_name_bound_behind_a_command_handed_one_wrapped_array_is_on_that_array(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; Write-Output (,$x) | Set-Variable z; $x[0] = 9; Write-Output $z')
        bound = any(
            any(_wraps_as_one_record(value, 'x') for value in _argument_values(writer))
            and _binds_the_name(binder, 'z')
            for writer, binder in _pipeline_pairs(tree, _WRITE_OUTPUT, _SET_VARIABLE)
        )
        self._assertBoundToTheArray(tree, bound)


class TestPs1AStoreIntoAPlaceOfAnArrayDoesNotExcuseTheReadOfItsName(_Ps1Ledger):

    def _assertStoresTheArrayItself(self, tree: Ps1Script, key: str) -> None:
        stored = [
            store for store in _element_stores(tree, key) if _reads_variable(store.value, 'x')
        ]
        compared = [
            call for call in _static_calls(tree, 'object', 'referenceequals')
            if len(call.arguments) == 2
            and _reads_variable(call.arguments[0], key)
            and _reads_variable(call.arguments[1], 'x')
        ]
        self.assertTrue(
            _writes_true(tree) or bool(stored) and bool(compared),
            F'${key} was given an array of its own, or the comparison observing it was dropped',
        )

    def test_an_array_written_into_an_element_of_itself_is_the_one_the_name_holds(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $x[0] = $x; $r = [Object]::ReferenceEquals($x[0], $x); Write-Output $r')
        self._assertStoresTheArrayItself(tree, 'x')

    def test_an_array_written_into_an_element_reached_by_its_other_name_is_that_one_too(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $a = $x; $a[0] = $x; '
            '$r = [Object]::ReferenceEquals($a[0], $x); Write-Output $r')
        self.assertTrue(
            _writes_true(tree)
            or any(_reads_variable(store.value, 'x') for store in _stores(tree, 'a')),
            'the two names were taken off the one array',
        )
        self._assertStoresTheArrayItself(tree, 'a')


class TestPs1AnObjectPutIntoAContainerIsStillTheOneItsNameHolds(_Ps1Ledger):

    def test_a_store_through_a_property_reaches_the_array_the_name_holds(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $o = [pscustomobject]@{ P = 0 }; $o.P = $x; $o.P[0] = 9; Write-Output $x',
            'x', [[9, 2, 3]], [[1, 2, 3]])

    def test_a_store_through_an_element_reaches_the_array_the_name_holds(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $a = 0, 0; $a[0] = $x; $a[0][0] = 9; Write-Output $x',
            'x', [[9, 2, 3]], [[1, 2, 3]])

    def test_a_store_through_a_list_slot_reaches_the_array_the_name_holds(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $l = New-Object Collections.ArrayList; [void]$l.Add($x); '
            '$l[0][0] = 9; Write-Output $x',
            'x', [[9, 2, 3]], [[1, 2, 3]])

    def test_a_store_through_a_key_of_a_hash_literal_reaches_the_array_the_name_holds(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $h = @{ k = $x }; $h.k[0] = 9; Write-Output $x',
            'x', [[9, 2, 3]], [[1, 2, 3]])

    def test_a_name_taken_back_out_of_a_container_is_on_the_array_that_was_put_in(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $h = @{ k = $x }; $y = $h['k']; $y[0] = 9; Write-Output $x",
            'x', [[9, 2, 3]], [[1, 2, 3]])

    def test_a_name_taken_from_an_element_is_on_the_array_that_element_holds(self):
        self._assertTheStoreReachesTheName(
            '$p = @(@(1, 2), @(3, 4)); $q = $p[0]; $q[0] = 9; Write-Output $p[0][0]',
            'p', [[9]], [[1]])


class TestPs1AnObjectHandedToABodyIsStillTheOneItsNameHolds(_Ps1Ledger):

    def test_a_pipeline_variable_is_bound_to_the_element_and_not_to_a_copy(self):
        self._assertTheStoreReachesTheName(
            '$p = @(@(1, 2), @(3, 4)); $p | ForEach-Object { [Array]::Reverse($_) }; '
            'Write-Output $p[0]',
            'p', [[2, 1]], [[1, 2]])

    def test_a_function_parameter_is_bound_to_the_array_the_argument_named(self):
        self._assertTheStoreReachesTheName(
            'function f($a) { [Array]::Reverse($a) }; $x = 1, 2, 3; f $x; Write-Output $x',
            'x', [[3, 2, 1]], [[1, 2, 3]])

    def test_a_script_block_parameter_is_bound_to_the_array_the_argument_named(self):
        self._assertTheStoreReachesTheName(
            '$sb = { param($a) [Array]::Reverse($a) }; $x = 1, 2, 3; & $sb $x; Write-Output $x',
            'x', [[3, 2, 1]], [[1, 2, 3]])

    def test_a_call_through_a_multi_assignment_slot_reaches_the_array_it_was_handed(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $a, $b = $x, 9; [Array]::Reverse($a); Write-Output $x',
            'x', [[3, 2, 1]], [[1, 2, 3]])


class TestPs1APositionThatBuildsANewObjectIsNotAHandOff(_Ps1Ledger):

    def test_a_store_through_an_index_the_text_does_not_fix_reaches_the_collection(self):
        tree = self._deobfuscated_tree(
            '$p = @(@(1, 2), @(3, 4)); for ($i = 0; $i -lt 1; $i++) { [Array]::Reverse($p[$i]) }; '
            'Write-Output $p[0]')
        self._assertWrites(
            tree, [[2, 1]], [[1, 2]], _mutates_through_argument(tree, 'array', 'reverse', 'p'))

    @opportunity
    def test_a_store_through_an_index_the_text_does_not_fix_is_answered_with_the_reversal(self):
        tree = self._deobfuscated_tree(
            '$p = @(@(1, 2), @(3, 4)); for ($i = 0; $i -lt 1; $i++) { [Array]::Reverse($p[$i]) }; '
            'Write-Output $p[0]'
        )
        self.assertEqual(_output_writes(tree), [[2, 1]])

    def test_a_name_bound_from_a_wrapped_script_scope_return_is_on_the_array_that_was_wrapped(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; function f { , $script:x }; $y = f; $y[0] = 9; Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )

    @opportunity
    def test_a_name_bound_from_a_wrapped_return_is_answered_with_the_store_through_it(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; function f { , $script:x }; $y = f; $y[0] = 9; Write-Output $x[0]')
        self.assertEqual(_output_writes(tree), [[9]])


class TestPs1AnArrayHandedOnWithoutBeingPutAnywhereIsStillTheOneItsNameHolds(_Ps1Ledger):

    def test_a_name_bound_from_a_wrapped_return_is_on_the_array_that_was_wrapped(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; function f { , $x }; $y = f; $y[0] = 9; Write-Output $x[0]',
            'x', [[9]], [[1]])

    def test_a_name_bound_from_a_record_written_without_enumerating_is_on_the_array(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $y = Write-Output -NoEnumerate $x; $y[0] = 9; Write-Output $x[0]',
            'x', [[9]], [[1]])

    def test_a_name_bound_from_a_wrapped_block_output_is_on_the_array_that_was_wrapped(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $y = & { , $x }; $y[0] = 9; Write-Output $x[0]',
            'x', [[9]], [[1]])

    def test_an_array_subexpression_copies_the_outer_array_and_not_the_arrays_it_holds(self):
        self._assertTheStoreReachesTheName(
            '$x = @(@(1, 2), @(3, 4)); $y = @($x); $y[0][0] = 9; Write-Output $x[0][0]',
            'x', [[9]], [[1]])


class TestPs1AHandOffSpelledThroughTheScriptQualifierIsStillAHandOff(_Ps1Ledger):

    def test_a_function_parameter_is_bound_to_the_array_a_qualified_argument_named(self):
        self._assertTheStoreReachesTheName(
            'function g($a) { [Array]::Reverse($a) }; $x = 1, 2, 3; g $script:x; Write-Output $x',
            'x', [[3, 2, 1]], [[1, 2, 3]])

    def test_a_script_block_parameter_is_bound_to_the_array_a_qualified_argument_named(self):
        self._assertTheStoreReachesTheName(
            '$sb = { param($a) [Array]::Reverse($a) }; $x = 1, 2, 3; & $sb $script:x; '
            'Write-Output $x',
            'x', [[3, 2, 1]], [[1, 2, 3]])

    def test_a_key_given_a_qualified_read_holds_the_array_the_name_holds(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $h = @{}; $h['k'] = $script:x; [Array]::Reverse($h['k']); "
            'Write-Output $x',
            'x', [[3, 2, 1]], [[1, 2, 3]])

    def test_a_list_handed_a_qualified_read_holds_the_array_the_name_holds(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $l = New-Object Collections.ArrayList; [void]$l.Add($script:x); '
            '$l[0][0] = 9; Write-Output $x',
            'x', [[9, 2, 3]], [[1, 2, 3]])

    def test_a_property_given_a_qualified_read_holds_the_array_the_name_holds(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $o = [pscustomobject]@{ P = 0 }; $o.P = $script:x; $o.P[0] = 9; '
            'Write-Output $x',
            'x', [[9, 2, 3]], [[1, 2, 3]])

    def test_a_name_bound_from_a_qualified_record_written_whole_is_on_the_array(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; Write-Output -NoEnumerate $script:x | Set-Variable z; $z[0] = 9; '
            'Write-Output $x',
            'x', [[9, 2, 3]], [[1, 2, 3]])


class TestPs1APrivateVariableIsSeenOnlyByTheScopeThatHoldsIt(_Ps1Ledger):

    def _assertTheChildScopeWritesNull(self, source: str) -> None:
        tree = self._deobfuscated_tree(source)
        stays_private = all(
            target.scope is Ps1ScopeModifier.PRIVATE
            for store in _stores(tree, 'x')
            for target in _target_variables(store.target)
        )
        self._assertWrites(tree, [[None]], [['a']], stays_private)

    def test_a_bare_read_in_a_child_scope_does_not_see_the_private_variable(self):
        self._assertTheChildScopeWritesNull("$private:x = 'a'; & { Write-Output $x }")

    def test_a_script_qualified_read_in_a_child_scope_does_not_see_the_private_variable(self):
        self._assertTheChildScopeWritesNull("$private:x = 'a'; & { Write-Output $script:x }")

    def test_a_read_in_the_scope_that_holds_the_private_variable_is_answered(self):
        tree = self._deobfuscated_tree("$private:x = 'a'; Write-Output $x")
        self.assertEqual(_output_writes(tree), [['a']])


class TestPs1AStoreIsReadByEveryCallStandingAfterIt(_Ps1Ledger):

    def _assertBothStoresReachTheCalls(self, source: str) -> None:
        tree = self._deobfuscated_tree(source)
        for printed in ('a', 'b'):
            self.assertTrue(
                printed in _printed_values(tree) or _stores_value(tree, 'x', printed),
                F'nothing left in the output can give $x the value {printed!r}',
            )

    def test_a_store_between_two_calls_is_read_by_the_first(self):
        self._assertBothStoresReachTheCalls(
            "function f { Write-Host $x }; $x = 'a'; f; $x = 'b'; f")

    def test_a_store_between_two_calls_is_read_through_the_script_qualifier(self):
        self._assertBothStoresReachTheCalls(
            "function f { Write-Host $script:x }; $x = 'a'; f; $x = 'b'; f")


class TestPs1ALocalQualifierInABlockRunInItsCallersScopeNamesTheCallersVariable(_Ps1Ledger):

    def test_a_local_store_in_the_block_is_seen_by_the_caller(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; 1 | ForEach-Object { $local:x = 'b' }; Write-Output $x")
        self._assertWrites(tree, [['b']], [['a']], _stores_value(tree, 'x', 'b'))

    @backlog
    def test_a_local_read_in_the_block_sees_the_callers_store(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; 1 | ForEach-Object { Write-Output $local:x }; $x = 'b'")
        self._assertWrites(tree, [['a']], [[None]], _stores_value(tree, 'x', 'a'))

    def test_a_local_store_in_a_dot_sourced_block_is_seen_by_the_caller(self):
        tree = self._deobfuscated_tree("$x = 'a'; . { $local:x = 'b' }; Write-Output $x")
        self._assertWrites(tree, [['b']], [['a']], _stores_value(tree, 'x', 'b'))

    @backlog
    def test_a_local_read_in_a_dot_sourced_block_sees_the_callers_store(self):
        tree = self._deobfuscated_tree("$x = 'a'; . { Write-Output $local:x }; $x = 'b'")
        self._assertWrites(tree, [['a']], [[None]], _stores_value(tree, 'x', 'a'))


class TestPs1AnAssignmentUsedAsAValueHandsOnTheObjectItStored(_Ps1Ledger):

    def test_the_outer_name_of_a_chained_assignment_holds_the_array_the_read_names(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $z = $y = $x; $z[0] = 9; Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )

    def test_the_outer_name_of_a_chained_assignment_holds_the_array_the_inner_one_was_given(self):
        self._assertTheStoreReachesTheName(
            '$y = $x = 1, 2, 3; $y[0] = 9; Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )

    def test_a_hash_entry_given_an_assignment_holds_the_array_it_stored(self):
        self._assertTheStoreReachesTheName(
            '$h = @{ k = ($x = 1, 2, 3) }; $h.k[0] = 9; Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )


class TestPs1APlaceTheClimbPassesByKeepsWhatItIsHanded(_Ps1Ledger):

    def test_a_name_given_the_sync_root_holds_the_array_itself(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $y = $x.SyncRoot; $y[0] = 9; Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )

    def test_a_name_given_the_base_object_of_the_wrapper_holds_the_array_itself(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $y = $x.psobject.BaseObject; $y[0] = 9; Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )

    def test_select_object_writes_an_input_object_whole(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $y = Select-Object -InputObject $x; $y[0] = 9; Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )

    def test_a_where_object_filter_runs_over_the_element_and_not_a_copy(self):
        self._assertTheStoreReachesTheName(
            '$p = @(@(1, 2), @(3, 4)); $p | Where-Object { $_[0] = 9 }; Write-Output $p[0][0]',
            'p',
            [[9]],
            [[1]],
        )

    def test_an_information_record_holds_the_array_it_was_handed(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $r = Write-Information $x 6>&1; $r.MessageData[0] = 9; '
            'Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )

    def test_a_parameter_default_is_bound_to_the_array_it_reads(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; & { param($a = $x) [Array]::Reverse($a) }; Write-Output $x',
            'x',
            [[3, 2, 1]],
            [[1, 2, 3]],
        )

    def test_a_hashtable_keeps_the_array_it_is_given_as_a_key(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $h = @{}; $h[$x] = 'v'; foreach ($k in @($h.Keys)) { $k[0] = 9 }; "
            'Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )

    def test_copy_to_fills_the_slot_with_the_arrays_its_receiver_holds(self):
        self._assertTheStoreReachesTheName(
            '$x = @(@(1, 2), @(3, 4)); $y = 0, 0; $x.CopyTo($y, 0); $y[0][0] = 9; '
            'Write-Output $x[0][0]',
            'x',
            [[9]],
            [[1]],
        )

    def test_reverse_turns_around_the_array_a_subexpression_hands_it(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; [Array]::Reverse($(,$x)); Write-Output $x',
            'x',
            [[3, 2, 1]],
            [[1, 2, 3]],
        )

    def test_a_class_method_returns_the_array_whole(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; class C { static [object] M() { return $script:x } }; '
            '$y = [C]::M(); $y[0] = 9; Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )

    def test_a_class_property_is_initialized_with_the_array_itself(self):
        self._assertTheStoreReachesTheName(
            'class C { $P = $script:x }; $x = 1, 2, 3; $o = [C]::new(); $o.P[0] = 9; '
            'Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )

    def test_adding_the_array_to_null_hands_on_the_array_itself(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $a = $null; $a = $a + $x; $a[0] = 9; Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )


class TestPs1ACollectionOfWrittenObjectsHoldsTheObjectsThemselves(_Ps1Ledger):

    def test_a_foreach_over_a_collected_array_binds_the_array_itself(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; foreach ($e in @(,$x)) { $e[0] = 9 }; Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )

    def test_a_multi_assignment_of_one_written_record_binds_the_record(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $a, $b = Write-Output -NoEnumerate $x; $a[0] = 9; Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )


class TestPs1ASecondNameInABodyIsOnTheArrayTheReadReached(_Ps1Ledger):

    def test_a_read_before_the_bodys_own_write_hands_on_the_callers_array(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; & { $y = $x; $y[0] = 9; $x = 5 }; Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )

    def test_a_name_assigned_in_a_foreach_object_body_is_the_callers(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; 1 | ForEach-Object { $y = $x }; $y[0] = 9; Write-Output $x[0]',
            'x',
            [[9]],
            [[1]],
        )


class TestPs1AnIncrementThroughAnElementChangesTheArray(_Ps1Ledger):

    def test_an_increment_through_a_second_name_reaches_the_array(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $y = $x; $y[0]++; Write-Output $x[0]',
            'x',
            [[2]],
            [[1]],
        )


class TestPs1AnInvocationEvaluatesItsArgumentsBeforeItRunsTheBlock(_Ps1Ledger):

    def test_a_read_in_the_block_observes_the_store_an_argument_made_through_a_container(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $h = @{ k = $x }; & { Write-Output $x[0] } ($h.k[0] = 9)',
            'x',
            [[9]],
            [[1]],
        )

    def test_a_read_in_the_block_observes_the_store_an_argument_made(self):
        tree = self._deobfuscated_tree("$x = 'a'; & { Write-Output $x } ($x = 'b')")
        self._assertWrites(tree, [['b']], [['a']], _stores_value(tree, 'x', 'b'))


class TestPs1AReadAScopeCannotSeeIsNotGivenTheValue(_Ps1Ledger):

    def test_a_local_read_in_a_trap_body_does_not_see_the_enclosing_variable(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; if ($true) { trap { Write-Output $local:x; continue }; throw 'e' }")
        self.assertNotIn(['a'], _output_writes(tree))

    def test_a_variable_new_variable_made_private_is_hidden_from_a_child_scope(self):
        tree = self._deobfuscated_tree(
            "New-Variable -Name x -Option Private; $x = 'a'; & { Write-Output $x }")
        self.assertNotIn(['a'], _output_writes(tree))


class TestPs1ANameIsWrittenByMoreThanItsSpellingsAsAVariable(_Ps1Ledger):

    def test_a_store_read_through_the_script_qualifier_is_not_overwritten_unread(self):
        tree = self._deobfuscated_tree(
            '$x = Get-Random -Maximum 1; Write-Output $script:x; $x = 5; Write-Output $x')
        draws = frozenset({'get-random'})
        self.assertTrue(
            any(_invocations(store, draws) for store in _stores(tree, 'x'))
            or any(_invocations(write, draws) for write in _invocations(tree, _WRITE_OUTPUT)[:1]),
            'nothing left in the output hands the first read the number Get-Random drew',
        )

    def test_a_name_new_variable_assigns_is_not_read_as_null(self):
        tree = self._deobfuscated_tree('New-Variable -Name q -Value 5; Write-Output ($q + 1)')
        self._assertWrites(tree, [[6]], [[1]], bool(_occurrences(tree, 'q')))


class TestPs1AStoreNoStatementOfTheScriptPlacesIsStillAStore(_Ps1Ledger):

    def test_a_reference_in_a_class_property_initializer_writes_at_construction(self):
        tree = self._deobfuscated_tree(
            "class C { $P = [int]::TryParse('42', [ref]$script:x) }; $x = 0; $o = [C]::new(); "
            'Write-Output $x')
        self._assertWrites(tree, [[42]], [[0]], _stores_value(tree, 'x', 0))

    def test_a_store_in_a_class_property_initializer_writes_at_construction(self):
        tree = self._deobfuscated_tree(
            "class C { $P = ($script:x = 5) }; $x = 0; $o = [C]::new(); Write-Output $x")
        self._assertWrites(tree, [[5]], [[0]], _stores_value(tree, 'x', 0))

    def test_an_array_set_writes_the_array_it_is_called_on(self):
        tree = self._deobfuscated_tree('$x = 1, 2, 3; $x.Set(0, 9); Write-Output $x[0]')
        writes_into_the_variable = any(
            _reads_variable(call.object, 'x') for call in _instance_calls(tree, 'set'))
        self._assertWrites(tree, [[9]], [[1]], writes_into_the_variable)

    def test_an_array_clear_writes_the_array_it_is_called_on(self):
        tree = self._deobfuscated_tree('$x = 1, 2, 3; $x.Clear(); Write-Output $x[0]')
        writes_into_the_variable = any(
            _reads_variable(call.object, 'x') for call in _instance_calls(tree, 'clear'))
        self._assertWrites(tree, [[None]], [[1]], writes_into_the_variable)


class TestPs1AVariableTheSessionStateWritesByNameIsWritten(_Ps1Ledger):

    def test_a_read_after_the_session_state_wrote_the_name_is_not_the_store_before_it(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; $ExecutionContext.SessionState.PSVariable.Set('x', 'b'); Write-Output $x")
        self._assertWrites(tree, [['b']], [['a']], bool(_instance_calls(tree, 'set')))


class TestPs1ACopyIsNotPutWhereCodeNobodyCanReadMayStoreThroughIt(_Ps1Ledger):

    def test_the_container_is_still_handed_the_array_the_name_holds(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $h = @{ k = $x }; $c = @('$h.k[0] = 9')[(Get-Random -Maximum 1)]; "
            'iex $c; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )


class TestPs1ABodyWritingAByteArrayWritesBytes(_Ps1Ledger):

    @backlog
    def test_a_folded_call_to_a_body_writing_a_byte_array_does_not_spell_bare_numbers(self):
        tree = self._deobfuscated_tree(
            'function dec($d) { $o = New-Object byte[] 2; $o[0] = $d; $o[1] = 1; $o }; '
            'Write-Output (dec 5)')
        self.assertNotEqual(_output_writes(tree), [[5, 1]])


class TestPs1AVariableWrittenThroughTheVariableItselfIsWritten(_Ps1Ledger):

    def test_a_store_through_the_variable_get_variable_hands_out(self):
        self._assertTheStoreReachesTheName(
            "$b = 'a'; $v = Get-Variable b; $v.Value = 'b'; Write-Output $b",
            'b',
            [['b']],
            [['a']],
        )

    def test_a_call_of_the_setter_of_the_variable_get_variable_hands_out(self):
        self._assertTheStoreReachesTheName(
            "$b = 'a'; (Get-Variable b).set_Value('b'); Write-Output $b",
            'b',
            [['b']],
            [['a']],
        )

    def test_a_store_through_the_variable_the_session_state_hands_out(self):
        self._assertTheStoreReachesTheName(
            "$b = 'a'; $ExecutionContext.SessionState.PSVariable.Get('b').Value = 'b'; "
            'Write-Output $b',
            'b',
            [['b']],
            [['a']],
        )

    def test_a_store_a_called_function_makes_through_its_callers_variable(self):
        self._assertTheStoreReachesTheName(
            "function g { (Get-Variable b -Scope 1).Value = 'b' }; $b = 'a'; g; Write-Output $b",
            'b',
            [['b']],
            [['a']],
        )

    def test_a_store_through_the_variable_get_child_item_hands_out(self):
        self._assertTheStoreReachesTheName(
            "$b = 'a'; $v = Get-ChildItem variable:b; $v.Value = 'b'; Write-Output $b",
            'b',
            [['b']],
            [['a']],
        )

    def test_a_store_by_the_block_the_variable_is_piped_into(self):
        self._assertTheStoreReachesTheName(
            "$b = 'a'; Get-Variable b | ForEach-Object { $_.Value = 'b' }; Write-Output $b",
            'b',
            [['b']],
            [['a']],
        )

    def test_a_store_through_a_variable_picked_out_of_every_variable(self):
        self._assertTheStoreReachesTheName(
            "$b = 'a'; $v = Get-Variable; ($v | Where-Object Name -eq 'b').Value = 'b'; "
            'Write-Output $b',
            'b',
            [['b']],
            [['a']],
        )

    def test_a_store_through_the_variable_new_variable_passes_through(self):
        self._assertTheStoreReachesTheName(
            '$v = New-Variable q 1 -PassThru; $v.Value = 5; Write-Output $q',
            'q',
            [[5]],
            [[1]],
        )

    def test_a_store_through_the_variable_where_it_is_fetched(self):
        self._assertTheStoreReachesTheName(
            "$b = 'a'; (Get-Variable b).Value = 'b'; Write-Output $b",
            'b',
            [['b']],
            [['a']],
        )

    def test_a_value_handed_out_alone_is_not_the_variable(self):
        tree = self._deobfuscated_tree(
            "$b = 'a'; $v = Get-Variable b -ValueOnly; $v = 'x'; Write-Output $b")
        self._assertWrites(tree, [['a']], [['x']], _stores_value(tree, 'b', 'a'))


class TestPs1APatternAddressesEveryVariableItMatches(_Ps1Ledger):

    def test_a_variable_a_removal_pattern_matches_is_removed(self):
        tree = self._deobfuscated_tree("$x = 'a'; Remove-Variable x*; Write-Output $x")
        self._assertWrites(tree, [[None]], [['a']], bool(_occurrences(tree, 'x')))


class TestPs1AStoreAListingOfEveryVariableReadsIsKept(_Ps1Ledger):

    def test_a_store_a_folded_subexpression_makes_survives_a_listing_that_reads_it(self):
        tree = self._deobfuscated_tree(
            "$x = $($y = 'a'; 'v'); Write-Output $x; "
            "Write-Output ((Get-Variable | Where-Object Name -eq 'y').Value)")
        self.assertTrue(_stores_value(tree, 'y', 'a'), 'the store the listing reads was removed')


class TestPs1AStoreCodeNobodyCanReadMayReadIsKept(_Ps1Ledger):

    def test_a_store_the_payload_reads_survives_the_reads_the_source_spells(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; Write-Host $x; $c = @('Write-Host $x')[(Get-Random -Maximum 1)]; iex $c")
        self.assertTrue(_stores_value(tree, 'x', 'a'), 'the store the payload reads was removed')


class TestPs1TheSessionStateReadsWritesAndRemovesAVariableByName(_Ps1Ledger):

    def test_a_read_by_name_writes_the_store_it_observes(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; Write-Output $ExecutionContext.SessionState.PSVariable.GetValue('x')")
        self._assertWrites(tree, [['a']], [[None]], _stores_value(tree, 'x', 'a'))

    def test_a_store_by_name_through_the_kept_session_state_is_seen(self):
        self._assertTheStoreReachesTheName(
            "$b = 'a'; $p = $ExecutionContext.SessionState.PSVariable; $p.Set('b', 'b'); "
            'Write-Output $b',
            'b',
            [['b']],
            [['a']],
        )

    def test_a_removal_by_name_is_seen(self):
        self._assertTheStoreReachesTheName(
            "$b = 'a'; $ExecutionContext.SessionState.PSVariable.Remove('b'); Write-Output $b",
            'b',
            [[None]],
            [['a']],
        )


class TestPs1AMultiAssignmentSlotHoldsTheElementOppositeIt(_Ps1Ledger):

    def test_a_slot_given_an_element_is_not_a_second_name_for_the_array(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $b, $c = $x; [Array]::Reverse($x); Write-Output $b',
            'b',
            [[1]],
            [[3, 2, 1]],
        )

    def test_a_slot_opposite_a_name_is_a_second_name_for_its_array(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $b, $c = $x, 5; $b[0] = 9; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_a_slot_beside_a_store_into_a_container_is_not_handed_the_whole_value(self):
        tree = self._deobfuscated_tree(
            "$h = @{}; $a, $h['k'] = 1, 2; Write-Output $a; Write-Output $h['k']")
        self._assertWrites(tree, [[1], [2]], [[1, 2], [2]], bool(_stores(tree, 'a')))


class TestPs1AnExpressionThatGivesBackItsOperandHandsOnTheArray(_Ps1Ledger):

    def test_an_array_subexpression_around_a_cast_hands_on_the_array(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $y = @([object[]]$x); $y[0] = 9; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_reversing_an_array_subexpression_around_a_cast_reverses_the_array(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; [Array]::Reverse(@([object[]]$x)); Write-Output $x',
            'x',
            [[3, 2, 1]],
            [[1, 2, 3]],
        )

    def test_reversing_an_array_subexpression_around_a_typed_local_is_kept(self):
        tree = self._deobfuscated_tree(
            'function f { [object[]]$a = 1, 2; [Array]::Reverse(@($a)); Write-Output $a }; f')
        self._assertWrites(tree, [[2, 1]], [[1, 2]], bool(_static_calls(tree, 'array', 'reverse')))

    def test_a_product_by_one_hands_on_the_array(self):
        self._assertTheStoreReachesTheName(
            '$y = 1, 2; $z = $y * 1; $z[0] = 9; Write-Output $y',
            'y',
            [[9, 2]],
            [[1, 2]],
        )

    def test_reversing_a_product_by_one_reverses_the_array(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; [Array]::Reverse($x * 1); Write-Output $x',
            'x',
            [[3, 2, 1]],
            [[1, 2, 3]],
        )

    def test_reversing_a_product_by_one_of_a_value_read_at_run_time_is_kept(self):
        tree = self._deobfuscated_tree(
            '$x = @(Get-Random -Maximum 1), 2, 3; [Array]::Reverse($x * 1); Write-Output $x')
        self._assertWrites(
            tree, [[3, 2, 0]], [[0, 2, 3]], bool(_static_calls(tree, 'array', 'reverse')))


class TestPs1CodeNobodyCanReadRunElsewhereStillReachesTheArray(_Ps1Ledger):

    def test_a_called_function_reaches_the_container(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $h = @{ k = $x }; $c = @('$h.k[0] = 9')[(Get-Random -Maximum 1)]; "
            'function f { iex $c }; f; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_a_called_function_reaches_the_second_name(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $y = $x; $c = @('$y[0] = 9')[(Get-Random -Maximum 1)]; "
            'function f { iex $c }; f; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_a_called_function_reaches_the_array_a_block_wrote_out(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $y = & { ,$x }; $c = @('$y[0] = 9')[(Get-Random -Maximum 1)]; "
            'function f { iex $c }; f; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_code_after_a_block_reaches_the_array_the_block_wrote_out(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $y = & { ,$x }; $c = @('$y[0] = 9')[(Get-Random -Maximum 1)]; iex $c; "
            'Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_a_created_block_reaches_the_container(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $h = @{ k = $x }; $c = @('$h.k[0] = 9')[(Get-Random -Maximum 1)]; "
            '$s = [scriptblock]::Create($c); & $s; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_invoke_script_reaches_the_container(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $h = @{ k = $x }; $c = @('$h.k[0] = 9')[(Get-Random -Maximum 1)]; "
            '$ExecutionContext.InvokeCommand.InvokeScript($c) | Out-Null; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_invoke_command_reaches_the_container(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $h = @{ k = $x }; $c = @('$h.k[0] = 9')[(Get-Random -Maximum 1)]; "
            '$s = [scriptblock]::Create($c); Invoke-Command -ScriptBlock $s; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_a_block_created_in_a_called_function_reaches_the_container(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $h = @{ k = $x }; function f { & ([scriptblock]::Create($c)) }; "
            "$c = @('$h.k[0] = 9')[(Get-Random -Maximum 1)]; f; Write-Output $x",
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )


class TestPs1CodeNobodyCanReadRunElsewhereMaySetAScriptVariable(_Ps1Ledger):

    @backlog
    def test_a_called_function_sets_the_script_variable(self):
        self._assertTheStoreReachesTheName(
            "$x = 'a'; function f { iex $c }; $c = @('$script:x = 5')[(Get-Random -Maximum 1)]; f; "
            'Write-Output $x',
            'x',
            [[5]],
            [['a']],
        )

    @backlog
    def test_a_created_block_sets_the_script_variable(self):
        self._assertTheStoreReachesTheName(
            "$x = 'a'; $c = @('$script:x = 5')[(Get-Random -Maximum 1)]; "
            '& ([scriptblock]::Create($c)); Write-Output $x',
            'x',
            [[5]],
            [['a']],
        )

    def test_a_called_function_stores_through_the_callers_array(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $c = @('$x[0] = 9')[(Get-Random -Maximum 1)]; "
            'function f { iex $c }; f; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    @backlog
    def test_a_created_block_stores_through_the_callers_array(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $c = @('$x[0] = 9')[(Get-Random -Maximum 1)]; "
            '& ([scriptblock]::Create($c)); Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    @backlog
    def test_a_called_function_stores_through_the_callers_array_before_an_element_is_read(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $c = @('$x[1] = 9')[(Get-Random -Maximum 1)]; "
            'function f { iex $c }; f; Write-Output $x[1]',
            'x',
            [[9]],
            [[2]],
        )


class TestPs1ACommandCodeNobodyCanReadRedefinedRunsThatCode(_Ps1Ledger):

    @backlog
    def test_a_redefined_command_sets_the_script_variable(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; $c = @('function Write-Host { $script:x = 5 }')[(Get-Random -Maximum 1)]; "
            "iex $c; $x = 'b'; Write-Host 'hi'; Write-Output $x")
        self._assertWrites(tree, [[5]], [['b']], _stores_value(tree, 'x', 'b'))

    @backlog
    def test_a_redefined_command_reaches_the_container(self):
        self._assertTheStoreReachesTheName(
            "$c = @('function Write-Host { $h.k[0] = 9 }')[(Get-Random -Maximum 1)]; iex $c; "
            "$x = 1, 2, 3; $h = @{ k = $x }; Write-Host 'hi'; Write-Output $x",
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )


class TestPs1AKeeperOfTheArrayIsReachedByCodeNobodyCanRead(_Ps1Ledger):

    def test_a_note_property_added_through_the_pipeline_keeps_the_array(self):
        self._assertTheStoreReachesTheName(
            "$o = New-Object PSObject; $x = 1, 2, 3; $o | Add-Member -NotePropertyName k "
            "-NotePropertyValue $x; $c = @('$o.k[0] = 9')[(Get-Random -Maximum 1)]; iex $c; "
            'Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_a_note_property_added_to_an_argument_keeps_the_array(self):
        self._assertTheStoreReachesTheName(
            "$o = New-Object PSObject; $x = 1, 2, 3; "
            'Add-Member -InputObject $o -NotePropertyName k '
            "-NotePropertyValue $x; $c = @('$o.k[0] = 9')[(Get-Random -Maximum 1)]; iex $c; "
            'Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_a_property_bag_keeps_the_array(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $o = New-Object PSObject -Property @{ k = $x }; "
            "$c = @('$o.k[0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x",
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_a_list_filled_through_for_each_object_keeps_the_array(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $l = New-Object Collections.ArrayList; "
            ",$l | ForEach-Object -MemberName Add -ArgumentList (,$x) | Out-Null; "
            "$c = @('$l[0][0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x",
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_a_list_filled_by_its_add_method_keeps_the_array(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $l = New-Object Collections.ArrayList; [void]$l.Add($x); "
            "$c = @('$l[0][0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x",
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_a_list_adapter_keeps_the_array(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $w = [Collections.ArrayList]::Adapter($x); "
            "$c = @('$w[0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x",
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_the_application_domain_keeps_the_array(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; [AppDomain]::CurrentDomain.SetData('k', $x); "
            "$c = @('[AppDomain]::CurrentDomain.GetData(''k'')[0] = 9')[(Get-Random -Maximum 1)]; "
            'iex $c; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_sort_object_handed_the_array_as_input_hands_it_back(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $y = Sort-Object -InputObject $x; "
            "$c = @('$y[0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x",
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )


class TestPs1AMethodOfAKeeperChangesTheArrayItKeeps(_Ps1Ledger):

    def test_reversing_the_adapter_reverses_the_array(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $w = [Collections.ArrayList]::Adapter($x); $w.Reverse(); '
            'Write-Output $x',
            'x',
            [[3, 2, 1]],
            [[1, 2, 3]],
        )


class TestPs1AStoreReachesEveryArrayItsNameMayHold(_Ps1Ledger):

    def _assertTheStoreReaches(self, source: str) -> None:
        self._assertTheStoreReachesTheName(source, 'x', [[9, 2, 3]], [[1, 2, 3]])

    def test_a_multi_assignment_slot_holds_the_array_opposite_it(self):
        self._assertTheStoreReaches('$x = 1, 2, 3; $a, $b = 0, $x; $b[0] = 9; Write-Output $x')

    def test_a_store_two_steps_into_the_last_multi_assignment_slot(self):
        self._assertTheStoreReaches(
            '$x = 1, 2, 3; $a, $b = 0, $x, 5; $b[0][0] = 9; Write-Output $x')

    def test_a_function_body_stores_through_the_variable_of_its_caller(self):
        self._assertTheStoreReaches(
            '$x = 1, 2, 3; function f { $o[0] = 9 }; function g($p) { $o = $p; f }; $o = 0, 0; '
            'g $x; Write-Output $x')

    def test_a_function_body_that_may_not_rebind_stores_through_the_variable_of_its_caller(self):
        self._assertTheStoreReaches(
            '$x = 1, 2, 3; function f { if ((Get-Random -Maximum 1) -eq 1) { $o = 0, 0 }; '
            '$o[0] = 9 }; function g($p) { $o = $p; f }; g $x; Write-Output $x')

    def test_a_chained_assignment_gives_every_name_in_it_the_array(self):
        self._assertTheStoreReaches('$x = 1, 2, 3; $a = $b = $x; $a[0] = 9; Write-Output $x')

    def test_a_callee_handed_the_variable_stores_through_it(self):
        self._assertTheStoreReaches(
            '$x = 1, 2, 3; function f([ref]$r) { $r.Value[0] = 9 }; f ([ref]$x); Write-Output $x')

    def test_a_rebinding_in_a_dot_sourced_block_hands_on_the_array(self):
        self._assertTheStoreReaches(
            '$x = 1, 2, 3; $y = 0, 0; . { $y = $x }; $y[0] = 9; Write-Output $x')

    def test_a_rebinding_on_a_branch_that_may_run_hands_on_the_array(self):
        self._assertTheStoreReaches(
            '$x = 1, 2, 3; $y = 0, 0; if ((Get-Random -Maximum 1) -eq 0) { $y = $x }; '
            '$y[0] = 9; Write-Output $x')

    def test_a_store_two_steps_into_a_table_reaches_the_array_it_holds(self):
        self._assertTheStoreReaches(
            '$x = 1, 2, 3; $h = @{ k = @{ j = $x } }; $h.k.j[0] = 9; Write-Output $x')


class TestPs1ABareReadInAFunctionBodyFindsTheVariableOfItsCaller(_Ps1Ledger):

    def test_the_read_is_not_answered_with_the_script_variable(self):
        tree = self._deobfuscated_tree(
            "function f { $script:o = 'a'; Write-Output $o }; function g { $o = 'b'; f }; g")
        self._assertWrites(tree, [['b']], [['a']], _stores_value(tree, 'o', 'b'))


class TestPs1AStoreIsPlacedAgainstEveryObjectItsNameMayHold(_Ps1Ledger):

    def test_a_block_rebinding_the_name_in_the_statement_of_the_store_hands_it_the_array(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $b = 7, 8; $null = (. { $b = $x }), ($b[0] = 9); Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_a_call_around_an_assignment_changes_the_array_the_assignment_stored(self):
        self._assertTheStoreReachesTheName(
            '[Array]::Reverse(($x = 1, 2, 3)); Write-Output $x',
            'x',
            [[3, 2, 1]],
            [[1, 2, 3]],
        )

    def test_a_member_the_source_does_not_name_is_the_entry_of_the_table(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $h = @{ k = $x }; $n = @('k')[(Get-Random -Maximum 1)]; "
            '$h.$n[0] = 9; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_a_key_of_a_table_answers_before_the_property_it_shadows(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $h = @{ SyncRoot = $x }; $h.SyncRoot[0] = 9; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_a_body_run_for_the_next_object_stores_into_the_array_the_last_one_kept(self):
        self._assertTheStoreReachesTheName(
            '$all = @(); 1..2 | ForEach-Object { if ($h) { $h.k[0] = 9 }; $x = 1, 2, 3; '
            '$h = @{ k = $x }; $all += ,$x }; Write-Output $all[0]',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_the_pipeline_variable_of_a_switch_is_the_element_its_clause_runs_for(self):
        self._assertTheStoreReachesTheName(
            '$_ = 0, 0; $x = 1, 2, 3; switch (,$x) { default { $_[0] = 9 } }; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )

    def test_each_name_of_a_chain_holds_the_array_whatever_is_read_off_the_chain(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $w = ($z = $y = $x)[0]; $z[0] = 9; Write-Output $x',
            'x',
            [[9, 2, 3]],
            [[1, 2, 3]],
        )


class TestPs1AVariableHandedOutUnderAnySpellingIsWrittenThroughIt(_Ps1Ledger):

    def test_a_variable_on_a_path_rooted_at_the_drive_is_written_through(self):
        self._assertTheStoreReachesTheName(
            "$x = 'a'; $v = Get-Item variable:\\x; $v.Value = 'b'; Write-Output $x",
            'x',
            [['b']],
            [['a']],
        )

    def test_a_variable_handed_out_by_a_value_only_switch_turned_off_is_written_through(self):
        self._assertTheStoreReachesTheName(
            "$x = 'a'; $v = Get-Variable x -ValueOnly:$false; $v.Value = 'b'; Write-Output $x",
            'x',
            [['b']],
            [['a']],
        )

    def test_a_qualified_holder_of_the_session_state_writes_the_name(self):
        self._assertTheStoreReachesTheName(
            "$x = 'a'; $global:ExecutionContext.SessionState.PSVariable.Set('x', 'b'); "
            'Write-Output $x',
            'x',
            [['b']],
            [['a']],
        )

    def test_a_variable_picked_out_of_a_listing_of_the_drive_root_is_written_through(self):
        self._assertTheStoreReachesTheName(
            "$x = 'a'; $v = Get-ChildItem variable:\\; "
            "($v | Where-Object Name -eq 'x').Value = 'b'; Write-Output $x",
            'x',
            [['b']],
            [['a']],
        )

    def test_a_store_into_the_value_in_a_slot_of_a_multi_assignment_writes_the_name(self):
        self._assertTheStoreReachesTheName(
            "$b = 'a'; $a, $ExecutionContext.SessionState.PSVariable.Get('b').Value = 1, 2; "
            'Write-Output $b',
            'b',
            [[2]],
            [['a']],
        )

    def test_a_reference_kept_in_a_variable_writes_the_name(self):
        self._assertTheStoreReachesTheName(
            "$y = 'x'; $r = [ref]$y; $y = 'a'; $r.Value = 'b'; Write-Output $y",
            'y',
            [['b']],
            [['a']],
        )

    def test_a_read_of_the_session_state_writes_the_store_it_reads(self):
        tree = self._deobfuscated_tree(
            "$b = 'a'; Write-Output $ExecutionContext.SessionState.PSVariable.GetValue('b'); "
            "$b = 'c'; Write-Output $b")
        self._assertWrites(tree, [['a'], ['c']], [['c'], ['c']], _stores_value(tree, 'b', 'a'))

    def test_a_variable_named_after_the_drive_is_spelled_is_written_through(self):
        self._assertTheStoreReachesTheName(
            "$x = 'a'; $n = @('x')[(Get-Random -Maximum 1)]; $v = Get-Item \"variable:$n\"; "
            "$v.Value = 'b'; Write-Output $x",
            'x',
            [['b']],
            [['a']],
        )

    def test_a_read_of_a_variable_named_after_the_drive_is_spelled_keeps_the_store(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; $n = @('x')[(Get-Random -Maximum 1)]; "
            "Write-Output (Get-Item \"variable:$n\").Value")
        self.assertTrue(_stores_value(tree, 'x', 'a'))


class TestPs1ACommandInAnotherScopeRemovesOrCopiesTheVariableItNames(_Ps1Ledger):

    def _assertTheReadIsNotTheRemovedValue(self, source: str) -> None:
        tree = self._deobfuscated_tree(source)
        self.assertNotIn(['a'], _output_writes(tree), 'the read was folded to the removed value')

    @backlog
    def test_the_session_state_removes_the_variable_of_the_function_s_caller(self):
        self._assertTheReadIsNotTheRemovedValue(
            "$x = 'a'; function f { $ExecutionContext.SessionState.PSVariable.Remove('x') }; f; "
            'Write-Output $x')

    @backlog
    def test_the_session_state_removes_the_variable_of_the_block_s_caller(self):
        self._assertTheReadIsNotTheRemovedValue(
            "$x = 'a'; & { $ExecutionContext.SessionState.PSVariable.Remove('x') }; "
            'Write-Output $x')

    @backlog
    def test_remove_item_removes_the_variable_of_the_function_s_caller(self):
        self._assertTheReadIsNotTheRemovedValue(
            "$x = 'a'; function f { Remove-Item variable:x }; f; Write-Output $x")

    def test_copy_item_writes_the_variable_it_copies_onto(self):
        tree = self._deobfuscated_tree(
            "$y = 'b'; $x = 'a'; Copy-Item variable:y variable:x; Write-Output $x")
        self._assertWrites(tree, [['b']], [['a']], _stores_value(tree, 'y', 'b'))

    def test_rename_item_reads_the_variable_it_renames(self):
        tree = self._deobfuscated_tree(
            "$y = 'b'; $x = 'a'; Remove-Variable x; Rename-Item variable:y x; Write-Output $x")
        self._assertWrites(tree, [['b']], [[None]], _stores_value(tree, 'y', 'b'))


class TestPs1AVariableHandedOutInAFunctionIsTheCallers(_Ps1Ledger):

    @backlog
    def test_an_increment_through_the_variable_a_function_is_handed_is_the_caller_s(self):
        tree = self._deobfuscated_tree(
            '$c = 1; function f { (Get-Variable c).Value++ }; f; Write-Output $c')
        self._assertWrites(tree, [[2]], [[1]], bool(_invocations(tree, _GET_VARIABLE)))

    def test_the_variable_an_output_variable_keeps_is_still_filled(self):
        tree = self._deobfuscated_tree(
            "$x = 'a'; Write-Output (Get-Variable x -OutVariable v).Value; Write-Output $v.Name")
        self.assertTrue(
            any(_binds(command, 'outvariable') for command in _commands(tree))
            or _output_writes(tree) == [['a'], ['x']],
            'nothing left in the output fills $v',
        )


class TestPs1AnErrorPreferenceSetByNameIsStillHandled(_Ps1Ledger):

    def _assertTheFailureIsStillHandled(self, source: str) -> None:
        tree = self._deobfuscated_tree(source)
        self.assertTrue(
            [node for node in tree.walk() if isinstance(node, Ps1TrapStatement)]
            or not [node for node in tree.walk() if isinstance(node, Ps1CastExpression)],
            'the trap that handles the failed conversion was removed while the conversion stayed',
        )
        self.assertIn(['after'], _output_writes(tree), 'the statement the trap resumes into went')

    def test_a_preference_the_session_state_sets_is_one_a_trap_handles(self):
        self._assertTheFailureIsStillHandled(
            "$ExecutionContext.SessionState.PSVariable.Set('ErrorActionPreference', 'Stop'); "
            "trap { continue }; Write-Output ([int]'a'); Write-Output 'after'"
        )

    @backlog
    def test_a_preference_set_through_the_handed_out_variable_is_one_a_trap_handles(self):
        self._assertTheFailureIsStillHandled(
            "$v = Get-Variable ErrorActionPreference; $v.Value = 'Stop'; trap { continue }; "
            "Write-Output ([int]'a'); Write-Output 'after'"
        )


class TestPs1AStoreACaughtErrorCutsShortIsTheOneObserved(_Ps1Ledger):

    def test_the_store_above_the_failure_is_observed_after_the_catch(self):
        tree = self._deobfuscated_tree(
            "$y = 'w'; try { $y = 'x'; [int]'a'; $y = 'v' } catch {}; Write-Output $y")
        self._assertWrites(tree, [['x']], [['w']], _stores_value(tree, 'y', 'x'))


class TestPs1AStoreNoOccurrenceOfTheNameSpellsIsStillSeen(_Ps1Ledger):

    def _assertTheStoreReaches(self, source: str, written: int, corrupt: int) -> None:
        self._assertTheStoreReachesTheName(source, 'x', [[written]], [[corrupt]])

    @backlog
    def test_code_nobody_can_read_in_a_child_block_stores_through_the_array(self):
        self._assertTheStoreReaches(
            "$x = 1, 2, 3; $c = @('$x[1] = 9')[(Get-Random -Maximum 1)]; & { iex $c }; "
            'Write-Output $x[1]',
            9, 2)

    @backlog
    def test_code_nobody_can_read_run_by_invoke_script_stores_through_the_array(self):
        self._assertTheStoreReaches(
            "$x = 1, 2, 3; $c = @('$x[1] = 9')[(Get-Random -Maximum 1)]; "
            '$ExecutionContext.InvokeCommand.InvokeScript($c) | Out-Null; Write-Output $x[1]',
            9, 2)

    @wontfix(
        'no script or obfuscator stores an array element by calling SetValue by name through '
        'ForEach on a comma-wrapped array'
    )
    def test_set_value_invoked_by_name_through_for_each_stores_into_the_array(self):
        self._assertTheStoreReaches(
            "$x = 1, 2, 3; (,$x).ForEach('SetValue', 9, 0); Write-Output $x[0]", 9, 1)

    @wontfix(
        'no script or obfuscator stores an array element by naming SetValue as the member '
        'ForEach-Object calls on a comma-wrapped array'
    )
    def test_set_value_invoked_by_name_through_for_each_object_stores_into_the_array(self):
        self._assertTheStoreReaches(
            '$x = 1, 2, 3; ,$x | ForEach-Object SetValue 9 0; Write-Output $x[0]', 9, 1)

    @wontfix(
        'no script or obfuscator stores into an array through the getter of its SyncRoot property'
    )
    def test_a_store_through_the_array_its_getter_hands_back_stores_into_it(self):
        self._assertTheStoreReaches(
            '$x = 1, 2, 3; $x.get_SyncRoot()[0] = 9; Write-Output $x[0]', 9, 1)

    @wontfix(
        'no script or obfuscator wraps an array in an ArrayList adapter to store one element '
        'through its setter'
    )
    def test_the_setter_of_an_adapter_stores_into_the_array_it_wraps(self):
        self._assertTheStoreReaches(
            '$x = 1, 2, 3; [Collections.ArrayList]::Adapter($x).set_Item(0, 9); '
            'Write-Output $x[0]',
            9, 1)

    @wontfix(
        'a join separator computed by a block that changes the joined array through a hashtable '
        'only shows evaluation order; no script writes it'
    )
    def test_the_right_operand_of_a_join_stores_into_the_array_the_left_one_named(self):
        source = "$x = 1, 2, 3; $h = @{ k = $x }; Write-Output ($x -join (& { $h.k[0] = 9; ',' }))"
        tree = self._deobfuscated_tree(source)
        kept = len(_occurrences(tree, 'x')) >= len(_occurrences(Ps1Parser(source).parse(), 'x'))
        self._assertWrites(tree, [['9,2,3']], [['1,2,3']], kept)


class TestPs1ABodyReadsTheNameItsCallerBinds(_Ps1Ledger):

    def test_a_function_called_from_a_block_writes_the_block_s_variable(self):
        tree = self._deobfuscated_tree("function f { $x }; & { $x = 'a'; f }")
        written = [
            _literal_value(node.expression) for node in tree.walk()
            if isinstance(node, Ps1ExpressionStatement)
        ]
        self.assertTrue(
            'a' in written or bool(_invocations(tree, frozenset({'f'}))),
            'nothing left in the output can write a',
        )

    def test_a_switch_clause_reads_the_value_it_runs_for(self):
        tree = self._deobfuscated_tree('$_ = 5; switch (1) { default { Write-Output $_ } }')
        self._assertWrites(
            tree,
            [[1]],
            [[5]],
            any(isinstance(node, Ps1SwitchStatement) for node in tree.walk()),
        )


class TestPs1ACopyIsToldApartFromTheArrayByItsIdentity(_Ps1Ledger):

    @wontfix(
        'only a reference-identity test tells the inlined copy from the array, and no script or '
        'obfuscator tests array identity'
    )
    def test_the_same_read_twice_is_the_same_array(self):
        self._assertTheIdentityIsKept(
            '$x = 1, 2; Write-Output ([object]::ReferenceEquals($x, $x))', 'x'
        )

    @wontfix(
        'only a reference-identity test tells the inlined copy from the array, and no script or '
        'obfuscator tests array identity'
    )
    def test_sort_object_hands_back_the_array_it_is_given_as_input(self):
        self._assertTheIdentityIsKept(
            '$x = 1, 2; $y = Sort-Object -InputObject $x; '
            'Write-Output ([object]::ReferenceEquals($x, $y))',
            'x',
        )

    @wontfix(
        'only a reference-identity test tells the inlined copy from the array, and no script or '
        'obfuscator tests array identity'
    )
    def test_the_application_domain_hands_back_the_array_it_keeps(self):
        self._assertTheIdentityIsKept(
            "$x = 1, 2; [AppDomain]::CurrentDomain.SetData('k', $x); "
            "Write-Output ([object]::ReferenceEquals($x, [AppDomain]::CurrentDomain.GetData('k')))",
            'x',
        )

    @wontfix(
        'only a reference-identity test tells the inlined copy from the array, and no script or '
        'obfuscator tests array identity'
    )
    def test_a_product_by_one_is_the_array(self):
        self._assertTheIdentityIsKept(
            '$y = 1, 2; $z = $y * 1; Write-Output ([object]::ReferenceEquals($y, $z))', 'y'
        )

    @wontfix(
        'only a reference-identity test tells the inlined copy from the array, and no script or '
        'obfuscator tests array identity'
    )
    def test_a_product_by_a_count_that_is_one_at_run_time_is_the_array(self):
        self._assertTheIdentityIsKept(
            '$y = 1, 2; $n = 1; $z = $y * $n; Write-Output ([object]::ReferenceEquals($y, $z))',
            'y',
        )

    @wontfix(
        'only a reference-identity test tells the inlined copy from the array, and no script or '
        'obfuscator tests array identity'
    )
    def test_a_product_by_a_count_that_converts_to_one_is_the_array(self):
        self._assertTheIdentityIsKept(
            '$y = 1, 2; $z = $y * 1.4; Write-Output ([object]::ReferenceEquals($y, $z))', 'y'
        )

    @wontfix(
        'only a reference-identity test tells the inlined copy from the array, and no script or '
        'obfuscator tests array identity'
    )
    def test_an_array_subexpression_around_a_cast_is_the_array(self):
        self._assertTheIdentityIsKept(
            '$x = 1, 2, 3; $b = @(([object[]]$x)); '
            'Write-Output ([object]::ReferenceEquals($x, $b))',
            'x',
        )

    @wontfix(
        'only a reference-identity test tells the inlined copy from the array, and no script or '
        'obfuscator tests array identity'
    )
    def test_the_one_element_of_a_multi_assignment_is_the_array(self):
        self._assertTheIdentityIsKept(
            '$x = 1, 2, 3; $a, $b = ,$x; Write-Output ([object]::ReferenceEquals($x, $a))', 'x'
        )

    @wontfix(
        'only a reference-identity test tells the inlined copy from the array, and no script or '
        'obfuscator tests array identity'
    )
    def test_adding_the_array_onto_null_is_the_array(self):
        self._assertTheIdentityIsKept(
            '$x = 1, 2, 3; $b = $null; $b += $x; Write-Output ([object]::ReferenceEquals($x, $b))',
            'x',
        )


class TestPs1TextRunAfterTheAcceleratorTableChangesStaysText(_Ps1Ledger):

    def _assertStaysText(self, source: str) -> None:
        tree = self._deobfuscated_tree(source)
        self.assertTrue(
            any(
                isinstance(node, Ps1CommandInvocation)
                and isinstance(node.name, Ps1StringLiteral)
                and node.name.value.lower() in ('iex', 'invoke-expression')
                for node in tree.walk()
            ),
            'the text was written into the script',
        )

    @wontfix(
        'no script or obfuscator registers a type accelerator under the full name of an existing '
        '.NET type'
    )
    def test_a_type_name_in_the_text_is_resolved_after_the_write(self):
        self._assertStaysText(
            "[psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')::Add('System.Math', [string]); "
            "iex 'Write-Host ([System.Math].FullName)'")

    @wontfix(
        'no script or obfuscator registers a type accelerator under the full name of an existing '
        '.NET type'
    )
    def test_a_call_in_the_text_fails_on_the_type_the_write_names(self):
        self._assertStaysText(
            "[psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')::Add('System.Math', [string]); "
            "iex 'try { throw ''x'' } catch { $k = [System.Math]::Sqrt(36); Write-Host ''rest'' }; Write-Host ''after'''")


class TestPs1ABase64TextDotNetRejectsIsNotDecoded(_Ps1Ledger):

    def test_the_call_on_a_text_holding_a_foreign_character_is_not_folded(self):
        tree = self._deobfuscated_tree(
            "Write-Host ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SGVs!bG8=')))")
        self.assertNotIn('Hello', _printed_values(tree))

    def test_a_call_that_fails_on_its_text_still_skips_the_store_behind_it(self):
        tree = self._deobfuscated_tree(
            "$k = 'one'; try { $b = [Convert]::FromBase64String('!!'); $k = 'two' } catch { }; "
            'Write-Host $k'
        )
        printed = _printed_values(tree)
        self.assertNotIn('two', printed, 'the read was folded to the store the failure skips')
        self.assertTrue(
            'one' in printed or _static_calls(tree, 'convert', 'frombase64string'),
            'the failing call was dropped and nothing prints the value it leaves behind',
        )
