"""
A ledger of scripts whose behaviour under real Windows PowerShell 5.1 is known, checked against
what the deobfuscator leaves of them.

Every entry pairs one small script with a measured 5.1 observation and asserts that the emitted
script can still produce it. The assertions are made over the *re-parsed* output rather than over
its text, because the failure being watched for is a silent change of meaning: a store deleted that
a later read needed, or a read folded to a value PowerShell would not have had. A substring check
cannot tell a surviving store from a coincidence, and nothing in the output marks such a change, so
an analyst reading it would never see one.

The docstring of each test carries what PowerShell 5.1 actually does, so a failure can be read
without leaving this file.

An entry marked `expectedFailure` is a defect the tool still has. That marking is a ratchet in both
directions: a fix makes the entry an unexpected success, which is reported as a failure until the
marking is removed, and a regression makes an unmarked entry fail outright. Neither direction can
pass silently, which is what the substring table this file replaces could not manage — it scored
entries on literals they did not contain, so a closed entry could reopen against a green suite.

The scoping facts the entries rest on, all measured:

  - a called body reads its caller's variables by naming them, with no qualifier
  - writing a caller's variable needs `$script:`, `$global:` or a dot-invocation
  - `Invoke-Expression` runs a string that may carry such a write, so it may change any variable
  - a script block is not a closure: it reads the variables of whoever invokes it
"""
from __future__ import annotations

import unittest

from typing import NamedTuple

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
    Ps1InputRedirection,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1Jump,
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
    Ps1TrapStatement,
    Ps1TryCatchFinally,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser

_WRITE_HOST = frozenset({'write-host'})
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
    """
    `node` with every wrapper that changes nothing about the value removed: parentheses,
    single-statement subexpressions and single-element pipelines.
    """
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
    """
    The constant `node` denotes, or `None` when it denotes no constant. A cast is not looked
    through, since it changes the value.
    """
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


def _stores(root: Node, key: str) -> list[Ps1AssignmentExpression]:
    return [
        node for node in root.walk()
        if isinstance(node, Ps1AssignmentExpression)
        and any(_binding_key(target) == key for target in _target_variables(node.target))
    ]


def _stores_value(root: Node, key: str, value) -> bool:
    return any(_literal_value(store.value) == value for store in _stores(root, key))


def _commands(root: Node) -> list[Ps1CommandInvocation]:
    return [node for node in root.walk() if isinstance(node, Ps1CommandInvocation)]


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


class _Redirection(NamedTuple):
    """
    What one redirection operator does, in a form two trees can be compared by. The operator's own
    class is part of it, so an operator reported as a different one cannot compare equal to the one
    that was written.
    """
    operator: type
    streams: tuple[Ps1RedirectionStream, ...]
    append: bool
    file: object


def _redirections(root: Node) -> list[_Redirection]:
    """
    Every redirection operator in `root`, in the order the source spells them.
    """
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
    """
    Every dash-prefixed argument name of `command`, exactly as written. Case is kept: the spelling
    is the whole question for a native program, which receives the argument as text.
    """
    return [
        argument.name for argument in command.arguments
        if isinstance(argument, Ps1CommandArgument) and argument.name
    ]


def _binds(command: Ps1CommandInvocation, parameter: str) -> bool:
    """
    Whether `command` writes a parameter name that binds `parameter`, given in full, lowercased and
    without its dash. PowerShell binds any unambiguous abbreviation, so the written name is a
    prefix of the parameter.
    """
    return any(
        parameter.startswith(written)
        for name in _switch_spellings(command)
        if (written := name.lstrip('-').lower())
    )


def _passes_variable(root: Node, key: str) -> bool:
    """
    Whether some command invocation in `root` still receives the variable under `key` as an
    argument. Asked instead of matching the command's name, because a computed name such as
    `&('i' + 'ex')` is a legitimate rendering that no name lookup finds.
    """
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
    """
    The arguments every `Write-Host` in `root` receives. `nested` selects the invocations inside a
    script block (`True`) or the ones outside every script block (`False`).
    """
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


def _inside_short_circuit(node: Node) -> bool:
    """
    Whether `node` sits in the right operand of `-and` or `-or`, which is the position PowerShell
    may never evaluate.
    """
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
    """
    Whether anything in `root` gives the variable under `key` a value derived from its own: `$v++`,
    a compound assignment, or a plain assignment whose value reads the variable back.

    A `$v++` that begins a statement is re-read on its own when the parser left it standing as an
    unresolved command name, so that the answer is about the emitted PowerShell rather than about
    how much of it this parser resolved.
    """
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


class TestPs1Corruptions(TestPs1):
    """
    Each test deobfuscates one script to a fixpoint and asks whether the result still behaves the
    way PowerShell 5.1 was measured to behave. A failure is a report that the deobfuscator changed
    what the script does.
    """

    def _deobfuscated_tree(self, source: str) -> Ps1Script:
        return Ps1Parser(self._deobfuscate_iterative(source)).parse()

    def _assertPrints(self, tree: Ps1Script, key: str, printed: str, never: str) -> None:
        """
        The output must still be able to print `printed` for the variable under `key`: either that
        value is already folded into a `Write-Host` argument, or the store supplying it survives
        for the read to reach. `never` is the value the corrupted output prints in its place.
        """
        values = _printed_values(tree)
        self.assertNotIn(
            never, values, F'${key} was folded to {never!r}, which is not the value it holds')
        self.assertTrue(
            printed in values or _stores_value(tree, key, printed),
            F'nothing left in the output can give ${key} the value {printed!r}',
        )

    def test_dot_sourced_remove_variable_unsets_the_callers_variable(self):
        """
        `$x = 'a'; . { Remove-Variable x }; Write-Host $x` prints nothing under 5.1: a dot-invoked
        body writes the caller's scope, so the variable is gone by the time it is read.
        """
        tree = self._deobfuscated_tree("$x = 'a'; . { Remove-Variable x }; Write-Host $x")
        self.assertTrue(
            _invocations(tree, _REMOVE_VARIABLE),
            'the call that unsets the caller variable was dropped',
        )
        self.assertNotIn(
            'a', _printed_values(tree), 'the read was folded to the value the removal discarded')

    def test_dot_sourced_new_variable_replaces_the_callers_value(self):
        """
        `$x = 'a'; . { New-Variable x 'b' -Force }; Write-Host $x` prints `b` under 5.1, not `a`.
        """
        tree = self._deobfuscated_tree("$x = 'a'; . { New-Variable x 'b' -Force }; Write-Host $x")
        self.assertTrue(
            _invocations(tree, _NEW_VARIABLE),
            'the call that redefines the caller variable was dropped',
        )
        self.assertNotIn(
            'a', _printed_values(tree), 'the read was folded to the value that was overwritten')

    def test_dot_sourced_out_variable_overwrites_the_callers_variable(self):
        """
        `$x = 'a'; . { Get-Process -OutVariable x }; Write-Host $x` prints the process list under
        5.1: `-OutVariable` writes `$x` in the caller's scope, so it no longer holds `a`.
        """
        tree = self._deobfuscated_tree("$x = 'a'; . { Get-Process -OutVariable x }; Write-Host $x")
        self.assertTrue(
            [call for call in _invocations(tree, _GET_PROCESS) if _binds(call, 'outvariable')],
            'the call whose -OutVariable writes the caller variable was dropped',
        )
        self.assertNotIn(
            'a', _printed_values(tree), 'the read was folded past a write it cannot see')

    @unittest.expectedFailure
    def test_function_running_invoke_expression_may_write_the_callers_variable(self):
        """
        In `$x = 'a'; function f { iex $c }; f; Write-Host $x` the string `$c` may contain
        `$script:x = ...`, so under 5.1 `$x` need not still be `a` when it is read.
        """
        tree = self._deobfuscated_tree("$x = 'a'; function f { iex $c }; f; Write-Host $x")
        self.assertTrue(
            _passes_variable(tree, 'c'), 'the call that may write any variable was dropped')
        self.assertNotIn(
            'a', _printed_values(tree), 'the read was folded across a call that may rewrite it')

    @unittest.expectedFailure
    def test_computed_invoke_expression_name_may_write_the_callers_variable(self):
        """
        `$x = 'a'; &('i' + 'ex') $c; Write-Host $x` reaches `Invoke-Expression` through a computed
        command name, and under 5.1 the string it runs may store into `$x`.
        """
        tree = self._deobfuscated_tree("$x = 'a'; &('i' + 'ex') $c; Write-Host $x")
        self.assertTrue(
            _passes_variable(tree, 'c'), 'the call that may write any variable was dropped')
        self.assertNotIn(
            'a', _printed_values(tree), 'the read was folded across a call that may rewrite it')

    @unittest.expectedFailure
    def test_set_variable_global_supplies_the_value_that_is_read_back(self):
        """
        `Set-Variable global:y 'b'; Write-Host $global:y` prints `b` under 5.1, so the store is the
        only thing that gives the read a value.
        """
        tree = self._deobfuscated_tree("Set-Variable global:y 'b'; Write-Host $global:y")
        self.assertTrue(
            _invocations(tree, _SET_VARIABLE) or 'b' in _printed_values(tree),
            'the store was deleted and nothing left in the output supplies the value it wrote',
        )

    @unittest.expectedFailure
    def test_short_circuited_and_operand_never_stores(self):
        """
        `$x = 'a'; $false -and ($x = 'b'); Write-Host $x` prints `a` under 5.1: the right operand of
        `-and` is not evaluated when the left one is false, so the store of `b` never happens.
        """
        tree = self._deobfuscated_tree("$x = 'a'; $false -and ($x = 'b'); Write-Host $x")
        self._assertPrints(tree, 'x', 'a', 'b')
        for store in _stores(tree, 'x'):
            if _literal_value(store.value) == 'b':
                self.assertTrue(
                    _inside_short_circuit(store),
                    'the store from the unevaluated operand is now reached unconditionally',
                )

    @unittest.expectedFailure
    def test_array_sort_sorts_the_variable_in_place(self):
        """
        `$x = @('b', 'a'); [Array]::Sort($x); Write-Host $x[0]` prints `a` under 5.1: the call
        reorders the array the variable holds rather than returning a new one.
        """
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

    @unittest.expectedFailure
    def test_trap_with_continue_resumes_after_the_throw(self):
        """
        `trap { continue }; throw 'e'; Write-Host 'after'` prints `after` under 5.1: the trap
        handles the exception and `continue` resumes at the next statement.
        """
        tree = self._deobfuscated_tree("trap { continue }; throw 'e'; Write-Host 'after'")
        self.assertTrue(
            [node for node in tree.walk() if isinstance(node, Ps1TrapStatement)],
            'the handler that makes execution resume was removed',
        )
        self.assertIn(
            'after', _printed_values(tree), 'the statement the trap resumes into was removed')

    def test_parameter_default_may_write_a_runtime_computed_name(self):
        """
        In `function g($p = (Set-Variable $n 'v')) { }; $x = 'a'; Write-Host $x` the parameter
        default writes a variable whose name is only known at run time, so while that code is in
        the script 5.1 does not guarantee `$x` is still `a`.
        """
        tree = self._deobfuscated_tree(
            "function g($p = (Set-Variable $n 'v')) { }; $x = 'a'; Write-Host $x")
        self.assertFalse(
            _invocations(tree, _SET_VARIABLE) and 'a' in _printed_values(tree),
            'a write to a runtime-computed name survives, so the read below it cannot be folded',
        )

    @unittest.expectedFailure
    def test_child_scope_may_change_the_process_environment(self):
        """
        `& { iex $c }; Write-Host $env:ComSpec` gives no guarantee about what is printed under 5.1:
        environment variables are process-global and the invoked string may set them.
        """
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

    @unittest.expectedFailure
    def test_invoke_command_with_computername_runs_on_another_machine(self):
        """
        `Invoke-Command -Comp $h -ScriptBlock { 1 }` runs its block on the host named by `$h` under
        5.1. Splicing the block into the script makes it run locally instead.
        """
        tree = self._deobfuscated_tree('Invoke-Command -Comp $h -ScriptBlock { 1 }')
        self.assertTrue(
            [
                call for call in _invocations(tree, _INVOKE_COMMAND)
                if _binds(call, 'computername')
                and any(isinstance(v, Ps1ScriptBlock) for v in _argument_values(call))
            ],
            'the block was taken out of the remote invocation and now runs on this machine',
        )

    @unittest.expectedFailure
    def test_native_openssl_argument_spelling_survives(self):
        """
        `openssl enc -d -a -in x` invokes a native program, which receives `-in` as text.
        PowerShell does not complete parameter names for it, so nothing may rewrite the spelling.
        """
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

    @unittest.expectedFailure
    def test_native_executable_switch_spelling_survives(self):
        """
        `foo.exe -noprofile -file x` passes both switches to a native program as text, so neither
        may be respelled the way a PowerShell parameter would be.
        """
        tree = self._deobfuscated_tree('foo.exe -noprofile -file x')
        commands = _invocations(tree, frozenset({'foo.exe'}))
        self.assertEqual(len(commands), 1, 'the native command did not survive as one invocation')
        self.assertListEqual(
            _switch_spellings(commands[0]),
            ['-noprofile', '-file'],
            'an argument of a native program was rewritten to a PowerShell parameter name',
        )

    def test_bare_script_path_is_a_call_and_not_a_dot_source(self):
        R"""
        `.\a.ps1` runs the script in a scope of its own under 5.1: with `$x = 'CALLER'` in the
        caller and `$x = 'REPLACED'` in the script, the caller still reads `CALLER` afterwards,
        while `. .\a.ps1` leaves it reading `REPLACED`. The dot is the dot-source operator only
        where it stands apart from its target; joined to a path it is part of the command name.
        """
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
        """
        A dot where an argument goes is a path under 5.1, not the dot-source operator, which exists
        in command-name position only: `Copy-Item . dest` is one command holding `.` and `dest`.
        Measured with a function of each name defined, `probe . dest` reported `a=[.] b=[dest]`,
        ran nothing named `dest` and left the caller's `$x` at `CALLER`; split over two statements
        the way this is rewritten, the same script ran `dest` and let it replace `$x` through
        `$script:`, which is a write into the caller that 5.1 never makes.
        """
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
        R"""
        `C:\x\y.exe` is one command name under 5.1: with the file missing, the name it reports
        having looked for is the whole path, not `C` with `:` and `\x\y.exe` behind it.
        """
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
        """
        `Get-Content < in.txt > out.txt` does not compile under 5.1, which reports `The '<' operator
        is reserved for future use`. The operator moves nothing, and the command 5.1 builds keeps
        its name and its `> out.txt` redirection, so out.txt is the only file the script writes.
        A write to in.txt is one the script never performs.
        """
        writes = _file_writes(self._deobfuscated_tree('Get-Content < in.txt > out.txt'))
        self.assertEqual(
            writes,
            [_Redirection(Ps1FileRedirection, (Ps1RedirectionStream.OUTPUT,), False, 'out.txt')],
            'the reserved operator reads as a write to the file behind it',
        )

    def test_reserved_input_operator_neither_gains_nor_loses_a_redirection(self):
        """
        The redirections of the re-emitted script have to be the ones the input spells: `<` is
        reserved under 5.1 and `> out.txt` is the one write, however the script is written down.
        """
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
        """
        `% { Write-Host 1 }` is one command under 5.1, named `%`, which `Get-Alias` resolves to
        ForEach-Object, and the block is its argument. The tool writes the alias out in full as
        `ForEach-Object { ... }`, so this entry is asked of the output: read back as the loop
        keyword that name begins with, the same block is written again as `foreach ( in -Object)
        { ... }`, which 5.1 refuses to parse at all.
        """
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
        """
        `Exit-PSSession`, `Break-Glass` and `Return-Value` are command names under 5.1: a name runs
        to whitespace, so its tokenizer never produces `exit` from `Exit-PSSession`. Running
        `Exit-PSSession` outside a session left the script running, and a name of that shape which
        resolves to nothing is reported whole, as `Break-Glass` and `Return-Value` were.
        """
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
        """
        `ForEach-Object { Write-Host 1 }` is a command under 5.1 in every position, and it is what
        the deobfuscator itself writes for `% { Write-Host 1 }`. Read as the loop keyword instead,
        it is written back as `foreach ( in -Object) { ... }`, which 5.1 refuses to parse at all.
        """
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
        """
        5.1 refuses `try{foo}catch[System.Exception]{bar}` outright, with `The Try statement is
        missing its Catch or Finally block`: a command name runs to whitespace, so
        `catch[System.Exception]` is one name and the try is left without a clause. Nothing in the
        script runs, so reading a handler there would invent one 5.1 never has. Whitespace anywhere
        ahead of the block restores the clause: both `try{foo}catch{bar}` and the form spaced after
        the keyword, `try{foo}catch [System.Exception]{bar}`, catch under 5.1.

        Since 5.1 has no such statement, neither does the tree: a `try` carrying neither a `catch`
        nor a `finally` has no spelling, so the parser keeps the source it read as an error node
        rather than building a statement that would print back as a script 5.1 also refuses. What
        is asserted is therefore that no try statement is read at all, and that the text survives.
        """
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
        """
        `$x = 'a'; function f { Write-Host $x }; f; $x = 'c'` prints `a` under 5.1: the body reads
        the caller's `$x`, so the first store is live and the last one is never read.
        """
        tree = self._deobfuscated_tree("$x = 'a'; function f { Write-Host $x }; f; $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_child_scope_block_reads_the_callers_variable(self):
        """
        `$v = 'a'; & { Write-Host $v }; $v = 'c'` prints `a` under 5.1, for the same reason a
        function body does: an unqualified read resolves in the caller's scope.
        """
        tree = self._deobfuscated_tree("$v = 'a'; & { Write-Host $v }; $v = 'c'")
        self._assertPrints(tree, 'v', 'a', 'c')

    @unittest.expectedFailure
    def test_child_scope_block_reads_the_script_scoped_variable(self):
        """
        `$x = 'a'; & { Write-Host $script:x }; $x = 'b'` prints `a` under 5.1: the qualifier names
        the script scope, which is where the first store put the value.
        """
        tree = self._deobfuscated_tree("$x = 'a'; & { Write-Host $script:x }; $x = 'b'")
        self._assertPrints(tree, 'x', 'a', 'b')

    @unittest.expectedFailure
    def test_function_body_reads_the_script_scoped_variable(self):
        """
        `$x = 'a'; function f { Write-Host $script:x }; f; $x = 'b'` prints `a` under 5.1.
        """
        tree = self._deobfuscated_tree("$x = 'a'; function f { Write-Host $script:x }; f; $x = 'b'")
        self._assertPrints(tree, 'x', 'a', 'b')

    def test_script_block_invoked_before_the_second_store_reads_the_first(self):
        """
        `$x = 'a'; $sb = { Write-Host $x }; & $sb; $x = 'c'` prints `a` under 5.1: the block reads
        the value current when it is invoked, and it is invoked before the second store.
        """
        tree = self._deobfuscated_tree("$x = 'a'; $sb = { Write-Host $x }; & $sb; $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    @unittest.expectedFailure
    def test_script_block_invoked_after_the_second_store_reads_the_second(self):
        """
        `$x = 'a'; $sb = { Write-Host $x }; $x = 'c'; & $sb` prints `c` under 5.1. A script block is
        not a closure: it reads the value current at invocation, not the one current where it was
        written, so folding the read to `a` is what would be wrong here.
        """
        tree = self._deobfuscated_tree("$x = 'a'; $sb = { Write-Host $x }; $x = 'c'; & $sb")
        self._assertPrints(tree, 'x', 'c', 'a')

    def test_script_block_invoke_method_reads_the_callers_variable(self):
        """
        `$x = 'a'; $sb = { Write-Host $x }; $sb.Invoke(); $x = 'c'` prints `a` under 5.1; the method
        call runs the block just as the call operator does.
        """
        tree = self._deobfuscated_tree("$x = 'a'; $sb = { Write-Host $x }; $sb.Invoke(); $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_local_invoke_command_script_block_reads_the_callers_variable(self):
        """
        `$x = 'a'; Invoke-Command -ScriptBlock { Write-Host $x }; $x = 'c'` prints `a` under 5.1.
        """
        tree = self._deobfuscated_tree(
            "$x = 'a'; Invoke-Command -ScriptBlock { Write-Host $x }; $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_foreach_object_block_reads_the_callers_variable(self):
        """
        `$x = 'a'; 1..2 | ForEach-Object { Write-Host $x }; $x = 'c'` prints `a` twice under 5.1.
        """
        tree = self._deobfuscated_tree(
            "$x = 'a'; 1..2 | ForEach-Object { Write-Host $x }; $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_invoke_script_string_reads_the_callers_variable(self):
        """
        `$x = 'a'; $ExecutionContext.InvokeCommand.InvokeScript('Write-Host $x'); $x = 'c'` prints
        `a` under 5.1: the string is compiled and run, and the read inside it resolves to `$x`.
        """
        tree = self._deobfuscated_tree(
            "$x = 'a'; $ExecutionContext.InvokeCommand.InvokeScript('Write-Host $x'); $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    @unittest.expectedFailure
    def test_invoke_expression_string_reads_the_callers_variable(self):
        """
        `$x = 'a'; $c = 'Write-Host $x'; function f { iex $c }; f; $x = 'c'` prints `a` under 5.1:
        the string names `$x` and resolves it in the scope that runs it.
        """
        tree = self._deobfuscated_tree(
            "$x = 'a'; $c = 'Write-Host $x'; function f { iex $c }; f; $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    def test_get_variable_reads_the_caller_by_name(self):
        """
        `$x = 'a'; function f { Write-Host (Get-Variable x -ValueOnly) }; f; $x = 'c'` prints `a`
        under 5.1. The read is addressed by a string, so no `$x` mention marks the first store live.
        """
        tree = self._deobfuscated_tree(
            "$x = 'a'; function f { Write-Host (Get-Variable x -ValueOnly) }; f; $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    @unittest.expectedFailure
    def test_get_variable_wildcard_reads_without_naming_the_variable(self):
        """
        `$x = 'a'; Write-Host (Get-Variable x* | ForEach-Object Value); $x = 'c'` prints `a` under
        5.1. The pattern reads a whole set of variables without naming any one of them.
        """
        tree = self._deobfuscated_tree(
            "$x = 'a'; Write-Host (Get-Variable x* | ForEach-Object Value); $x = 'c'")
        self._assertPrints(tree, 'x', 'a', 'c')

    @unittest.expectedFailure
    def test_get_variable_call_is_a_read_of_the_preceding_store(self):
        """
        In `$x = 'a'; Get-Variable x; $x = 'c'` the middle statement emits the variable, so 5.1
        reads the first store and it is not dead.
        """
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

    @unittest.expectedFailure
    def test_invoke_expression_may_read_the_preceding_store(self):
        """
        In `$x = 'a'; iex $c; $x = 'c'` the string may name `$x`, so 5.1 may read the first store
        and it cannot be treated as overwritten before use.
        """
        tree = self._deobfuscated_tree("$x = 'a'; iex $c; $x = 'c'")
        self.assertTrue(
            _passes_variable(tree, 'c'), 'the call that may read any variable was dropped')
        self.assertTrue(
            _stores_value(tree, 'x', 'a'), 'the store that call may read was deleted as dead')

    def test_increment_in_child_scope_creates_a_local_copy(self):
        """
        `$v = 41; & { $v++; Write-Host $v }; Write-Host $v` prints `42` and then `41` under 5.1: the
        child scope reads the caller's value, and writing it creates a local of its own, so the
        caller still holds `41`.
        """
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
        """
        `$i = 0; $null = [int]::TryParse('42', [ref]$script:i); Write-Host $i` prints `42` under
        5.1: a `[ref]` over a real variable hands the callee storage it writes back through, and the
        scope qualifier does not change that.
        """
        tree = self._deobfuscated_tree(
            "$i = 0; $null = [int]::TryParse('42', [ref]$script:i); Write-Host $i")
        self.assertTrue(
            [
                call for call in _static_calls(tree, 'int', 'tryparse')
                if any(_is_reference_to(argument, 'i') for argument in call.arguments)
            ],
            'the call that writes through the reference was dropped',
        )
        self.assertNotIn(
            0, _printed_values(tree), 'the read was folded past a write made through [ref]')

    def test_reference_to_an_environment_variable_is_never_written_back(self):
        """
        `$env:z = '7'; $ok = [int]::TryParse('42', [ref]$env:z); Write-Host $env:z` prints `7` under
        5.1. `$env:z` is a provider path rather than a variable slot, so the `[ref]` wraps a copy
        and the callee's write never reaches it; folding this read to `7` is correct.
        """
        tree = self._deobfuscated_tree(
            "$env:z = '7'; $ok = [int]::TryParse('42', [ref]$env:z); Write-Host $env:z")
        self._assertPrints(tree, 'env:z', '7', '42')
