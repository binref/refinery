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
pass silently.

The scoping facts the entries rest on, all measured:

  - a called body reads its caller's variables by naming them, with no qualifier
  - writing a caller's variable needs `$script:`, `$global:` or a dot-invocation
  - `Invoke-Expression` runs a string that may carry such a write, so it may change any variable
  - a script block is not a closure: it reads the variables of whoever invokes it
  - a .NET call may write through an argument or through its receiver, changing an array in place
    rather than returning a new one, so a call whose result is discarded is still a store
  - assigning one variable to another gives both names the same array rather than a copy of it
"""
from __future__ import annotations

import inspect
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


def _reads_variable(node: Node | None, key: str) -> bool:
    """
    Whether `node` still fetches from the variable under `key` when it runs, either by naming it or
    by indexing it. Both reach the array the variable holds, so both are how a mutating call is
    handed it and how a later read observes what the call did.
    """
    node = _unwrap(node)
    if isinstance(node, Ps1IndexExpression):
        return _reads_variable(node.object, key)
    return isinstance(node, Ps1Variable) and _binding_key(node) == key


def _emitted_constants(node: Node | None) -> list | None:
    """
    The values `node` writes to the output stream, one entry per value: an array writes its elements
    one after another, `$null` writes an empty line and is reported as `None`, and any other
    constant writes itself. The whole answer is `None` when the text does not decide what is
    written, which is what anything read out of a variable leaves open.
    """
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


def _stores_value(root: Node, key: str, value) -> bool:
    return any(_literal_value(store.value) == value for store in _stores(root, key))


def _element_stores(root: Node, key: str) -> list[Ps1AssignmentExpression]:
    """
    Every assignment in `root` writing into an element of the array the variable under `key` holds.
    Such a store changes the array itself rather than rebinding the name, so every other name for
    that array observes it, which is why `_stores` deliberately does not report it.
    """
    return [
        node for node in root.walk()
        if isinstance(node, Ps1AssignmentExpression)
        and isinstance(target := _unwrap(node.target), Ps1IndexExpression)
        and _reads_variable(target.object, key)
    ]


def _fetches_from(node: Node | None, key: str) -> bool:
    """
    Whether `node` still reaches the object the variable under `key` holds, through any number of
    indices and property names. `_reads_variable` stops at an index because that is all a mutating
    call is ever handed; a container is reached through its keys as well, and each step hands back
    what the container holds rather than a copy, so a store at the end of such a chain writes an
    object every other name for it observes.
    """
    node = _unwrap(node)
    if isinstance(node, (Ps1IndexExpression, Ps1MemberAccess)):
        return _fetches_from(node.object, key)
    return isinstance(node, Ps1Variable) and _binding_key(node) == key


def _container_stores(root: Node, key: str) -> list[Ps1AssignmentExpression]:
    """
    Every assignment in `root` writing into the object the variable under `key` holds, rather than
    rebinding the name itself. Both the store that fills a container and the store that writes
    through it are such an assignment, which is what tells the two apart from a rebinding that
    replaces the container wholesale.
    """
    return [
        node for node in root.walk()
        if isinstance(node, Ps1AssignmentExpression)
        and not isinstance(_unwrap(node.target), Ps1Variable)
        and _fetches_from(node.target, key)
    ]


def _hash_values(node: Node | None) -> list[Node]:
    """
    The value of every entry of the hash literal `node` spells, or nothing where it spells no hash
    literal. An entry written into the literal is a position a container is filled from just as an
    assignment into a key is.
    """
    node = _unwrap(node)
    if not isinstance(node, Ps1HashLiteral):
        return []
    return [value for _, value in node.pairs]


def _occurrences(root: Node, key: str) -> list[Ps1Variable]:
    """
    Every occurrence of the variable under `key` left in `root`, read or written.
    """
    return [
        node for node in root.walk()
        if isinstance(node, Ps1Variable) and _binding_key(node) == key
    ]


def _dot_sourced_blocks(root: Node) -> list[Ps1ScriptBlock]:
    """
    Every script block `root` dot-invokes. Such a block runs in the caller's scope, so a store it
    makes rebinds the caller's name rather than one of its own.
    """
    return [
        node.name for node in root.walk()
        if isinstance(node, Ps1CommandInvocation)
        and node.invocation_operator == '.'
        and isinstance(node.name, Ps1ScriptBlock)
    ]


def _constrained_stores(root: Node, key: str, type_name: str) -> list[Ps1AssignmentExpression]:
    """
    Every assignment in `root` writing the variable under `key` through `type_name` spelled at the
    target, given lowercased and without its namespace. Such a cast constrains the variable rather
    than that one store, so it converts what every later write to the name arrives with as well.
    """
    return [
        store for store in _stores(root, key)
        if isinstance(target := _unwrap(store.target), Ps1CastExpression)
        and target.type_name.lower().rpartition('.')[2] == type_name
    ]


def _piped_into(root: Node, key: str, names: frozenset[str]) -> list[Ps1CommandInvocation]:
    """
    Every command in `names` that `root` still pipes the variable under `key` into. A command that
    binds a name takes the value it binds from the pipeline rather than from an argument, so nothing
    in its argument list names the object it is handed.
    """
    found: list[Ps1CommandInvocation] = []
    for node in root.walk():
        if not isinstance(node, Ps1Pipeline):
            continue
        for source, sink in zip(node.elements, node.elements[1:]):
            if not _reads_variable(source.expression, key):
                continue
            command = _unwrap(sink.expression)
            if (
                isinstance(command, Ps1CommandInvocation)
                and isinstance(command.name, Ps1StringLiteral)
                and command.name.value.lower() in names
            ):
                found.append(command)
    return found


def _pipeline_pairs(
    root: Node,
    writing: frozenset[str],
    binding: frozenset[str],
) -> list[tuple[Ps1CommandInvocation, Ps1CommandInvocation]]:
    """
    Every pair of commands `root` still spells one behind the other in a pipeline, the first named
    in `writing` and the second in `binding`. What the second one binds is what the first one wrote,
    so the object it is handed is named among the first command's arguments and nowhere among its
    own, which is why `_piped_into` cannot find it: nothing pipes a variable in directly.
    """
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
    """
    Whether `node` is the one-element array a unary comma builds around the variable under `key`. A
    command hands such an array on as the single object it holds, where the array the variable holds
    by itself would be written one element at a time.
    """
    node = _unwrap(node)
    return (
        isinstance(node, Ps1ArrayLiteral)
        and len(node.elements) == 1
        and _reads_variable(node.elements[0], key)
    )


def _supplies_array(root: Node, node: Node | None, values: list) -> bool:
    """
    Whether `node` still hands on an array of `values`: either it spells them where it stands, or it
    names a variable that `root` stores them into. An array that is only read for what it holds is
    the same array to whoever receives it however the output spells it, so both are the one the call
    was given; a variable written through is not, and `_reads_variable` is what asks after that.
    """
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
    """
    Every command invocation in `root`, in the order the source spells them.
    """
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
    """
    Whether a static call to `member` of `type_name` in `root` is still handed the array the
    variable under `key` holds. Such a call writes through the argument, which is how the array a
    variable names changes without anything ever being assigned to that variable.
    """
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


def _binds_the_name(command: Ps1CommandInvocation, name: str) -> bool:
    """
    Whether `command` still spells `name` where the name it binds goes. The value bound to that name
    arrives from the pipeline, so the name is the whole of what the command's own arguments carry.
    """
    return name in [_literal_value(value) for value in _positional_values(command)]


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


def _output_writes(root: Node) -> list[list | None]:
    """
    What each `Write-Output` in `root` writes, one entry per invocation and in the order the source
    spells them: the values its arguments enumerate, or `None` where the text does not decide them.
    """
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


class _Ps1Ledger(TestPs1):
    """
    What every ledger entry below is made of: deobfuscate one script to a fixpoint, re-parse what
    came out, and ask whether it can still do what 5.1 was measured doing. The assertions live here
    rather than on one class of entries so that a claim about a new subject can open a class of its
    own instead of joining an unrelated one.
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

    def _assertWrites(self, tree: Ps1Script, written: list, corrupt: list, mutated: bool) -> None:
        """
        The output must still be able to write `written`, which is what 5.1 was measured to write:
        either its `Write-Output` invocations already spell exactly that, or `mutated` reports that
        the call producing it still reaches the array the read observes. `corrupt` is what the
        output writes in its place when it does neither.

        The corrupt half is checked per invocation and not against the whole list. `_output_writes`
        answers `None` for an invocation whose argument the output does not decide, so a rewrite
        that corrupts one read and leaves the next unanswered never reproduces `corrupt` entire —
        and comparing the lists would pass on exactly the partial corruption these rows exist to
        catch. Only the positions where `corrupt` and `written` disagree carry a claim; where the
        two spell the same thing the corrupt run writes what the script writes.
        """
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


class TestPs1Corruptions(_Ps1Ledger):
    """
    Each test deobfuscates one script to a fixpoint and asks whether the result still behaves the
    way PowerShell 5.1 was measured to behave. A failure is a report that the deobfuscator changed
    what the script does.
    """

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
    def test_short_circuited_or_operand_never_stores(self):
        """
        `$x = 'a'; $true -or ($x = 'b'); Write-Host $x` prints `a` under 5.1: the right operand of
        `-or` is not evaluated when the left one is true, so the store of `b` never happens.
        """
        tree = self._deobfuscated_tree("$x = 'a'; $true -or ($x = 'b'); Write-Host $x")
        self._assertPrints(tree, 'x', 'a', 'b')
        for store in _stores(tree, 'x'):
            if _literal_value(store.value) == 'b':
                self.assertTrue(
                    _inside_short_circuit(store),
                    'the store from the unevaluated operand is now reached unconditionally',
                )

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

    def test_invoke_command_with_computername_runs_on_another_machine(self):
        """
        `Invoke-Command -Comp $h -ScriptBlock { 1 }` runs its block on the host named by `$h` under
        5.1. Splicing the block into the script makes it run locally instead, and the splice once
        happened here because the remoting refusal read the parameter by its exact spelling and
        `-Comp` is an abbreviation of it. The abbreviation expansion spells the parameter out first,
        so the refusal sees it and the block stays in the remote invocation.
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

    def test_two_names_for_one_array_both_see_it_reversed(self):
        """
        `$x = 1, 2, 3; $y = $x; Write-Output $y[0]; [Array]::Reverse($x); Write-Output $y[0]` writes
        `1` and then `3` under 5.1: the assignment gives both names the one array, so reversing it
        through `$x` changes what `$y[0]` reads afterwards.
        """
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
        """
        `$x = 1, 2, 3; $c = '$x = 7, 8, 9'; iex $c; [Array]::Reverse($x); Write-Output $x` writes
        `9`, `8` and `7` under 5.1: the string rebinds `$x`, and the reversal turns around the array
        that store left behind rather than the one the first store did.
        """
        tree = self._deobfuscated_tree(
            "$x = 1, 2, 3; $c = '$x = 7, 8, 9'; iex $c; [Array]::Reverse($x); Write-Output $x")
        self._assertWrites(
            tree,
            [[9, 8, 7]],
            [[7, 8, 9]],
            _mutates_through_argument(tree, 'array', 'reverse', 'x'),
        )

    def test_function_body_reverses_the_callers_array_in_place(self):
        """
        `function f { [Array]::Reverse($x) }; $x = 1, 2, 3; f; Write-Output $x` writes `3`, `2` and
        `1` under 5.1: the body reads the caller's `$x` and reverses the array it holds. With that
        store gone the call is handed nothing and throws ArgumentNullException instead.
        """
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
        """
        `$x = $(Write-Host 'a'; 1), $(Write-Host 'b'; 2); [Array]::Reverse($x); Write-Output $x`
        writes `a` and then `b` to the information stream under 5.1 and afterwards writes `2` and
        `1`: the elements are evaluated where they stand, and only the finished array is turned
        around.
        """
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
        """
        `$x = 1, 2, 3; $r = [Array]::Reverse($x); Write-Output $x` writes `3`, `2` and `1` under
        5.1: the call returns nothing and does its work by writing through the argument, so binding
        its result changes neither what it does nor that it is done.
        """
        tree = self._deobfuscated_tree('$x = 1, 2, 3; $r = [Array]::Reverse($x); Write-Output $x')
        self._assertWrites(
            tree,
            [[3, 2, 1]],
            [[1, 2, 3]],
            _mutates_through_argument(tree, 'array', 'reverse', 'x'),
        )

    def test_clear_blanks_the_range_of_the_array_the_variable_holds(self):
        """
        `$x = 1, 2, 3; [Array]::Clear($x, 0, 1); Write-Output $x` writes an empty line and then `2`
        and `3` under 5.1: the call replaces the first element of the array `$x` holds by `$null`.
        """
        tree = self._deobfuscated_tree('$x = 1, 2, 3; [Array]::Clear($x, 0, 1); Write-Output $x')
        self._assertWrites(
            tree,
            [[None, 2, 3]],
            [[1, 2, 3]],
            _mutates_through_argument(tree, 'array', 'clear', 'x'),
        )

    def test_copy_writes_through_its_destination_argument(self):
        """
        `$x = 1, 2, 3; $y = 0, 0, 0; [Array]::Copy($x, $y, 3); Write-Output $y` writes `1`, `2` and
        `3` under 5.1: the call fills the array `$y` holds and returns nothing. Only the destination
        is written through, so the source is a value the call reads and may be spelled as one, while
        the destination has to keep naming the variable the read below observes, the array that
        variable is given has to keep room for what is copied into it, and the count has to stay the
        three elements 5.1 was measured writing.
        """
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
        """
        `$x = 1, 2, 3; [Array]::Reverse($x, 0, 2); Write-Output $x` writes `2`, `1` and `3` under
        5.1: this overload reverses the elements the index and the length name and leaves the rest
        of the array where it was.
        """
        tree = self._deobfuscated_tree('$x = 1, 2, 3; [Array]::Reverse($x, 0, 2); Write-Output $x')
        reverses_the_range = any(
            _reads_variable(call.arguments[0], 'x')
            and [_literal_value(argument) for argument in call.arguments[1:]] == [0, 2]
            for call in _static_calls(tree, 'array', 'reverse')
            if call.arguments
        )
        self._assertWrites(tree, [[2, 1, 3]], [[1, 2, 3]], reverses_the_range)

    def test_set_value_writes_through_the_receiver(self):
        """
        `$x = 1, 2, 3; $x.SetValue(9, 0); Write-Output $x` writes `9`, `2` and `3` under 5.1: the
        method stores into the array it is called on rather than returning a changed copy of it.
        """
        tree = self._deobfuscated_tree('$x = 1, 2, 3; $x.SetValue(9, 0); Write-Output $x')
        writes_into_the_variable = any(
            _reads_variable(call.object, 'x') for call in _instance_calls(tree, 'setvalue'))
        self._assertWrites(tree, [[9, 2, 3]], [[1, 2, 3]], writes_into_the_variable)

    def test_copy_to_writes_through_its_destination_argument(self):
        """
        `$x = 1, 2, 3; $y = 0, 0, 0; $x.CopyTo($y, 0); Write-Output $y` writes `1`, `2` and `3`
        under 5.1: the method fills the array `$y` holds and returns nothing. The receiver is only
        read, so it is a value the call reads and may be spelled as one, while the argument has to
        keep naming the variable the read below observes, the array that variable is given has to
        keep room for what is copied into it, and the copy has to keep starting where it did.
        """
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
        """
        `$x = 1, 2, 3; $y = $x; $y[0] = 9; Write-Output $x[0]` writes `9` under 5.1: the assignment
        hands over the array rather than a copy of it, so a store into an element through `$y` is a
        store into the array `$x` reads.
        """
        tree = self._deobfuscated_tree('$x = 1, 2, 3; $y = $x; $y[0] = 9; Write-Output $x[0]')
        aliased = any(_reads_variable(store.value, 'x') for store in _stores(tree, 'y'))
        self._assertWrites(tree, [[9]], [[1]], aliased and bool(_element_stores(tree, 'y')))

    @unittest.expectedFailure
    def test_a_multi_assignment_slot_is_handed_the_array_standing_against_it(self):
        """
        `$x = 1, 2, 3; $a, $b = $x, 9; $a[0] = 7; Write-Output $x[0]` writes `7` under 5.1: the slot
        takes the object standing against it rather than a copy, so `$a` and `$x` name one array.
        """
        tree = self._deobfuscated_tree('$x = 1, 2, 3; $a, $b = $x, 9; $a[0] = 7; Write-Output $x[0]')
        aliased = any(_reads_variable(store.value, 'x') for store in _stores(tree, 'a'))
        self._assertWrites(tree, [[7]], [[1]], aliased and bool(_element_stores(tree, 'a')))

    @unittest.expectedFailure
    def test_an_array_a_container_holds_is_the_one_the_call_reverses(self):
        """
        `$x = 1, 2, 3; $h = @{}; $h['k'] = $x; [Array]::Reverse($h['k']); Write-Output $x` writes
        `3 2 1` under 5.1: the key holds the array itself, so reversing what it names reverses what
        `$x` names.
        """
        tree = self._deobfuscated_tree(
            "$x = 1, 2, 3; $h = @{}; $h['k'] = $x; [Array]::Reverse($h['k']); Write-Output $x")
        stored = any(_reads_variable(store.value, 'x') for store in _element_stores(tree, 'h'))
        self._assertWrites(tree, [[3, 2, 1]], [[1, 2, 3]], stored)

    @unittest.expectedFailure
    def test_a_foreach_variable_is_bound_to_the_element_and_not_to_a_copy(self):
        """
        `$p = @(@(1, 2), @(3, 4)); foreach ($e in $p) { [Array]::Reverse($e) }; Write-Output $p[0]`
        writes `2 1` under 5.1: the loop variable names the element object, so reversing it reverses
        what the collection holds.
        """
        tree = self._deobfuscated_tree(
            '$p = @(@(1, 2), @(3, 4)); foreach ($e in $p) { [Array]::Reverse($e) }; '
            'Write-Output $p[0]')
        reverses_the_element = any(
            _reads_variable(call.arguments[0], 'e')
            for call in _static_calls(tree, 'array', 'reverse') if call.arguments
        )
        self._assertWrites(tree, [[2, 1]], [[1, 2]], reverses_the_element)

    @unittest.expectedFailure
    def test_a_called_body_that_keeps_its_argument_keeps_the_callers_array(self):
        """
        `function f($a) { $script:k = $a }; $x = 1, 2, 3; f $x; $x[0] = 9; Write-Output $k[0]` writes
        `9` under 5.1: the body stores what it was handed, so `$k` and `$x` name one array and the
        later element store is seen through both.
        """
        tree = self._deobfuscated_tree(
            'function f($a) { $script:k = $a }; $x = 1, 2, 3; f $x; $x[0] = 9; Write-Output $k[0]')
        hands_the_variable_on = any(
            any(_reads_variable(argument, 'x') for argument in invocation.arguments)
            for invocation in _invocations(tree, frozenset({'f'}))
        )
        self._assertWrites(tree, [[9]], [[1]], hands_the_variable_on)

    @unittest.expectedFailure
    def test_a_subexpression_between_two_names_gives_each_its_own_array(self):
        """
        `$x = 1, 2, 3; $y = $($x); [Array]::Reverse($x); Write-Output $y` writes `1 2 3` under 5.1:
        a subexpression collects what it evaluates into a fresh array, so `$y` does not name the
        array `$x` holds and reversing that array leaves `$y` alone.

        The store is not the defect. `Ps1Simplifications` rewrites `$($x)` to `$x` before anything
        reads the alias relation, so the share is minted by a pass that never asked whether the
        wrapper was carrying a copy.
        """
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $y = $($x); [Array]::Reverse($x); Write-Output $y')
        copies_the_array = any(
            isinstance(store.value, Ps1SubExpression) for store in _stores(tree, 'y'))
        self._assertWrites(tree, [[1, 2, 3]], [[3, 2, 1]], copies_the_array)

    def test_loop_reads_the_array_the_previous_iteration_reversed(self):
        """
        `$x = 1, 2, 3; for ($i = 0; $i -lt 2; $i++) { Write-Output $x[0]; [Array]::Reverse($x) }`
        writes `1` and then `3` under 5.1: one read in the source produces two different values,
        because the reversal ending the first iteration changes the array the second one reads.
        """
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
        """
        `$x = 1, 2, 3; [Array]::Reverse(($x)); Write-Output $x` writes `3`, `2` and `1` under 5.1:
        the parentheses group the expression and change nothing about what is handed to the call,
        so the array reversed is still the one `$x` holds.
        """
        tree = self._deobfuscated_tree('$x = 1, 2, 3; [Array]::Reverse(($x)); Write-Output $x')
        self._assertWrites(
            tree,
            [[3, 2, 1]],
            [[1, 2, 3]],
            _mutates_through_argument(tree, 'array', 'reverse', 'x'),
        )

    def test_reversing_an_element_of_an_array_of_arrays_mutates_that_element(self):
        """
        `$p = @(@(1, 2), @(3, 4)); [Array]::Reverse($p[0]); Write-Output $p[0]` writes `2` and then
        `1` under 5.1: the index fetches the inner array itself, so reversing it changes what the
        first element of the outer array holds.
        """
        tree = self._deobfuscated_tree(
            '$p = @(@(1, 2), @(3, 4)); [Array]::Reverse($p[0]); Write-Output $p[0]')
        self._assertWrites(
            tree, [[2, 1]], [[1, 2]], _mutates_through_argument(tree, 'array', 'reverse', 'p'))


class TestPs1AStoreThroughAContainerReachesTheArrayTheContainerWasHanded(_Ps1Ledger):
    """
    A container is handed the array itself, not a copy. Measured on 5.1 in `corpus.BEHAVIOURS`, a
    store made through `$x` after the array is put into a hashtable key, an element of another array,
    a key of a hashtable literal or one target of a multi-assignment is observed by a read of the
    container: each script writes the array with the number stored at its front — `9 2 3` for the
    first four, `7 2 3` for the multi-assignment — never the `1 2 3` the array held when the
    container was filled.

    Each entry asserts that the position still *names* `$x`: an array spelled where the name stood is
    a second array of the same numbers, which no store reaches and no read observes, so identity is
    what is checked. The property shape is given a receiver that has the property, because
    `New-Object PSObject` mints none — `$o = New-Object PSObject; $o.P = $x` throws rather than
    storing, and a script that throws before the shape under test states nothing about it.
    """

    #: The same five shapes with nothing storing through the container afterwards. Measured on 5.1
    #: in `corpus.BEHAVIOURS`, each writes `1 2 3`, so the array may be spelled where the name
    #: stands: the refusal above is scoped to the store-through-container case, not the shape itself.
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
        """
        The output must still be able to write the array with `stored` at its front: either it
        already spells it, or the container under `key` is still handed the array `$x` names and a
        store through that container still reaches it. `1 2 3` is what the output writes in its
        place when it answers the read with the array as it stood before that store.
        """
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
    """
    `. { }` runs in the caller's scope and `& { }` opens one of its own, so one store written inside
    the block says two different things about the name outside it. Measured on 5.1, dot-invoking
    `{ $y = 9, 9, 9 }` gives `$y` an array of its own and the `[Array]::Reverse($x)` below it cannot
    reach that array, so the script writes `9 9 9`; the same block invoked with `&` writes a name
    the child scope keeps, leaving the caller's `$y` on the array `$x` holds, so that script writes
    `3 2 1`.

    The two scripts differ in one character, so neither answer may be given to the other.
    """

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
    """
    `[string]$y = 0` puts a converter on the variable rather than on that one store, so the
    `$y = $x` below it leaves `$y` holding the String `1 2 3` and not the array `$x` names. Measured
    on 5.1 in `corpus.BEHAVIOURS`, reversing that array afterwards leaves the read writing `1 2 3`.

    The second entry is the same script with the constraint taken away, where `$y` is on the array
    itself and the read writes `3 2 1`. It is the control and it is the one the tool answers: what
    may not happen is the constrained script being answered with it.
    """

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
    """
    A pipeline enumerates what it is handed, so `$x | Set-Variable z` binds `$z` to a collection
    built from the elements rather than to the array `$x` holds. Measured on 5.1 in
    `corpus.BEHAVIOURS`, the `$y[0] = 9` below therefore leaves the read of `$z` writing `1 2 3`:
    the store reaches the array `$x` and `$y` share, and `$z` is not on it.

    This is the control for the class below it, where `-NoEnumerate` sends the array on as one
    record and the share is real — the two scripts differ by a switch and 5.1 answers them
    oppositely, `1 2 3` here and `9 2 3` there. An output that read a pipe as a hand-off would
    satisfy one and corrupt the other, which asking only the second cannot tell.
    """

    def test_a_name_bound_from_an_enumerating_pipeline_is_not_on_the_array_piped_into_it(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; $y = $x; $x | Set-Variable z; $y[0] = 9; Write-Output $z')
        bound = any(
            _literal_value(value) == 'z'
            for command in _piped_into(tree, 'x', _SET_VARIABLE)
            for value in _positional_values(command)
        )
        self._assertWrites(tree, [[1, 2, 3]], [[9, 2, 3]], bound)


class TestPs1AValueReachingANameBindingCommandThroughACommandStillReachesIt(_Ps1Ledger):
    """
    `Write-Output -NoEnumerate $x` and `Write-Output (,$x)` each write the array `$x` holds as one
    record instead of one record per element, and a command binding a name from the pipeline binds
    it to the single record that reached it. Under 5.1 `$z` and `$x` therefore name one array, and
    the `$x[0] = 9` behind the pipeline leaves the read of `$z` writing `9 2 3`.

    Nothing in either argument list spells that `9`, and the binding command is not handed the array
    directly either: it takes what the command ahead of it wrote. So the whole of what carries the
    store to the read is that the command ahead is still handed the array the name holds. An array
    spelled where `$x` stands is a second array of the same three numbers, and it is that one which
    is bound to `$z` while the store below reaches the other.
    """

    def _assertBoundToTheArray(self, tree: Ps1Script, bound: bool) -> None:
        """
        The output must still be able to write `9 2 3` for `$z`: either it already spells it, or
        `bound` reports that the array `$x` names still reaches the command binding the name, and
        the store that puts the `9` into that array still stands. `1 2 3` is what the output writes
        in its place when the command was handed an array of its own.
        """
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
    """
    `$x = 1, 2, 3; $x[0] = $x` puts the array into its own first element, so `$x[0]` is that array
    and `[Object]::ReferenceEquals($x[0], $x)` writes `True` under 5.1. The target of that
    assignment is rooted at `$x` and its value reads `$x`, and the one does not excuse the other: an
    array spelled where the value stands is a second array, and the comparison writes `False`.

    `$a = $x` ahead of the store changes nothing, the two names being one array: `$a[0] = $x` puts
    that array into itself exactly as `$x[0] = $x` does.

    The comparison is bound to a name and that name is written, rather than being written where it
    stands, because an argument holding a static call is a bracket the synthesizer does not put back
    — a defect of its own, and one a script asserting something else has no business tripping.
    """

    def _assertStoresTheArrayItself(self, tree: Ps1Script, key: str) -> None:
        self.assertTrue(
            [store for store in _element_stores(tree, key) if _reads_variable(store.value, 'x')],
            F'${key} was given an array of its own, which is not the one $x holds',
        )
        self.assertTrue(
            [
                call for call in _static_calls(tree, 'object', 'referenceequals')
                if len(call.arguments) == 2
                and _reads_variable(call.arguments[0], key)
                and _reads_variable(call.arguments[1], 'x')
            ],
            'the comparison that observes the two as one array was dropped',
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
            any(_reads_variable(store.value, 'x') for store in _stores(tree, 'a')),
            'the two names were taken off the one array',
        )
        self._assertStoresTheArrayItself(tree, 'a')


class TestPs1AnObjectPutIntoAContainerIsStillTheOneItsNameHolds(_Ps1Ledger):
    """
    A container is handed the array and not a copy, so a store made *through the container* reaches
    the array the name still holds. Measured on 5.1 in `corpus.BEHAVIOURS`, each script here writes
    the number the store put at the front and never the array as it was written.

    These are the direction the class above does not ask. There the store is made through `$x` and
    the read is of the container; here the store is made through the container and the read is of
    `$x`, and answering the first says nothing about the second: the tool relates two *names*, and a
    hashtable key, a property, an element and a list slot are not names.

    The last two take the object back out of the container into a name, which is the same fact
    reached from the third side.
    """

    def _assertTheStoreReachesTheName(
        self, source: str, key: str, written: list, corrupt: list,
    ) -> None:
        """
        The output must still be able to write `written`: either it already spells it, or the name
        under `key` is still spelled where the container was handed the object, which is the whole
        of what carries the store to the read. `corrupt` is what an output that spelled the array
        in that position writes instead.
        """
        tree = self._deobfuscated_tree(source)
        names_it = any(
            isinstance(node, Ps1Variable) and _binding_key(node) == key for node in tree.walk())
        self._assertWrites(tree, written, corrupt, names_it)

    @unittest.expectedFailure
    def test_a_store_through_a_property_reaches_the_array_the_name_holds(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $o = [pscustomobject]@{ P = 0 }; $o.P = $x; $o.P[0] = 9; Write-Output $x',
            'x', [[9, 2, 3]], [[1, 2, 3]])

    @unittest.expectedFailure
    def test_a_store_through_an_element_reaches_the_array_the_name_holds(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $a = 0, 0; $a[0] = $x; $a[0][0] = 9; Write-Output $x',
            'x', [[9, 2, 3]], [[1, 2, 3]])

    @unittest.expectedFailure
    def test_a_store_through_a_list_slot_reaches_the_array_the_name_holds(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $l = New-Object Collections.ArrayList; [void]$l.Add($x); '
            '$l[0][0] = 9; Write-Output $x',
            'x', [[9, 2, 3]], [[1, 2, 3]])

    @unittest.expectedFailure
    def test_a_store_through_a_key_of_a_hash_literal_reaches_the_array_the_name_holds(self):
        self._assertTheStoreReachesTheName(
            '$x = 1, 2, 3; $h = @{ k = $x }; $h.k[0] = 9; Write-Output $x',
            'x', [[9, 2, 3]], [[1, 2, 3]])

    @unittest.expectedFailure
    def test_a_name_taken_back_out_of_a_container_is_on_the_array_that_was_put_in(self):
        self._assertTheStoreReachesTheName(
            "$x = 1, 2, 3; $h = @{ k = $x }; $y = $h['k']; $y[0] = 9; Write-Output $x",
            'x', [[9, 2, 3]], [[1, 2, 3]])

    @unittest.expectedFailure
    def test_a_name_taken_from_an_element_is_on_the_array_that_element_holds(self):
        self._assertTheStoreReachesTheName(
            '$p = @(@(1, 2), @(3, 4)); $q = $p[0]; $q[0] = 9; Write-Output $p[0][0]',
            'p', [[9]], [[1]])


class TestPs1AnObjectHandedToABodyIsStillTheOneItsNameHolds(_Ps1Ledger):
    """
    A body is handed the array and not a copy of it, so a call that changes what it was given
    changes what the caller's name holds. Measured on 5.1 in `corpus.BEHAVIOURS`, each script here
    writes the reversal and never the array as it was written.

    A pipeline variable, a function parameter, a script block parameter and a multi-assignment slot
    are four spellings of one hand-off, and none of the four is a name the tool can relate to `$x`.
    The `foreach` variable of the entry above is the fifth.
    """

    def _assertTheCallReachesTheName(
        self, source: str, key: str, written: list, corrupt: list,
    ) -> None:
        tree = self._deobfuscated_tree(source)
        names_it = any(
            isinstance(node, Ps1Variable) and _binding_key(node) == key for node in tree.walk())
        self._assertWrites(tree, written, corrupt, names_it)

    @unittest.expectedFailure
    def test_a_pipeline_variable_is_bound_to_the_element_and_not_to_a_copy(self):
        self._assertTheCallReachesTheName(
            '$p = @(@(1, 2), @(3, 4)); $p | ForEach-Object { [Array]::Reverse($_) }; '
            'Write-Output $p[0]',
            'p', [[2, 1]], [[1, 2]])

    @unittest.expectedFailure
    def test_a_function_parameter_is_bound_to_the_array_the_argument_named(self):
        self._assertTheCallReachesTheName(
            'function f($a) { [Array]::Reverse($a) }; $x = 1, 2, 3; f $x; Write-Output $x',
            'x', [[3, 2, 1]], [[1, 2, 3]])

    @unittest.expectedFailure
    def test_a_script_block_parameter_is_bound_to_the_array_the_argument_named(self):
        self._assertTheCallReachesTheName(
            '$sb = { param($a) [Array]::Reverse($a) }; $x = 1, 2, 3; & $sb $x; Write-Output $x',
            'x', [[3, 2, 1]], [[1, 2, 3]])

    @unittest.expectedFailure
    def test_a_call_through_a_multi_assignment_slot_reaches_the_array_it_was_handed(self):
        self._assertTheCallReachesTheName(
            '$x = 1, 2, 3; $a, $b = $x, 9; [Array]::Reverse($a); Write-Output $x',
            'x', [[3, 2, 1]], [[1, 2, 3]])


class TestPs1APositionThatBuildsANewObjectIsNotAHandOff(_Ps1Ledger):
    """
    The controls for the two classes above: a blanket refusal would satisfy both, so both scripts
    must stay correctly answered rather than merely refused. Measured on 5.1 in `corpus.BEHAVIOURS`,
    both are answered correctly today.

    An index whose value the text does not fix already reaches its whole collection, so the loop is
    a store through `$p` and needs no hand-off to be seen. A function writing `, $script:x` returns
    a wrapper the caller unrolls into a collection of its own, so the name it is bound to is on an
    array of one element and not on the array itself.
    """

    def test_a_store_through_an_index_the_text_does_not_fix_reaches_the_collection(self):
        tree = self._deobfuscated_tree(
            '$p = @(@(1, 2), @(3, 4)); for ($i = 0; $i -lt 1; $i++) { [Array]::Reverse($p[$i]) }; '
            'Write-Output $p[0]')
        self._assertWrites(
            tree, [[2, 1]], [[1, 2]], _mutates_through_argument(tree, 'array', 'reverse', 'p'))

    def test_a_name_bound_from_a_wrapped_return_is_not_on_the_array_that_was_wrapped(self):
        tree = self._deobfuscated_tree(
            '$x = 1, 2, 3; function f { , $script:x }; $y = f; $y[0] = 9; Write-Output $x[0]')
        self._assertWrites(tree, [[9]], [[1]], True)
