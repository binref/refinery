from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import Block, Node
from refinery.lib.scripts.ps1.ast import (
    bound_argument_value,
    free_positional_values,
    get_command_name,
    implicit_get_retry,
    in_evaluation_order,
    is_reference_cast,
    resolved_command_names,
    standalone_command_statement,
)
from refinery.lib.scripts.ps1.data import (
    KNOWN_ALIAS,
    KNOWN_CMDLETS,
    PROGRAM_NAMES,
)
from refinery.lib.scripts.ps1.model import (
    Ps1CastExpression,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1Script,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _command(source: str) -> Ps1CommandInvocation:
    for node in Ps1Parser(source).parse().walk():
        if isinstance(node, Ps1CommandInvocation):
            return node
    raise AssertionError(F'no command in {source!r}')


class TestPs1EvaluationOrder(TestBase):
    """
    The order PowerShell evaluates the parts of one statement in, which is where a read and a write
    of the same name sitting at one control-flow node are told apart.
    """

    @staticmethod
    def _order(source: str) -> list[str]:
        """
        The variables and string literals of *source*, in evaluation order, a variable rendered with
        its `$`. Only these two forms carry a name, and every case below turns on their order.
        """
        rendered: list[str] = []
        for node in in_evaluation_order(Ps1Parser(source).parse()):
            if isinstance(node, Ps1Variable):
                rendered.append(F'${node.name}')
            elif isinstance(node, Ps1StringLiteral):
                rendered.append(node.value)
        return rendered

    def test_an_assignment_produces_its_value_before_it_stores_it(self):
        """
        Why `$x = [char]($x)` reads the previous `$x`: the target is written first and stored last.
        """
        self.assertEqual(self._order("$x = $y"), ['$y', '$x'])

    def test_arguments_are_evaluated_left_to_right(self):
        self.assertEqual(self._order("f $a 'lit' $b"), ['f', '$a', 'lit', '$b'])

    def test_a_nested_assignment_stores_before_the_one_holding_it(self):
        self.assertEqual(self._order("$x = ($y = $z)"), ['$z', '$y', '$x'])

    def test_the_operands_of_a_binary_expression_keep_their_order(self):
        self.assertEqual(self._order("$y = $a + $b"), ['$a', '$b', '$y'])

    def test_a_multi_assignment_stores_every_target_after_the_whole_value(self):
        """
        `$x, $y = $y, $x` swaps, so neither target may be ordered before either source.
        """
        self.assertEqual(self._order("$x, $y = $y, $x"), ['$y', '$x', '$x', '$y'])


class TestPs1StandaloneCommandStatement(TestBase):
    """
    The statement a command is the whole of, which is what a pass that has decided the command need
    not run has to take out. A command whose value goes anywhere is the whole of nothing, since the
    statement around it cannot go without the value going too.
    """

    @staticmethod
    def _parse(source: str) -> tuple[Ps1Script, Ps1CommandInvocation]:
        script = Ps1Parser(source).parse()
        for node in script.walk_in_order():
            if isinstance(node, Ps1CommandInvocation) and get_command_name(node) == 'target':
                return script, node
        raise AssertionError(F'no command named target in {source!r}')

    def test_a_bare_command_is_the_whole_of_the_statement_that_holds_it(self):
        for source in ('target', "target 'a' -Switch", '& target', '. target'):
            with self.subTest(source):
                script, cmd = self._parse(source)
                self.assertIs(standalone_command_statement(cmd), script.body[0])

    def test_a_redirection_the_command_carries_leaves_it_standing_alone(self):
        """
        The redirection is written on the command, so the command is still the whole of what the
        statement spells. Whether the statement may then be taken out is a different question, and
        the one `refinery.lib.scripts.ps1.deobfuscation.substitution.carried_redirections` answers.
        """
        for source in ('target > C:\\o.txt', 'target 2>&1', 'target >> C:\\o.txt'):
            with self.subTest(source):
                script, cmd = self._parse(source)
                self.assertIs(standalone_command_statement(cmd), script.body[0])

    def test_a_command_that_is_one_stage_of_a_pipeline_is_the_whole_of_nothing(self):
        for source in ('target | Out-Null', 'Get-ChildItem | target', 'a | target | b'):
            with self.subTest(source):
                self.assertIsNone(standalone_command_statement(self._parse(source)[1]))

    def test_a_command_whose_value_is_stored_is_the_whole_of_nothing(self):
        for source in ('$x = target', '$x += target', '[string]$x = target', '$a[0] = target'):
            with self.subTest(source):
                self.assertIsNone(standalone_command_statement(self._parse(source)[1]))

    def test_a_command_that_is_an_argument_is_the_whole_of_nothing(self):
        for source in ('other (target)', 'other -Value (target)', 'outer (inner (target))'):
            with self.subTest(source):
                self.assertIsNone(standalone_command_statement(self._parse(source)[1]))

    def test_a_command_that_is_a_condition_is_the_whole_of_nothing(self):
        for source in (
            'if (target) { }',
            'while (target) { }',
            'do { } while (target)',
            'switch (target) { 1 { } }',
            'foreach ($i in target) { }',
        ):
            with self.subTest(source):
                self.assertIsNone(standalone_command_statement(self._parse(source)[1]))

    def test_a_command_whose_value_leaves_the_body_is_the_whole_of_nothing(self):
        for source in ('return target', 'throw target'):
            with self.subTest(source):
                self.assertIsNone(standalone_command_statement(self._parse(source)[1]))

    def test_a_command_alone_in_a_nested_block_names_the_statement_of_that_block(self):
        script, cmd = self._parse('if ($true) { target }')
        block = next(node for node in script.walk_in_order() if isinstance(node, Block))
        self.assertIs(standalone_command_statement(cmd), block.body[0])

    def test_a_command_alone_in_a_subexpression_names_the_statement_inside_it(self):
        """
        Standing alone is syntax, so the statement reported is the one the command stands in and
        not one the script's own body holds. Which body it came out of is the caller's question.
        """
        script, cmd = self._parse('other $(target)')
        inner = next(node for node in script.walk_in_order() if isinstance(node, Ps1SubExpression))
        self.assertIs(standalone_command_statement(cmd), inner.body[0])

    @classmethod
    def _one_stage(cls, redirections: list) -> tuple[Ps1ExpressionStatement, Ps1CommandInvocation]:
        """
        A command wrapped in a pipeline of one stage carrying *redirections*. No parser builds this
        shape — a stage holding a command never takes a redirection of its own, and a pipeline of
        one is never assembled — so it reaches the accessor only from a transform that built it.
        """
        cmd = cls._parse('target')[1]
        element = Ps1PipelineElement(expression=cmd, redirections=redirections)
        return Ps1ExpressionStatement(expression=Ps1Pipeline(elements=[element])), cmd

    def test_a_pipeline_of_one_stage_is_climbed_through_to_the_statement_around_it(self):
        statement, cmd = self._one_stage([])
        self.assertIs(standalone_command_statement(cmd), statement)

    def test_a_stage_that_redirects_is_not_climbed_through(self):
        written = self._parse('target > C:\\o.txt')[1]
        self.assertIsNone(standalone_command_statement(self._one_stage(written.redirections)[1]))


class TestPs1ReferenceCast(TestBase):
    """
    The `[ref]` recognizer, which decides whether a callee is handed storage it can write back
    through rather than a value. Its answer is what makes the difference between a name a store may
    be folded across and one it may not.
    """

    @staticmethod
    def _cast(source: str) -> Node:
        for node in Ps1Parser(source).parse().walk():
            if isinstance(node, Ps1CastExpression):
                return node
        raise AssertionError(F'no cast in {source!r}')

    def test_both_spellings_of_the_wrapper_type_are_recognized(self):
        for source in (
            '[ref]$n',
            '[Ref]$n',
            '[REF]$n',
            '[management.automation.psreference]$n',
            '[System.Management.Automation.PSReference]$n',
        ):
            with self.subTest(source):
                self.assertTrue(is_reference_cast(self._cast(source)))

    def test_an_unrelated_cast_is_not_a_reference(self):
        for source in ('[int]$n', '[string]$n', '[scriptblock]$n', '[refx]$n'):
            with self.subTest(source):
                self.assertFalse(is_reference_cast(self._cast(source)))

    def test_something_that_is_not_a_cast_is_not_a_reference(self):
        node = Ps1Parser('$n').parse()
        self.assertFalse(is_reference_cast(node))
        self.assertFalse(is_reference_cast(None))


class TestPs1BoundArgumentValue(TestBase):
    """
    Which value a command binds to a named parameter. PowerShell decides this from the command's own
    parameter metadata, which the parser does not have — it leaves `-Name x` as a switch followed by
    a positional, exactly as it leaves `-Recurse C:\\` — so the accessor has to reconstruct it and
    the caller has to know the parameter takes a value.
    """

    def _value(self, source: str, parameter: str) -> str | None:
        found = bound_argument_value(_command(source), parameter)
        return None if found is None else found.value

    def test_both_spellings_of_a_binding_are_found(self):
        for source in (
            'Set-Variable -Name x -Value 5',
            'Set-Variable -Name:x -Value:5',
        ):
            with self.subTest(source):
                self.assertEqual(self._value(source, 'name'), 'x')

    def test_an_abbreviation_binds_the_parameter_it_abbreviates(self):
        for source in ('Set-Variable -Na x', 'Set-Variable -N x', 'Set-Variable -Nam:x'):
            with self.subTest(source):
                self.assertEqual(self._value(source, 'name'), 'x')

    def test_a_longer_parameter_that_merely_starts_the_same_does_not_bind(self):
        """
        `-Namespace` is not an abbreviation of `-Name`; the abbreviation relation runs the other way,
        and testing it backwards binds every parameter whose name begins with this one's.
        """
        self.assertIsNone(self._value('Set-Variable -Namespace x', 'name'))

    def test_a_parameter_that_is_not_written_binds_nothing(self):
        self.assertIsNone(self._value('Set-Variable -Value 5', 'name'))

    def test_the_append_form_of_a_name_keeps_its_marker(self):
        """
        `-OutVariable +p` appends to `$p` and reads its previous value where `-OutVariable p`
        replaces it, so the `+` has to survive to the caller that tells the two apart.
        """
        self.assertEqual(self._value('Get-Process -OutVariable +p', 'outvariable'), '+p')
        self.assertEqual(self._value('Get-Process -OutVariable p', 'outvariable'), 'p')

    def test_an_alias_of_a_parameter_binds_it_only_as_its_own_name(self):
        self.assertEqual(self._value('Get-Process -ov p', 'ov'), 'p')
        self.assertIsNone(self._value('Get-Process -ov p', 'outvariable'))


class TestPs1FreePositionalValues(TestBase):
    """
    Which arguments a command binds by position. The parser has no parameter metadata, so a
    value-taking parameter written without a colon reaches the tree as a switch followed by a
    positional, and any consumer that reads the argument list as written takes that value for an
    argument of its own.

    Measured on 5.1: after `Set-Variable -Scope Global y 'b'` the global `$y` holds `'b'` and no
    variable named `Global` exists at all — see `temp/ps1/census_measurements.md`.
    """

    def _values(self, source: str, command: str) -> list[str]:
        return [
            value.value for value in free_positional_values(_command(source), command)
        ]

    def test_a_value_taking_parameter_does_not_contribute_a_positional(self):
        for source in (
            "Set-Variable -Scope Global y 'b'",
            "Set-Variable y -Scope Global 'b'",
            "Set-Variable y 'b' -Scope Global",
        ):
            with self.subTest(source):
                self.assertEqual(self._values(source, 'set-variable'), ['y', 'b'])

    def test_a_switch_that_takes_no_value_leaves_the_positionals_alone(self):
        self.assertEqual(self._values("Set-Variable y 'b' -Force", 'set-variable'), ['y', 'b'])

    def test_the_colon_spelling_of_a_parameter_consumes_nothing_that_follows(self):
        self.assertEqual(
            self._values("Set-Variable -Scope:Global y 'b'", 'set-variable'), ['y', 'b'])

    def test_a_parameter_the_command_does_not_have_consumes_nothing(self):
        """
        `-Scope` is a parameter of `Set-Variable` and not of `Write-Host`, so the same spelling
        binds a value on one and stands beside an unrelated positional on the other.
        """
        self.assertEqual(
            self._values("Write-Host -Separator x 'b'", 'write-host'), ['b'])
        self.assertEqual(
            self._values("Write-Host -NoNewline x 'b'", 'write-host'), ['x', 'b'])

    def test_an_unknown_command_binds_every_positional(self):
        self.assertEqual(self._values("Frobnicate -Foo x 'b'", 'frobnicate'), ['x', 'b'])


class TestPs1ImplicitGetRetry(TestBase):
    """
    The name a 5.1 host tries once nothing claims the one that was written. `item` runs `Get-Item`
    only because no alias, no function and no cmdlet claims `item`, so the retry is what a name has
    left when every table has missed it.
    """

    def test_a_bare_noun_no_host_table_claims_is_retried_under_the_get_prefix(self):
        for name, retried in (
            ('item', 'get-item'),
            ('member', 'get-member'),
            ('variable', 'get-variable'),
            ('childitem', 'get-childitem'),
        ):
            with self.subTest(name):
                self.assertEqual(implicit_get_retry(name), retried)

    def test_a_name_that_carries_a_dash_is_not_retried(self):
        """
        Measured on 5.1: `function Get-Zq-Frob { }; Zq-Frob` raises CommandNotFoundException, and so
        does `function Get-Get-Zqfrob { }; Get-Zqfrob`. The engine prefixes a bare noun and never a
        name that already carries a dash, so prefixing regardless invents a resolution for a name
        the host reports as not found.
        """
        for name in ('Zq-Frob', 'Get-Zqfrob', 'Get-Item', 'Some-Unknown-Command'):
            with self.subTest(name):
                self.assertIsNone(implicit_get_retry(name))

    def test_a_name_a_host_table_already_claims_is_not_retried(self):
        """
        `help` is the one that costs something: 5.1 spells it as a function and the host answers to
        both `help` and `Get-Help`, so a retry that did not ask about the bare name first would
        resolve `help` to a different command than the one that runs.
        """
        for name in ('iex', 'gci', 'echo', 'ls', 'help'):
            with self.subTest(name):
                self.assertIsNone(implicit_get_retry(name))


class TestPs1ImplicitGetRetryYieldsToAProgramWindowsShips(TestBase):
    """
    The tier the retry is not the last of: 5.1 searches the executables on `PATH` before it prefixes
    a bare noun, so a noun that names a program the machine has runs the program instead. Measured
    on this machine, intersecting every program Windows itself ships against the nouns the retry
    rewrites leaves `tpm` alone, which is `C:\\Windows\\system32\\tpm.msc`.
    """

    @staticmethod
    def _tables(name: str) -> tuple[bool, bool, bool]:
        """
        Whether an alias claims *name*, whether a cmdlet claims it, and whether the name the retry
        would produce is a cmdlet: everything the retry reads apart from the program tier.
        """
        return (
            name in KNOWN_ALIAS,
            name in KNOWN_CMDLETS,
            F'get-{name}' in KNOWN_CMDLETS,
        )

    def test_a_noun_naming_a_shipped_program_is_not_retried_where_an_ordinary_one_is(self):
        self.assertIsNone(implicit_get_retry('tpm'))
        self.assertEqual(implicit_get_retry('item'), 'get-item')

    def test_the_two_nouns_are_told_apart_by_the_program_and_by_nothing_else(self):
        """
        `Get-Tpm` is a cmdlet the table carries and nothing claims the bare `tpm`, so every table
        the retry reads answers for `tpm` exactly what it answers for `item`. Were the refusal a
        missing cmdlet rather than the program, `tpm` would be rewritten like any other noun.
        """
        self.assertEqual(self._tables('tpm'), (False, False, True))
        self.assertEqual(self._tables('item'), (False, False, True))
        self.assertEqual(sorted(PROGRAM_NAMES.intersection({'item', 'tpm'})), ['tpm'])

    def test_the_refusal_reaches_the_script_the_unit_emits(self):
        unit = self.ldu('ps1')

        def emitted(source: str) -> str:
            return bytes(source.encode('utf8') | unit).decode('utf8')

        self.assertEqual(emitted('item'), 'Get-Item')
        self.assertEqual(emitted('tpm'), 'tpm')


class TestPs1ResolvedCommandNames(TestBase):
    """
    Every name a call may run, read as a deny-list: the name the call spells and, where the engine
    would retry it, the prefixed name beside it.
    """

    def _names(self, source: str) -> tuple[str, ...]:
        return resolved_command_names(_command(source))

    def test_a_bare_noun_reports_the_written_name_and_the_retried_one(self):
        for source, expected in (
            ('item env:zzq', ('item', 'get-item')),
            ('variable x -ValueOnly', ('variable', 'get-variable')),
            ('member', ('member', 'get-member')),
        ):
            with self.subTest(source):
                self.assertEqual(self._names(source), expected)

    def test_a_name_the_engine_does_not_retry_reports_only_itself(self):
        for source, expected in (
            ('Get-Item env:zzq', ('get-item',)),
            ('Zq-Frob', ('zq-frob',)),
            ('Get-Zqfrob', ('get-zqfrob',)),
            ('gci', ('get-childitem',)),
            ('iex $x', ('invoke-expression',)),
        ):
            with self.subTest(source):
                self.assertEqual(self._names(source), expected)

    def test_a_call_whose_name_is_not_written_reports_nothing(self):
        for source in ('& $f', '. $f'):
            with self.subTest(source):
                self.assertEqual(self._names(source), ())
