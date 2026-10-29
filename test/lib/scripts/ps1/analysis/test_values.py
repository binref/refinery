from __future__ import annotations

import gc
import weakref

from test import TestBase

from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.calls import call_reader
from refinery.lib.scripts.ps1.analysis.values import (
    NULL,
    UNKNOWN,
    Ps1Outcome,
    Ps1Throws,
    Ps1Typed,
    candidate_types,
    evaluate,
    resolve_expression_type,
)
from refinery.lib.scripts.ps1.analysis.world import Ps1TypeWorld
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach
from refinery.lib.scripts.ps1.data import CallKind, call_facts, named_type, resolve_type
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation, Ps1ExpressionStatement, Ps1Variable
from refinery.lib.scripts.ps1.parser import Ps1Parser


class Ps1ExpressionTypeTest(TestBase):

    #: The world every script that redefines nothing and runs no opaque code has. Typing questions
    #: are asked against it because a command name is only trustworthy in a closed world, so an open
    #: world answers nothing and would test the absence, not the typing.
    CLOSED = Ps1WorldReach(Ps1TypeWorld(True, frozenset()))

    @staticmethod
    def _expr(source: str):
        statement = Ps1Parser(source).parse().body[0]
        assert isinstance(statement, Ps1ExpressionStatement)
        assert statement.expression is not None
        return statement.expression


class TestPs1CandidateTypes(Ps1ExpressionTypeTest):
    """
    The candidate set is the primitive the member gate reasons over: a conclusion about a value has
    to hold for every type the value could carry, so what matters is that a genuinely multi-valued
    result is reported as such and an unknowable one as the empty set, never as a single guess.
    """

    def _candidates(self, source: str, world: Ps1WorldReach | None = None):
        return candidate_types(self._expr(source), self.CLOSED if world is None else world)

    def test_a_cmdlet_contributes_every_output_type_it_declares(self):
        # Get-Date carries [OutputType([datetime], [string])]; both are candidates, since which one
        # a call yields depends on its arguments.
        self.assertEqual(
            self._candidates('(Get-Date)'),
            frozenset({resolve_type('System.DateTime'), resolve_type('System.String')}),
        )

    def test_an_untrusted_cmdlet_contributes_no_candidates(self):
        # [OutputType] is only a lower bound: a command that forwards its input emits types it never
        # declares, so a declaration is trusted only for a curated closed set. Get-Random forwards
        # -InputObject and Get-Command's declaration is not vouched for, so both are left untyped —
        # which is what keeps a member read on their result (e.g. (Get-Command X).Name).
        self.assertEqual(self._candidates('Get-Random'), frozenset())
        self.assertEqual(self._candidates('Get-Command'), frozenset())

    def test_a_static_call_takes_the_return_its_overloads_agree_on(self):
        self.assertEqual(
            self._candidates('[Diagnostics.Process]::GetCurrentProcess()'),
            frozenset({resolve_type('System.Diagnostics.Process')}),
        )

    def test_a_static_call_with_disagreeing_overloads_is_empty(self):
        # Math.Max is overloaded across every numeric type; with no argument typing the return is
        # not decidable, so nothing is reported rather than one of them picked.
        self.assertEqual(self._candidates('[Math]::Max(1, 2)'), frozenset())

    def test_a_static_call_surfaces_an_imprecise_supertype_return(self):
        # Convert.ChangeType is declared to return Object; that supertype is reported as-is.
        # Narrowing it is not this layer's job — a caller that must not act on a supertype is the
        # one that neutralises it.
        self.assertEqual(
            self._candidates('[Convert]::ChangeType($x, [int])'),
            frozenset({resolve_type('System.Object')}),
        )

    def test_an_instance_method_call_is_not_resolved(self):
        # String.Substring returns a string, but selecting an instance overload needs the receiver
        # type and argument types; that is deferred, so the call contributes no candidate.
        self.assertEqual(self._candidates('$s.Substring(0, 2)'), frozenset())

    def test_a_command_without_a_declared_output_is_empty(self):
        # Write-Host carries no [OutputType]; an undeclared output is unknown, not empty, so nothing
        # is contributed rather than absence read as "emits nothing".
        self.assertEqual(self._candidates('Write-Host x'), frozenset())

    def test_single_type_forms_are_delegated_to_the_free_function(self):
        for source in ("'abc'", '42', 'New-Object Net.WebClient', '[int]', '[datetime]$t'):
            with self.subTest(source):
                single = resolve_expression_type(self._expr(source))
                self.assertIsNotNone(single)
                self.assertEqual(self._candidates(source), frozenset({single}))

    def test_the_candidate_set_is_a_strict_superset_of_the_free_function(self):
        # The free function has no arm for a static method call and returns None; the set-valued
        # view resolves it. This is the widening that keeps it out of the transforms that depend on
        # the narrower answer.
        call = self._expr('[Diagnostics.Process]::GetCurrentProcess()')
        self.assertIsNone(resolve_expression_type(call))
        self.assertEqual(
            candidate_types(call, self.CLOSED),
            frozenset({resolve_type('System.Diagnostics.Process')}),
        )

    def test_an_untyped_variable_is_empty_without_a_model(self):
        # No variable typing is supplied here; a bare local resolves to nothing until a model
        # supplies it. Automatic-variable typing still applies, so this is a plain local.
        self.assertEqual(self._candidates('$notavariabletype'), frozenset())

    def test_supplied_variable_typing_resolves_a_typed_variable(self):
        webclient = resolve_type('System.Net.WebClient')
        assert webclient is not None
        self.assertEqual(
            candidate_types(self._expr('$client'), self.CLOSED, lambda var: webclient),
            frozenset({webclient}),
        )
        self.assertEqual(self._candidates('$client'), frozenset())

    def test_an_open_world_contributes_no_command_candidates(self):
        # A command name means what the metadata says only while nothing can have rebound it, so the
        # cmdlet whose declaration is trusted in a closed world contributes nothing in an open one.
        self.assertEqual(
            self._candidates('(Get-Date)', Ps1WorldReach(Ps1TypeWorld(False, frozenset()))),
            frozenset())


if __name__ == '__main__':
    import unittest
    unittest.main()


class TestPs1TheCurrentPipelineObjectIsTypedByWhatFeedsIt(Ps1ExpressionTypeTest):
    """
    Measured on Windows PowerShell 5.1:
    `(@('one', 'two', 'three') | Measure-Object).GetType().FullName` is
    `Microsoft.PowerShell.Commands.GenericMeasureInfo`, and
    `@('one', 'two', 'three') | Measure-Object | ForEach-Object { $_.Count }` writes `3`.

    A cmdlet declares what it writes to the pipeline *per object*, which is already what `$_` is
    bound to. Anything else upstream is a value the pipeline enumerates, and the type of the whole
    is not the type of an element — so it contributes nothing rather than the collection's type.
    """

    def _current_object(self, source: str):
        script = Ps1Parser(source).parse()
        node = next(
            node for node in script.walk()
            if isinstance(node, Ps1Variable) and node.name == '_'
        )
        return candidate_types(node, self.CLOSED)

    def test_a_cmdlet_upstream_types_the_current_object(self):
        self.assertEqual(
            self._current_object("'a' | Measure-Object | ForEach-Object { $_ }"),
            frozenset({
                resolve_type('Microsoft.PowerShell.Commands.GenericMeasureInfo'),
                resolve_type('Microsoft.PowerShell.Commands.GenericObjectMeasureInfo'),
                resolve_type('Microsoft.PowerShell.Commands.TextMeasureInfo'),
            }),
        )

    def test_an_enumerated_value_upstream_types_nothing(self):
        self.assertEqual(self._current_object("1, 2 | ForEach-Object { $_ }"), frozenset())

    def test_the_first_element_of_a_pipeline_has_nothing_upstream(self):
        self.assertEqual(self._current_object("ForEach-Object { $_ }"), frozenset())

    def test_a_begin_body_reads_a_current_object_nothing_here_bound(self):
        self.assertEqual(
            self._current_object("'a' | Measure-Object | ForEach-Object -Begin { $_ }"),
            frozenset(),
        )

    def test_a_stored_body_is_not_bound_by_the_pipeline_it_is_written_in(self):
        self.assertEqual(
            self._current_object("'a' | Measure-Object | Out-Null; $b = { $_ }"),
            frozenset(),
        )

    def test_a_command_the_script_takes_over_types_nothing(self):
        world = Ps1WorldReach(Ps1TypeWorld(True, frozenset({'measure-object'})))
        script = Ps1Parser("'a' | Measure-Object | ForEach-Object { $_ }").parse()
        node = next(
            node for node in script.walk()
            if isinstance(node, Ps1Variable) and node.name == '_'
        )
        self.assertEqual(candidate_types(node, world), frozenset())


class TestPs1ACallTheFactsDescribe(TestBase):
    """
    What a call answers where a measured fact covers it, and the refusals that keep a fact from
    answering for a call it was not measured on.
    """

    def _called(self, source: str):
        script = Ps1Parser(source).parse()
        statement = script.body[-1]
        assert isinstance(statement, Ps1ExpressionStatement)
        world = Ps1ModelCache(script).world_reach
        return evaluate(statement.expression, calls=call_reader(world))

    def _assertCannotFail(self, source: str, value):
        outcome = self._called(source)
        self.assertIs(outcome.throws, Ps1Throws.NEVER)
        self.assertEqual(outcome.value, value)

    def _assertNotCovered(self, source: str):
        self.assertTrue(self._called(source).may_throw)

    def test_the_square_root_of_a_number_is_a_double(self):
        for argument in ('36', '-1.5', '9223372036854775807', '79228162514264337593543950335d', '[byte]5', '6 * 7'):
            with self.subTest(argument):
                self._assertCannotFail(F'[Math]::Sqrt({argument})', Ps1Typed(named_type('System.Double')))

    def test_reversing_a_list_written_out_hands_back_nothing(self):
        for argument in ('(1, 2, 3, 4)', '@()', '@($null)', "(1, 'a', $null, @(2, 3))"):
            with self.subTest(argument):
                self._assertCannotFail(F'[array]::Reverse({argument})', NULL)

    def test_the_hash_code_of_an_integer_is_an_integer(self):
        self._assertCannotFail('(5).GetHashCode()', Ps1Typed(named_type('System.Int32')))

    def test_a_random_number_is_an_integer_with_a_hash_code(self):
        self._assertCannotFail('Get-Random', Ps1Typed(named_type('System.Int32')))
        self._assertCannotFail('(Get-Random).GetHashCode()', Ps1Typed(named_type('System.Int32')))

    def test_an_argument_of_a_type_no_fact_names_is_not_covered(self):
        for source in (
            "[Math]::Sqrt('36')",
            '[Math]::Sqrt($x)',
            '[Math]::Sqrt($null)',
            '[array]::Reverse($x)',
            "[array]::Reverse('abc')",
            '[array]::Reverse([int[,]]::new(2, 2))',
            "'a'.GetHashCode()",
        ):
            with self.subTest(source):
                self._assertNotCovered(source)

    def test_an_argument_list_no_fact_names_is_not_covered(self):
        for source in ('[Math]::Sqrt()', '[Math]::Sqrt(1, 2)', '(5).GetHashCode(1)', 'Get-Random -Maximum 5'):
            with self.subTest(source):
                self._assertNotCovered(source)

    def test_an_argument_that_may_fail_makes_the_call_one_that_may_fail(self):
        self._assertNotCovered("[Math]::Sqrt([int]'a')")

    def test_a_value_that_may_be_null_has_no_method_a_fact_covers(self):
        self._assertNotCovered('$x.GetHashCode()')

    def test_a_reader_whose_world_is_gone_reads_no_fact(self):
        script = Ps1Parser('[Math]::Sqrt(36)').parse()
        statement = script.body[-1]
        assert isinstance(statement, Ps1ExpressionStatement)
        world = Ps1ModelCache(script).world_reach
        reader, gone = call_reader(world), weakref.ref(world)
        del world
        gc.collect()
        self.assertIsNone(gone())
        self.assertEqual(evaluate(statement.expression, calls=reader), evaluate(statement.expression))

    def test_a_command_handed_pipeline_input_or_writing_to_a_redirection_is_not_covered(self):
        for source in ('1 | Get-Random', 'Get-Random 2>$null'):
            with self.subTest(source):
                self._assertNotCovered(F'({source}).GetHashCode()')

    def test_a_command_is_not_covered_where_default_parameter_values_may_be_bound(self):
        # Measured on 5.1: with `Get-Random:Maximum` bound to 0, a bare `Get-Random` fails.
        for binding in (
            "$PSDefaultParameterValues['Get-Random:Maximum'] = 0",
            "$PSDefaultParameterValues = @{ 'Get-Random:Maximum' = 0 }",
            "$ExecutionContext.SessionState.PSVariable.Set('PSDefaultParameterValues', @{ 'Get-Random:Maximum' = 0 })",
        ):
            with self.subTest(binding):
                self._assertNotCovered(F'{binding}; Get-Random')

    def test_a_call_answers_wherever_it_stands_in_an_expression(self):
        for source in ('[Math]::Sqrt(36) + 1', '[double][Math]::Sqrt(36)', '[Math]::Sqrt(36) * [Math]::Sqrt(4)'):
            with self.subTest(source):
                self.assertIs(self._called(source).throws, Ps1Throws.NEVER)

    def test_a_command_in_a_pipeline_is_not_covered_where_the_walk_asks_it_alone(self):
        script = Ps1Parser('1 | Get-Random').parse()
        command = next(node for node in script.walk() if isinstance(node, Ps1CommandInvocation))
        world = Ps1ModelCache(script).world_reach
        self.assertTrue(call_reader(world).outcome(command).may_throw)

    def test_a_fact_that_may_fail_answers_that_the_call_may_fail(self):
        fact, = call_facts(CallKind.INSTANCE, named_type('System.Text.StringBuilder'), 'tostring')
        script = Ps1Parser("$sb = [Text.StringBuilder]::new('ab')").parse()
        world = Ps1ModelCache(script).world_reach
        outcome = call_reader(world).recorded(fact, Ps1Outcome(Ps1Throws.NEVER, UNKNOWN), [])
        self.assertTrue(outcome.may_throw)

    def test_a_command_lookup_hook_takes_every_command_over(self):
        self._assertNotCovered(
            "$ExecutionContext.InvokeCommand.PreCommandLookupAction = { throw 'x' }; Get-Random")

    def test_a_command_the_script_takes_over_is_not_covered(self):
        self._assertNotCovered("function Get-Random { throw 'x' }; (Get-Random).GetHashCode()")

    def test_a_type_the_script_defines_is_not_covered(self):
        self._assertNotCovered("class Math { static [double] Sqrt([double]$x) { throw 'x' } }; [Math]::Sqrt(36)")

    def test_a_method_named_by_a_value_is_not_covered(self):
        self._assertNotCovered('[Math]::$m(36)')
