from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.identity import (
    Ps1ObjectSources,
    object_sources,
    passage_out_of,
)
from refinery.lib.scripts.ps1.ast import unwrap_parens
from refinery.lib.scripts.ps1.model import (
    Ps1ArrayExpression,
    Ps1AssignmentExpression,
    Ps1CastExpression,
    Ps1ExpressionStatement,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


def _last_value(source: str) -> Node:
    """
    The expression the last statement of *source* evaluates.
    """
    statement = Ps1Parser(source).parse().body[-1]
    if not isinstance(statement, Ps1ExpressionStatement) or statement.expression is None:
        raise AssertionError(F'the last statement of {source!r} is not an expression')
    return statement.expression


def _first(source: str, kind: type, name: str | None = None) -> Node:
    """
    The first node of *kind* in *source*, in source order; a variable is picked by its *name*.
    """
    for node in Ps1Parser(source).parse().walk_in_order():
        if isinstance(node, kind) and (name is None or getattr(node, 'name', None) == name):
            return node
    raise AssertionError(F'no {kind.__name__} in {source!r}')


def _spelled(node: Node | None) -> str | None:
    return None if node is None else Ps1Synthesizer().convert(node)


class TestPs1ObjectSources(TestBase):
    """
    Which object the value of an expression may be. Each expectation is a 5.1 fact: the store or
    the call through the expression's value changes what the operand's name holds exactly where
    the value is that name's object, and `[object]::ReferenceEquals` compares the two directly.
    """

    def _assertMayBe(self, sources: Ps1ObjectSources, operand: str, *, certain: bool):
        self.assertEqual(_spelled(sources.operand), operand)
        self.assertEqual(sources.certain, certain)

    def _assertMadeHere(self, sources: Ps1ObjectSources):
        self.assertEqual(sources, Ps1ObjectSources(made_here=True))

    def _assertUnknown(self, sources: Ps1ObjectSources):
        self.assertEqual(sources, Ps1ObjectSources(unknown=True))

    def test_a_parenthesis_is_the_object_it_holds(self):
        self._assertMayBe(object_sources(_last_value('($x)')), '$x', certain=True)

    def test_a_conversion_may_be_the_object_it_converts_or_a_new_one(self):
        """
        Measured: `[array]$x` over an `Object[]` is the array `$x` holds, and `[int[]]$x` over the
        same array is a new one. Which of the two a conversion is depends on the operand.
        """
        for source in ('[array]$x', '[int[]]$x', '$x -as [array]'):
            with self.subTest(source):
                sources = object_sources(_last_value(source))
                self._assertMayBe(sources, '$x', certain=False)
                self.assertTrue(sources.made_here)

    def test_a_reference_is_not_the_object(self):
        self._assertUnknown(object_sources(_last_value('[ref]$x')))

    def test_a_product_by_a_count_that_converts_to_one_is_its_left_operand(self):
        """
        Measured: `$y * 1`, `$y * '1'`, `$y * 1.4` and `$y * $n` with `$n = 1` are each the array
        `$y` holds. Over a number the product is a new number, so none of them is certain.
        """
        for source in ('$y * 1', "$y * '1'", '$y * 1.4', '$y * $n'):
            with self.subTest(source):
                self._assertMayBe(object_sources(_last_value(source)), '$y', certain=False)

    def test_a_product_by_two_is_a_new_array(self):
        self._assertMadeHere(object_sources(_last_value('$y * 2')))

    def test_a_sum_onto_null_is_its_right_operand(self):
        for source in ('$null + $x', '$b + $x'):
            with self.subTest(source):
                self._assertMayBe(object_sources(_last_value(source)), '$x', certain=False)

    def test_a_sum_onto_a_value_that_is_not_null_is_a_new_object(self):
        for source in ('@() + $x', "'a' + $x"):
            with self.subTest(source):
                self._assertMadeHere(object_sources(_last_value(source)))

    def test_a_sum_is_never_its_left_operand(self):
        for source in ('$y + @()', '$y + $x'):
            with self.subTest(source):
                sources = object_sources(_last_value(source))
                self.assertNotEqual(_spelled(sources.operand), '$y')
                self.assertTrue(sources.made_here)

    def test_an_array_subexpression_around_a_conversion_to_an_array_type_is_that_conversion(self):
        """
        Measured: `@([object[]]$x)` and `@(([object[]]$x))` are the array `$x` holds.
        """
        for source in ('@([object[]]$x)', '@(([object[]]$x))'):
            with self.subTest(source):
                sources = object_sources(_last_value(source))
                self.assertTrue(sources.certain)
                assert sources.operand is not None
                self.assertEqual(_spelled(unwrap_parens(sources.operand)), '[object[]]$x')

    def test_an_array_subexpression_around_a_variable_is_a_new_array(self):
        self._assertMadeHere(object_sources(_last_value('@($x)')))

    def test_an_array_subexpression_around_a_local_constrained_to_an_array_type_may_be_it(self):
        """
        Measured: `@($a)` over a local constrained as `[object[]]` is that local's array in a
        function body, and a new array at the top of a dot-sourced script.
        """
        for source in (
            'function f { [object[]]$a = 1, 2; @($a) }',
            '[object[]]$a = 1, 2; @($a)',
            'function f([object[]]$a) { @($a) }',
        ):
            with self.subTest(source):
                sources = object_sources(_first(source, Ps1ArrayExpression))
                self._assertMayBe(sources, '$a', certain=False)
                self.assertTrue(sources.made_here)

    def test_an_array_subexpression_around_a_local_constrained_to_a_scalar_is_a_new_array(self):
        self._assertMadeHere(
            object_sources(_first('[string]$a = 1; @($a)', Ps1ArrayExpression)))

    def test_the_sync_root_of_an_array_is_the_array(self):
        self._assertMayBe(object_sources(_last_value('$x.SyncRoot')), '$x', certain=False)

    def test_an_assignment_used_as_a_value_is_the_object_it_stored(self):
        inner = _first('$y = ($x = $v)', Ps1Variable, 'v').parent
        self.assertIsInstance(inner, Ps1AssignmentExpression)
        assert inner is not None
        self._assertMayBe(object_sources(inner), '$v', certain=True)

    def test_an_assignment_to_a_constrained_local_may_convert_what_it_stores(self):
        inner = _first('[string]$x = 0; $y = ($x = $v)', Ps1Variable, 'v').parent
        self.assertIsInstance(inner, Ps1AssignmentExpression)
        assert inner is not None
        self._assertMayBe(object_sources(inner), '$v', certain=False)

    def test_an_element_and_a_method_result_are_unknown(self):
        for source in ('$x[0]', '$x.Clone()', '$(,$x)', 'Get-Thing $x'):
            with self.subTest(source):
                self._assertUnknown(object_sources(_last_value(source)))

    def test_an_array_constructor_makes_a_new_array(self):
        self._assertMadeHere(object_sources(_last_value('[object[]]::new(3)')))

    def test_new_object_makes_its_array_where_the_command_name_is_trusted(self):
        value = _last_value("New-Object 'object[]' 3")
        self._assertMadeHere(object_sources(value, lambda name: name == 'new-object'))
        self._assertUnknown(object_sources(value))


class TestPs1PassageOutOf(TestBase):

    def test_the_passage_out_of_an_array_subexpression_steps_over_its_statement(self):
        source = '@([object[]]$x)'
        passage = passage_out_of(_first(source, Ps1CastExpression))
        self.assertIsNotNone(passage)
        assert passage is not None
        self.assertIsInstance(passage.expression, Ps1ArrayExpression)
        self.assertTrue(passage.certain)

    def test_an_assignment_standing_as_a_statement_is_no_passage(self):
        self.assertIsNone(passage_out_of(_first('$y = $x', Ps1Variable, 'x')))

    def test_an_assignment_used_as_a_value_is_a_passage(self):
        passage = passage_out_of(_first('$z = ($y = $x)', Ps1Variable, 'x'))
        self.assertIsNotNone(passage)
        assert passage is not None
        self.assertIsInstance(passage.expression, Ps1AssignmentExpression)
        self.assertTrue(passage.certain)
