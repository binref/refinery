"""
The one constant evaluator over the policies its callers choose: a literal shape read back
whatever the bound, a variable read through a lookup within the bound, an operator over proven
operands, a call over the builtin table or the caller's hook, and a fallback for the shapes only
the caller can hold. The bound itself is complete over the value domain — a string, a binary, an
array and its recursive payload — so the refusals asserted here are the ones every caller shares.

Every expected answer is the printed text of the value, the same reading the AutoIt3 probes
pinned for the value tables, so a wrong operator answer shows up as a wrong string and every
refusal is `None`.
"""
from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.au3.analysis.constants import (
    Policy,
    combine,
    constant_value,
    within_limit,
)
from refinery.lib.scripts.au3.analysis.values import (
    of_array,
    of_binary,
    of_bool,
    of_int,
    of_string,
    to_string,
)
from refinery.lib.scripts.au3.parser import Au3Parser


class TestAu3Constants(TestBase):

    def _evaluated(self, source: str, **kwargs):
        expression = Au3Parser(source).parse_expression()
        result = constant_value(expression, Policy(kwargs.pop('functions', frozenset()), **kwargs))
        return None if result is None else to_string(result)

    def test_a_literal_shape_is_read_back_over_any_limit(self):
        self.assertEqual(self._evaluated(F'"{"a" * 20}"', limit=4), 'a' * 20)

    def test_a_variable_read_answers_the_lookup_within_the_limit(self):
        for limit, expected in ((None, 'abcd'), (4, 'abcd'), (3, None)):
            with self.subTest(limit=limit):
                self.assertEqual(
                    self._evaluated('$x', lookup=lambda name: of_string('abcd'), limit=limit),
                    expected)

    def test_a_variable_read_without_a_lookup_is_refused(self):
        for name, lookup in (('absent', None), ('empty', lambda name: None)):
            with self.subTest(lookup=name):
                self.assertIsNone(self._evaluated('$x', lookup=lookup))

    def test_an_operator_answers_over_proven_operands(self):
        for source, expected in (
            ('1 + 2 * 3', '7'),
            ('0 - 2 - 3', '-5'),
            ('-2', '-2'),
            ('1 = 1', 'True'),
            ('2 <> 2', 'False'),
            ('"a" & "b"', 'ab'),
            ('True And True', 'True'),
            ('True Or False', 'True'),
        ):
            with self.subTest(source=source):
                self.assertEqual(self._evaluated(source), expected)

    def test_an_operator_refuses_an_unproven_operand(self):
        for source in ('1 + $x', '$x & "a"', '1 + Unknown()'):
            with self.subTest(source=source):
                self.assertIsNone(self._evaluated(source))

    def test_a_concatenation_refuses_over_the_limit(self):
        """
        A `&` chain of literals is itself a literal shape, read back uncapped, so the bound bites
        only where a lookup, not the source, supplies an operand.
        """
        for limit, expected in ((1, None), (2, 'ab')):
            with self.subTest(limit=limit):
                self.assertEqual(
                    self._evaluated(
                        '$x & "b"',
                        lookup=lambda name: of_string('a'),
                        limit=limit),
                    expected)

    def test_a_decided_left_operand_never_evaluates_the_right(self):
        """
        AutoIt runs no right operand once the left decides an `And`/`Or` (probe4 60, 61), so a call
        on that side — a name no builtin table owns — still folds.
        """
        for source, expected in (
            ('False And Unknown()', 'False'),
            ('True Or Unknown()', 'True'),
            ('True And Unknown()', None),
            ('False Or Unknown()', None),
        ):
            with self.subTest(source=source):
                self.assertEqual(self._evaluated(source), expected)

    def test_a_ternary_answers_the_branch_the_condition_chooses(self):
        """
        AutoIt runs only the chosen branch (probe4 66, 67), so the unchosen side — a name no
        builtin table owns — never has to prove a value.
        """
        for source, expected in (
            ('True ? 1 : Unknown()', '1'),
            ('False ? Unknown() : 2', '2'),
            ('Unknown() ? 1 : 2', None),
        ):
            with self.subTest(source=source):
                self.assertEqual(self._evaluated(source), expected)

    def test_a_call_refuses_a_name_a_script_function_shadows(self):
        self.assertIsNone(self._evaluated('StringLen("ab")', functions=frozenset({'stringlen'})))

    def test_a_call_answers_the_builtin_table(self):
        for limit, expected in ((None, 'edcba'), (4, None)):
            with self.subTest(limit=limit):
                self.assertEqual(self._evaluated('StringReverse("abcde")', limit=limit), expected)

    def test_a_call_hook_owns_the_dispatch(self):
        """
        A hook is the interpreter's, so it answers before the builtin table does and reaches the
        script functions the shadow check would refuse.
        """
        for functions, expected in (
            (frozenset(), 'hooked'),
            (frozenset({'stringlen'}), 'hooked'),
        ):
            with self.subTest(functions=functions):
                self.assertEqual(
                    self._evaluated(
                        'StringLen("ab")',
                        functions=functions,
                        call=lambda name, arguments: of_string('hooked')),
                    expected)

    def test_a_fallback_answers_the_shapes_the_evaluator_does_not_own(self):
        self.assertEqual(
            self._evaluated('$a[0] + 1', fallback=lambda expression: of_int(9)),
            '10')
        self.assertIsNone(self._evaluated('$a[0] + 1'))

    def test_within_limit_measures_every_kind(self):
        for value, limit, expected in (
            (of_string('ab'), 2, True),
            (of_string('ab'), 1, False),
            (of_binary(b'abc'), 3, True),
            (of_binary(b'abc'), 2, False),
            (of_array((of_int(1), of_int(2))), 2, True),
            (of_array((of_int(1), of_int(2))), 1, False),
            (of_array((of_string('ab'), of_string('cd'))), 3, False),
            (of_array((of_array((of_string('ab'),)),)), 1, False),
            (of_array((of_array((of_int(1),)),)), 1, True),
            (of_int(10 ** 20), 0, True),
            (of_bool(False), 0, True),
            (of_string('anything'), None, True),
        ):
            with self.subTest(kind=value.kind.name, limit=limit):
                self.assertIs(within_limit(value, limit), expected)

    def test_combine_answers_within_the_limit(self):
        for operator, left, right, limit, expected in (
            ('+', of_int(1), of_int(2), None, '3'),
            ('+', of_int(2 ** 62), of_int(1), 0, F'{2 ** 62 + 1}'),
            ('&', of_string('a'), of_string('b'), 2, 'ab'),
            ('&', of_string('a'), of_string('b'), 1, None),
            ('&', of_string('a'), of_string('b'), None, 'ab'),
        ):
            with self.subTest(operator=operator, limit=limit):
                result = combine(operator, left, right, limit)
                self.assertEqual(None if result is None else to_string(result), expected)
