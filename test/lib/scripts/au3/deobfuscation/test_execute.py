"""
`Execute` flattening on its own: the gates the pinned `Execute` semantics draw around what a
string-literal argument may splice into, and the no-effect cases the interpreter answered `""`
for, which a splice must never make fatal.
"""
from __future__ import annotations

from test.lib.scripts.au3.deobfuscation import TestAu3

from refinery.lib.scripts.au3.deobfuscation.execute import Au3ExecuteFlattening


class TestAu3ExecuteFlattening(TestAu3):

    def test_a_literal_expression_splices_in_expression_position(self):
        self.assertEqual(
            self._apply('$x = Execute("1 + 1")', Au3ExecuteFlattening),
            '$x = 1 + 1\n')

    def test_a_literal_expression_splices_in_statement_position(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Return 1
                EndFunc

                Execute("f()")
                ''',
                Au3ExecuteFlattening,
            ),
            'Func f()\n    Return 1\nEndFunc\nf()\n')

    def test_an_assignment_inside_the_literal_stays_a_comparison(self):
        """
        The interpreter parses `=` inside an `Execute` argument as a comparison and writes
        nothing (probe3 10), so the splice keeps the comparison the argument held.
        """
        self.assertEqual(
            self._apply('$x = Execute("$y = 5")', Au3ExecuteFlattening),
            '$x = $y = 5\n')

    def test_an_assignment_as_the_whole_statement_is_not_spliced(self):
        """
        A top-level `=` in statement position would re-parse as an assignment, which the
        interpreter never ran (probe3 10: the write did not happen), so the call stands.
        """
        self.assertEqual(
            self._apply('Execute("$y = 5")', Au3ExecuteFlattening),
            'Execute("$y = 5")\n')

    def test_a_bare_name_is_never_spliced(self):
        """
        What a bare name evaluates to is not a fact any probe pinned — an unseen include may
        declare it — and the alias map owns the declaration, so the call stands.
        """
        self.assertEqual(
            self._apply('$x = Execute("f")', Au3ExecuteFlattening),
            '$x = Execute("f")\n')

    def test_an_unparseable_literal_is_not_spliced(self):
        """
        A literal that fails to parse never ran at runtime (probe 111: `Execute("1 +")` answered
        `""`), so splicing it would change a no-op into a parse error.
        """
        self.assertEqual(
            self._apply('$x = Execute("1 +")', Au3ExecuteFlattening),
            '$x = Execute("1 +")\n')

    def test_a_statement_sequence_is_not_spliced(self):
        """
        Declarations and statement sequences are parse errors inside `Execute` (probe3 12/14:
        both answered `""` and wrote nothing), so the call stands.
        """
        self.assertEqual(
            self._apply('$x = Execute("Local $y = 3")', Au3ExecuteFlattening),
            '$x = Execute("Local $y = 3")\n')
        self.assertEqual(
            self._apply('$x = Execute("$y = 1" & @LF & "$y = 2")', Au3ExecuteFlattening),
            '$x = Execute("$y = 1" & @LF & "$y = 2")\n')

    def test_a_return_is_not_spliced(self):
        """
        `Return` inside `Execute` answers `""` and does not return from the enclosing function
        (probe3 15), which no splice can spell.
        """
        self.assertEqual(
            self._apply('$x = Execute("Return 42")', Au3ExecuteFlattening),
            '$x = Execute("Return 42")\n')

    def test_a_call_to_an_unknown_function_is_not_spliced(self):
        """
        An unknown callee is one of `Execute`'s pinned failure modes (probe 112: it answered
        `""`), and a splice would make that error fatal where the original swallowed it.
        """
        self.assertEqual(
            self._apply('$x = Execute("Undefined()")', Au3ExecuteFlattening),
            '$x = Execute("Undefined()")\n')

    def test_a_call_through_a_variable_is_not_spliced(self):
        self.assertEqual(
            self._apply('$x = Execute("$f()")', Au3ExecuteFlattening),
            '$x = Execute("$f()")\n')

    def test_a_shadowed_execute_is_not_flattened(self):
        self.assertEqual(
            self._apply(
                '''
                Func Execute($s)
                    Return 1
                EndFunc

                $x = Execute("1 + 1")
                ''',
                Au3ExecuteFlattening,
            ),
            'Func Execute($s)\n    Return 1\nEndFunc\n$x = Execute("1 + 1")\n')

    def test_a_missing_or_extra_argument_is_not_flattened(self):
        self.assertEqual(
            self._apply('$x = Execute()', Au3ExecuteFlattening),
            '$x = Execute()\n')
        self.assertEqual(
            self._apply('$x = Execute("1", "2")', Au3ExecuteFlattening),
            '$x = Execute("1", "2")\n')

    def test_a_non_literal_argument_is_not_flattened(self):
        self.assertEqual(
            self._apply('$x = Execute($y)', Au3ExecuteFlattening),
            '$x = Execute($y)\n')
