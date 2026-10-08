"""
Constant folding on its own: which expressions a probe-pinned value replaces, and the refusals —
unpinned operators, shadowed builtins, values no literal spells, and the folds that would spell
the text the tree already holds.
"""
from __future__ import annotations

from test.lib.scripts.au3.deobfuscation import TestAu3

from refinery.lib.scripts.au3.deobfuscation.fold import Au3ConstantFolding


class TestAu3ConstantFolding(TestAu3):

    def test_arithmetic_folds_to_the_literal(self):
        self.assertEqual(
            self._apply('$x = 1 + 2 * 3', Au3ConstantFolding),
            '$x = 7\n')

    def test_a_string_concatenation_folds(self):
        self.assertEqual(
            self._apply('$x = "a" & "b" & "c"', Au3ConstantFolding),
            '$x = "abc"\n')

    def test_a_comparison_folds_wherever_it_stands(self):
        self.assertEqual(
            self._apply('$x = 10 > "9"', Au3ConstantFolding),
            '$x = True\n')
        self.assertEqual(
            self._apply('$x = "abc" = "ABC"', Au3ConstantFolding),
            '$x = True\n')

    def test_a_builtin_call_folds_over_literal_arguments(self):
        self.assertEqual(
            self._apply('$x = BinaryToString("0x414243")', Au3ConstantFolding),
            '$x = "ABC"\n')
        self.assertEqual(
            self._apply('$x = StringLen(@CR)', Au3ConstantFolding),
            '$x = 1\n')

    def test_binary_concatenation_folds_over_the_binary_spelling(self):
        """
        A `Binary("0x…")` call is the literal spelling of its value, so the operands read as
        values and the concatenation folds (probe3 41: the interpreter printed `0x4142`).
        """
        self.assertEqual(
            self._apply('$x = Binary("0x41") & Binary("0x42")', Au3ConstantFolding),
            '$x = Binary("0x4142")\n')

    def test_a_shadowed_builtin_is_not_folded(self):
        self.assertEqual(
            self._apply(
                '''
                Func Binary($s)
                    Return 1
                EndFunc

                $x = Binary("0x41")
                ''',
                Au3ConstantFolding,
            ),
            'Func Binary($s)\n    Return 1\nEndFunc\n$x = Binary("0x41")\n')

    def test_execute_is_never_folded_as_a_value(self):
        self.assertEqual(
            self._apply('$x = Execute("1 + 1")', Au3ConstantFolding),
            '$x = Execute("1 + 1")\n')

    def test_an_unpinned_operand_leaves_the_expression_standing(self):
        self.assertEqual(
            self._apply('$x = $y + 1', Au3ConstantFolding),
            '$x = $y + 1\n')

    def test_an_unspellable_value_leaves_the_expression_standing(self):
        """
        `Chr(0)` holds a NUL, which no AutoIt3 literal spells, and `@CR` renders the same way —
        so folding either would print text the parser reads back as a different program.
        """
        self.assertEqual(
            self._apply('$x = Chr(0)', Au3ConstantFolding),
            '$x = Chr(0)\n')
        self.assertEqual(
            self._apply('$x = @CR', Au3ConstantFolding),
            '$x = @CR\n')

    def test_a_fold_that_spells_the_same_text_is_not_a_change(self):
        """
        `-5` folds to `-5` and `Binary("0x41")` to itself, so a pass that installed the
        replacement would report a change the next pass reports again, and the group would
        never settle.
        """
        self.assertEqual(
            self._apply('$x = -5', Au3ConstantFolding),
            '$x = -5\n')
        self.assertEqual(
            self._apply('$x = Binary("0x41")', Au3ConstantFolding),
            '$x = Binary("0x41")\n')

    def test_and_or_folds_only_as_a_decided_condition(self):
        """
        Whether AutoIt skips the right side of a decided `And` is not a fact any probe pinned,
        so a condition folds only when both sides' truth is known and neither holds a call, and
        the same operators in expression position never fold.
        """
        self.assertEqual(
            self._apply(
                '''
                If 1 And 2 Then
                    $x = 1
                EndIf
                ''',
                Au3ConstantFolding,
            ),
            'If True Then\n    $x = 1\nEndIf\n')
        self.assertEqual(
            self._apply('$x = True and False', Au3ConstantFolding),
            '$x = True and False\n')

    def test_and_or_with_a_call_on_either_side_does_not_fold(self):
        """
        The decided side may not be dropped while the other still does something, so a call on
        either side of the condition refuses the fold.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Return 1
                EndFunc

                If True And f() Then
                    $x = 1
                EndIf
                ''',
                Au3ConstantFolding,
            ),
            'Func f()\n    Return 1\nEndFunc\nIf True and f() Then\n    $x = 1\nEndIf\n')

    def test_and_or_with_an_unknown_truth_does_not_fold(self):
        self.assertEqual(
            self._apply(
                '''
                If True And $x Then
                    $x = 1
                EndIf
                ''',
                Au3ConstantFolding,
            ),
            'If True and $x Then\n    $x = 1\nEndIf\n')

    def test_a_loop_condition_folds(self):
        self.assertEqual(
            self._apply(
                '''
                While 1 > 2
                    $x = 1
                WEnd
                ''',
                Au3ConstantFolding,
            ),
            'While False\n    $x = 1\nWend\n')
