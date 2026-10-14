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

    def test_a_folded_string_with_an_unspellable_character_spells_a_chain(self):
        self.assertEqual(
            self._apply('$x = "a" & Chr(10) & "b"', Au3ConstantFolding),
            '$x = "a" & @LF & "b"\n')

    def test_a_chain_spells_the_text_it_already_holds(self):
        """
        The fold re-renders a chain to the same text it holds, because `literal_value` reads the
        chain back — the symmetry that keeps a decoded payload's line breaks standing.
        """
        self._assertKept('MsgBox(0, 0, "a" & @CRLF & "b")')

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

    def test_a_builtin_call_folds_over_arguments_the_evaluator_proves(self):
        """
        A call folds over a compound argument — an operator or another builtin's result — the
        same way it folds over a literal, because the evaluator proves the argument's value in
        one pass instead of waiting for a fold of the argument first.
        """
        self.assertEqual(
            self._apply('$x = StringLen("a" & "bc")', Au3ConstantFolding),
            '$x = 3\n')
        self.assertEqual(
            self._apply('$x = StringLen(BinaryToString("0x414243"))', Au3ConstantFolding),
            '$x = 3\n')

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

    def test_and_or_fold_to_their_boolean_value(self):
        """
        In expression position the operators answer a boolean (probe4 62-65), so the fold no
        longer needs the condition position to consume them.
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
            '$x = False\n')

    def test_a_decided_left_operand_folds_without_the_right_side(self):
        """
        AutoIt skips the right side of a decided `And`/`Or` (probe4 60, 61), so the fold drops a
        call there soundly — it is code the interpreter never runs.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Return 1
                EndFunc

                If False And f() Then
                    $x = 1
                EndIf
                ''',
                Au3ConstantFolding,
            ),
            'Func f()\n    Return 1\nEndFunc\nIf False Then\n    $x = 1\nEndIf\n')
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Return 1
                EndFunc

                If True Or f() Then
                    $x = 1
                EndIf
                ''',
                Au3ConstantFolding,
            ),
            'Func f()\n    Return 1\nEndFunc\nIf True Then\n    $x = 1\nEndIf\n')

    def test_a_ternary_over_a_literal_condition_folds_to_its_branch(self):
        """
        AutoIt evaluates only the chosen branch (probe4 66, 67), so the other side is dropped
        soundly, call included.
        """
        self.assertEqual(
            self._apply('$x = True ? "yes" : "no"', Au3ConstantFolding),
            '$x = "yes"\n')
        self.assertEqual(
            self._apply('$x = 0 ? 1 : 2', Au3ConstantFolding),
            '$x = 2\n')
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Return 1
                EndFunc

                $x = True ? "yes" : f()
                ''',
                Au3ConstantFolding,
            ),
            'Func f()\n    Return 1\nEndFunc\n$x = "yes"\n')

    def test_an_elseif_test_folds_as_a_condition(self):
        self.assertEqual(
            self._apply(
                '''
                If 0 Then
                    $x = 1
                ElseIf 1 And 2 Then
                    $x = 2
                EndIf
                ''',
                Au3ConstantFolding,
            ),
            'If 0 Then\n    $x = 1\nElseIf True Then\n    $x = 2\nEndIf\n')

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

    def test_an_array_folds_only_where_a_declaration_initializes(self):
        """
        An array spells only as an array literal, which AutoIt accepts only where a declaration
        initializes; everywhere else the call that builds it stands.
        """
        self.assertEqual(
            self._apply('Local $x[3] = StringSplit("a,b", ",")', Au3ConstantFolding),
            'Local $x[3] = [2, "a", "b"]\n')
        self.assertEqual(
            self._apply('$x = StringSplit("a,b", ",")', Au3ConstantFolding),
            '$x = StringSplit("a,b", ",")\n')
        self.assertEqual(
            self._apply('MsgBox(0, "", StringSplit("a,b", ","))', Au3ConstantFolding),
            'MsgBox(0, "", StringSplit("a,b", ","))\n')

    def test_the_int64_minimum_is_not_rendered(self):
        """
        The minimum int64 spells only as a hex literal, which the renderer does not choose; the
        negated decimal it would print reads back one off, so the fold leaves the expression
        standing.
        """
        self.assertEqual(
            self._apply('$x = 0x8000000000000000 + 0', Au3ConstantFolding),
            '$x = 0x8000000000000000 + 0\n')

    def test_a_string_holding_a_line_break_code_point_is_not_rendered(self):
        """
        The lexer ends a line on U+2028, so a literal holding one would re-parse as two
        statements; AutoIt spells no literal for it and the fold leaves the call standing.
        """
        self.assertEqual(
            self._apply('$x = ChrW(8232)', Au3ConstantFolding),
            '$x = ChrW(8232)\n')

    def test_a_negative_zero_is_not_rendered(self):
        """
        AutoIt prints `-0` for the negative zero, which the parser reads back as the integer
        zero, so the fold refuses the spelling.
        """
        self.assertEqual(
            self._apply('$x = 0 / -1', Au3ConstantFolding),
            '$x = 0 / -1\n')

    def test_an_empty_binary_is_not_rendered(self):
        """
        No literal spells the empty binary: `Binary("0x")` reads back as the two bytes `0x` holds
        as text, so a fold that installed it would decay a step at a time.
        """
        self.assertEqual(
            self._apply('$x = Binary("")', Au3ConstantFolding),
            '$x = Binary("")\n')

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
