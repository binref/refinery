from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import canonical, set_child
from refinery.lib.scripts.au3.model import Au3ExpressionStatement
from refinery.lib.scripts.au3.parser import Au3Parser
from refinery.lib.scripts.au3.synth import Au3Synthesizer

#: A statement the interpreter accepts only as a continued line. The fidelity harvest reads the
#: string like any other program this package holds, so the continuation has to round-trip
#: through the parser the same way a one-line statement does.
CONTINUED_ASSIGNMENT = (
    '$x = "aaaaaaaaaaaaaaaaaaaa" & _\n'
    '"bbbbbbbbbbbbbbbbbbbb"\n'
)


class TestAu3Synthesizer(TestBase):

    def _round_trip(self, source: str, line_length: int | None = None) -> str:
        synth = Au3Synthesizer() if line_length is None else Au3Synthesizer(line_length=line_length)
        ast1 = Au3Parser(source).parse()
        self.assertEqual(
            ast1.errors, [],
            F'Parse produced errors for {source!r}: '
            F'{[e.message for e in ast1.errors]}',
        )
        out1 = synth.convert(ast1)
        ast2 = Au3Parser(out1).parse()
        self.assertEqual(
            ast2.errors, [],
            F'Synthesized output does not re-parse cleanly for {source!r}:\n'
            F'Output: {out1!r}\nErrors: {[e.message for e in ast2.errors]}',
        )
        out2 = synth.convert(ast2)
        self.assertEqual(
            out1, out2,
            F'Round-trip not a fixpoint:\nInput: {source!r}\n'
            F'First: {out1!r}\nSecond: {out2!r}',
        )
        return out1

    def _continued(self, source: str, line_length: int) -> str:
        """
        The source printed under a line length small enough to force continuations, asserted to
        re-parse cleanly before the caller checks its shape.
        """
        return self._round_trip(source, line_length)

    def test_int_literal(self):
        self.assertEqual(self._round_trip('42\n'), '42\n')

    def test_float_literal(self):
        self._round_trip('3.5\n')

    def test_hex_literal(self):
        self.assertEqual(self._round_trip('0x80000000\n'), '0x80000000\n')

    def test_string_double_quotes(self):
        self._round_trip('"hello"\n')

    def test_string_single_quotes(self):
        self._round_trip("'hello'\n")

    def test_string_doubled_quote_escape(self):
        out = self._round_trip("'it''s'\n")
        self.assertEqual(out, "'it''s'\n")

    def test_boolean_and_null(self):
        self._round_trip('$x = True And False Or Null\n')

    def test_variable_and_macro_casing_preserved(self):
        self.assertEqual(self._round_trip('$FOO = @SCRIPTDIR\n'), '$FOO = @SCRIPTDIR\n')

    def test_arithmetic_precedence(self):
        self.assertEqual(self._round_trip('$x = 1 + 2 * 3\n'), '$x = 1 + 2 * 3\n')

    def test_parenthesized_grouping_preserved(self):
        self.assertEqual(self._round_trip('$x = (1 + 2) * 3\n'), '$x = (1 + 2) * 3\n')

    def test_parens_added_where_precedence_requires(self):
        out = self._round_trip('$x = 1 + (2 + 3)\n')
        self.assertEqual(out, '$x = 1 + (2 + 3)\n')

    def test_concat(self):
        self._round_trip('$s = "a" & "b" & $c\n')

    def test_a_concatenation_chain_hundreds_of_pieces_deep(self):
        """
        An obfuscated script spells a concatenation chain hundreds of pieces deep, which prints
        from a loop over the left spine rather than one recursion frame per level.
        """
        chain = ' & '.join(F'"a{i}"' for i in range(300))
        self.assertEqual(self._round_trip(F'$q = {chain}\n'), F'$q = {chain}\n')

    def test_a_statement_past_the_line_length_is_continued_behind_the_operator(self):
        out = self._continued(
            '$x = "aaaaaaaaaaaaaaaaaaaa" & "bbbbbbbbbbbbbbbbbbbb" & "cccccccccccccccccccc"\n', 40)
        self.assertEqual(out, (
            '$x = "aaaaaaaaaaaaaaaaaaaa" &  _\n'
            '"bbbbbbbbbbbbbbbbbbbb" &  _\n'
            '"cccccccccccccccccccc"\n'
        ))

    def test_a_call_is_continued_between_arguments(self):
        out = self._continued('MsgBox(0, "title", "text")\n', 20)
        self.assertEqual(out, 'MsgBox(0,  _\n"title",  _\n"text")\n')

    def test_a_return_is_continued_behind_its_keyword(self):
        out = self._continued(
            'Func f()\nReturn "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"\nEndFunc\n', 30)
        self.assertEqual(
            out, 'Func f()\n    Return  _\n"aaaaaaaaaaaaaaaaaaaaaaaaaaaa"\nEndFunc\n')

    def test_an_array_literal_is_continued_between_elements(self):
        out = self._continued('Local $a = ["aaaaaaaa", "bbbbbbbb"]\n', 25)
        self.assertEqual(out, 'Local $a = [ _\n"aaaaaaaa",  _\n"bbbbbbbb"]\n')

    def test_continued_output_reparses_to_the_same_program(self):
        """
        A continuation changes only where the line breaks fall, never the program the lines spell,
        so the tree under a continued print is the tree that went in.
        """
        for source in (
            '$x = "aaaaaaaaaaaaaaaaaaaa" & "bbbbbbbbbbbbbbbbbbbb" & $c & f(1, "dd")\n',
            'MsgBox(0, "title", "text", $i, $j)\n',
            'Local $a = ["aaaaaaaa", "bbbbbbbb", $c], $b[2], $d\n',
            'Func f($p, $q = "eeee")\nReturn $p & "ffffffffffffffff"\nEndFunc\n',
            'If $aaaaaaa & "bbbbbbbb" Then\n$c = 1\nEndIf\n',
        ):
            with self.subTest(source=source):
                tree = Au3Parser(source).parse()
                printed = Au3Synthesizer(line_length=24).convert(tree)
                self.assertGreater(
                    len(printed.splitlines()), len(Au3Synthesizer().convert(tree).splitlines()))
                self.assertEqual(canonical(tree), canonical(Au3Parser(printed).parse()))

    def test_a_long_concatenation_fits_the_interpreters_line_limit(self):
        """
        The interpreter refuses a physical line past 4094 characters, so a chain whose pieces
        outgrow one is continued behind the `&` at column zero: every line of the output fits the
        limit and every continued line starts with the piece that would not.
        """
        chain = ' & '.join(F'"{"a" * 3000}"' for _ in range(6))
        out = self._round_trip(F'$q = {chain}\n')
        lines = out.splitlines()
        self.assertGreater(len(lines), 2)
        for line in lines:
            self.assertLessEqual(len(line), 4094)
        for line in lines[:-1]:
            self.assertTrue(line.endswith(' _'))
        for line in lines[1:]:
            self.assertTrue(line.startswith('"'))

    def test_call_arguments_fill_each_line_to_the_limit(self):
        """
        A call with thousands of arguments is continued between them, and each line before the
        last carries as many arguments as the limit admits.
        """
        source = F'f({", ".join(str(i) for i in range(2000))})\n'
        out = self._round_trip(source)
        lines = out.splitlines()
        self.assertGreater(len(lines), 1)
        for line in lines:
            self.assertLessEqual(len(line), 4094)
        self.assertGreater(len(lines[0]), 4000)

    def test_comparison(self):
        for operator in ('=', '==', '<>', '<', '>', '<=', '>='):
            self._round_trip(F'$x {operator} $y\n')

    def test_a_statement_comparison_over_a_writable_left_operand_is_bracketed(self):
        """
        The parser reads `=` at statement position as an assignment whenever the left operand is
        writable, so a comparison over one prints bracketed to stay a comparison. No source spells
        the tree directly — unbracketed, the statement is an assignment — so the comparison is
        parsed with parentheses and the parentheses removed, which is the tree a pass rewriting the
        left operand leaves behind.
        """
        tree = Au3Parser('($x) = side()\n').parse()
        statement = next(
            node for node in tree.walk() if isinstance(node, Au3ExpressionStatement))
        comparison = statement.expression
        set_child(comparison, 'left', comparison.left.expression)
        self.assertEqual(Au3Synthesizer().convert(tree), '($x = side())\n')

    def test_a_statement_ternary_over_a_writable_condition_is_bracketed(self):
        """
        A ternary's condition prints without brackets of its own, so a statement whose ternary
        compares a writable shape in its condition would re-read as an assignment of the whole
        ternary — the tree a pass leaves behind when it splices a stored value into the statement
        it stood in.
        """
        tree = Au3Parser('$x = $y = 0 ? 1 / $y : 2\n').parse()
        statement = next(
            node for node in tree.walk() if isinstance(node, Au3ExpressionStatement))
        set_child(statement, 'expression', statement.expression.value)
        self.assertEqual(Au3Synthesizer().convert(tree), '($y = 0 ? 1 / $y : 2)\n')

    def test_a_statement_and_over_a_writable_left_operand_is_bracketed(self):
        """
        The left operand of an `And` prints without brackets of its own, so a statement whose
        `And` compares a writable shape on its left would re-read as an assignment of the whole
        expression — and the call on its right would fall under the short circuit.
        """
        tree = Au3Parser('$x = $y = 0 And DllCall("a", "b", "c")\n').parse()
        statement = next(
            node for node in tree.walk() if isinstance(node, Au3ExpressionStatement))
        set_child(statement, 'expression', statement.expression.value)
        self.assertEqual(Au3Synthesizer().convert(tree), '($y = 0 and DllCall("a", "b", "c"))\n')

    def test_a_statement_comparison_chain_over_a_writable_left_operand_is_bracketed(self):
        """
        A chain of equal-precedence comparisons prints its left links without brackets of their
        own, so a statement opening with one over a writable shape would re-read as an assignment
        of the rest of the chain.
        """
        tree = Au3Parser('$x = $y = 0 == 1\n').parse()
        statement = next(
            node for node in tree.walk() if isinstance(node, Au3ExpressionStatement))
        set_child(statement, 'expression', statement.expression.value)
        self.assertEqual(Au3Synthesizer().convert(tree), '($y = 0 == 1)\n')

    def test_logical_and_ternary(self):
        self._round_trip('$x = $c ? $a : $b And $d\n')

    def test_unary_not(self):
        self.assertEqual(self._round_trip('$x = Not $y\n'), '$x = Not $y\n')

    def test_unary_minus_stacking_needs_no_parens(self):
        out = self._round_trip('$x = - -1\n')
        self.assertEqual(out, '$x = --1\n')

    def test_call_and_arguments(self):
        self._round_trip('MsgBox(0, "title", "text")\n')

    def test_nested_calls(self):
        self._round_trip('f(g(1), 2)\n')

    def test_member_access(self):
        self._round_trip('$x = $obj.prop\n')

    def test_array_access(self):
        self._round_trip('$x = $a[0][1]\n')

    def test_array_literal(self):
        self._round_trip('Local $a = [1, "two", [3]]\n')

    def test_assignment_compound(self):
        for operator in ('+=', '-=', '*=', '/=', '&='):
            self._round_trip(F'$x {operator} 1\n')

    def test_if_block(self):
        out = self._round_trip('If $x = 1 Then\n$y = 2\nEndIf\n')
        self.assertEqual(out, 'If $x = 1 Then\n    $y = 2\nEndIf\n')

    def test_if_single_line_prints_block_form(self):
        out = self._round_trip('If $x Then $y = 1\n')
        self.assertEqual(out, 'If $x Then\n    $y = 1\nEndIf\n')

    def test_if_elseif_else(self):
        out = self._round_trip('If $a Then\n$b = 1\nElseIf $c Then\n$b = 2\nElse\n$b = 3\nEndIf\n')
        self.assertEqual(out, 'If $a Then\n    $b = 1\nElseIf $c Then\n    $b = 2\n'
                              'Else\n    $b = 3\nEndIf\n')

    def test_while(self):
        out = self._round_trip('While $x < 10\n$x += 1\nWend\n')
        self.assertEqual(out, 'While $x < 10\n    $x += 1\nWend\n')

    def test_do_until(self):
        out = self._round_trip('Do\n$x += 1\nUntil $x = 10\n')
        self.assertEqual(out, 'Do\n    $x += 1\nUntil $x = 10\n')

    def test_for_to_step(self):
        out = self._round_trip('For $i = 0 To 10 Step 2\n$s &= $i\nNext\n')
        self.assertEqual(out, 'For $i = 0 To 10 Step 2\n    $s &= $i\nNext\n')

    def test_for_in(self):
        out = self._round_trip('For $x In $array\n$s &= $x\nNext\n')
        self.assertEqual(out, 'For $x In $array\n    $s &= $x\nNext\n')

    def test_select(self):
        out = self._round_trip(
            'Select\nCase $x = 1\n$a = 1\nCase Else\n$a = 0\nEndSelect\n')
        self.assertEqual(out, 'Select\nCase $x = 1\n    $a = 1\n'
                              'Case Else\n    $a = 0\nEndSelect\n')

    def test_switch_ranges_and_lists(self):
        out = self._round_trip(
            'Switch $s\nCase 1, 5 To 9, 20\n$a = 1\nCase Else\n$a = 0\nEndSwitch\n')
        self.assertEqual(out, 'Switch $s\nCase 1, 5 To 9, 20\n    $a = 1\n'
                              'Case Else\n    $a = 0\nEndSwitch\n')

    def test_with(self):
        out = self._round_trip('With $obj\n.prop = 1\nEndWith\n')
        self.assertEqual(out, 'With $obj\n    .prop = 1\nEndWith\n')

    def test_variable_declaration(self):
        out = self._round_trip('Local $a = 1, $b[2], $c\n')
        self.assertEqual(out, 'Local $a = 1, $b[2], $c\n')

    def test_declaration_modifiers(self):
        self._round_trip('Global Const $x = 1\n')
        self._round_trip('Static Local $x = 1\n')
        self._round_trip('Dim $x\n')

    def test_declaration_empty_dimension(self):
        self._round_trip('Local $a[] = [1, 2]\n')

    def test_enum(self):
        out = self._round_trip('Enum $a, $b\n')
        self.assertEqual(out, 'Enum $a, $b\n')

    def test_enum_step(self):
        self.assertEqual(self._round_trip('Enum Step *2 $x = 1, $y\n'),
                         'Enum Step *2 $x = 1, $y\n')

    def test_enum_step_canonicalized(self):
        out = self._round_trip('Enum Step +1 $a\n')
        self.assertEqual(out, 'Enum $a\n')

    def test_redim(self):
        self._round_trip('ReDim $a[10], $b[2][3]\n')

    def test_function(self):
        out = self._round_trip('Func Add($a, $b)\nReturn $a + $b\nEndFunc\n')
        self.assertEqual(out, 'Func Add($a, $b)\n    Return $a + $b\nEndFunc\n')

    def test_function_volatile(self):
        out = self._round_trip('Volatile Func OnExit()\nEndFunc\n')
        self.assertEqual(out, 'Volatile Func OnExit()\nEndFunc\n')

    def test_function_parameter_modifiers(self):
        self._round_trip('Func F(ByRef $a, Const $b, $c = Default)\nEndFunc\n')

    def test_exit_and_loop_control(self):
        self._round_trip('Exit\n')
        self._round_trip('Exit 1\n')
        self._round_trip('ExitLoop\n')
        self._round_trip('ExitLoop 2\n')
        self._round_trip('ContinueLoop\n')
        self._round_trip('ContinueCase\n')

    def test_include_and_directive(self):
        self.assertEqual(self._round_trip('#include <File.au3>\n'), '#include <File.au3>\n')
        self.assertEqual(self._round_trip('#include-once\n'), '#include-once\n')
        self._round_trip('#RequireAdmin\n')

    def test_error_node_text_is_written_verbatim(self):
        ast = Au3Parser('$x = = 1\n$y = 2\n').parse()
        out = Au3Synthesizer().convert(ast)
        self.assertEqual(out, '$x = = 1\n$y = 2\n')

    def test_leading_comment(self):
        out = self._round_trip('; before\n$x = 1\n')
        self.assertEqual(out, '; before\n$x = 1\n')

    def test_trailing_comment(self):
        out = self._round_trip('$x = 1 ; after\n')
        self.assertEqual(out, '$x = 1 ; after\n')

    def test_trailing_block_comment_left_open_at_eof(self):
        out = self._round_trip('$x = 1\n#cs\n$y = = = broken\n')
        self.assertEqual(out, '$x = 1 #cs\n$y = = = broken\n')

    def test_comment_on_error_statement(self):
        synth = Au3Synthesizer()
        ast = Au3Parser('$x = = 1 ; note\n$y = 2\n').parse()
        out1 = synth.convert(ast)
        self.assertEqual(out1, '$x = = 1 ; note\n$y = 2\n')
        ast2 = Au3Parser(out1).parse()
        self.assertEqual(synth.convert(ast2), out1)

    def test_comment_alone_in_a_body_no_statement_follows(self):
        out = self._round_trip('Func F($p) ; setup\n; only a comment\nEndFunc\n')
        self.assertEqual(out, 'Func F($p)\nEndFunc ; setup ; only a comment\n')

    def test_output_ends_with_newline(self):
        self.assertTrue(self._round_trip('$x = 1\n').endswith('\n'))

    def test_empty_script_is_empty(self):
        self.assertEqual(Au3Synthesizer().convert(Au3Parser('').parse()), '')

    def test_case_folded_input_is_canonical_equal(self):
        upper = Au3Parser('If $FOO Then\n$BAR = @SCRIPTDIR\nEndIf\n').parse()
        lower = Au3Parser('If $foo Then\n$bar = @scriptdir\nEndIf\n').parse()
        self.assertEqual(canonical(upper), canonical(lower))

    def test_printed_tree_is_canonical_equal_to_input_tree(self):
        source = 'If $x = 1 Then\nLocal $a = [1, 2]\n$f(1, $a[0])\nEndIf\n'
        tree = Au3Parser(source).parse()
        printed = Au3Synthesizer().convert(tree)
        reparsed = Au3Parser(printed).parse()
        self.assertEqual(canonical(tree), canonical(reparsed))
