from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import canonical
from refinery.lib.scripts.au3.parser import Au3Parser
from refinery.lib.scripts.au3.synth import Au3Synthesizer


class TestAu3Synthesizer(TestBase):

    def _round_trip(self, source: str) -> str:
        synth = Au3Synthesizer()
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

    def test_comparison(self):
        for operator in ('=', '==', '<>', '<', '>', '<=', '>='):
            self._round_trip(F'$x {operator} $y\n')

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
