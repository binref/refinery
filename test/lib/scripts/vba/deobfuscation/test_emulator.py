from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.vba.deobfuscation import TestVba

from refinery.lib.scripts.vba.deobfuscation.constants import VbaConstantInlining
from refinery.lib.scripts.vba.deobfuscation.emulator import VbaFunctionEvaluator
from refinery.lib.scripts.vba.deobfuscation.simplify import VbaSimplifications


class TestVbaFunctionEvaluator(TestVba):

    def test_emulator_simple_return(self):
        code = cleandoc("""
            Function F()
              F = "hello"
            End Function
            Sub T()
              x = F()
              G x
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G "hello"
            End Sub
        """))
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), cleandoc("""
            Sub T()
              x = "hello"
              G x
            End Sub
        """))

    def test_emulator_self_referential_return(self):
        code = cleandoc("""
            Function dtiss()
              dtiss = "cellvalue"
              dtiss = dtiss + "if"
            End Function
            Sub T()
              melb = dtiss
              F melb
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              F "cellvalueif"
            End Sub
        """))
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), cleandoc("""
            Sub T()
              melb = "cellvalueif"
              F melb
            End Sub
        """))

    def test_emulator_with_params(self):
        code = cleandoc("""
            Function XorKey(s As String, k As Integer) As String
              XorKey = s & Chr(k)
            End Function
            Sub T()
              x = XorKey("AB", 67)
              G x
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G "ABC"
            End Sub
        """))
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), cleandoc("""
            Sub T()
              x = "ABC"
              G x
            End Sub
        """))

    def test_emulator_nonconstant_arg_preserved(self):
        code = cleandoc("""
            Function F(x)
              F = x & "!"
            End Function

            Sub T()
              G F(y)
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), code)

    def test_emulator_loop(self):
        code = cleandoc("""
            Function Build()
              For i = 1 To 3
                Build = Build & "x"
              Next
            End Function
            Sub T()
              G Build()
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), cleandoc("""
            Sub T()
              G "xxx"
            End Sub
        """))

    def test_emulator_impure_not_inlined(self):
        code = cleandoc("""
            Function F()
              F = Application.Name
            End Function

            Sub T()
              G F()
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), code)

    def test_emulator_do_while_false_skips_body(self):
        code = cleandoc("""
            Function F()
              F = "before"
              Do While False
                F = "inside"
              Loop
            End Function
            Sub T()
              G F()
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), cleandoc("""
            Sub T()
              G "before"
            End Sub
        """))

    def test_emulator_do_until_true_skips_body(self):
        code = cleandoc("""
            Function F()
              F = "before"
              Do Until True
                F = "inside"
              Loop
            End Function
            Sub T()
              G F()
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), cleandoc("""
            Sub T()
              G "before"
            End Sub
        """))

    def test_emulator_preserves_side_effecting_function(self):
        code = cleandoc("""
            Function Builder()
              On Error Resume Next
              Builder = "payload"
              Shell "cmd " & Chr(80) & Builder, 0
            End Function

            Sub Autoopen()
              On Error Resume Next
              Builder
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Function Builder()
              On Error Resume Next
              Shell "cmd Ppayload", 0
            End Function

            Sub Autoopen()
              On Error Resume Next
              Builder
            End Sub
        """))
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), code)

    def test_emulator_instr(self):
        code = cleandoc("""
            Function F()
              F = InStr("hello world", "world")
            End Function
            Sub T()
              x = F()
              G x
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G 7
            End Sub
        """))
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), cleandoc("""
            Sub T()
              x = 7
              G x
            End Sub
        """))

    def test_emulator_instrrev(self):
        code = cleandoc("""
            Function F()
              F = InStrRev("abcabc", "abc")
            End Function
            Sub T()
              x = F()
              G x
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G 4
            End Sub
        """))
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), cleandoc("""
            Sub T()
              x = 4
              G x
            End Sub
        """))

    def test_emulator_refuses_nonprintable_result(self):
        code = cleandoc("""
            Function F()
              F = "a" & Chr(13) & "b"
            End Function
            Sub T()
              G F()
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), cleandoc("""
            Sub T()
              G "a" & Chr(13) & "b"
            End Sub
        """))

    def test_emulator_nonprintable_result_synthesized(self):
        code = cleandoc("""
            Function F()
              F = Chr(13) & "payload" & Chr(10)
            End Function
            Sub T()
              G F()
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), cleandoc("""
            Sub T()
              G Chr(13) & "payload" & Chr(10)
            End Sub
        """))

    def test_emulator_string_compare_is_case_sensitive(self):
        code = cleandoc("""
            Function F()
              If "A" = "a" Then
                F = "same"
              Else
                F = "diff"
              End If
            End Function
            Sub T()
              G F()
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), cleandoc("""
            Sub T()
              G "diff"
            End Sub
        """))

    def test_undefined_var_eliminated_in_concat(self):
        code = cleandoc("""
            Function F()
              On Error Resume Next
              F = junk + "hello"
            End Function
            Sub T()
              G F()
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G "hello"
            End Sub
        """))
        self.assertEqual(self._apply(code, VbaSimplifications), cleandoc("""
            Function F()
              On Error Resume Next
              F = "hello"
            End Function

            Sub T()
              G F()
            End Sub
        """))

    def test_return_variable_inlined(self):
        code = cleandoc("""
            Function F()
              F = "hello"
              Shell "cmd " & F, 0
            End Function
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Function F()
              Shell "cmd hello", 0
            End Function
        """))
        self.assertEqual(self._apply(code, VbaConstantInlining), cleandoc("""
            Function F()
              Shell "cmd " & "hello", 0
            End Function
        """))

    def test_regression_multi_assign_no_inline(self):
        code = cleandoc("""
            Function dtiss()
              dtiss = "cellvalue"
              dtiss = dtiss + "if"
            End Function
            Sub T()
              melb = dtiss
              F melb
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F "cellvalueif"
            End Sub
        """))
        self.assertEqual(self._apply(code, VbaFunctionEvaluator), cleandoc("""
            Sub T()
              melb = "cellvalueif"
              F melb
            End Sub
        """))

    def _compare_branch(self, option: str, expr: str) -> str:
        return self._apply(cleandoc(F"""
            {option}
            Function F()
              If {expr} Then
                F = "same"
              Else
                F = "diff"
              End If
            End Function
            Sub T()
              G F()
            End Sub
        """), VbaFunctionEvaluator)

    def test_text_equality_folds_for_safe_operands(self):
        self.assertIn('G "same"', self._compare_branch('Option Compare Text', '"AB" = "ab"'))

    def test_binary_equality_is_case_sensitive(self):
        for option in ('Option Compare Binary', "' no option"):
            self.assertIn('G "diff"', self._compare_branch(option, '"AB" = "ab"'), option)

    def test_text_equality_bails_on_turkic_letters(self):
        self.assertIn('G F()', self._compare_branch('Option Compare Text', '"FILE" = "file"'))

    def test_text_ordering_always_bails(self):
        self.assertIn('G F()', self._compare_branch('Option Compare Text', '"b" < "A"'))

    def test_database_equality_not_folded(self):
        self.assertIn('G F()', self._compare_branch('Option Compare Database', '"AB" = "ab"'))

    def test_database_numeric_comparison_still_folds(self):
        self.assertIn('G "same"', self._compare_branch('Option Compare Database', '2 > 1'))
