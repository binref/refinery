from __future__ import annotations

from inspect import cleandoc

from test import TestBase

from refinery.lib.scripts.vba.parser import VbaParser
from refinery.lib.scripts.vba.synth import VbaSynthesizer


class TestVbaSynthesizer(TestBase):

    def _roundtrip(self, source: str) -> str:
        synth = VbaSynthesizer()
        ast1 = VbaParser(source).parse()
        out1 = synth.convert(ast1)
        ast2 = VbaParser(out1).parse()
        out2 = synth.convert(ast2)
        self.assertEqual(out1, out2)
        return out1

    def test_sub_empty(self):
        code = cleandoc("""
            Sub Test()
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('Sub Test()', result)
        self.assertIn('End Sub', result)

    def test_function_with_return(self):
        code = cleandoc("""
            Function Add(a As Long, b As Long) As Long
              Add = a + b
            End Function
        """)
        result = self._roundtrip(code)
        self.assertIn('Function Add(a As Long, b As Long) As Long', result)
        self.assertIn('Add = a + b', result)
        self.assertIn('End Function', result)

    def test_if_block(self):
        code = cleandoc("""
            Sub T()
              If x > 0 Then
                y = 1
              End If
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('If x > 0 Then', result)
        self.assertIn('End If', result)

    def test_if_else(self):
        code = cleandoc("""
            Sub T()
              If x > 0 Then
                y = 1
              Else
                y = 0
              End If
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('Else', result)

    def test_for_loop(self):
        code = cleandoc("""
            Sub T()
              For i = 1 To 10
                Debug.Print i
              Next
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('For i = 1 To 10', result)
        self.assertIn('Next', result)

    def test_for_step(self):
        code = cleandoc("""
            Sub T()
              For i = 10 To 0 Step -1
              Next
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('Step', result)

    def test_for_each(self):
        code = cleandoc("""
            Sub T()
              For Each x In col
              Next
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('For Each x In col', result)

    def test_do_while(self):
        code = cleandoc("""
            Sub T()
              Do While x > 0
              Loop
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('Do While x > 0', result)
        self.assertIn('Loop', result)

    def test_do_loop_until(self):
        code = cleandoc("""
            Sub T()
              Do
              Loop Until x > 10
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('Loop Until x > 10', result)

    def test_while_wend(self):
        code = cleandoc("""
            Sub T()
              While x > 0
              Wend
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('While x > 0', result)
        self.assertIn('Wend', result)

    def test_select_case(self):
        code = cleandoc("""
            Sub T()
              Select Case x
              Case 1
                y = 1
              Case Else
                y = 0
              End Select
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('Select Case x', result)
        self.assertIn('Case 1', result)
        self.assertIn('Case Else', result)
        self.assertIn('End Select', result)

    def test_with_statement(self):
        code = cleandoc("""
            Sub T()
              With obj
              End With
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('With obj', result)
        self.assertIn('End With', result)

    def test_set_statement(self):
        code = cleandoc("""
            Sub T()
              Set x = Nothing
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('Set x = Nothing', result)

    def test_on_error_resume_next(self):
        code = cleandoc("""
            Sub T()
              On Error Resume Next
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('On Error Resume Next', result)

    def test_on_error_goto(self):
        code = cleandoc("""
            Sub T()
              On Error GoTo Handler
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('On Error GoTo Handler', result)

    def test_on_error_goto_minus_1(self):
        code = cleandoc("""
            Sub T()
              On Error GoTo -1
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('On Error GoTo -1', result)

    def test_option_explicit(self):
        result = self._roundtrip('Option Explicit')
        self.assertIn('Option Explicit', result)

    def test_const(self):
        result = self._roundtrip('Const PI As Double = 3.14')
        self.assertIn('Const PI As Double = 3.14', result)

    def test_dim(self):
        result = self._roundtrip('Dim x As Long')
        self.assertIn('Dim x As Long', result)

    def test_dim_withevents(self):
        result = self._roundtrip('Dim WithEvents obj As SomeClass')
        self.assertIn('WithEvents obj As SomeClass', result)

    def test_private_withevents(self):
        result = self._roundtrip('Private WithEvents m_App As Application')
        self.assertIn('WithEvents m_App As Application', result)

    def test_type_definition(self):
        code = cleandoc("""
            Type MyType
              x As Long
              y As String
            End Type
        """)
        result = self._roundtrip(code)
        self.assertIn('Type MyType', result)
        self.assertIn('End Type', result)

    def test_enum_definition(self):
        code = cleandoc("""
            Enum Colors
              Red = 1
              Green = 2
            End Enum
        """)
        result = self._roundtrip(code)
        self.assertIn('Enum Colors', result)
        self.assertIn('Red = 1', result)
        self.assertIn('End Enum', result)

    def test_single_line_if(self):
        code = cleandoc("""
            Sub T()
              If x > 0 Then y = 1 Else y = 0
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('If x > 0 Then', result)
        self.assertIn('Else', result)

    def test_property_get(self):
        code = cleandoc("""
            Property Get Name() As String
              Name = "test"
            End Property
        """)
        result = self._roundtrip(code)
        self.assertIn('Property Get Name()', result)
        self.assertIn('End Property', result)

    def test_declare(self):
        code = 'Declare Function GetTickCount Lib "kernel32" () As Long'
        result = self._roundtrip(code)
        self.assertIn('Declare Function GetTickCount', result)

    def test_exit_sub(self):
        code = cleandoc("""
            Sub T()
              Exit Sub
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('Exit Sub', result)

    def test_goto(self):
        code = cleandoc("""
            Sub T()
              GoTo Cleanup
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('GoTo Cleanup', result)

    def test_goto_two_word_roundtrip(self):
        code = cleandoc("""
            Sub T()
              Go To done
              done:
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('GoTo', result)

    def test_resume(self):
        code = cleandoc("""
            Sub T()
              Resume Next
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('Resume Next', result)

    def test_redim_preserve(self):
        code = cleandoc("""
            Sub T()
              ReDim Preserve arr(20)
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('ReDim Preserve', result)

    def test_debug_print(self):
        code = cleandoc("""
            Sub T()
              Debug.Print "hello"
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('Debug.Print', result)

    def test_debug_print_comma_roundtrip(self):
        self._roundtrip(cleandoc("""
            Sub T()
              Debug.Print "a", "b"
            End Sub
        """))

    def test_debug_print_semicolon_roundtrip(self):
        self._roundtrip(cleandoc("""
            Sub T()
              Debug.Print "a"; "b"
            End Sub
        """))

    def test_debug_print_mixed_separators_roundtrip(self):
        self._roundtrip(cleandoc("""
            Sub T()
              Debug.Print "a", "b"; "c"
            End Sub
        """))

    def test_dim_fixed_length_string(self):
        result = self._roundtrip('Dim s As String * 20')
        self.assertIn('As String * 20', result)

    def test_attribute_roundtrip(self):
        code = cleandoc("""
            Attribute VB_Name = "Module1"
            Sub T()
              x = 1
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('Sub T()', result)

    def test_type_member_fixed_length_string(self):
        code = cleandoc("""
            Type MyType
              name As String * 50
            End Type
        """)
        result = self._roundtrip(code)
        self.assertIn('As String * 50', result)

    def test_lset_roundtrip(self):
        # LSet must survive the round-trip as LSet, not become Let.
        code = cleandoc("""
            Sub T()
              LSet a = b
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('LSet a = b', result,
            'LSet must round-trip as LSet, not as Let')

    def test_rset_roundtrip(self):
        # RSet must survive the round-trip as RSet, not become Let.
        code = cleandoc("""
            Sub T()
              RSet a = b
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('RSet a = b', result,
            'RSet must round-trip as RSet, not as Let')

    def test_open_statement_roundtrip(self):
        # The Open statement must not be misparsed as a For loop.
        # Before the fix, "For Input" triggered the For-loop parser and subsequent
        # statements were lost into a loop body.
        code = cleandoc("""
            Sub T()
              Open "file.txt" For Input As #1
              x = 1
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('x = 1', result,
            'Statement following Open must not be swallowed by a misparsed For loop')
        self.assertNotIn('Next', result,
            'Open statement must not produce a For/Next loop')

    def test_line_input_roundtrip(self):
        # Line Input must round-trip as a single unit and not lose the variable.
        code = cleandoc("""
            Sub T()
              Line Input #1, a
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('Line Input', result,
            'Line Input must appear in the synthesized output as a unit')

    def test_conditional_compilation_roundtrip(self):
        code = cleandoc("""
            Sub T()
              #If VBA7 Then
              x = 1
              #Else
              x = 2
              #End If
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('Sub T()', result)
        self.assertIn('x = 1', result)
        self.assertIn('x = 2', result)
        # Directive lines must not appear in output
        self.assertNotIn('#If', result,
            'Conditional compilation directives must not appear in synthesized output')
        self.assertNotIn('#Else', result)
        self.assertNotIn('#End', result)

    def test_else_if_two_word_roundtrip(self):
        code = cleandoc("""
            Sub T()
              If x = 1 Then
                y = 1
              Else If x = 2 Then
                y = 2
              End If
            End Sub
        """)
        result = self._roundtrip(code)
        self.assertIn('ElseIf', result,
            '"Else If" must round-trip as ElseIf')

    def test_end_in_select_case_roundtrip(self):
        code = cleandoc("""
            Sub T()
              Select Case x
              Case 1
                End
              End Select
            End Sub
        """)
        result = self._roundtrip(code)
        lines = [l.strip() for l in result.splitlines() if l.strip()]
        self.assertIn('End', lines,
            'standalone End statement must survive round-trip inside Select Case')

    def test_negative_hex_literal_base_needs_no_parentheses(self):
        # &HFFFF is a single-token literal (-1), not a unary minus, so as a ^ base it needs no
        # parentheses, unlike a folded "-1".
        self.assertEqual(self._roundtrip('x = &HFFFF ^ 2'), 'x = &HFFFF ^ 2')
