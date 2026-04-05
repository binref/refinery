from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.vba.parser import VbaParser
from refinery.lib.scripts.vba.synth import VbaSynthesizer


class TestVbaSynthesizer(TestBase):

    def _roundtrip(self, source: str) -> str:
        ast = VbaParser(source).parse()
        return VbaSynthesizer().convert(ast)

    def test_sub_empty(self):
        code = 'Sub Test()\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('Sub Test()', result)
        self.assertIn('End Sub', result)

    def test_function_with_return(self):
        code = 'Function Add(a As Long, b As Long) As Long\nAdd = a + b\nEnd Function'
        result = self._roundtrip(code)
        self.assertIn('Function Add(a As Long, b As Long) As Long', result)
        self.assertIn('Add = a + b', result)
        self.assertIn('End Function', result)

    def test_if_block(self):
        code = 'Sub T()\nIf x > 0 Then\ny = 1\nEnd If\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('If x > 0 Then', result)
        self.assertIn('End If', result)

    def test_if_else(self):
        code = 'Sub T()\nIf x > 0 Then\ny = 1\nElse\ny = 0\nEnd If\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('Else', result)

    def test_for_loop(self):
        code = 'Sub T()\nFor i = 1 To 10\nDebug.Print i\nNext\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('For i = 1 To 10', result)
        self.assertIn('Next', result)

    def test_for_step(self):
        code = 'Sub T()\nFor i = 10 To 0 Step -1\nNext\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('Step', result)

    def test_for_each(self):
        code = 'Sub T()\nFor Each x In col\nNext\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('For Each x In col', result)

    def test_do_while(self):
        code = 'Sub T()\nDo While x > 0\nLoop\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('Do While x > 0', result)
        self.assertIn('Loop', result)

    def test_do_loop_until(self):
        code = 'Sub T()\nDo\nLoop Until x > 10\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('Loop Until x > 10', result)

    def test_while_wend(self):
        code = 'Sub T()\nWhile x > 0\nWend\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('While x > 0', result)
        self.assertIn('Wend', result)

    def test_select_case(self):
        code = 'Sub T()\nSelect Case x\nCase 1\ny = 1\nCase Else\ny = 0\nEnd Select\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('Select Case x', result)
        self.assertIn('Case 1', result)
        self.assertIn('Case Else', result)
        self.assertIn('End Select', result)

    def test_with_statement(self):
        code = 'Sub T()\nWith obj\nEnd With\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('With obj', result)
        self.assertIn('End With', result)

    def test_set_statement(self):
        code = 'Sub T()\nSet x = Nothing\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('Set x = Nothing', result)

    def test_on_error_resume_next(self):
        code = 'Sub T()\nOn Error Resume Next\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('On Error Resume Next', result)

    def test_on_error_goto(self):
        code = 'Sub T()\nOn Error GoTo Handler\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('On Error GoTo Handler', result)

    def test_on_error_goto_minus_1(self):
        code = 'Sub T()\nOn Error GoTo -1\nEnd Sub'
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
        code = 'Type MyType\nx As Long\ny As String\nEnd Type'
        result = self._roundtrip(code)
        self.assertIn('Type MyType', result)
        self.assertIn('End Type', result)

    def test_enum_definition(self):
        code = 'Enum Colors\nRed = 1\nGreen = 2\nEnd Enum'
        result = self._roundtrip(code)
        self.assertIn('Enum Colors', result)
        self.assertIn('Red = 1', result)
        self.assertIn('End Enum', result)

    def test_single_line_if(self):
        code = 'Sub T()\nIf x > 0 Then y = 1 Else y = 0\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('If x > 0 Then', result)
        self.assertIn('Else', result)

    def test_property_get(self):
        code = 'Property Get Name() As String\nName = "test"\nEnd Property'
        result = self._roundtrip(code)
        self.assertIn('Property Get Name()', result)
        self.assertIn('End Property', result)

    def test_declare(self):
        code = 'Declare Function GetTickCount Lib "kernel32" () As Long'
        result = self._roundtrip(code)
        self.assertIn('Declare Function GetTickCount', result)

    def test_exit_sub(self):
        code = 'Sub T()\nExit Sub\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('Exit Sub', result)

    def test_goto(self):
        code = 'Sub T()\nGoTo Cleanup\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('GoTo Cleanup', result)

    def test_goto_two_word_roundtrip(self):
        code = 'Sub T()\nGo To done\ndone:\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('GoTo', result)

    def test_resume(self):
        code = 'Sub T()\nResume Next\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('Resume Next', result)

    def test_redim_preserve(self):
        code = 'Sub T()\nReDim Preserve arr(20)\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('ReDim Preserve', result)

    def test_debug_print(self):
        code = 'Sub T()\nDebug.Print "hello"\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('Debug.Print', result)

    def test_debug_print_comma_roundtrip(self):
        self._roundtrip('Sub T()\nDebug.Print "a", "b"\nEnd Sub')

    def test_debug_print_semicolon_roundtrip(self):
        self._roundtrip('Sub T()\nDebug.Print "a"; "b"\nEnd Sub')

    def test_debug_print_mixed_separators_roundtrip(self):
        self._roundtrip('Sub T()\nDebug.Print "a", "b"; "c"\nEnd Sub')

    def test_dim_fixed_length_string(self):
        result = self._roundtrip('Dim s As String * 20')
        self.assertIn('As String * 20', result)

    def test_type_member_fixed_length_string(self):
        code = 'Type MyType\nname As String * 50\nEnd Type'
        result = self._roundtrip(code)
        self.assertIn('As String * 50', result)

    def test_lset_roundtrip(self):
        # LSet must survive the round-trip as LSet, not become Let.
        code = 'Sub T()\nLSet a = b\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('LSet a = b', result,
            'LSet must round-trip as LSet, not as Let')

    def test_rset_roundtrip(self):
        # RSet must survive the round-trip as RSet, not become Let.
        code = 'Sub T()\nRSet a = b\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('RSet a = b', result,
            'RSet must round-trip as RSet, not as Let')

    def test_open_statement_roundtrip(self):
        # The Open statement must not be misparsed as a For loop.
        # Before the fix, "For Input" triggered the For-loop parser and subsequent
        # statements were lost into a loop body.
        code = 'Sub T()\nOpen "file.txt" For Input As #1\nx = 1\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('x = 1', result,
            'Statement following Open must not be swallowed by a misparsed For loop')
        self.assertNotIn('Next', result,
            'Open statement must not produce a For/Next loop')

    def test_line_input_roundtrip(self):
        # Line Input must round-trip as a single unit and not lose the variable.
        code = 'Sub T()\nLine Input #1, a\nEnd Sub'
        result = self._roundtrip(code)
        self.assertIn('Line Input', result,
            'Line Input must appear in the synthesized output as a unit')
