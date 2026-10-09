from .. import TestUnitBase

import inspect
import pytest

from test.lib.scripts.au3.test_deobfuscation import (
    FIXTURE_DEOBFUSCATED,
    FIXTURE_OBFUSCATED,
)


_PRETTY_INPUT = inspect.cleandoc(
    """
    #include <File.au3>
    Global Const $g = 3
    Local $x = 1 + 2 * 3
    If $x > 4 Then
        MsgBox(0, "t", "m")
    ElseIf $x = 4 Then
        $x &= "four"
    Else
        $x = 0
    EndIf
    For $i = 0 To 10 Step 2
        $x += $i
    Next
    """
)

_PRETTY_GOAL = (
    '#include <File.au3>\n'
    'Global Const $g = 3\n'
    'Local $x = 7\n'
    'If True Then\n'
    '    MsgBox(0, "t", "m")\n'
    'ElseIf False Then\n'
    '    $x &= "four"\n'
    'Else\n'
    '    $x = 0\n'
    'EndIf\n'
    'For $i = 0 To 10 Step 2\n'
    '    $x += $i\n'
    'Next\n'
)

#: A function body in the exact style `a3x_decompile` emits: four-space indents, one space
#: between tokens, no space in front of a comma-attached closing parenthesis, and a blank line
#: after a nested block closes inside a function.
_A3X_STYLE_INPUT = (
    'Func _test($p)\n'
    '    If $p = 0 Then\n'
    '        Return 0\n'
    '    EndIf\n'
    '\n'
    '    For $i = 0 To 10 Step 1\n'
    '        $p = $p + $i\n'
    '    Next\n'
    '\n'
    '    Return $p\n'
    'EndFunc\n'
)

_A3X_STYLE_GOAL = (
    'Func _test($p)\n'
    '    If $p = 0 Then\n'
    '        Return 0\n'
    '    EndIf\n'
    '    For $i = 0 To 10 Step 1\n'
    '        $p = $p + $i\n'
    '    Next\n'
    '    Return $p\n'
    'EndFunc\n'
)


class TestDAu3(TestUnitBase):

    def test_pretty_print_golden(self):
        result = _PRETTY_INPUT.encode() | self.load() | str
        self.assertEqual(result, _PRETTY_GOAL)

    def test_a3x_decompile_style(self):
        result = _A3X_STYLE_INPUT.encode() | self.load() | str
        self.assertEqual(result, _A3X_STYLE_GOAL)

    def test_execute_chain_flattens(self):
        result = B'$x = Execute("1 + 2 * 3")\n' | self.load() | str
        self.assertEqual(result, '$x = 7\n')

    def test_alias_chain_resolves(self):
        """
        The distilled decoder shape: the `Execute` alias is rewritten, the second alias through
        it resolves, the argument folds to the string literal the splice reads, and the decoded
        string is what the decoder returned.
        """
        result = (
            B'Local $e = Execute\n'
            B'Local $b = $e("BinaryToString")\n'
            B'$v = $e($b("0x22414243" & "4422"))\n'
        ) | self.load() | str
        self.assertEqual(result, (
            'Local $e = Execute\n'
            'Local $b = Execute("BinaryToString")\n'
            '$v = "ABCD"\n'
        ))

    def test_constant_soup_folds(self):
        result = B'$x = 1 + 2 * 3\nMsgBox(0, "", $x)\n' | self.load() | str
        self.assertEqual(result, '$x = 7\nMsgBox(0, "", 7)\n')

    def test_idempotent(self):
        first = _PRETTY_INPUT.encode() | self.load() | bytes
        second = first | self.load() | bytes
        self.assertEqual(first, second)

    def test_keyword_casing_normalized(self):
        data = B'IF $X THEN\n$Y = 1\nENDIF\n'
        result = data | self.load() | str
        self.assertEqual(result, 'If $X Then\n    $Y = 1\nEndIf\n')

    def test_single_line_if_prints_block_form(self):
        result = B'If $x Then $y = 1\n' | self.load() | str
        self.assertEqual(result, 'If $x Then\n    $y = 1\nEndIf\n')

    def test_case_folded_source_is_stable(self):
        upper = B'If $FOO Then\n    $BAR = @SCRIPTDIR\nEndIf\n' | self.load() | str
        lower = B'If $foo Then\n    $bar = @scriptdir\nEndIf\n' | self.load() | str
        self.assertEqual(upper.lower(), lower.lower())

    def test_malformed_input_still_yields_output(self):
        result = B'$x = = 1\n$y = 2\n' | self.load() | bytes
        self.assertEqual(result, B'$x = = 1\n$y = 2\n')

    def test_error_line_with_trailing_comment(self):
        result = B'$x = = 1 ; note\n$y = 2\n' | self.load() | bytes
        self.assertEqual(result, B'$x = = 1 ; note\n$y = 2\n')

    def test_crlf_input(self):
        result = B'If $x Then\r\n    $y = 1\r\nEndIf\r\n' | self.load() | str
        self.assertEqual(result, 'If $x Then\n    $y = 1\nEndIf\n')

    def test_comments_survive_every_position(self):
        """
        A comment the header line of a block carries, one standing between a `Select` and its
        first `Case`, and one standing alone in a body no statement follows: each was dropped
        from the output or corrupted the parse around it before the round trip kept them.
        """
        data = (
            b'Select\n; pick one\nCase $x\n$y = 1\nEndSelect\n'
            b'While $x ; loop\n$y = 2\nWend\n'
            b'Func F() ; setup\n; only a comment\nEndFunc\n'
        )
        result = data | self.load() | str
        self.assertEqual(result, (
            'Select\n'
            '; pick one\n'
            'Case $x\n'
            '    $y = 1\n'
            'EndSelect\n'
            'While $x\n'
            '    $y = 2\n'
            'Wend ; loop\n'
            'Func F()\n'
            'EndFunc ; setup ; only a comment\n'
        ))

    def test_comment_only_file(self):
        result = B'; nothing but a comment\n' | self.load() | str
        self.assertEqual(result, '; nothing but a comment\n')

    def test_bom_input(self):
        result = B'\xEF\xBB\xBF$x = 1\n' | self.load() | str
        self.assertEqual(result, '$x = 1\n')

    def test_empty_input(self):
        result = B'' | self.load() | str
        self.assertEqual(result, '')

    def test_the_obfuscated_fixture_decodes_to_its_cleaned_form(self):
        result = FIXTURE_OBFUSCATED.encode('ASCII') | self.load() | str
        self.assertEqual(result, FIXTURE_DEOBFUSCATED)

    @pytest.mark.cythonized
    def test_decompiled_a3x_script_parses_error_free(self):
        sample = self.download_sample(
            '3b775e678568cd3d55187443a3f7aae2116b7e9762b3c3879f5e1c6225434b25')
        extracted = sample | self.ldu('a3x') | {'path': [...]}
        script, = extracted['script.au3']
        self.assertContains(script, B'FileInstall("msc.exe", @SYSTEMDIR & "\\msc0nfig.exe")')
        deobfuscator = self.load()
        first = script | deobfuscator | bytes
        second = first | deobfuscator | bytes
        self.assertEqual(first, second)
        from refinery.lib.scripts.au3.parser import Au3Parser
        ast = Au3Parser(first.decode('latin1')).parse()
        self.assertEqual(ast.errors, [])
