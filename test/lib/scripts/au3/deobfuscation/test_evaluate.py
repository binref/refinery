"""
The Phase 3 transform on its own: which calls to script functions become the literal of the value
the function returns, and which callee shape or result position forfeits that replacement.
"""
from __future__ import annotations

from test.lib.scripts.au3.deobfuscation import TestAu3

from refinery.lib.scripts.au3.deobfuscation.evaluate import Au3FunctionEvaluation


class TestAu3FunctionEvaluation(TestAu3):

    def test_a_decoder_call_becomes_the_literal_of_its_result(self):
        self.assertEqual(
            self._apply(
                '''
                Func dec($s)
                    Local $r = ""
                    For $i = 1 To StringLen($s)
                        $r &= Chr(Asc(StringMid($s, $i, 1)) - 1)
                    Next
                    Return $r
                EndFunc

                $x = dec("IBM")
                ''',
                Au3FunctionEvaluation,
            ),
            'Func dec($s)\n'
            '    Local $r = ""\n'
            '    For $i = 1 To StringLen($s)\n'
            '        $r &= Chr(Asc(StringMid($s, $i, 1)) - 1)\n'
            '    Next\n'
            '    Return $r\n'
            'EndFunc\n'
            '$x = "HAL"\n')

    def test_a_composed_decoder_call_resolves_in_one_pass(self):
        """
        The visit is bottom-up, so the inner call is already its literal when the outer one is
        asked, and a single pass resolves the composition.
        """
        self.assertEqual(
            self._apply(
                '''
                Func inner($s)
                    Return StringUpper($s)
                EndFunc

                Func outer($s, $n)
                    Return StringMid($s & StringLen($s), 1, $n)
                EndFunc

                $x = outer(inner("ab"), 3)
                ''',
                Au3FunctionEvaluation,
            ),
            'Func inner($s)\n'
            '    Return StringUpper($s)\n'
            'EndFunc\n'
            'Func outer($s, $n)\n'
            '    Return StringMid($s & StringLen($s), 1, $n)\n'
            'EndFunc\n'
            '$x = "AB2"\n')

    def test_a_call_standing_as_a_whole_statement_stays(self):
        """
        A call that is itself the statement produces no value, and a bare literal is not a
        statement, so the call stays for the dead-code phase to remove.
        """
        self.assertEqual(
            self._apply(
                '''
                Func dec($s)
                    Return $s
                EndFunc

                dec("IBM")
                ''',
                Au3FunctionEvaluation,
            ),
            'Func dec($s)\n    Return $s\nEndFunc\ndec("IBM")\n')

    def test_a_call_wrapped_in_parens_as_a_whole_statement_stays(self):
        """
        A call wrapped in parentheses is still the whole statement, and a parenthesized literal is
        no more a statement AutoIt runs than a bare one, so the call stays.
        """
        self.assertEqual(
            self._apply(
                '''
                Func dec($s)
                    Return $s
                EndFunc

                (dec("IBM"))
                ''',
                Au3FunctionEvaluation,
            ),
            'Func dec($s)\n    Return $s\nEndFunc\n(dec("IBM"))\n')

    def test_an_array_result_splices_only_into_a_declaration_initializer(self):
        self.assertEqual(
            self._apply(
                '''
                Func arr()
                    Local $a[2] = ["a", "b"]
                    Return $a
                EndFunc

                Local $x[2] = arr()
                $y = arr()
                ''',
                Au3FunctionEvaluation,
            ),
            'Func arr()\n'
            '    Local $a[2] = ["a", "b"]\n'
            '    Return $a\n'
            'EndFunc\n'
            'Local $x[2] = ["a", "b"]\n'
            '$y = arr()\n')

    def test_a_global_read_at_a_script_level_call_resolves(self):
        """
        The propagation walk knows the script's globals at a script-level call site, so the
        interpreter reads the global and the call becomes its result.
        """
        self.assertEqual(
            self._apply(
                '''
                Global Const $g = "one"

                Func f()
                    Return $g & "!"
                EndFunc

                $x = f()
                ''',
                Au3FunctionEvaluation,
            ),
            'Global Const $g = "one"\nFunc f()\n    Return $g & "!"\nEndFunc\n$x = "one!"\n')

    def test_a_global_read_at_a_call_inside_a_function_stays(self):
        """
        The walk knows no globals at a call inside a function body, so the interpreter refuses
        the global read and the call stands.
        """
        self.assertEqual(
            self._apply(
                '''
                Global Const $g = "one"

                Func f()
                    Return $g & "!"
                EndFunc

                Func h()
                    $x = f()
                EndFunc
                ''',
                Au3FunctionEvaluation,
            ),
            'Global Const $g = "one"\n'
            'Func f()\n'
            '    Return $g & "!"\n'
            'EndFunc\n'
            'Func h()\n'
            '    $x = f()\n'
            'EndFunc\n')

    def test_a_function_that_writes_a_global_stays(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Global $g = 1
                    Return 2
                EndFunc

                $x = f()
                ''',
                Au3FunctionEvaluation,
            ),
            'Func f()\n    Global $g = 1\n    Return 2\nEndFunc\n$x = f()\n')

    def test_a_function_that_calls_an_unevaluated_builtin_stays(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    MsgBox(0, "", "t")
                    Return 2
                EndFunc

                $x = f()
                ''',
                Au3FunctionEvaluation,
            ),
            'Func f()\n    MsgBox(0, "", "t")\n    Return 2\nEndFunc\n$x = f()\n')

    def test_a_random_name_builder_stays(self):
        """
        The `r` shape of the a3x samples: a name built from `Random`, which has no evaluator, so
        the function's summary is unknown and the call stands.
        """
        self.assertEqual(
            self._apply(
                '''
                Func r($n)
                    Local $s = ""
                    For $i = 1 To $n
                        $s &= Chr(Random(97, 122, 1))
                    Next
                    Return $s
                EndFunc

                $name = r(8)
                ''',
                Au3FunctionEvaluation,
            ),
            'Func r($n)\n'
            '    Local $s = ""\n'
            '    For $i = 1 To $n\n'
            '        $s &= Chr(Random(97, 122, 1))\n'
            '    Next\n'
            '    Return $s\n'
            'EndFunc\n'
            '$name = r(8)\n')

    def test_a_base64_decoder_through_dllcall_stays(self):
        """
        The `x` shape of the a3x samples: the decoding runs through `DllCall`, which has no
        evaluator, so the call stands.
        """
        self.assertEqual(
            self._apply(
                '''
                Func x($s)
                    Return DllCall("crypt32.dll", "bool", "CryptStringToBinary", "str", $s)
                EndFunc

                $d = x("aGVsbG8=")
                ''',
                Au3FunctionEvaluation,
            ),
            'Func x($s)\n'
            '    Return DllCall("crypt32.dll", "bool", "CryptStringToBinary", "str", $s)\n'
            'EndFunc\n'
            '$d = x("aGVsbG8=")\n')

    def test_a_winapi_wrapper_stays(self):
        """
        The inlined WinAPI wrapper shape of the a3x samples: every argument is a literal, but the
        body is one `DllCall`, so the call stands.
        """
        self.assertEqual(
            self._apply(
                '''
                Func close_handle($h)
                    Return DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $h)
                EndFunc

                $r = close_handle(0)
                ''',
                Au3FunctionEvaluation,
            ),
            'Func close_handle($h)\n'
            '    Return DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $h)\n'
            'EndFunc\n'
            '$r = close_handle(0)\n')
