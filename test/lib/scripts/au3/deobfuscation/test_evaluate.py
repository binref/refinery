"""
The Phase 3 transform on its own: which calls to script functions become the literal of the value
the function returns, and which callee shape or result position forfeits that replacement.
"""
from __future__ import annotations

import pytest

from test.lib.scripts.au3.deobfuscation import TestAu3

from refinery.lib.scripts.au3.deobfuscation.evaluate import Au3FunctionEvaluation


class TestAu3FunctionEvaluation(TestAu3):

    @pytest.mark.xfail(
        strict=True,
        reason='the replacement drops the entry clearing of @error and @extended',
    )
    def test_a_call_that_clears_the_error_state_stays_where_the_script_reads_it(self):
        """
        Entering a user function clears `@error` and `@extended` (probe9 A17/A17b), so a script
        that reads either holds no call this pass may replace with its value: the replacement
        drops the clearing, and a read after the call site sees the error state the entry would
        have wiped. The dead branch spells the call through a builtin the widened builtin table
        answers bounded, which is what empties the summary and admits the replacement; a precise
        refusal needs to know which reads an intervening entry or error-setting builtin shields.
        """
        source = '''
            Func dec($x)
                If 0 Then
                    MsgBox(0, 0, 0)
                EndIf
                Return $x + 1
            EndFunc

            IniDelete("nope.ini", "s")
            $y = dec(4)
            If @error Then
                ConsoleWrite("E")
            EndIf
            '''
        self.assertEqual(
            self._apply(source, Au3FunctionEvaluation),
            self._laid_out(source),
        )

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

    def test_a_decoder_with_implicit_locals_becomes_the_literal_of_its_result(self):
        """
        The probe10 decoder, verbatim: every intermediate lives in an implicit local — a bare
        write the census cannot tie to a global — so the summary stays empty and the call
        becomes the pinned decoding.
        """
        self.assertEqual(
            self._apply(
                '''
                Func decode10($hx, $ky)
                    $d_bin = BinaryToString($hx, 1)
                    $d_out = ""
                    For $d_i = 1 To StringLen($d_bin)
                        $d_c = AscW(StringMid($d_bin, $d_i, 1))
                        $d_k = AscW(StringMid($ky, Mod($d_i - 1, StringLen($ky)) + 1, 1))
                        $d_out &= ChrW(BitXOR($d_c, $d_k))
                    Next
                    Return $d_out
                EndFunc

                $x = decode10("0x31275C23300271", "AU3")
                ''',
                Au3FunctionEvaluation,
            ),
            'Func decode10($hx, $ky)\n'
            '    $d_bin = BinaryToString($hx, 1)\n'
            '    $d_out = ""\n'
            '    For $d_i = 1 To StringLen($d_bin)\n'
            '        $d_c = AscW(StringMid($d_bin, $d_i, 1))\n'
            '        $d_k = AscW(StringMid($ky, Mod($d_i - 1, StringLen($ky)) + 1, 1))\n'
            '        $d_out &= ChrW(BitXOR($d_c, $d_k))\n'
            '    Next\n'
            '    Return $d_out\n'
            'EndFunc\n'
            '$x = "probe10"\n')

    def test_a_decoder_whose_implicit_name_a_script_level_write_spells_stays(self):
        """
        A script-level write creates a global, so a bare write of the same name inside the
        function may reach it — the load-bearing case the summary must keep refusing.
        """
        self.assertEqual(
            self._apply(
                '''
                $d_out = "touched"

                Func decode10($hx, $ky)
                    $d_bin = BinaryToString($hx, 1)
                    $d_out = ""
                    For $d_i = 1 To StringLen($d_bin)
                        $d_c = AscW(StringMid($d_bin, $d_i, 1))
                        $d_k = AscW(StringMid($ky, Mod($d_i - 1, StringLen($ky)) + 1, 1))
                        $d_out &= ChrW(BitXOR($d_c, $d_k))
                    Next
                    Return $d_out
                EndFunc

                $x = decode10("0x31275C23300271", "AU3")
                ''',
                Au3FunctionEvaluation,
            ),
            '$d_out = "touched"\n'
            'Func decode10($hx, $ky)\n'
            '    $d_bin = BinaryToString($hx, 1)\n'
            '    $d_out = ""\n'
            '    For $d_i = 1 To StringLen($d_bin)\n'
            '        $d_c = AscW(StringMid($d_bin, $d_i, 1))\n'
            '        $d_k = AscW(StringMid($ky, Mod($d_i - 1, StringLen($ky)) + 1, 1))\n'
            '        $d_out &= ChrW(BitXOR($d_c, $d_k))\n'
            '    Next\n'
            '    Return $d_out\n'
            'EndFunc\n'
            '$x = decode10("0x31275C23300271", "AU3")\n')

    def test_a_decoder_under_mustdeclarevars_stays(self):
        """
        The tree may set `MustDeclareVars`, which makes every implicit write fatal, so the
        summary refinement refuses to lean on the census and the call stands.
        """
        self.assertEqual(
            self._apply(
                '''
                Opt("MustDeclareVars", 1)

                Func decode10($hx, $ky)
                    $d_bin = BinaryToString($hx, 1)
                    $d_out = ""
                    For $d_i = 1 To StringLen($d_bin)
                        $d_c = AscW(StringMid($d_bin, $d_i, 1))
                        $d_k = AscW(StringMid($ky, Mod($d_i - 1, StringLen($ky)) + 1, 1))
                        $d_out &= ChrW(BitXOR($d_c, $d_k))
                    Next
                    Return $d_out
                EndFunc

                $x = decode10("0x31275C23300271", "AU3")
                ''',
                Au3FunctionEvaluation,
            ),
            'Opt("MustDeclareVars", 1)\n'
            'Func decode10($hx, $ky)\n'
            '    $d_bin = BinaryToString($hx, 1)\n'
            '    $d_out = ""\n'
            '    For $d_i = 1 To StringLen($d_bin)\n'
            '        $d_c = AscW(StringMid($d_bin, $d_i, 1))\n'
            '        $d_k = AscW(StringMid($ky, Mod($d_i - 1, StringLen($ky)) + 1, 1))\n'
            '        $d_out &= ChrW(BitXOR($d_c, $d_k))\n'
            '    Next\n'
            '    Return $d_out\n'
            'EndFunc\n'
            '$x = decode10("0x31275C23300271", "AU3")\n')

    def test_a_decoder_under_a_mustdeclarevars_that_a_later_zero_follows_stays(self):
        """
        Which setting is in force when the call runs depends on the order the calls run in, not
        on where they stand: here the function that sets the option runs after the zero.
        """
        self.assertEqual(
            self._apply(
                '''
                Func strict()
                    Opt("MustDeclareVars", 1)
                EndFunc

                Func decode()
                    $d = "x"
                    Return $d
                EndFunc

                Opt("MustDeclareVars", 0)
                strict()
                $r = decode()
                ''',
                Au3FunctionEvaluation,
            ),
            'Func strict()\n'
            '    Opt("MustDeclareVars", 1)\n'
            'EndFunc\n'
            'Func decode()\n'
            '    $d = "x"\n'
            '    Return $d\n'
            'EndFunc\n'
            'Opt("MustDeclareVars", 0)\n'
            'strict()\n'
            '$r = decode()\n')

    def test_a_function_that_writes_a_command_line_constant_stays(self):
        """
        `$CmdLineRaw` exists in every script, so the bare write inside the function reaches the
        constant — a fatal error — instead of creating a local the call could run over.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    $CmdLineRaw = "x"
                    Return $CmdLineRaw
                EndFunc

                $r = f()
                ''',
                Au3FunctionEvaluation,
            ),
            'Func f()\n'
            '    $CmdLineRaw = "x"\n'
            '    Return $CmdLineRaw\n'
            'EndFunc\n'
            '$r = f()\n')

    def test_a_function_that_writes_a_name_an_unparsed_declaration_spells_stays(self):
        """
        The first line does not parse here, but it may be the `Global` declaration AutoIt runs,
        so the bare write inside the function may reach that global.
        """
        self.assertEqual(
            self._apply(
                '''
                Global $x = 1.

                Func f()
                    $x = "y"
                    Return $x
                EndFunc

                $r = f()
                ''',
                Au3FunctionEvaluation,
            ),
            'Global $x = 1.\n'
            'Func f()\n'
            '    $x = "y"\n'
            '    Return $x\n'
            'EndFunc\n'
            '$r = f()\n')

    def test_a_decoder_whose_implicit_name_an_expanded_literal_spells_stays(self):
        """
        Under `ExpandVarStrings`, the literal `"$n$"` names the global `q` that the bare write
        inside the function then reaches, and the message box reads what the call wrote there.
        """
        self.assertEqual(
            self._apply(
                '''
                Opt("ExpandVarStrings", 1)
                $n = "q"
                Assign("$n$", "global!")

                Func dec($s)
                    $q = StringReverse($s)
                    Return $q
                EndFunc

                $r = dec("cba")
                MsgBox(0, $r, $q)
                ''',
                Au3FunctionEvaluation,
            ),
            'Opt("ExpandVarStrings", 1)\n'
            '$n = "q"\n'
            'Assign("$n$", "global!")\n'
            'Func dec($s)\n'
            '    $q = StringReverse($s)\n'
            '    Return $q\n'
            'EndFunc\n'
            '$r = dec("cba")\n'
            'MsgBox(0, $r, $q)\n')

    def test_a_call_after_a_binding_sees_the_globals_it_proves(self):
        """
        Every script-level call sees the globals proven where it stands, not those an earlier
        call proved: the first call runs before the global is written and stays, the one after
        the write folds over it.
        """
        self.assertEqual(
            self._apply(
                '''
                Func dec($s)
                    Return $g & $s
                EndFunc

                $x = dec("a")
                $g = "1"
                $r = dec("b")
                ''',
                Au3FunctionEvaluation,
            ),
            'Func dec($s)\n'
            '    Return $g & $s\n'
            'EndFunc\n'
            '$x = dec("a")\n'
            '$g = "1"\n'
            '$r = "1b"\n')
