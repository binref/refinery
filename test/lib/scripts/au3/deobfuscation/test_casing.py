"""
Builtin case normalization on its own: which references to a builtin take the official spelling,
and which spellings the gates leave standing. The tests near the end run the whole pipeline
instead, pinning that a shape another pass produces — a call spliced out of an `Execute`
payload — is printed officially too.
"""
from __future__ import annotations

import inspect

from test.lib.scripts.au3.deobfuscation import TestAu3

from refinery.lib.scripts.au3.deobfuscation.casing import Au3BuiltinCaseNormalization


class TestAu3BuiltinCaseNormalization(TestAu3):

    def test_a_scrambled_callee_prints_the_official_spelling(self):
        self.assertEqual(
            self._apply(
                'mSgBoX(0, "", "t")',
                Au3BuiltinCaseNormalization,
            ),
            'MsgBox(0, "", "t")\n')

    def test_the_spellings_the_docs_and_the_interpreter_disagree_on_come_out_documented(self):
        """
        Nine builtin spellings differ between the interpreter's call table and the documentation;
        four of them, scrambled, print the documented one.
        """
        self.assertEqual(
            self._apply(
                '''
                aCoS(0)
                bItAnd(1, 2)
                hWnD(0)
                sTaTuSbArGeTtExT("t")
                ''',
                Au3BuiltinCaseNormalization,
            ),
            'ACos(0)\nBitAND(1, 2)\nHWnd(0)\nStatusbarGetText("t")\n')

    def test_a_callee_a_declared_function_owns_keeps_its_spelling(self):
        """
        The call resolves to the declared function whatever the case, so the rewrite is sound —
        but printing a builtin's name there would tell the reader the call is one.
        """
        self.assertEqual(
            self._apply(
                '''
                Func msgbox($a)
                    Return $a
                EndFunc

                mSgBoX(0)
                ''',
                Au3BuiltinCaseNormalization,
            ),
            'Func msgbox($a)\n    Return $a\nEndFunc\nmSgBoX(0)\n')

    def test_a_name_a_declared_function_owns_keeps_the_spelling_a_call_holds(self):
        """
        `msgbox` is a builtin's name, so only the declared function keeps the string standing.
        """
        self.assertEqual(
            self._apply(
                '''
                Func msgbox($a)
                    Return $a
                EndFunc

                Call("mSgBoX", 0)
                ''',
                Au3BuiltinCaseNormalization,
            ),
            'Func msgbox($a)\n    Return $a\nEndFunc\nCall("mSgBoX", 0)\n')

    def test_the_name_a_call_holds_prints_the_official_spelling(self):
        """
        The docs say `Call` invokes builtins too, and no earlier pass resolves that name, so the
        string stays behind the `Call` — printed the way the documentation spells it.
        """
        self.assertEqual(
            self._apply(
                'cAlL("mSgBoX", 0, "", "t")',
                Au3BuiltinCaseNormalization,
            ),
            'Call("MsgBox", 0, "", "t")\n')

    def test_a_parenthesized_name_a_call_holds_prints_the_official_spelling(self):
        self.assertEqual(
            self._apply(
                'Call(("msgbox"), 0)',
                Au3BuiltinCaseNormalization,
            ),
            'Call(("MsgBox"), 0)\n')

    def test_a_registration_name_argument_keeps_its_spelling(self):
        """
        A registration builtin's string argument names a script function, never a builtin, so no
        rule of this pass reads it.
        """
        self.assertEqual(
            self._apply(
                'AdlibRegister("mSgBoX", 1000)',
                Au3BuiltinCaseNormalization,
            ),
            'AdlibRegister("mSgBoX", 1000)\n')

    def test_an_execute_payload_keeps_its_spelling(self):
        """
        The pass reads only a `Call`'s first argument, never a string an `Execute` holds, so the
        payload's spelling is left to the pass that resolves it.
        """
        self.assertEqual(
            self._apply(
                '$x = Execute("aSsIgN(""e"", 1)")',
                Au3BuiltinCaseNormalization,
            ),
            '$x = Execute("aSsIgN(""e"", 1)")\n')

    def test_a_shadowing_call_function_keeps_the_argument_spelling(self):
        self.assertEqual(
            self._apply(
                '''
                Func call($s)
                    Return $s
                EndFunc

                Call("mSgBoX", 0)
                ''',
                Au3BuiltinCaseNormalization,
            ),
            'Func call($s)\n    Return $s\nEndFunc\nCall("mSgBoX", 0)\n')

    def test_an_include_keeps_the_name_a_call_holds(self):
        """
        An included file may declare a `Func Call` no walk of the tree sees, and under one the
        string is data the called function reads, not a name. The callee rewrite carries no
        include gate: it changes only the printed spelling, never what the call resolves to.
        """
        self.assertEqual(
            self._apply(
                '''
                #include <Array.au3>
                Call("mSgBoX", 0)
                mSgBoX(0, "", "t")
                ''',
                Au3BuiltinCaseNormalization,
            ),
            '#include <Array.au3>\nCall("mSgBoX", 0)\nMsgBox(0, "", "t")\n')

    def test_a_parse_error_keeps_the_name_a_call_holds(self):
        """
        A tree whose parse failed anywhere holds text no walk reads, which may hide a
        `Func Call`; the callee rewrite carries no parse-error gate either.
        """
        self.assertEqual(
            self._apply(
                '''
                $x = = 1
                Call("mSgBoX", 0)
                mSgBoX(0, "", "t")
                ''',
                Au3BuiltinCaseNormalization,
            ),
            '$x = = 1\nCall("mSgBoX", 0)\nMsgBox(0, "", "t")\n')

    def test_a_computed_name_a_call_holds_keeps_its_spelling(self):
        self.assertEqual(
            self._apply('$x = Call($f)', Au3BuiltinCaseNormalization),
            '$x = Call($f)\n')

    def test_a_name_the_function_table_holds_no_entry_for_keeps_its_spelling(self):
        self.assertEqual(
            self._apply('$x = Call("nosuchfunction")', Au3BuiltinCaseNormalization),
            '$x = Call("nosuchfunction")\n')

    def test_a_name_python_folds_into_a_builtin_keeps_its_spelling(self):
        """
        U+212A KELVIN SIGN lowercases to ASCII `k` for Python; whether AutoIt folds it too is
        unpinned, and the source spelling is right under either answer.
        """
        self.assertEqual(
            self._apply('Call("Win\u212aill", "t")', Au3BuiltinCaseNormalization),
            'Call("Win\u212aill", "t")\n')

    def test_a_callee_python_folds_into_a_builtin_keeps_its_spelling(self):
        self.assertEqual(
            self._apply('Win\u212aill("t")', Au3BuiltinCaseNormalization),
            'Win\u212aill("t")\n')

    def test_a_call_without_arguments_keeps_standing(self):
        self.assertEqual(
            self._apply('$x = Call()', Au3BuiltinCaseNormalization),
            '$x = Call()\n')

    def test_a_spliced_execute_payload_prints_its_inner_call_officially(self):
        self._assertDeobfuscatesTo(
            '$x = Execute("mSgBoX(0, """", ""t"")")',
            'MsgBox(0, "", "t")')

    def test_every_surviving_shape_prints_its_official_spelling(self):
        """
        The flattened user-function call site keeps the spelling the `Call` argument held —
        aligning it with the declaration is the later phase's question.
        """
        self._assertDeobfuscatesTo(
            '''
            Func checkip()
                mSgBoX(0, "", "t")
            EndFunc

            Call("cHeCkIp")
            cAlL("mSgBoX", 0, "", "t")
            ''',
            '''
            Func checkip()
                MsgBox(0, "", "t")
            EndFunc

            cHeCkIp()
            Call("MsgBox", 0, "", "t")
            ''')

    def test_a_full_run_is_idempotent_in_spelling(self):
        once = self._deobfuscate(inspect.cleandoc('''
            Func checkip()
                mSgBoX(0, "", "t")
            EndFunc
            Call("cHeCkIp")
            cAlL("mSgBoX", 0, "", "t")
        '''))
        self.assertEqual(once, self._deobfuscate(once))
