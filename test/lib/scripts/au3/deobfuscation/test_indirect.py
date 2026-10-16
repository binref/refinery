"""
The callee rewrite through an alias variable on its own: which variables provably name one
function, and the shapes that forfeit or refuse that proof.
"""
from __future__ import annotations

import pytest

from test.lib.scripts.au3.deobfuscation import TestAu3

from refinery.lib.scripts.au3.deobfuscation.indirect import Au3IndirectCallRewrite


class TestAu3IndirectCallRewrite(TestAu3):

    def test_a_variable_holding_execute_names_execute(self):
        self.assertEqual(
            self._apply(
                '''
                Local $e = Execute
                $x = $e("1 + 1")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Local $e = Execute\n$x = Execute("1 + 1")\n')

    def test_a_variable_initialized_from_execute_names_the_function(self):
        self.assertEqual(
            self._apply(
                '''
                Local $b = Execute("BinaryToString")
                $x = $b("0x41")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Local $b = Execute("BinaryToString")\n$x = BinaryToString("0x41")\n')

    def test_a_real_but_unemulated_builtin_alias_resolves(self):
        """
        `MsgBox` is a real builtin this project never emulates the return value of; the alias
        still names it, because the alias map validates against every core builtin, not only the
        emulated subset.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $f = Execute("MsgBox")
                $x = $f(0, "", "t")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Local $f = Execute("MsgBox")\n$x = MsgBox(0, "", "t")\n')

    def test_an_alias_keeps_the_spelling_the_execute_argument_holds(self):
        """
        The direct call resolves exactly as the `Execute` argument does; printing a builtin's
        official spelling is the case normalization's job, which runs last.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $f = Execute("msGbox")
                $x = $f(0, "", "t")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Local $f = Execute("msGbox")\n$x = msGbox(0, "", "t")\n')

    def test_a_declared_name_outside_ascii_is_an_alias_in_any_ascii_case(self):
        self.assertEqual(
            self._apply(
                '''
                Func ÄRGER($a)
                    Return $a
                EndFunc

                Local $b = Execute("Ärger")
                $b(1)
                ''',
                Au3IndirectCallRewrite,
            ),
            'Func ÄRGER($a)\n    Return $a\nEndFunc\n'
            'Local $b = Execute("Ärger")\nÄrger(1)\n')

    @pytest.mark.xfail(
        strict=True,
        reason='names are identified by `str.lower`, which folds U+212A into `k`',
    )
    def test_a_name_python_folds_into_a_builtin_is_no_alias(self):
        """
        U+212A KELVIN SIGN lowercases to ASCII `k` for Python; whether AutoIt folds it too is
        unpinned. If it does not, the direct call names no function and fails when the script
        loads, where the original `Execute` fails softly when it runs.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $b = Execute("Win\u212aill")
                $b("t")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Local $b = Execute("Win\u212aill")\n$b("t")\n')

    def test_an_include_refuses_every_alias(self):
        """
        An included file may declare a `Func Execute` no walk of the tree sees.
        """
        self.assertEqual(
            self._apply(
                '''
                #include "other.au3"
                Local $b = Execute("MsgBox")
                $b(0)
                ''',
                Au3IndirectCallRewrite,
            ),
            '#include "other.au3"\nLocal $b = Execute("MsgBox")\n$b(0)\n')

    def test_a_parse_error_refuses_every_alias(self):
        """
        Text the parser could not read may hold a `Func Execute` no walk of the tree sees.
        """
        self.assertEqual(
            self._apply(
                '''
                $x = = 1
                Local $b = Execute("MsgBox")
                $b(0)
                ''',
                Au3IndirectCallRewrite,
            ),
            '$x = = 1\nLocal $b = Execute("MsgBox")\n$b(0)\n')

    def test_a_local_alias_inside_a_function_is_rewritten(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $e = Execute
                    $e("1")
                EndFunc
                ''',
                Au3IndirectCallRewrite,
            ),
            'Func f()\n    Local $e = Execute\n    Execute("1")\nEndFunc\n')

    def test_an_alias_of_a_function_name_is_rewritten_only_after_execute(self):
        """
        A call initialized from `Execute("name")` is the shape the rewrite resolves; the same
        initializer spelled without `Execute` is not one the probe pinned, so it stands.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $b = BinaryToString
                $x = $b("0x41")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Local $b = BinaryToString\n$x = $b("0x41")\n')

    def test_a_second_write_forfeits_the_alias(self):
        self.assertEqual(
            self._apply(
                '''
                Local $e = Execute
                $e = MsgBox
                $x = $e("t")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Local $e = Execute\n$e = MsgBox\n$x = $e("t")\n')

    def test_a_read_outside_a_callee_forfeits_the_alias(self):
        """
        A variable read anywhere but the callee of a call is not a call the rewrite can serve,
        and it proves the initializer's value escapes, so the callee read stays too.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $e = Execute
                $w = $e & "B"
                $x = $e("t")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Local $e = Execute\n$w = $e & "B"\n$x = $e("t")\n')

    def test_a_shadowed_execute_refuses_every_alias(self):
        self.assertEqual(
            self._apply(
                '''
                Func Execute($s)
                    Return 1
                EndFunc

                Local $e = Execute
                $x = $e("t")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Func Execute($s)\n    Return 1\nEndFunc\n'
            'Local $e = Execute\n$x = $e("t")\n')

    def test_a_direct_assign_rebind_forfeits_the_alias(self):
        """
        `Assign` names a variable at run time; a constant first argument is the one shape the
        scan reads, and it costs the alias that name.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $e = Execute
                Assign("e", "MsgBox")
                $x = $e("t")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Local $e = Execute\nAssign("e", "MsgBox")\n$x = $e("t")\n')

    def test_an_execute_wrapped_assign_rebind_forfeits_the_alias(self):
        """
        An `Execute` over a string literal that parses to code holding a call is the one
        `Execute` shape the scan reads; this one runs an `Assign`, so the alias is forfeited and
        the call stays behind the variable.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $e = Execute
                $x = Execute("Assign(""e"", ""MsgBox"")")
                $y = $e("t")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Local $e = Execute\n$x = Execute("Assign(""e"", ""MsgBox"")")\n$y = $e("t")\n')

    def test_a_provably_local_alias_survives_a_global_write_threat(self):
        """
        No call outside the function can reach a provably local variable, so a script function
        whose summary may write the global of the same name costs a script-level alias nothing
        inside the function.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $e = Execute
                    $e("1")
                EndFunc

                Func g()
                    Global $e = 1
                EndFunc

                g()
                ''',
                Au3IndirectCallRewrite,
            ),
            'Func f()\n    Local $e = Execute\n    Execute("1")\nEndFunc\n'
            'Func g()\n    Global $e = 1\nEndFunc\ng()\n')

    def test_a_global_alias_is_forfeit_where_a_summary_writes_the_name(self):
        """
        A script function whose may-write summary contains the alias name can rebind the global
        the initializer wrote, so a script-level alias of that name is not qualified.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $e = Execute

                Func g()
                    Global $e = 1
                EndFunc

                g()
                $x = $e("t")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Local $e = Execute\nFunc g()\n    Global $e = 1\nEndFunc\ng()\n$x = $e("t")\n')

    def test_a_call_dispatch_rebind_forfeits_the_alias(self):
        """
        `Call` runs the function its argument names, so a dispatch that rebinds the global the
        initializer wrote costs the alias exactly the direct call to that function would.
        """
        self.assertEqual(
            self._apply(
                '''
                Global $e = Execute("MsgBox")

                Func w()
                    Global $e = Execute("WinKill")
                EndFunc

                Call("w")
                $x = $e(0, "", "t")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Global $e = Execute("MsgBox")\n'
            'Func w()\n    Global $e = Execute("WinKill")\nEndFunc\n'
            'Call("w")\n$x = $e(0, "", "t")\n')

    def test_a_registered_callback_rebind_forfeits_the_alias(self):
        """
        A registration builtin runs its registered function on a trigger no walk of the tree can
        place, so a global alias may not survive one even where the call sites look ordered.
        """
        self.assertEqual(
            self._apply(
                '''
                Global $e = Execute("MsgBox")

                Func w()
                    Global $e = Execute("WinKill")
                EndFunc

                AdlibRegister("w", 1000)
                $x = $e(0, "", "t")
                ''',
                Au3IndirectCallRewrite,
            ),
            'Global $e = Execute("MsgBox")\n'
            'Func w()\n    Global $e = Execute("WinKill")\nEndFunc\n'
            'AdlibRegister("w", 1000)\n$x = $e(0, "", "t")\n')

    def test_an_unknown_name_stays_a_variable_callee(self):
        self.assertEqual(
            self._apply('$x = $f("t")', Au3IndirectCallRewrite),
            '$x = $f("t")\n')
