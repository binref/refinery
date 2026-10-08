"""
The callee rewrite through an alias variable on its own: which variables provably name one
function, and the shapes that forfeit or refuse that proof.
"""
from __future__ import annotations

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

    def test_an_unknown_name_stays_a_variable_callee(self):
        self.assertEqual(
            self._apply('$x = $f("t")', Au3IndirectCallRewrite),
            '$x = $f("t")\n')
