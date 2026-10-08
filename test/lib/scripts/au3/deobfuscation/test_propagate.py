"""
Constant propagation on its own: which reads a provable value replaces, and the refusals —
positions where the value is not known (branch disagreement, loop writes, unproven targets) and
positions where the literal that spells the value is not legal AutoIt3.
"""
from __future__ import annotations

from test.lib.scripts.au3.deobfuscation import TestAu3

from refinery.lib.scripts.au3.deobfuscation.propagate import Au3ConstantPropagation


class TestAu3ConstantPropagation(TestAu3):

    def test_a_proven_read_is_replaced_by_its_literal(self):
        self.assertEqual(
            self._apply(
                '''
                Local $x = 5
                $y = $x + 1
                ''',
                Au3ConstantPropagation,
            ),
            'Local $x = 5\n$y = 5 + 1\n')

    def test_a_const_declaration_propagates(self):
        self.assertEqual(
            self._apply(
                '''
                Global Const $c = 7
                $y = $c + 1
                ''',
                Au3ConstantPropagation,
            ),
            'Global Const $c = 7\n$y = 7 + 1\n')

    def test_a_compound_assignment_propagates_the_known_value(self):
        self.assertEqual(
            self._apply(
                '''
                Local $x = 5
                $x += 2
                $y = $x
                ''',
                Au3ConstantPropagation,
            ),
            'Local $x = 5\n$x += 2\n$y = 7\n')

    def test_a_disagreeing_branch_propagates_nothing(self):
        self.assertEqual(
            self._apply(
                '''
                Local $x = 1
                If $z Then
                    $x = 1
                Else
                    $x = 2
                EndIf
                $y = $x
                ''',
                Au3ConstantPropagation,
            ),
            'Local $x = 1\nIf $z Then\n    $x = 1\nElse\n    $x = 2\nEndIf\n$y = $x\n')

    def test_an_agreeing_branch_propagates(self):
        self.assertEqual(
            self._apply(
                '''
                Local $x = 1
                If $z Then
                    $x = 5
                Else
                    $x = 5
                EndIf
                $y = $x
                ''',
                Au3ConstantPropagation,
            ),
            'Local $x = 1\nIf $z Then\n    $x = 5\nElse\n    $x = 5\nEndIf\n$y = 5\n')

    def test_a_write_inside_a_loop_kills_the_value(self):
        self.assertEqual(
            self._apply(
                '''
                Local $x = 1
                While $z
                    $x = 2
                Wend
                $y = $x
                ''',
                Au3ConstantPropagation,
            ),
            'Local $x = 1\nWhile $z\n    $x = 2\nWend\n$y = $x\n')

    def test_a_bare_assignment_inside_a_function_binds_nothing(self):
        """
        Inside a function only a declaration proves which storage a write targets, and a bare
        assignment may hit a same-named global from an unseen include, so it binds nothing.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    $x = 5
                    $y = $x
                EndFunc
                ''',
                Au3ConstantPropagation,
            ),
            'Func f()\n    $x = 5\n    $y = $x\nEndFunc\n')

    def test_a_local_declaration_inside_a_function_binds(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x = 5
                    $y = $x
                EndFunc
                ''',
                Au3ConstantPropagation,
            ),
            'Func f()\n    Local $x = 5\n    $y = 5\nEndFunc\n')

    def test_a_static_declaration_binds_nothing(self):
        """
        A `Static` keeps its value across calls, so no single pass can know what a later call
        reads, and the declaration binds nothing.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Static $x = 5
                    $y = $x
                EndFunc
                ''',
                Au3ConstantPropagation,
            ),
            'Func f()\n    Static $x = 5\n    $y = $x\nEndFunc\n')

    def test_a_global_is_not_seeded_into_a_function_walk(self):
        """
        A local of the same name shadows the global inside the function, and an unseen include
        cannot be told apart from one that does not, so the function walk starts from nothing.
        """
        self.assertEqual(
            self._apply(
                '''
                Global $g = 5
                Func f()
                    $y = $g
                EndFunc
                ''',
                Au3ConstantPropagation,
            ),
            'Global $g = 5\nFunc f()\n    $y = $g\nEndFunc\n')

    def test_a_reassigned_name_propagates_the_new_value(self):
        self.assertEqual(
            self._apply(
                '''
                Local $x = 5
                $x = 6
                $y = $x
                ''',
                Au3ConstantPropagation,
            ),
            'Local $x = 5\n$x = 6\n$y = 6\n')

    def test_an_unknown_call_kills_the_globals_after_it(self):
        self.assertEqual(
            self._apply(
                '''
                Local $x = 5
                Unknown()
                $y = $x
                ''',
                Au3ConstantPropagation,
            ),
            'Local $x = 5\nUnknown()\n$y = $x\n')

    def test_a_script_function_call_kills_only_what_it_may_write(self):
        self.assertEqual(
            self._apply(
                '''
                Local $x = 5

                Func f()
                    Global $g = 1
                EndFunc

                f()
                $y = $x
                ''',
                Au3ConstantPropagation,
            ),
            'Local $x = 5\nFunc f()\n    Global $g = 1\nEndFunc\nf()\n$y = 5\n')

    def test_a_byref_argument_kills_the_variable(self):
        self.assertEqual(
            self._apply(
                '''
                Local $x = 5

                Func f(ByRef $p)
                    $p = 1
                EndFunc

                f($x)
                $y = $x
                ''',
                Au3ConstantPropagation,
            ),
            'Local $x = 5\nFunc f(ByRef $p)\n    $p = 1\nEndFunc\nf($x)\n$y = $x\n')

    def test_an_array_value_splices_only_into_a_declaration_initializer(self):
        """
        An array spells only as an array literal, which AutoIt accepts only where a declaration
        initializes, so a read anywhere else stands.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $a[2] = [1, 2]
                Local $b[2] = [$a]
                $y = $a
                ''',
                Au3ConstantPropagation,
            ),
            'Local $a[2] = [1, 2]\nLocal $b[2] = [[1, 2]]\n$y = $a\n')

    def test_an_array_index_read_is_not_replaced_by_the_whole_array(self):
        self.assertEqual(
            self._apply(
                '''
                Local $a[2] = [1, 2]
                $y = $a[0]
                ''',
                Au3ConstantPropagation,
            ),
            'Local $a[2] = [1, 2]\n$y = $a[0]\n')

    def test_a_binary_value_refuses_a_position_inside_an_array_literal(self):
        self.assertEqual(
            self._apply(
                '''
                Local $b = Binary("0x41")
                Local $a[1] = [$b]
                ''',
                Au3ConstantPropagation,
            ),
            'Local $b = Binary("0x41")\nLocal $a[1] = [$b]\n')

    def test_a_binary_value_replaces_a_scalar_read(self):
        self.assertEqual(
            self._apply(
                '''
                Local $b = Binary("0x41")
                $y = $b
                ''',
                Au3ConstantPropagation,
            ),
            'Local $b = Binary("0x41")\n$y = Binary("0x41")\n')

    def test_the_fold_pass_does_not_respond_to_a_replaced_read(self):
        """
        The replaced read is the value itself, so the pipeline's fold group turns the propagated
        literal into whatever it folds to, end to end.
        """
        self.assertEqual(
            self._deobfuscate(
                '''
                Local $x = 5
                $y = $x + 1
                '''),
            'Local $x = 5\n$y = 6\n')
