"""
Constant propagation on its own: which reads a provable value replaces, and the refusals —
positions where the value is not known (branch disagreement, loop writes, unproven targets) and
positions where the literal that spells the value is not legal AutoIt3, is past the depth bound,
or is past the growth budget its name owns.
"""
from __future__ import annotations

import unittest

from test.lib.scripts.au3.deobfuscation import TestAu3

from refinery.lib.scripts.au3.deobfuscation import deobfuscate
from refinery.lib.scripts.au3.deobfuscation.propagate import Au3ConstantPropagation
from refinery.lib.scripts.au3.parser import Au3Parser
from refinery.lib.scripts.au3.synth import Au3Synthesizer


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

    def test_a_bare_write_to_a_proven_local_binds(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x
                    $x = 5
                    $y = $x
                EndFunc
                ''',
                Au3ConstantPropagation,
            ),
            'Func f()\n    Local $x\n    $x = 5\n    $y = 5\nEndFunc\n')

    def test_a_parameter_write_binds_the_local(self):
        self.assertEqual(
            self._apply(
                '''
                Func f($p)
                    $p = 5
                    $y = $p
                EndFunc
                ''',
                Au3ConstantPropagation,
            ),
            'Func f($p)\n    $p = 5\n    $y = 5\nEndFunc\n')

    def test_a_global_declaration_in_the_function_breaks_the_local_proof(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x
                    $x = 5
                    Global $x
                    $y = $x
                EndFunc
                ''',
                Au3ConstantPropagation,
            ),
            'Func f()\n    Local $x\n    $x = 5\n    Global $x\n    $y = $x\nEndFunc\n')

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

    def test_a_byref_write_reached_through_another_function_kills_the_variable(self):
        """
        The variable a function hands to a `ByRef` parameter is written by that call, so a
        caller of the function kills it, although the function's own body never spells a write.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $x = 5

                Func modify(ByRef $p)
                    $p = 1
                EndFunc

                Func f()
                    modify($x)
                EndFunc

                f()
                $y = $x
                ''',
                Au3ConstantPropagation,
            ),
            'Local $x = 5\n'
            'Func modify(ByRef $p)\n'
            '    $p = 1\n'
            'EndFunc\n'
            'Func f()\n'
            '    modify($x)\n'
            'EndFunc\n'
            'f()\n'
            '$y = $x\n')

    def test_a_byref_write_reached_through_another_function_spares_other_globals(self):
        self.assertEqual(
            self._apply(
                '''
                Local $x = 5
                Local $z = 7

                Func modify(ByRef $p)
                    $p = 1
                EndFunc

                Func f()
                    modify($x)
                EndFunc

                f()
                $y = $x
                $w = $z
                ''',
                Au3ConstantPropagation,
            ),
            'Local $x = 5\n'
            'Local $z = 7\n'
            'Func modify(ByRef $p)\n'
            '    $p = 1\n'
            'EndFunc\n'
            'Func f()\n'
            '    modify($x)\n'
            'EndFunc\n'
            'f()\n'
            '$y = $x\n'
            '$w = 7\n')

    def test_a_byref_chain_through_a_byref_parameter_kills_the_outermost_variable(self):
        self.assertEqual(
            self._apply(
                '''
                Local $x = 5

                Func modify(ByRef $p)
                    $p = 1
                EndFunc

                Func relay(ByRef $q)
                    modify($q)
                EndFunc

                relay($x)
                $y = $x
                ''',
                Au3ConstantPropagation,
            ),
            'Local $x = 5\n'
            'Func modify(ByRef $p)\n'
            '    $p = 1\n'
            'EndFunc\n'
            'Func relay(ByRef $q)\n'
            '    modify($q)\n'
            'EndFunc\n'
            'relay($x)\n'
            '$y = $x\n')

    def test_an_indexed_store_kills_the_whole_array(self):
        """
        A store through an index mutates one element, so the array as a value is no longer the
        literal it was initialized to, and no read of it is replaced afterwards.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $a[2] = [1, 2]
                $a[0] = 5
                Local $b[2] = [$a]
                ''',
                Au3ConstantPropagation,
            ),
            'Local $a[2] = [1, 2]\n$a[0] = 5\nLocal $b[2] = [$a]\n')

    def test_a_member_store_kills_the_variable(self):
        """
        A store through a member mutates the object the variable holds, so the value the variable
        was initialized to no longer describes it and the read stands.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $o = "abc"
                $o.prop = "x"
                $y = $o
                ''',
                Au3ConstantPropagation,
            ),
            'Local $o = "abc"\n$o.prop = "x"\n$y = $o\n')

    def test_a_callee_position_read_is_not_replaced(self):
        """
        The call runs what the variable names, not what it holds, so the callee read stands even
        where the walk knows the value.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $f = "MsgBox"
                $f(0, "", "t")
                ''',
                Au3ConstantPropagation,
            ),
            'Local $f = "MsgBox"\n$f(0, "", "t")\n')

    @unittest.expectedFailure
    def test_an_unknown_callee_argument_is_not_replaced(self):
        """
        An unseen callee may hold a bare-variable argument by reference, so replacing the read
        would divert what the callee receives. Telling an unseen function from an unemulated
        builtin needs the builtin name universe, which no module owns yet.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $x = 5
                Unknown($x)
                ''',
                Au3ConstantPropagation,
            ),
            'Local $x = 5\nUnknown($x)\n')

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

    def test_a_binary_value_replaces_a_read_inside_an_array_literal(self):
        self.assertEqual(
            self._apply(
                '''
                Local $b = Binary("0x41")
                Local $a[1] = [$b]
                ''',
                Au3ConstantPropagation,
            ),
            'Local $b = Binary("0x41")\n'
            'Local $a[1] = [Binary("0x41")]\n')

    def test_a_value_with_a_line_break_propagates_as_its_chain(self):
        self.assertEqual(
            self._apply(
                '''
                Global Const $c = "a" & @CRLF & "b"
                $y = $c
                ''',
                Au3ConstantPropagation,
            ),
            'Global Const $c = "a" & @CRLF & "b"\n$y = "a" & @CRLF & "b"\n')

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
        literal into whatever it folds to, end to end — and the declaration the read left behind
        then leaves as dead code, its name bound by no occurrence anymore.
        """
        self.assertEqual(
            self._deobfuscate(
                '''
                Local $x = 5
                $y = $x + 1
                '''),
            '$y = 6\n')

    def test_derived_constants_collapse_in_one_pass(self):
        """
        A binding is taken from the value the evaluator proves, not the shape the fold leaves
        behind, so a chain of derived constants propagates to its end without a fold between.
        """
        self.assertEqual(
            self._apply(
                '''
                Local $a = 1 + 2
                Local $b = $a * 3
                Local $c = $b + 1
                ''',
                Au3ConstantPropagation,
            ),
            'Local $a = 1 + 2\nLocal $b = 3 * 3\nLocal $c = 9 + 1\n')

    def test_a_builtin_result_binds(self):
        self.assertEqual(
            self._apply(
                '''
                Local $n = StringLen("ab")
                $y = $n
                ''',
                Au3ConstantPropagation,
            ),
            'Local $n = StringLen("ab")\n$y = 2\n')

    def test_a_value_past_the_payload_bound_is_never_inlined(self):
        self.assertEqual(
            self._apply(
                F'''
                Local $s = "{"a" * 5000}"
                $y = $s
                ''',
                Au3ConstantPropagation,
            ),
            F'Local $s = "{"a" * 5000}"\n$y = $s\n')

    def test_a_compound_assignment_within_the_bound_binds(self):
        self.assertEqual(
            self._apply(
                '''
                Local $s = "a"
                $s &= "bc"
                $y = $s
                ''',
                Au3ConstantPropagation,
            ),
            'Local $s = "a"\n$s &= "bc"\n$y = "abc"\n')

    def test_a_compound_assignment_past_the_bound_binds_nothing(self):
        self.assertEqual(
            self._apply(
                F'''
                Local $s = "a"
                $s &= "{"b" * 5000}"
                $y = $s
                ''',
                Au3ConstantPropagation,
            ),
            F'Local $s = "a"\n$s &= "{"b" * 5000}"\n$y = $s\n')

    def test_an_array_past_the_payload_bound_is_never_recorded(self):
        self.assertEqual(
            self._apply(
                F'''
                Local $a = StringSplit("{"a," * 5000}a", ",")
                Local $b[1] = [$a]
                ''',
                Au3ConstantPropagation,
            ),
            F'Local $a = StringSplit("{"a," * 5000}a", ",")\nLocal $b[1] = [$a]\n')

    def test_a_rendered_chain_past_the_depth_bound_is_refused(self):
        """
        A NUL-heavy string renders as one chain level per character, so a value whose spelling
        outgrows the depth bound keeps its reads however small its payload is.
        """
        self.assertEqual(
            self._apply(
                F'''
                Global Const $c = StringReplace("{"x" * 400}", "x", Chr(0))
                $y = $c
                ''',
                Au3ConstantPropagation,
            ),
            F'Global Const $c = StringReplace("{"x" * 400}", "x", Chr(0))\n$y = $c\n')

    def test_a_rendered_chain_within_the_depth_bound_is_installed(self):
        self.assertEqual(
            self._apply(
                '''
                Global Const $c = StringReplace("xx", "x", Chr(0))
                $y = $c
                ''',
                Au3ConstantPropagation,
            ),
            'Global Const $c = StringReplace("xx", "x", Chr(0))\n$y = Chr(0) & Chr(0)\n')

    def test_a_name_past_its_growth_budget_keeps_its_reads(self):
        """
        Every read of a name charges the length its replacement adds, and a payload spelled at
        every read would multiply the tree where the definition already spells it once.
        """
        reads = '\n'.join(F'$y{i} = $c' for i in range(1, 11))
        self.assertEqual(
            self._apply(
                F'''
                Global Const $c = "{"v" * 100}"
                {reads}
                ''',
                Au3ConstantPropagation,
            ),
            F'Global Const $c = "{"v" * 100}"\n{reads}\n')

    def test_a_name_within_its_growth_budget_is_inlined(self):
        self.assertEqual(
            self._apply(
                F'''
                Global Const $c = "{"v" * 100}"
                $y = $c
                ''',
                Au3ConstantPropagation,
            ),
            F'Global Const $c = "{"v" * 100}"\n$y = "{"v" * 100}"\n')

    def test_a_local_keeps_its_budget_apart_from_a_same_named_global(self):
        """
        The budget is charged per definition, so a local that shares its name with a global past
        the global's budget still inlines the local's own reads.
        """
        reads = '\n'.join(F'$y{i} = $c' for i in range(1, 11))
        self.assertEqual(
            self._apply(
                F'''
                Global Const $c = "{"v" * 100}"
                {reads}
                Func f()
                    Local $c = 5
                    $z = $c
                EndFunc
                ''',
                Au3ConstantPropagation,
            ),
            F'Global Const $c = "{"v" * 100}"\n{reads}\n'
            'Func f()\n'
            '    Local $c = 5\n'
            '    $z = 5\n'
            'EndFunc\n')

    def test_a_wide_array_literal_inlines_on_its_budget_alone(self):
        """
        A wide array literal is two levels deep however many elements it holds, so the depth
        bound never refuses it and the growth budget alone decides the inline.
        """
        elements = ', '.join(str(i) for i in range(1100))
        self.assertEqual(
            self._apply(
                F'''
                Global Const $pad = "{"p" * 30000}"
                Local $a[1100] = [{elements}]
                Local $b[1] = [$a]
                ''',
                Au3ConstantPropagation,
            ),
            F'Global Const $pad = "{"p" * 30000}"\n'
            F'Local $a[1100] = [{elements}]\n'
            F'Local $b[1] = [[{elements}]]\n')

    def test_a_derived_constant_chain_settles_within_a_small_step_budget(self):
        """
        One propagation pass carries a chain of derived constants to its end, so the pipeline
        settles it in a handful of passes — where a walk that bound only literal shapes needed a
        fold between every two links and a step budget on the order of the chain's length.
        """
        chain = '\n'.join(
            ['Local $a0 = 1 + 2'] + [F'Local $a{i} = $a{i - 1} + {i}' for i in range(1, 9)])
        ast = Au3Parser(chain).parse()
        deobfuscate(ast, max_steps=8)
        self.assertEqual(
            Au3Synthesizer().convert(ast),
            '\n'.join(
                F'Local $a{i} = {value}'
                for i, value in enumerate((3, 4, 6, 9, 13, 18, 24, 31, 39))
            ) + '\n')
