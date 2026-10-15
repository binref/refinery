"""
The write-only store sweep on its own: which assignments one visit removes or splices, and
which guard — read count, spelling, binding, or channel — keeps what would otherwise go.
"""
from __future__ import annotations

from test.lib.scripts.au3.deobfuscation import TestAu3

from refinery.lib.scripts.au3.deobfuscation.propagate import Au3ConstantPropagation
from refinery.lib.scripts.au3.deobfuscation.unused import Au3UnusedVariableRemoval


class TestAu3UnusedVariableRemoval(TestAu3):

    def test_a_write_only_script_level_store_is_removed(self):
        self.assertEqual(
            self._apply(
                '''
                $x = 1
                $y = 1.5
                $z = "2"
                $w = (1 + 2) * 3
                MsgBox(0, 0, 0)
                ''',
                Au3UnusedVariableRemoval,
            ),
            'MsgBox(0, 0, 0)\n')

    def test_an_implicit_write_inside_a_called_function_is_removed(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    $v = 1
                    MsgBox(0, 0, 0)
                EndFunc

                f()
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Func f()\n'
            '    MsgBox(0, 0, 0)\n'
            'EndFunc\n'
            'f()\n')

    def test_a_local_claimed_before_the_store_is_removed(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x
                    $x = 1
                    MsgBox(0, 0, 0)
                EndFunc

                f()
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Func f()\n'
            '    Local $x\n'
            '    MsgBox(0, 0, 0)\n'
            'EndFunc\n'
            'f()\n')

    def test_a_local_store_leaves_in_a_fragment(self):
        """
        A fragment's locals are private to it, so the local rule needs no open entry the way the
        global and implicit-write rules do.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x
                    $x = 1
                EndFunc
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Func f()\n'
            '    Local $x\n'
            'EndFunc\n')

    def test_an_impure_store_is_spliced_to_its_right_hand_side(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    $w = DllCall("kernel32.dll", "none", "Sleep", "int", 10)
                    $q = TCPNameToIP("127.0.0.1")
                EndFunc

                f()
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Func f()\n'
            '    DllCall("kernel32.dll", "none", "Sleep", "int", 10)\n'
            '    TCPNameToIP("127.0.0.1")\n'
            'EndFunc\n'
            'f()\n')

    def test_a_spliced_ternary_over_a_writable_condition_is_bracketed(self):
        """
        The value compares `$y` in the ternary's condition, so an unbracketed splice would re-read
        as a store into `$y` — the read of `$y` below would see the stored value, not the one the
        program kept.
        """
        self.assertEqual(
            self._apply(
                '''
                $x = $y = 0 ? 1 / $y : 2
                MsgBox(0, 0, $y)
                ''',
                Au3UnusedVariableRemoval,
            ),
            '($y = 0 ? 1 / $y : 2)\n'
            'MsgBox(0, 0, $y)\n')

    def test_a_spliced_and_over_a_writable_left_operand_is_bracketed(self):
        """
        The value compares `$y` on the `And`'s left, so an unbracketed splice would re-read as a
        store into `$y` and the call on its right would fall under the short circuit.
        """
        self.assertEqual(
            self._apply(
                '''
                $x = $y = 0 And DllCall("a", "b", "c")
                MsgBox(0, 0, $y)
                ''',
                Au3UnusedVariableRemoval,
            ),
            '($y = 0 and DllCall("a", "b", "c"))\n'
            'MsgBox(0, 0, $y)\n')

    def test_a_pure_array_literal_store_is_dropped(self):
        self.assertEqual(
            self._apply(
                '''
                $x = [1, 2]
                MsgBox(0, 0, 0)
                ''',
                Au3UnusedVariableRemoval,
            ),
            'MsgBox(0, 0, 0)\n')

    def test_the_cascade_removes_a_comparison_chain_in_one_visit(self):
        self.assertEqual(
            self._apply(
                '''
                $b = "y"
                $a = $b = "x"
                MsgBox(0, 0, 0)
                ''',
                Au3UnusedVariableRemoval,
            ),
            'MsgBox(0, 0, 0)\n')

    def test_the_cascade_removes_a_read_chain_in_one_visit(self):
        self.assertEqual(
            self._apply(
                '''
                $a1 = $a2
                $a2 = $a3
                $a3 = 5
                MsgBox(0, 0, 0)
                ''',
                Au3UnusedVariableRemoval,
            ),
            'MsgBox(0, 0, 0)\n')

    def test_a_store_whose_only_read_propagation_replaced_leaves(self):
        self.assertEqual(
            self._apply(
                '''
                Local $x = 5
                $y = $x
                MsgBox(0, 0, $y)
                ''',
                Au3ConstantPropagation,
                Au3UnusedVariableRemoval,
            ),
            'Local $x = 5\n'
            'MsgBox(0, 0, 5)\n')

    def test_a_spliced_store_keeps_its_reads_alive(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    $y = 1
                    $x = MsgBox(0, 0, $y)
                EndFunc

                f()
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Func f()\n'
            '    $y = 1\n'
            '    MsgBox(0, 0, $y)\n'
            'EndFunc\n'
            'f()\n')

    def test_a_function_of_only_removed_stores_stays_empty(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    $x = 1
                EndFunc

                f()
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Func f()\n'
            'EndFunc\n'
            'f()\n')

    def test_a_read_in_the_same_scope_keeps_the_store(self):
        source = '''
            $x = 1
            MsgBox(0, 0, $x)
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_read_in_another_scope_keeps_the_store(self):
        source = '''
            $x = 1

            Func f()
                MsgBox(0, 0, $x)
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_read_of_another_function_local_does_not_keep_a_store(self):
        """
        Each function's `Local $x` is storage of its own, so the read in `g` reaches nothing `f`
        writes.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x
                    $x = 1
                EndFunc

                Func g()
                    Local $x = 2
                    MsgBox(0, 0, $x)
                EndFunc

                f()
                g()
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Func f()\n'
            '    Local $x\n'
            'EndFunc\n'
            'Func g()\n'
            '    Local $x = 2\n'
            '    MsgBox(0, 0, $x)\n'
            'EndFunc\n'
            'f()\n'
            'g()\n')

    def test_a_read_before_the_claim_binds_the_global(self):
        """
        The read stands before the `Local` claim, so it observes the global and keeps nothing of
        the local storage.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    MsgBox(0, 0, $x)
                    Local $x
                    $x = 1
                EndFunc

                f()
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Func f()\n'
            '    MsgBox(0, 0, $x)\n'
            '    Local $x\n'
            'EndFunc\n'
            'f()\n')

    def test_a_read_in_another_scope_does_not_keep_an_implicit_store(self):
        """
        The implicit write creates a local of `f` only, invisible in `g`, where the name is
        missing whether or not the store leaves.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    $v = 1
                EndFunc

                Func g()
                    MsgBox(0, 0, $v)
                EndFunc

                f()
                g()
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Func f()\n'
            'EndFunc\n'
            'Func g()\n'
            '    MsgBox(0, 0, $v)\n'
            'EndFunc\n'
            'f()\n'
            'g()\n')

    def test_a_read_of_another_function_local_does_not_keep_a_script_level_store(self):
        self.assertEqual(
            self._apply(
                '''
                $x = 1

                Func g()
                    Local $x = 2
                    MsgBox(0, 0, $x)
                EndFunc

                g()
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Func g()\n'
            '    Local $x = 2\n'
            '    MsgBox(0, 0, $x)\n'
            'EndFunc\n'
            'g()\n')

    def test_the_cascade_releases_only_the_reads_of_the_store_s_scope(self):
        """
        `$y`'s drop releases the read that kept `f`'s local store of `$x`; the read of `g`'s own
        `$x` counts into no counter of `f`.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x
                    $x = 1
                    $y = $x
                EndFunc

                Func g()
                    Local $x = 2
                    MsgBox(0, 0, $x)
                EndFunc

                f()
                g()
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Func f()\n'
            '    Local $x\n'
            'EndFunc\n'
            'Func g()\n'
            '    Local $x = 2\n'
            '    MsgBox(0, 0, $x)\n'
            'EndFunc\n'
            'f()\n'
            'g()\n')

    def test_a_name_spelled_in_a_string_keeps_the_store(self):
        source = '''
            $x = 1
            MsgBox(0, 0, "x")
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_compound_assignment_reads_its_target(self):
        source = '''
            Func f()
                $x = 1
                $x += 2
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_an_element_store_reads_its_root(self):
        source = '''
            Func f()
                $x = StringSplit("a,b", ",")
                $x[0] = 99
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_member_store_reads_its_root(self):
        source = '''
            Func f()
                $m = ObjCreate("Scripting.Dictionary")
                $m.add = 1
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_byref_parameter_store_is_kept(self):
        source = '''
            Func f(ByRef $p)
                $p = 1
            EndFunc

            f($g)
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_byref_argument_is_a_read_of_its_name(self):
        source = '''
            Func f(ByRef $p)
                $p = 1
            EndFunc

            $y = 2
            f($y)
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_declarator_initializer_is_a_read_of_its_name(self):
        """
        A bare-variable initializer is not the declarator's own variable, so the name it reads
        keeps the store feeding it.
        """
        source = '''
            $x = DllCall("a", "b", "c")
            Global $y = $x
            MsgBox(0, 0, $y)
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_claim_sharing_initializer_read_keeps_the_global_store(self):
        """
        The local does not exist while its own initializer runs, so the initializer read may
        observe the global.
        """
        source = '''
            $x = 5

            Func f()
                Local $x = $x
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_claim_sharing_loop_header_read_keeps_the_global_store(self):
        """
        The loop's own claim does not exist for the reads its header makes, so they may observe
        the global.
        """
        source = '''
            $i = 5

            Func f()
                For $i = $i To 9
                    MsgBox(0, 0, $i)
                Next
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_parameter_default_is_a_read_of_its_name(self):
        """
        A default evaluates in the function when a call leaves its argument out, so the store
        feeding it cannot leave.
        """
        source = '''
            $x = DllCall("a", "b", "c")

            Func f($p = $x)
                MsgBox(0, 0, $p)
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_redim_target_reads_its_name(self):
        source = '''
            Global $a[3]
            $a = 9
            ReDim $a[5]
            MsgBox(0, 0, 0)
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_for_to_loop_variable_store_is_kept(self):
        """
        The loop compares and steps on its variable at every iteration, so the store changes
        the iteration count — an input that never terminates must not gain an end.
        """
        source = '''
            Func f()
                For $i = 1 To 10
                    $i = 5
                Next
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_an_impure_for_to_loop_variable_store_is_kept(self):
        source = '''
            Func f()
                For $i = 1 To 10
                    $i = Random(1, 5)
                Next
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_for_in_loop_variable_store_is_removed(self):
        """
        The loop only assigns its variable, every iteration overwriting a store the body makes.
        """
        self.assertEqual(
            self._apply(
                '''
                Global $arr[3]

                Func f()
                    For $x In $arr
                        $x = 5
                    Next
                EndFunc

                f()
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Global $arr[3]\n'
            'Func f()\n'
            '    For $x In $arr\n'
            '    Next\n'
            'EndFunc\n'
            'f()\n')

    def test_a_computed_execute_in_the_scope_keeps_a_local_store(self):
        source = '''
            Func f()
                Local $x
                $x = 1
                Execute($cmd)
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_computed_execute_in_the_scope_keeps_an_implicit_store(self):
        """
        An implicit write creates a local only when no global of the name may exist, so the
        in-scope gate answers for it the same way it answers for a claimed local.
        """
        source = '''
            Func f()
                $v = DllCall("a", "b", "c")
                Execute($cmd)
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_computed_execute_anywhere_keeps_an_implicit_store_of_a_global_name(self):
        """
        A global of the name may exist, so the store could target it and only the anywhere gate
        answers.
        """
        source = '''
            Global $g

            Func f()
                $g = DllCall("a", "b", "c")
            EndFunc

            Func h()
                Execute($cmd)
            EndFunc

            f()
            h()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_computed_execute_anywhere_keeps_a_script_level_store(self):
        source = '''
            $x = 1

            Func f()
                Execute($cmd)
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_computed_name_in_the_scope_keeps_an_implicit_store(self):
        """
        A computed `Execute` payload also makes the existence census refuse, which keeps every
        store on its own; `Eval` over a computed name is a channel the census tolerates, so the
        in-scope gate alone answers here.
        """
        source = '''
            Func f()
                $v = 1
                Eval($n)
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_computed_name_elsewhere_does_not_keep_an_implicit_store(self):
        """
        The in-scope gate answers per scope: a channel in `h` cannot name a local of `g`.
        """
        self.assertEqual(
            self._apply(
                '''
                Func h()
                    Eval($n)
                EndFunc

                Func g()
                    $x = 1
                EndFunc

                h()
                g()
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Func h()\n'
            '    Eval($n)\n'
            'EndFunc\n'
            'Func g()\n'
            'EndFunc\n'
            'h()\n'
            'g()\n')

    def test_a_computed_name_anywhere_keeps_an_implicit_store_of_a_global_name(self):
        """
        A global of the name may exist, so the store could target it and only the anywhere gate
        answers.
        """
        source = '''
            Global $g

            Func f()
                $g = DllCall("a", "b", "c")
            EndFunc

            Func h()
                Eval($n)
            EndFunc

            f()
            h()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_computed_name_anywhere_keeps_a_script_level_store(self):
        source = '''
            $x = 1

            Func f()
                Eval($n)
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_literal_execute_payload_blocks_nothing(self):
        """
        The payload parses and holds no computed name, so the call reads nothing no census sees —
        the differential that forces a read-side verdict beside the write-side channel one.
        """
        self.assertEqual(
            self._apply(
                '''
                $x = 1

                Func f()
                    Execute("Random(784,1020,1)")
                EndFunc

                f()
                ''',
                Au3UnusedVariableRemoval,
            ),
            'Func f()\n'
            '    Execute("Random(784,1020,1)")\n'
            'EndFunc\n'
            'f()\n')

    def test_a_literal_execute_payload_holding_a_computed_name_keeps_a_local_store(self):
        source = '''
            Func f()
                Local $x
                $x = 1
                Execute("Eval($n)")
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_call_resolved_to_eval_keeps_the_store(self):
        source = '''
            $x = 1
            Call("Eval", $n)
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_forwarding_call_of_call_keeps_the_store(self):
        source = '''
            $x = 1
            Call("Call", "Eval", $n)
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_call_resolved_to_execute_over_a_variable_keeps_the_store(self):
        source = '''
            $x = 1
            Call("Execute", $p)
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_an_include_keeps_script_level_stores(self):
        source = '''
            #include "other.au3"
            $x = 1
            MsgBox(0, 0, 0)
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_fragment_keeps_its_implicit_writes(self):
        source = '''
            Func f()
                $v = 1
                MsgBox(0, 0, 0)
            EndFunc
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_mustdeclarevars_keeps_script_level_implicit_writes(self):
        source = '''
            Opt("MustDeclareVars", 1)
            $x = 1
            MsgBox(0, 0, 0)
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_mustdeclarevars_keeps_function_level_implicit_writes(self):
        source = '''
            Opt("MustDeclareVars", 1)

            Func f()
                $z = 1
                MsgBox(0, 0, 0)
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_command_line_constant_store_is_kept(self):
        source = '''
            $CmdLine = 1
            MsgBox(0, 0, 0)
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_a_store_to_a_name_declared_constant_is_kept(self):
        source = '''
            Const $x = 1
            $x = 2
            MsgBox(0, 0, 0)
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_error_text_spelling_the_name_keeps_the_store(self):
        source = '''
            $x = 1
            MsgBox(0, 0, 0)
            $y = 1, $x = 2
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_error_text_naming_execute_keeps_a_local_store(self):
        source = '''
            Func f()
                Local $x
                $x = 1
                $y = 1, Execute(2)
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))

    def test_an_impure_array_literal_store_is_not_spliced(self):
        source = '''
            Func f()
                $x = [MsgBox(0, 0, 0)]
            EndFunc

            f()
            '''
        self.assertEqual(
            self._apply(source, Au3UnusedVariableRemoval),
            self._laid_out(source))
