"""
The Phase 4 transform on its own: which functions, declarations and statements a single sweep
removes, and which gate — entry, channel, or parse error — keeps what would otherwise go. The
fixpoint cases run through the whole pipeline, because the group's run loop is what sweeps again.
"""
from __future__ import annotations

from test.lib.scripts.au3.deobfuscation import TestAu3

from refinery.lib.scripts.au3.deobfuscation.eliminate import Au3DeadCodeElimination


class TestAu3DeadCodeElimination(TestAu3):

    def test_an_uncalled_function_is_removed(self):
        self.assertEqual(
            self._apply(
                '''
                Func dead()
                EndFunc

                Func live()
                    $g = 1
                EndFunc

                live()
                ''',
                Au3DeadCodeElimination,
            ),
            'Func live()\n'
            '    $g = 1\n'
            'EndFunc\n'
            'live()\n')

    def test_a_function_called_only_from_removed_code_goes_in_a_later_sweep(self):
        self._assertDeobfuscatesTo(
            '''
            Func outer()
                inner()
            EndFunc

            Func inner()
            EndFunc

            MsgBox(0, 0, 0)
            ''',
            '''
            MsgBox(0, 0, 0)
            ''')

    def test_a_function_holding_a_surviving_nested_function_is_kept(self):
        self._assertKept(
            '''
            Func outer()
                Func inner()
                    $g = 1
                EndFunc
            EndFunc

            inner()

            MsgBox(0, 0, 0)
            ''')

    def test_a_function_holding_only_a_dead_nested_function_is_removed(self):
        self.assertEqual(
            self._apply(
                '''
                Func outer()
                    Func inner()
                    EndFunc
                EndFunc

                MsgBox(0, 0, 0)
                ''',
                Au3DeadCodeElimination,
            ),
            'MsgBox(0, 0, 0)\n')

    def test_a_function_spelled_in_a_call_string_is_kept(self):
        """
        The extra argument is one `Call` answers with `@error` and a direct call does not, so the
        flattening of dynamic names refuses — and the string keeps protecting the function.
        """
        self._assertKept(
            '''
            Func checkip()
            EndFunc

            Call("checkip", 1)
            ''')

    def test_a_function_spelled_in_a_hotkeyset_string_is_kept(self):
        self._assertKept(
            '''
            Func p()
            EndFunc

            HotKeySet("^a", "p")
            ''')

    def test_a_function_a_directive_names_is_kept(self):
        self.assertEqual(
            self._apply(
                '''
                #OnAutoItStartRegister "startup"

                Func startup()
                EndFunc

                Func dead()
                EndFunc

                MsgBox(0, 0, 0)
                ''',
                Au3DeadCodeElimination,
            ),
            '#OnAutoItStartRegister "startup"\n'
            'Func startup()\n'
            'EndFunc\n'
            'MsgBox(0, 0, 0)\n')

    def test_a_function_only_fragment_is_unchanged(self):
        self._assertKept(
            '''
            Func dead()
            EndFunc
            ''')

    def test_a_script_holding_an_include_is_unchanged(self):
        self._assertKept(
            '''
            #include <String.au3>

            Func dead()
            EndFunc
            ''')

    def test_a_script_holding_an_include_line_with_trailing_text_is_unchanged(self):
        """
        The parser reads an include line with trailing text as a plain directive, but the included
        file is spliced in all the same, so its calls reach the tree's functions — where the
        executable statement below would leave the entry open without the include.
        """
        self._assertKept(
            '''
            #include <String.au3> ; Required for the constants.

            Func dead()
            EndFunc

            MsgBox(0, 0, 0)
            ''')

    def test_a_live_channel_blocks_function_and_global_removal(self):
        """
        The `Execute` over a non-literal may compute any name, so no function and no global
        leaves while it stands — and its payload could read `@error`, so the pure call that
        would have cleared the error state stays as well.
        """
        self.assertEqual(
            self._apply(
                '''
                Global $dead = 1

                Func gone()
                EndFunc

                Func live()
                    $g = 1
                EndFunc

                live()
                gone()
                Execute($x)
                ''',
                Au3DeadCodeElimination,
            ),
            'Global $dead = 1\n'
            'Func gone()\n'
            'EndFunc\n'
            'Func live()\n'
            '    $g = 1\n'
            'EndFunc\n'
            'live()\n'
            'gone()\n'
            'Execute($x)\n')

    def test_a_computed_name_inside_an_execute_payload_is_kept(self):
        self._assertKept(
            '''
            Func checkip()
            EndFunc

            Execute("Call(""che"" & ""ckip"")")
            ''')

    def test_a_nonliteral_hotkeyset_name_is_kept(self):
        self.assertEqual(
            self._apply(
                '''
                Func p()
                EndFunc

                Global $n = "q"

                HotKeySet("^a", $n)
                ''',
                Au3DeadCodeElimination,
            ),
            'Func p()\n'
            'EndFunc\n'
            'Global $n = "q"\n'
            'HotKeySet("^a", $n)\n')

    def test_an_unparseable_line_leaves_the_whole_tree_unchanged(self):
        self._assertKept(
            '''
            Func dead()
            EndFunc

            $x = = 1
            ''')

    def test_an_unbound_global_is_removed(self):
        self.assertEqual(
            self._apply(
                '''
                Global $dead = 1

                MsgBox(0, 0, 0)
                ''',
                Au3DeadCodeElimination,
            ),
            'MsgBox(0, 0, 0)\n')

    def test_a_global_read_at_script_level_is_kept(self):
        self.assertEqual(
            self._apply(
                '''
                Global $g = 1

                MsgBox(0, 0, $g)
                ''',
                Au3DeadCodeElimination,
            ),
            'Global $g = 1\n'
            'MsgBox(0, 0, $g)\n')

    def test_a_global_read_from_a_function_is_kept(self):
        self._assertKept(
            '''
            Global $g = 1

            Func f()
                $x = $g
            EndFunc

            f()
            ''')

    def test_a_global_a_reader_shadows_with_a_local_is_removed(self):
        self.assertEqual(
            self._apply(
                '''
                Global $g = 1

                Func f()
                    Local $g
                    $x = $g
                EndFunc

                $x = f()
                ''',
                Au3DeadCodeElimination,
            ),
            'Func f()\n'
            '    Local $g\n'
            '    $x = $g\n'
            'EndFunc\n'
            '$x = f()\n')

    def test_a_global_declared_inside_a_function_is_kept(self):
        self._assertKept(
            '''
            Func a()
                Global $v = 1
            EndFunc

            Func c()
                $y = $v
            EndFunc

            a()
            $y = c()
            ''')

    def test_a_global_initialized_through_a_builtin_is_kept(self):
        self._assertKept(
            '''
            Global $p = ptr()

            MsgBox(0, 0, 0)
            ''')

    def test_a_global_initialized_with_a_division_is_kept(self):
        self._assertKept(
            '''
            Global $d = 1 / 0

            MsgBox(0, 0, 0)
            ''')

    def test_a_global_initialized_with_an_array_access_is_kept(self):
        self._assertKept(
            '''
            Global $i = $arr[1]

            MsgBox(0, 0, 0)
            ''')

    def test_a_nonliteral_eval_argument_blocks_global_removal(self):
        self._assertKept(
            '''
            Func p()
            EndFunc

            Global $dead = 1
            Global $n = $x & "q"

            Eval($n)
            ''')

    def test_a_dead_local_in_a_live_function_is_removed(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $dead = 7
                    $x = 1
                EndFunc

                f()
                ''',
                Au3DeadCodeElimination,
            ),
            'Func f()\n'
            '    $x = 1\n'
            'EndFunc\n'
            'f()\n')

    def test_a_declaration_is_pruned_per_declarator(self):
        self.assertEqual(
            self._apply(
                '''
                Global $dead = 1, $live = 2

                MsgBox(0, 0, $live)
                ''',
                Au3DeadCodeElimination,
            ),
            'Global $live = 2\n'
            'MsgBox(0, 0, $live)\n')

    def test_a_dead_local_inside_control_flow_is_removed(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    If True Then
                        Local $dead = 7
                    EndIf
                    $x = 1
                EndFunc

                f()
                ''',
                Au3DeadCodeElimination,
            ),
            'Func f()\n'
            '    If True Then\n'
            '    EndIf\n'
            '    $x = 1\n'
            'EndFunc\n'
            'f()\n')

    def test_a_local_read_in_the_branch_that_declares_it_is_kept(self):
        self._assertKept(
            '''
            Global $y

            Func f($c, $z)
                If $c Then
                    Local $x = $z
                    $y = $x
                EndIf
                Return $y
            EndFunc

            MsgBox(0, 0, f(1, 5))
            ''')

    def test_a_local_read_after_the_branch_that_declares_it_is_kept(self):
        self._assertKept(
            '''
            Global $y

            Func f($c, $z)
                If $c Then
                    Local $x = $z
                EndIf
                $y = $x
                Return $y
            EndFunc

            MsgBox(0, 0, f(1, 5))
            ''')

    def test_a_local_read_before_the_branch_that_declares_it_is_removed(self):
        self.assertEqual(
            self._deobfuscate(
                '''
                Func f($c, $z)
                    $y = $x
                    If $c Then
                        Local $x = $z
                    EndIf
                    Return $y
                EndFunc

                MsgBox(0, 0, f(1, 5))
                '''),
            'Func f($c, $z)\n'
            '    $y = $x\n'
            '    If $c Then\n'
            '    EndIf\n'
            '    Return $y\n'
            'EndFunc\n'
            'MsgBox(0, 0, f(1, 5))\n')

    def test_a_local_read_earlier_in_the_loop_that_declares_it_is_kept(self):
        self._assertKept(
            '''
            Func f($n)
                Local $y = 0
                While $n > 0
                    $y = $x
                    Local $x = 7
                    $n -= 1
                Wend
                Return $y
            EndFunc

            MsgBox(0, 0, f(2))
            ''')

    def test_a_global_read_only_in_a_parameter_default_is_kept(self):
        self._assertKept(
            '''
            Global $g = 5

            Func f($p = $g)
                Return $p
            EndFunc

            MsgBox(0, 0, f())
            ''')

    def test_a_global_read_in_a_default_of_its_own_parameter_name_is_kept(self):
        """
        A parameter default runs before any parameter is bound, so a read of a parameter name
        there targets the global — the reader that keeps the global alive — and not the local
        the bound parameter would be.
        """
        self._assertKept(
            '''
            Global $p = 5

            Func g($p = $p)
                Return $p
            EndFunc

            MsgBox(0, 0, g())
            ''')

    def test_a_local_named_by_a_dynamic_execute_payload_in_its_scope_is_kept(self):
        """
        A dynamic payload runs in the scope it stands in, so the name it computes can be a local
        of the same function: the local and the channel stay together.
        """
        self._assertKept(
            '''
            Func f($prefix)
                Local $data = 7
                Execute($prefix & "ta")
                Return 1
            EndFunc

            $x = f("$da")
            ''')

    def test_a_dim_inside_a_function_is_untouched(self):
        self._assertKept(
            '''
            Func f()
                Dim $x
                $x = 5
            EndFunc

            f()
            ''')

    def test_an_initializer_of_any_effect_free_shape_leaves(self):
        self.assertEqual(
            self._apply(
                '''
                Global $n = Not 1
                Global $t = $x > 1 ? 2 : 3
                Global $a[2] = [1, 2]

                MsgBox(0, 0, 0)
                ''',
                Au3DeadCodeElimination,
            ),
            'MsgBox(0, 0, 0)\n')

    def test_a_statement_through_a_variable_callee_is_kept(self):
        self._assertKept(
            '''
            Global $f = 1

            $f()
            ''')

    def test_an_execute_over_an_inert_literal_is_removed(self):
        self.assertEqual(
            self._apply(
                '''
                Execute("1 + 1")

                MsgBox(0, 0, 0)
                ''',
                Au3DeadCodeElimination,
            ),
            'MsgBox(0, 0, 0)\n')

    def test_a_member_callee_is_no_channel(self):
        self.assertEqual(
            self._apply(
                '''
                Func gone()
                EndFunc

                $o.f(1)
                ''',
                Au3DeadCodeElimination,
            ),
            '$o.f(1)\n')

    def test_an_enum_is_removed_only_as_a_whole_statement(self):
        self.assertEqual(
            self._apply(
                '''
                Enum $a = 1, $b = 2

                $x = 1
                ''',
                Au3DeadCodeElimination,
            ),
            '$x = 1\n')

    def test_an_enum_with_one_live_entry_stays_whole(self):
        self.assertEqual(
            self._apply(
                '''
                Enum $a = 1, $b = 2

                $x = $b
                ''',
                Au3DeadCodeElimination,
            ),
            'Enum $a = 1, $b = 2\n'
            '$x = $b\n')

    def test_a_declaration_whose_name_a_string_spells_is_kept(self):
        self._assertKept(
            '''
            Global $dead = 1

            MsgBox(0, 0, "dead")
            ''')

    def test_a_call_to_a_pure_script_function_is_removed(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                EndFunc

                f()
                ''',
                Au3DeadCodeElimination,
            ),
            'Func f()\n'
            'EndFunc\n')

    def test_a_pure_call_is_kept_where_the_tree_reads_the_error_state(self):
        """
        Entering a user function clears `@error` and `@extended` (probe9 A17/A17b), so a tree
        that may read the error state holds no pure function: the removed call is the one that
        would have cleared what the read observes.
        """
        self._assertKept(
            '''
            Func f()
                Return 1
            EndFunc

            f()
            $e = @error
            ''')

    def test_a_pure_call_is_kept_where_the_tree_calls_execute(self):
        """
        An unflattened `Execute` payload could read `@error` invisibly, so the clear every call
        into a user function performs is observable and the call stays.
        """
        self._assertKept(
            '''
            Func f()
                Return 1
            EndFunc

            f()
            Execute($s)
            ''')

    def test_a_call_of_a_function_holding_a_static_is_kept(self):
        """
        A static's value survives the call that first initializes it, so which call runs first —
        and what the global held when it did — is observable: the removed call is the one that
        would have initialized the static from the global's earlier value.
        """
        self._assertKept(
            '''
            Global $g = 1

            Func f()
                Static $s = $g
                Return $s
            EndFunc

            f()
            $g = 2
            MsgBox(0, 0, f())
            ''')

    def test_a_call_into_a_self_recursive_pure_function_is_kept(self):
        """
        The recursion never returns — AutoIt ends the script at its recursion limit — so
        evaluating the call would terminate the script and the statement stays.
        """
        self._assertKept(
            '''
            Func f()
                Return f()
            EndFunc

            f()

            MsgBox(0, 0, 0)
            ''')

    def test_a_call_into_a_mutually_recursive_pure_cluster_is_kept(self):
        """
        No call into the cluster returns — AutoIt ends the script at its recursion limit before
        one would — so the statement that starts the recursion stays, and the cluster keeps its
        call sites among itself besides.
        """
        self._assertKept(
            '''
            Func a($n)
                Return b($n)
            EndFunc

            Func b($n)
                Return a($n)
            EndFunc

            a(3)
            ''')

    def test_a_call_of_a_function_calling_a_recursive_cluster_is_kept(self):
        """
        Impurity travels up the call chain: a caller of a cycle member is a call that may never
        return as well.
        """
        self._assertKept(
            '''
            Func a($n)
                Return a($n)
            EndFunc

            Func g()
                Return a(1)
            EndFunc

            g()

            MsgBox(0, 0, 0)
            ''')

    def test_a_call_into_a_dividing_body_is_kept(self):
        self._assertKept(
            '''
            Func f()
                Return 1 / 0
            EndFunc

            f()
            ''')

    def test_a_call_into_an_array_accessing_body_is_kept(self):
        self._assertKept(
            '''
            Func f()
                Return $arr[1]
            EndFunc

            f()
            ''')

    def test_a_call_into_a_body_holding_exit_is_kept(self):
        self._assertKept(
            '''
            Func f()
                Exit
            EndFunc

            f()
            ''')

    def test_a_call_of_the_wrong_arity_is_kept(self):
        self._assertKept(
            '''
            Func f($p)
            EndFunc

            f(1, 2)
            ''')

    def test_a_call_whose_argument_is_impure_is_kept(self):
        """
        The global the argument writes is read after the call, so no earlier removal of its
        declaration can empty the write summary the call's survival rests on.
        """
        self._assertKept(
            '''
            Global $g

            Func imp()
                $g = 1
            EndFunc

            Func f($p)
            EndFunc

            f(imp())
            MsgBox(0, 0, $g)
            ''')

    def test_a_call_whose_function_redims_an_undeclared_array_is_kept(self):
        """
        A `ReDim` resizes an array that exists and creates none, so over a name no local and no
        global holds it ends the script, and the call that reaches it is not effect-free.
        """
        self._assertKept(
            '''
            Func f()
                ReDim $q[2]
            EndFunc

            f()
            MsgBox(0, "", "after")
            ''')

    def test_a_builtin_call_statement_is_kept(self):
        self._assertKept(
            '''
            MsgBox(0, 0, 0)
            DllCall("a.dll", "int", "f")
            Call("nope")
            ''')

    def test_a_byref_call_is_kept(self):
        self._assertKept(
            '''
            Func f(ByRef $x)
                Return 1
            EndFunc

            f($g)
            ''')

    def test_a_division_and_an_array_access_as_a_statement_are_kept(self):
        self._assertKept(
            '''
            1 / 0
            $arr[1]
            ''')
