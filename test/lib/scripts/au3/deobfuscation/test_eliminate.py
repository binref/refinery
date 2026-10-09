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
        self._assertKept(
            '''
            Func checkip()
            EndFunc

            Call("checkip")
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

    def test_a_live_channel_blocks_function_and_global_removal(self):
        """
        The `Execute` over a non-literal may compute any name, so no function and no global leaves
        while it stands — while the effect-free `gone()` statement still goes, the statement rule
        being ungated.
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

    def test_a_mutually_recursive_pure_cluster_keeps_its_statement_removed_only(self):
        """
        The purity fixpoint qualifies both functions, so the call statement is effect-free and
        goes — and the cluster keeps its call sites among itself, so the functions stay behind,
        sound and the measured corpus outcome.
        """
        self.assertEqual(
            self._apply(
                '''
                Func a($n)
                    Return b($n)
                EndFunc

                Func b($n)
                    Return a($n)
                EndFunc

                a(3)
                ''',
                Au3DeadCodeElimination,
            ),
            'Func a($n)\n'
            '    Return b($n)\n'
            'EndFunc\n'
            'Func b($n)\n'
            '    Return a($n)\n'
            'EndFunc\n')

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
        self._assertKept(
            '''
            Func imp()
                $g = 1
            EndFunc

            Func f($p)
            EndFunc

            f(imp())
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
