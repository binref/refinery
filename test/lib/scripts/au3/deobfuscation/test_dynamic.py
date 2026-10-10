"""
Dynamic-name flattening on its own: the gates the pinned `Call`, `Assign`, and `Eval`
semantics draw around what a string-literal name may flatten into, and the no-effect cases the
interpreter answered with `@error` or `""` for, which a flatten must never make fatal.
"""
from __future__ import annotations

from test.lib.scripts.au3.deobfuscation import TestAu3

from refinery.lib.scripts.au3.deobfuscation.names import Au3DynamicNameFlattening


class TestAu3DynamicNameFlattening(TestAu3):

    def test_a_call_at_exact_arity_flattens(self):
        self.assertEqual(
            self._apply(
                '''
                Func f($a)
                    Return $a
                EndFunc

                $r = Call("f", 1)
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f($a)\n    Return $a\nEndFunc\n$r = f(1)\n')

    def test_a_short_call_over_defaulted_parameters_flattens(self):
        """
        `Call` fills a defaulted parameter the direct call fills too (probe9 A13).
        """
        self.assertEqual(
            self._apply(
                '''
                Func f($a, $b = 2)
                    Return $b
                EndFunc

                Call("f", 1)
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f($a, $b = 2)\n    Return $b\nEndFunc\nf(1)\n')

    def test_a_call_in_statement_position_flattens(self):
        self.assertEqual(
            self._apply(
                '''
                Func f($a = 1)
                    Return $a
                EndFunc

                Call("f")
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f($a = 1)\n    Return $a\nEndFunc\nf()\n')

    def test_more_arguments_than_parameters_are_kept(self):
        """
        `Call` answers one argument too many with `@error` (probe9 A13b) while the direct call
        terminates the script.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f($a)
                    Return $a
                EndFunc

                Call("f", 1, 2)
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f($a)\n    Return $a\nEndFunc\nCall("f", 1, 2)\n')

    def test_an_undeclared_name_is_kept(self):
        """
        An unknown function is a failure `Call` answers with `@error` where the direct call is
        fatal, and no builtin arity is pinned.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f($a)
                    Return $a
                EndFunc

                Call("nosuch", 1)
                Call("msgbox", 0, "t")
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f($a)\n    Return $a\nEndFunc\nCall("nosuch", 1)\nCall("msgbox", 0, "t")\n')

    def test_a_shadowing_call_function_is_kept(self):
        self.assertEqual(
            self._apply(
                '''
                Func call($a)
                    Return 1
                EndFunc

                Func f($a)
                    Return $a
                EndFunc

                Call("f", 1)
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func call($a)\n    Return 1\nEndFunc\nFunc f($a)\n    Return $a\nEndFunc\n'
            'Call("f", 1)\n')

    def test_a_callee_position_call_is_kept(self):
        """
        Flattening the inner call of `Call("f")(1)` would rewrite two calls into one.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f($a)
                    Return $a
                EndFunc

                $r = Call("f")(1)
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f($a)\n    Return $a\nEndFunc\n$r = Call("f")(1)\n')

    def test_a_byref_position_with_a_variable_flattens(self):
        """
        `ByRef` parameters mutate through `Call` exactly as through the direct call (probe9
        A15).
        """
        self.assertEqual(
            self._apply(
                '''
                Func h($a, ByRef $r)
                    $r = $a
                EndFunc

                Func f()
                    Local $x
                    Call("h", 1, $x)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func h($a, ByRef $r)\n    $r = $a\nEndFunc\nFunc f()\n    Local $x\n'
            '    h(1, $x)\nEndFunc\n')

    def test_a_byref_position_with_a_literal_flattens(self):
        """
        A literal into a `ByRef` parameter succeeds identically through `Call` and directly, the
        mutation discarded in both (probe9h A30).
        """
        self.assertEqual(
            self._apply(
                '''
                Func h($a, ByRef $r)
                    $r = $a
                EndFunc

                Func f()
                    Call("h", 1, "lit")
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func h($a, ByRef $r)\n    $r = $a\nEndFunc\nFunc f()\n    h(1, "lit")\nEndFunc\n')

    def test_a_byref_position_with_an_expression_is_kept(self):
        """
        No probe pins what a computed expression into a `ByRef` parameter does in either form.
        """
        self.assertEqual(
            self._apply(
                '''
                Func h($a, ByRef $r)
                    $r = $a
                EndFunc

                Func f()
                    Local $x
                    Call("h", 1, $x + 1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func h($a, ByRef $r)\n    $r = $a\nEndFunc\nFunc f()\n    Local $x\n'
            '    Call("h", 1, $x + 1)\nEndFunc\n')

    def test_a_sole_string_literal_argument_flattens(self):
        """
        A sole string literal never expands, the spelling `CallArgArray` included (probe9 A14c).
        """
        self.assertEqual(
            self._apply(
                '''
                Func f($a)
                    Return $a
                EndFunc

                Call("f", "x")
                Call("f", "CallArgArray")
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f($a)\n    Return $a\nEndFunc\nf("x")\nf("CallArgArray")\n')

    def test_a_sole_non_literal_argument_is_kept(self):
        """
        A sole variable may hold the array a `CallArgArray` expansion reads (probe9 A14a), so the
        call stands.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f($a)
                    Return $a
                EndFunc

                Func g()
                    Local $arr
                    Call("f", $arr)
                    Call("f", f(1))
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f($a)\n    Return $a\nEndFunc\nFunc g()\n    Local $arr\n'
            '    Call("f", $arr)\n    Call("f", f(1))\nEndFunc\n')

    def test_an_array_literal_argument_is_kept(self):
        """
        An array literal is legal AutoIt only where a declaration initializes, and the
        `CallArgArray` array is the expansion's own shape (probe9 A14a/A14b).
        """
        self.assertEqual(
            self._apply(
                '''
                Func f($a)
                    Return $a
                EndFunc

                Call("f", [1, 2])
                Call("f", ["CallArgArray", 1])
                Call("f", ["callargarray", 1])
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f($a)\n    Return $a\nEndFunc\nCall("f", [1, 2])\n'
            'Call("f", ["CallArgArray", 1])\nCall("f", ["callargarray", 1])\n')

    def test_a_name_of_unspellable_shape_is_kept(self):
        self.assertEqual(
            self._apply(
                '''
                Func f($a)
                    Return $a
                EndFunc

                Call("f()")
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f($a)\n    Return $a\nEndFunc\nCall("f()")\n')

    def test_a_dollar_prefixed_name_is_kept_in_every_rule(self):
        """
        Whether the three builtins accept a `$`-prefixed name is unpinned — `Assign` restricts
        the name to letters, digits, and underscore.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f($a)
                    Return $a
                EndFunc

                Call("$f", 1)
                Assign("$x", 1)
                $r = Eval("$x")
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f($a)\n    Return $a\nEndFunc\nCall("$f", 1)\nAssign("$x", 1)\n'
            '$r = Eval("$x")\n')

    def test_an_include_directive_keeps_every_rule(self):
        """
        An unseen include may declare storage and constants no tree declaration covers.
        """
        self.assertEqual(
            self._apply(
                '''
                #include <Array.au3>

                Func f()
                    Local $x
                    Assign("x", 1)
                    $r = Eval("x")
                    Call("f")
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            '#include <Array.au3>\nFunc f()\n    Local $x\n    Assign("x", 1)\n'
            '    $r = Eval("x")\n    Call("f")\nEndFunc\n')

    def test_an_assign_behind_a_preceding_local_flattens(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x
                    Assign("x", 1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Local $x\n    $x = 1\nEndFunc\n')

    def test_an_assign_at_script_level_flattens(self):
        """
        Flag 0 creates the global the plain write creates (probe9 A23), over an existing global
        included (probe9 A3).
        """
        self.assertEqual(
            self._apply(
                '''
                Global $g

                Assign("g", 1)
                Assign("h", 1)
                ''',
                Au3DynamicNameFlattening,
            ),
            'Global $g\n$g = 1\n$h = 1\n')

    def test_a_bare_in_function_assign_flattens(self):
        """
        A name undeclared anywhere makes flag 0 and the plain write both create the
        function-local (probe9 A1/A2).
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Assign("q", 1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    $q = 1\nEndFunc\n')

    def test_an_assign_behind_a_parameter_flattens(self):
        self.assertEqual(
            self._apply(
                '''
                Func f($p)
                    Assign("p", 1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f($p)\n    $p = 1\nEndFunc\n')

    def test_an_assign_behind_an_in_function_global_flattens(self):
        """
        An in-function `Global` declaration behaves identically for both forms (probe9 A18/A19).
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Global $g
                    Assign("g", 1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Global $g\n    $g = 1\nEndFunc\n')

    def test_an_assign_behind_a_static_claim_flattens(self):
        """
        A `Static` claim makes flag 0 write the static local, as the plain write does (probe9
        A20).
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Static $s
                    Assign("s", 1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Static $s\n    $s = 1\nEndFunc\n')

    def test_an_assign_behind_a_dim_claim_flattens(self):
        """
        Behind an in-function `Dim` claim both forms write the local (probe9 A24).
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Dim $d
                    Assign("d", 1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Dim $d\n    $d = 1\nEndFunc\n')

    def test_a_three_argument_assign_with_flag_zero_flattens(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x
                    Assign("x", 1, 0)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Local $x\n    $x = 1\nEndFunc\n')

    def test_forced_scope_flags_are_kept(self):
        """
        Flags 1 and 2 create storages the plain write does not (probe9 A6/A7), and flag 4
        answers 0 on an undeclared name (probe9 A8).
        """
        self.assertEqual(
            self._apply(
                '''
                Global $x

                Func f()
                    Assign("x", 1, 1)
                    Assign("x", 1, 2)
                    Assign("x", 1, 4)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Global $x\nFunc f()\n    Assign("x", 1, 1)\n    Assign("x", 1, 2)\n'
            '    Assign("x", 1, 4)\nEndFunc\n')

    def test_a_variable_flag_is_kept(self):
        """
        A flag spelled by a variable may name a forced scope an unseen include defines.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x
                    Assign("x", 1, $flag)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Local $x\n    Assign("x", 1, $flag)\nEndFunc\n')

    def test_a_non_literal_name_is_kept(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Assign($n, 1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Assign($n, 1)\nEndFunc\n')

    def test_a_consumed_return_value_is_kept(self):
        """
        The flattened write drops the 1 a statement-position `Assign` returns; a call whose
        value is read has no plain form.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x
                    $r = Assign("x", 1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Local $x\n    $r = Assign("x", 1)\nEndFunc\n')

    def test_a_constant_name_is_kept(self):
        """
        `Assign` over a constant answers 0 and continues (probe9 A9) while the plain write is
        the fatal refusal (probe9d A10).
        """
        self.assertEqual(
            self._apply(
                '''
                Const $c = 1

                Enum $e1 = 1, $e2 = 2

                Assign("c", 2)
                Assign("e2", 3)
                ''',
                Au3DynamicNameFlattening,
            ),
            'Const $c = 1\nEnum $e1 = 1, $e2 = 2\nAssign("c", 2)\nAssign("e2", 3)\n')

    def test_a_const_parameter_name_is_kept(self):
        """
        `Func f(Const $p)` makes `Assign("p", 1)` the constant refusal the plain write answers
        fatally.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f(Const $p)
                    Assign("p", 1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f(Const $p)\n    Assign("p", 1)\nEndFunc\n')

    def test_an_array_literal_value_is_kept(self):
        """
        An array literal is legal AutoIt only where a declaration initializes.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Assign("x", [1, 2])
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Assign("x", [1, 2])\nEndFunc\n')

    def test_an_autoitsetoption_call_keeps_an_unbacked_write(self):
        """
        Under `MustDeclareVars` the plain write to an undeclared name is a documented refusal
        while `Assign`'s behavior under the option is unpinned, so the write stands — at script
        level and bare inside a function, the two shapes no declaration of the scope backs.
        """
        self.assertEqual(
            self._apply(
                '''
                AutoItSetOption("MustDeclareVars", 1)

                Func f()
                    Assign("q", 1)
                EndFunc

                Assign("g", 1)
                ''',
                Au3DynamicNameFlattening,
            ),
            'AutoItSetOption("MustDeclareVars", 1)\nFunc f()\n    Assign("q", 1)\nEndFunc\n'
            'Assign("g", 1)\n')

    def test_an_autoitsetoption_call_keeps_a_declared_backed_write_flattened(self):
        """
        A parameter is declared by the function itself, so the plain write is legal under
        `MustDeclareVars` whatever the option does to `Assign`.
        """
        self.assertEqual(
            self._apply(
                '''
                AutoItSetOption("MustDeclareVars", 1)

                Func f($p)
                    Assign("p", 1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'AutoItSetOption("MustDeclareVars", 1)\nFunc f($p)\n    $p = 1\nEndFunc\n')

    def test_an_error_macro_read_keeps_the_assign_flatten(self):
        """
        A successful `Assign` clears a previous `@error`/`@extended` while the plain write
        leaves both (probe9f A21), so a read anywhere in the tree could observe a stale value the
        original never shows.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x
                    $e = @error
                    Assign("x", 1)
                EndFunc

                Func g()
                    Local $y
                    $e = @extended
                    Assign("y", 1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Local $x\n    $e = @error\n    Assign("x", 1)\nEndFunc\n'
            'Func g()\n    Local $y\n    $e = @extended\n    Assign("y", 1)\nEndFunc\n')

    def test_an_execute_call_keeps_the_assign_flatten(self):
        """
        An unflattened `Execute` payload could read `@error` invisibly.
        """
        self.assertEqual(
            self._apply(
                '''
                Execute($s)

                Func f()
                    Local $x
                    Assign("x", 1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Execute($s)\nFunc f()\n    Local $x\n    Assign("x", 1)\nEndFunc\n')

    def test_an_eval_behind_a_preceding_local_flattens(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x = 1
                    $r = Eval("x")
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Local $x = 1\n    $r = $x\nEndFunc\n')

    def test_an_eval_behind_a_parameter_flattens(self):
        self.assertEqual(
            self._apply(
                '''
                Func f($p)
                    $r = Eval("p")
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f($p)\n    $r = $p\nEndFunc\n')

    def test_an_eval_in_statement_position_flattens(self):
        """
        A statement-position bare variable line runs (probe9b A16).
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x = 1
                    Eval("x")
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Local $x = 1\n    $x\nEndFunc\n')

    def test_an_eval_inside_the_claiming_statement_is_kept(self):
        """
        The flattened `Local $x = $x` is an interpreter refusal (probe9g A29) where the dynamic
        read answered `""`; a `For` header claiming its own variable is the same boundary.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x = Eval("x")
                    For $i = Eval("i") To 1
                        $y = $i
                    Next
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Local $x = Eval("x")\n    For $i = Eval("i") To 1\n'
            '        $y = $i\n    Next\nEndFunc\n')

    def test_an_eval_without_a_local_claim_is_kept(self):
        """
        The plain read of a name no local claims is fatal when the global is missing (probe9c
        A11) where `Eval` answered `""`, so the global case refuses permanently.
        """
        self.assertEqual(
            self._apply(
                '''
                Global $g

                Func f()
                    $r = Eval("g")
                    $r = Eval("q")
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Global $g\nFunc f()\n    $r = Eval("g")\n    $r = Eval("q")\nEndFunc\n')

    def test_a_non_literal_eval_name_is_kept(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x
                    $r = Eval($n)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Local $x\n    $r = Eval($n)\nEndFunc\n')

    def test_a_shadowing_eval_function_is_kept(self):
        self.assertEqual(
            self._apply(
                '''
                Func eval($a)
                    Return 1
                EndFunc

                Func f()
                    Local $x
                    $r = Eval("x")
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func eval($a)\n    Return 1\nEndFunc\nFunc f()\n    Local $x\n'
            '    $r = Eval("x")\nEndFunc\n')

    def test_a_callee_position_eval_is_kept(self):
        """
        Replacing a callee with a variable read would turn a name-computed call into a variable
        callee — a different dynamic shape.
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x = 1
                    $r = Eval("x")(1)
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Local $x = 1\n    $r = Eval("x")(1)\nEndFunc\n')

    def test_an_error_macro_read_keeps_the_eval_flatten(self):
        """
        A successful `Eval` clears a previous `@error`/`@extended` while the plain read leaves
        both (probe9f A22).
        """
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Local $x
                    $e = @error
                    $r = Eval("x")
                EndFunc

                Func g()
                    Local $y
                    $e = @extended
                    $r = Eval("y")
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Func f()\n    Local $x\n    $e = @error\n    $r = Eval("x")\nEndFunc\n'
            'Func g()\n    Local $y\n    $e = @extended\n    $r = Eval("y")\nEndFunc\n')

    def test_an_execute_call_keeps_the_eval_flatten(self):
        self.assertEqual(
            self._apply(
                '''
                Execute($s)

                Func f()
                    Local $x
                    $r = Eval("x")
                EndFunc
                ''',
                Au3DynamicNameFlattening,
            ),
            'Execute($s)\nFunc f()\n    Local $x\n    $r = Eval("x")\nEndFunc\n')

    def test_a_function_called_only_through_call_leaves(self):
        self._assertDeobfuscatesTo(
            '''
            Func dead()
                Return 1
            EndFunc

            Call("dead")

            MsgBox(0, 0, 0)
            ''',
            'MsgBox(0, 0, 0)')

    def test_a_global_written_through_assign_survives(self):
        self._assertDeobfuscatesTo(
            '''
            Global $g

            Func w()
                Assign("g", 1)
            EndFunc

            w()

            Eval("g")
            ''',
            '''
            Global $g

            Func w()
                $g = 1
            EndFunc

            w()

            Eval("g")
            ''')
