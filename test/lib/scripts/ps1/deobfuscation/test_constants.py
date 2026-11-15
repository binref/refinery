from __future__ import annotations

from inspect import cleandoc

from test import backlog, opportunity, todo
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.analysis.values import render
from refinery.lib.scripts.ps1.data import VARIABLE_TYPES, enum_ordinal, is_enum
from refinery.lib.scripts.ps1.deobfuscation import Ps1ConstantInlining
from refinery.lib.scripts.ps1.deobfuscation.constants import (
    _PS1_DEFAULT_FACTS,
    _PS1_DEFAULT_VARIABLES,
)
from refinery.lib.scripts.ps1.options import Ps1DeobfuscationOptions
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


class TestPs1ConstantInlining(TestPs1):

    def test_scalar_string_inlining(self):
        result = self._deobfuscate("$x = 'hello'; Write-Output $x")
        self.assertIn("'hello'", result)
        self.assertNotIn('$x', result)

    def test_scalar_integer_inlining(self):
        result = self._deobfuscate('$x = 42; Write-Output $x')
        self.assertIn('42', result)
        self.assertNotIn('$x', result)

    def test_array_index_inlining(self):
        result = self._deobfuscate("$a = @('foo','bar','baz'); Write-Output $a[1]")
        self.assertIn("'bar'", result)
        self.assertNotIn('$a', result)

    def test_array_multiple_indices(self):
        result = self._deobfuscate(
            "$a = @('X','Y','Z'); $r = $a[0] + $a[2]")
        self.assertIn('XZ', result)
        self.assertNotIn('$a', result)

    def test_same_value_multiple_assignments_inlined(self):
        result = self._deobfuscate(
            "$x = 'hello'; Write-Host $x; $x = 'hello'; Write-Host $x")
        self.assertNotIn('$x', result)
        self.assertEqual(result.count("'hello'"), 2)

    def test_same_value_integer_multiple_assignments_folded(self):
        result = self._deobfuscate_iterative(
            '$x = 150; $y = ($x + 1); $x = 150; $z = ($x + 2)')
        self.assertNotIn('$x', result)
        self.assertIn('151', result)
        self.assertIn('152', result)

    def test_variable_index_skipped(self):
        result = self._deobfuscate("$a = @('x','y'); Write-Output $a[$i]")
        self.assertIn('$a', result)
        self.assertIn('$i', result)

    def test_try_body_inlined(self):
        result = self._deobfuscate(
            "$x = 'val'; try { Write-Output $x } catch { }")
        self.assertIn("'val'", result)
        self.assertNotIn('$x', result)

    def test_try_body_array_inlined(self):
        result = self._deobfuscate(
            "$a = @('x','y','z'); try { Write-Output $a[1] } catch { }")
        self.assertIn("'y'", result)
        self.assertNotIn('$a', result)

    def test_catch_body_inlined(self):
        result = self._deobfuscate(
            "$x = 'val'; try { foo } catch { Write-Output $x }")
        self.assertIn("Write-Output 'val'", result)
        self.assertNotIn('$x', result)

    def test_foreach_variable_not_candidate(self):
        self._assertDeobfuscatesToOneOf(
            "foreach ($item in @('a','b')) { Write-Output $item }",
            cleandoc("""
                foreach ($item in @('a', 'b')) {
                  Write-Output $item
                }
            """),
            cleandoc("""
                Write-Output 'a'
                Write-Output 'b'
            """),
        )

    def test_param_variable_not_candidate(self):
        result = self._deobfuscate(
            "param($x); Write-Output $x")
        self.assertIn('Write-Output $x', result)

    def test_assignment_kept_when_some_refs_remain(self):
        self._assertDeobfuscatesToOneOf(
            "$a = @('x','y'); Write-Output $a[0]; Write-Output $a[$i]",
            cleandoc("""
                $a = @('x', 'y')
                Write-Output 'x'
                Write-Output $a[$i]
            """),
            "Write-Output 'x'",
        )

    def test_case_insensitive_matching(self):
        result = self._deobfuscate("$Foo = 'bar'; Write-Output $foo")
        self.assertIn("'bar'", result)
        self.assertNotIn('$foo', result)
        self.assertNotIn('$Foo', result)

    def test_scoped_variable_inlined(self):
        result = self._deobfuscate("$script:x = 'val'; Write-Output $script:x")
        self.assertEqual(result, "Write-Output 'val'")

    def test_an_engine_default_every_scope_holds_is_inlined_through_a_narrower_qualifier(self):
        for source in [
            '& { Write-Output $local:ShellId }',
            'Write-Output $script:ShellId',
        ]:
            with self.subTest(source):
                result = self._deobfuscate(source)
                self.assertIn("'Microsoft.PowerShell'", result)
                self.assertNotIn('ShellId', result)

    def test_a_preference_read_through_a_narrower_qualifier_is_null(self):
        source = '& { Write-Output $local:ErrorActionPreference }'
        self._assertDeobfuscatesToOneOf(
            source,
            source,
            '& { Write-Output $Null }',
            'Write-Output $Null',
        )

    def test_nonconst_value_not_inlined(self):
        result = self._deobfuscate("$x = Get-Date; Write-Output $x")
        self.assertIn('$x', result)

    def test_env_comspec_inlined(self):
        self.assertEqual(self._deobfuscate('$x = $env:ComSpec[4]'), '$x = [char]73')

    def test_null_variable_inlined(self):
        result = self._deobfuscate_iterative(
            '$x = $Null; Write-Host (5 + $x)')
        self.assertIn('5', result)
        self.assertNotIn('$x', result)

    def test_null_assigned_variable_folds(self):
        result = self._deobfuscate_iterative(
            '$x = $Null; $y = 10 - $x; Write-Host $y')
        self.assertIn('10', result)
        self.assertNotIn('$x', result)
        self.assertNotIn('$y', result)

    def test_multiassign_target_not_inlined(self):
        from refinery.lib.scripts.ps1.model import (
            Ps1ArrayLiteral,
            Ps1AssignmentExpression,
            Ps1Variable,
        )
        source = cleandoc("""
            $x = 509
            $x, $y, $z = 1, 2, 3
            Write-Output $x
        """)
        ast = Ps1Parser(source).parse()
        Ps1ConstantInlining().visit(ast)
        multi = [
            n for n in ast.walk()
            if isinstance(n, Ps1AssignmentExpression) and isinstance(n.target, Ps1ArrayLiteral)
        ]
        self.assertEqual(len(multi), 1)
        self.assertEqual(
            [type(e).__name__ for e in multi[0].target.elements],
            ['Ps1Variable', 'Ps1Variable', 'Ps1Variable'])
        self.assertTrue(all(isinstance(e, Ps1Variable) for e in multi[0].target.elements))


class TestPs1DeadBranchInlining(TestPs1):

    def test_conditional_only_variable_not_inlined(self):
        result = self._deobfuscate_iterative(
            cleandoc("""
                $x = 1
                if (0 -GE 1) { $x = 999 }
                Write-Host $x
            """)
        )
        self.assertIn('1', result)
        self.assertNotIn('999', result)

    def test_dead_branch_arithmetic_not_evaluated(self):
        result = self._deobfuscate_iterative(
            cleandoc("""
                if (0 -GT 1) { $a = 500 }
                $b = $a - 200
                $c = [Char][int]$b
            """)
        )
        self.assertNotIn('500', result)
        self.assertNotIn('300', result)

    def test_unconditional_assignment_still_inlined(self):
        result = self._deobfuscate_iterative(
            cleandoc("""
                $x = 42
                if (1 -GT 0) { $x = 42 }
                Write-Host $x
            """)
        )
        self.assertEqual(result, 'Write-Host 42')

    def test_conditional_only_not_inlined_nonconstant_condition(self):
        result = self._deobfuscate_iterative(
            cleandoc("""
                if ($env:UserInput -eq "yes") { $x = 42 }
                Write-Host $x
            """)
        )
        self.assertNotIn('Write-Host 42', result)

    def test_a_read_after_a_failing_char_cast_of_a_negative_number_is_not_given_a_character(self):
        result = self._deobfuscate_iterative(
            cleandoc("""
                if ($y -GE 100) { $a = 500 }
                $b = $a - 700
                $c = [Char][int]$b
                Write-Host $c
            """)
        )
        self.assertNotIn('$y', result)
        self.assertNotIn('$a', result)
        self.assertIn(result.splitlines()[-1], ('Write-Host $c', 'Write-Host $Null'))


class TestPs1NullVariableInlining(TestPs1):

    def test_null_arithmetic(self):
        result = self._deobfuscate_iterative(
            cleandoc("""
                $x = 5 + $unset
                Write-Host $x
            """)
        )
        self.assertIn('5', result)
        self.assertNotIn('$unset', result)

    def test_null_if_branch_elimination(self):
        result = self._deobfuscate_iterative(
            cleandoc("""
                if ($undefined) {
                    Write-Host 'dead'
                } else {
                    Write-Host 'live'
                }
            """)
        )
        self.assertIn('live', result)
        self.assertNotIn('dead', result)

    def test_null_complex_arithmetic(self):
        result = self._deobfuscate_iterative(
            cleandoc("""
                $x = (10 - $a + 3)
                Write-Host $x
            """)
        )
        self.assertIn('13', result)
        self.assertNotIn('$a', result)

    def test_no_inlining_for_assigned_variable(self):
        result = self._deobfuscate_iterative(
            cleandoc("""
                $y = 5
                $x = $y + 1
                Write-Host $x
            """)
        )
        self.assertIn('6', result)

    def test_no_inlining_for_known_variable(self):
        result = self._deobfuscate_iterative(
            'Write-Host $Host'
        )
        self.assertIn('$Host', result)

    def test_no_inlining_for_automatic_variable(self):
        result = self._deobfuscate_iterative(
            '$_ | Write-Host'
        )
        self.assertIn('$_', result)

    def test_no_inlining_for_parameter_variable(self):
        result = self._deobfuscate_iterative(
            cleandoc("""
                function f {
                    Param($x)
                    $x + 1
                }
            """)
        )
        self.assertIn('$x + 1', result)

    def test_no_inlining_for_typed_assignment(self):
        result = self._deobfuscate_iterative(
            cleandoc("""
                [Byte[]]$data = Get-Content -Encoding Byte "test.bin"
                Write-Host $data.Length
            """)
        )
        self.assertNotIn('$Null', result)
        self.assertIn('$data', result)

    def test_no_inlining_for_cast_parameter_in_command(self):
        result = self._deobfuscate_iterative(
            'class B { static [int] A([string]$xWdH){return $xWdH[0]}}'
        )
        self.assertIn('$xWdH', result)
        self.assertNotIn('$Null', result)


class TestPs1ArrayInliningGuard(TestPs1):

    def test_small_array_inlined_with_parens(self):
        result = self._deobfuscate('$x = @(1, 2, 3); Write-Host $x')
        self.assertEqual(result, 'Write-Host (1, 2, 3)')

    def test_large_array_not_inlined(self):
        elements = ', '.join(str(i) for i in range(100))
        code = F'$x = @({elements}); Write-Host $x; Write-Host $x'
        result = self._deobfuscate(code)
        self.assertIn('$x', result)


class TestPs1ReassignedVariableInlining(TestPs1):

    def test_both_regions_inlined(self):
        result = self._deobfuscate(
            "$x='hello'; Write-Host $x; $x='world'; Write-Host $x"
        )
        self.assertIn('hello', result)
        self.assertIn('world', result)
        self.assertNotIn('$x', result)

    def test_constant_before_nonconst_inlined(self):
        result = self._deobfuscate(
            "$x='hello'; Write-Host $x; $x=$y; Write-Host $x"
        )
        self.assertIn('hello', result)
        self.assertNotIn("$x = 'hello'", result)

    def test_nested_nonconst_blocks_outer_reference(self):
        code = cleandoc("""
            $s = 'initial'
            if ($env:Cond) { $s = $env:Dynamic }
            Write-Host $s
        """)
        result = self._deobfuscate(code)
        self.assertNotIn("Write-Host 'initial'", result)

    def test_seal_point_rhs_inlined(self):
        self.assertEqual(
            self._deobfuscate(cleandoc("""
                $x = 39
                $x = [char]($x)
                Write-Host $x
            """)),
            'Write-Host ([char]39)')

    def test_seal_point_string_rhs_inlined(self):
        result = self._deobfuscate(
            cleandoc("""
                $x = 'hello'
                $x = $x + ' world'
                Write-Host $x
            """)
        )
        self.assertNotIn('$x', result)
        self.assertIn('hello world', result)

    def test_seal_point_multiple_rhs_refs_inlined(self):
        result = self._deobfuscate(cleandoc("""
            $x = 10
            $x = $x + $x
            Write-Host $x
        """))
        self.assertNotIn('$x', result)
        self.assertIn('20', result)

    def test_seal_point_does_not_affect_later_ref(self):
        result = self._deobfuscate(
            cleandoc("""
                $x = 39
                $x = [char]($x)
                $y = $x + 'test'
            """)
        )
        self.assertNotIn('$x', result)
        self.assertIn('test', result)

    def test_seal_point_index_rhs_inlined(self):
        result = self._deobfuscate(cleandoc("""
            $x = 'abc'
            $x = $x[0]
            Write-Host $x
        """))
        self.assertNotIn('$x', result)
        self.assertIn('a', result)

    def test_seal_point_array_index_rhs_inlined(self):
        result = self._deobfuscate(
            cleandoc("""
                $x = @('a','b','c')
                $x = $x[1]
                Write-Host $x
            """)
        )
        self.assertNotIn('$x', result)
        self.assertIn('b', result)

    def test_self_ref_in_loop_not_inlined(self):
        code = cleandoc("""
            $s = 0
            while ($s -ne 10) {
              $s = $s + 1
            }
        """)
        result = self._deobfuscate(code)
        self.assertNotIn('$s = 1\n', result)

    def test_a_read_after_an_index_assignment_sees_the_element_it_wrote(self):
        self._assertDeobfuscatesToOneOf(
            cleandoc("""
                $x = @('a','b','c')
                $x[0] = 'z'
                Write-Host $x[0]
            """),
            cleandoc("""
                $x = @('a', 'b', 'c')
                $x[0] = 'z'
                Write-Host $x[0]
            """),
            "Write-Host 'z'",
        )

    def test_a_read_after_a_failing_member_assignment_sees_the_value_it_had(self):
        source = cleandoc("""
            $x = 'hello'
            $x.Length = 5
            Write-Host $x
        """)
        self._assertDeobfuscatesToOneOf(
            source,
            source,
            cleandoc("""
                $x = 'hello'
                $x.Length = 5
                Write-Host 'hello'
            """),
            "Write-Host 'hello'",
        )

    def test_a_single_use_name_folds_into_the_member_position(self):
        self.assertEqual(
            self._deobfuscate("$m = 'StartsWith'; $x.($m)('::')"),
            "$x.StartsWith('::')",
        )

    def test_a_member_that_is_not_an_identifier_keeps_its_quotes(self):
        self.assertEqual(
            self._deobfuscate("$m = 'a-b'; $x.($m)('::')"),
            "$x.'a-b'('::')",
        )

    def test_a_value_a_sub_expression_fold_produces_folds_into_the_member_position(self):
        self.assertEqual(
            self._deobfuscate("$m = $($s = 'StartsWith'; $s); $x.($m)('::')"),
            "$x.StartsWith('::')",
        )

    def test_a_name_read_in_and_out_of_the_member_position_folds_into_both(self):
        self.assertEqual(
            self._deobfuscate("$m = 'a-b'; $x.($m)('::'); $z = $m + '!'; Write-Output $z"),
            cleandoc("""
                $x.'a-b'('::')
                Write-Output 'a-b!'
            """),
        )

    def test_switch_array_self_ref_not_inlined(self):
        result = self._deobfuscate(
            cleandoc("""
                $x = 0
                switch (1, 2, 3) {
                  default { $x = $x + 1 }
                }
            """)
        )
        self.assertNotIn('$x = 1\n', result)

    def test_constant_re_established_after_seal(self):
        code = cleandoc("""
            $x = 'first'
            if ($script:c) { $x = $script:d }
            $x = 'second'
            Write-Host $x
        """)
        result = self._deobfuscate(code)
        self.assertIn('second', result)
        self.assertNotIn('$x', result)

    def test_both_branches_seal(self):
        code = cleandoc("""
            $x = 'const'
            if ($script:c) { $x = $script:d } else { $x = $script:e }
            Write-Host $x
        """)
        result = self._deobfuscate(code)
        self.assertNotIn("Write-Host 'const'", result)

    def test_inline_before_seal_preserves_after(self):
        code = cleandoc("""
            $x = 'hello'
            Write-Host $x
            if ($env:Cond) { $x = $env:Dynamic }
            Write-Host $x
        """)
        result = self._deobfuscate(code)
        self.assertIn("Write-Host 'hello'", result)
        self.assertIn('Write-Host $x', result)

    def test_self_ref_in_do_while_not_inlined(self):
        code = cleandoc("""
            $x = 0
            do { $x = $x + 1 } while ($x -lt 10)
        """)
        result = self._deobfuscate(code)
        self.assertNotIn('$x = 1\n', result)

    def test_self_ref_in_for_loop_not_inlined(self):
        code = cleandoc("""
            $x = ''
            for ($i = 0; $i -lt 3; $i++) { $x = $x + 'a' }
        """)
        result = self._deobfuscate(code)
        self.assertNotIn("$x = 'a'\n", result)

    def test_self_ref_in_a_parameter_default_inside_a_loop_not_inlined(self):
        code = cleandoc("""
            $x = 'a'
            foreach ($i in $args) { & { param($p = ($x = $x + 'b')) $p } }
            Write-Host $x
        """)
        result = self._deobfuscate(code)
        self.assertIn("$x + 'b'", result)

    def test_foreach_rejects_candidate(self):
        result = self._deobfuscate(
            cleandoc("""
                $x = 'const'
                foreach ($x in @(1, 2, 3)) { Write-Host $x }
            """)
        )
        self.assertNotIn("Write-Host 'const'", result)

    def test_seal_rhs_then_new_constant(self):
        code = cleandoc("""
            $x = 10
            $x = $x * 2
            $x = 'done'
            Write-Host $x
        """)
        result = self._deobfuscate(code)
        self.assertIn('done', result)
        self.assertNotIn('$x', result)

    def test_same_stmt_assign_does_not_dominate_earlier_ref(self):
        self._assertDeobfuscatesToOneOf(
            cleandoc("""
                $x = 'old'
                Write-Host $x ($x = 'new')
            """),
            "Write-Host 'old' ($x = 'new')",
            "Write-Host 'old' 'new'",
        )

    def test_same_stmt_binary_assign_does_not_dominate(self):
        self.assertEqual(
            self._deobfuscate(cleandoc("""
                $x = 'old'
                $y = $x + ($x = 'new')
            """)),
            "$y = 'old' + ($x = 'new')")

    def test_nested_assign_seal_exclusion(self):
        result = self._deobfuscate(
            cleandoc("""
                $x = 'hello'
                $x = ($y = $x)
                Write-Host $y
            """)
        )
        self.assertIn('hello', result)
        self.assertNotIn('$x', result)

    def test_deeply_nested_assign_seal_exclusion(self):
        result = self._deobfuscate(
            cleandoc("""
                $x = 'deep'
                $x = ($y = ($z = $x))
                Write-Host $z
            """)
        )
        self.assertIn('deep', result)
        self.assertNotIn('$x', result)


class TestPs1ConstantInliningAcrossControlFlow(TestPs1):

    def test_a_write_in_a_branch_is_not_ignored_because_its_value_is_constant(self):
        self.assertEqual(
            self._apply("$x = 'a'; if ($c) { $x = 'b' }; Write-Host $x", Ps1ConstantInlining),
            cleandoc("""
                $x = 'a'
                if ($c) {
                  $x = 'b'
                }
                Write-Host $x
            """))

    def test_a_dotted_block_writes_the_scope_that_invokes_it(self):
        self.assertEqual(
            self._apply("$x = 'a'; . { $x = 'b' }; Write-Host $x", Ps1ConstantInlining),
            cleandoc("""
                $x = 'a'
                . {
                  $x = 'b'
                }
                Write-Host $x
            """))

    def test_an_ampersand_block_writes_a_scope_of_its_own(self):
        self.assertEqual(
            self._apply("$x = 'a'; & { $x = 'b' }; Write-Host $x", Ps1ConstantInlining),
            cleandoc("""
                & {
                  $x = 'b'
                }
                Write-Host 'a'
            """))

    def test_a_body_that_writes_its_caller_writes_the_names_it_only_spells_as_strings(self):
        for source in (
            cleandoc("""
                $x = 'a'
                . {
                  Remove-Variable x
                }
                Write-Host $x
            """),
            cleandoc("""
                $x = 'a'
                . {
                  Set-Variable x 'b'
                }
                Write-Host $x
            """),
            cleandoc("""
                $x = 'a'
                . {
                  Remove-Item Variable:x
                }
                Write-Host $x
            """),
            cleandoc("""
                $x = 'a'
                1 | ForEach-Object {
                  Clear-Variable x
                }
                Write-Host $x
            """),
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1ConstantInlining)

    def test_a_child_scope_that_writes_a_name_as_a_string_leaves_the_caller_value_standing(self):
        self.assertEqual(
            self._apply("$x = 'a'; & { Set-Variable x 'b' }; Write-Host $x", Ps1ConstantInlining),
            cleandoc("""
                & {
                  Set-Variable x 'b'
                }
                Write-Host 'a'
            """))

    def test_a_body_that_writes_its_caller_still_leaves_names_it_does_not_write_standing(self):
        for source, expected in (
            (
                "$x = 'a'; . { Get-Variable x -ValueOnly }; Write-Host $x",
                cleandoc("""
                    $x = 'a'
                    . {
                      Get-Variable x -ValueOnly
                    }
                    Write-Host 'a'
                """),
            ),
            (
                "$x = 'a'; . { Remove-Variable y }; Write-Host $x",
                cleandoc("""
                    . {
                      Remove-Variable y
                    }
                    Write-Host 'a'
                """),
            ),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1ConstantInlining), expected)

    def test_a_read_inside_a_stored_block_is_not_ordered_against_the_script_holding_it(self):
        self._assertUnchanged(
            cleandoc("""
                $x = 'a'
                $b = {
                  Write-Host $x
                }
                $x = 'b'
                & $b
            """), Ps1ConstantInlining)

    def test_a_read_inside_a_function_body_keeps_the_assignment_it_observes(self):
        self.assertEqual(
            self._apply(
                "$x = 'a'; function f { Write-Host $x }; Write-Host $x; f", Ps1ConstantInlining),
            cleandoc("""
                $x = 'a'
                function f {
                  Write-Host $x
                }
                Write-Host 'a'
                f
            """))

    def test_a_body_a_cmdlet_runs_per_input_object_is_not_a_single_visit(self):
        self._assertUnchanged(
            cleandoc("""
                $x = 5
                1..3 | % {
                  $x = $x + 1
                }
                Write-Host $x
            """), Ps1ConstantInlining)

    def test_a_write_that_observes_the_previous_value_keeps_the_write_before_it(self):
        for source, expected in [
            ("$x = 'a'; Write-Host $x; $x += 'b'", cleandoc("""
                $x = 'a'
                Write-Host 'a'
                $x += 'b'
            """)),
            ('$x = 1; Write-Host $x; $x++', cleandoc("""
                $x = 1
                Write-Host 1
                $x++
            """)),
        ]:
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1ConstantInlining), expected)

    def test_a_default_the_engine_supplies_is_not_a_value_the_script_overwrote(self):
        self._assertUnchanged(
            cleandoc("""
                . {
                  $ErrorActionPreference = 'Stop'
                }
                Write-Host $ErrorActionPreference
            """),
            Ps1ConstantInlining)
        self.assertEqual(
            self._apply('Write-Host $ErrorActionPreference', Ps1ConstantInlining),
            "Write-Host ([System.Management.Automation.ActionPreference]'Continue')")

    def test_a_branch_that_writes_nothing_still_leaves_the_value_standing(self):
        self.assertEqual(
            self._apply("$x = 'a'; if ($c) { Write-Host 1 }; Write-Host $x", Ps1ConstantInlining),
            cleandoc("""
                if ($c) {
                  Write-Host 1
                }
                Write-Host 'a'
            """))

    def test_a_loop_that_only_reads_still_leaves_the_value_standing(self):
        self.assertEqual(
            self._apply("$x = 'a'; while ($c) { Write-Host $x }", Ps1ConstantInlining),
            cleandoc("""
                while ($c) {
                  Write-Host 'a'
                }
            """))


class TestPs1AnEngineDefaultIsAMemberOfTheTypeTheVariableHolds(TestPs1):

    def test_every_enum_typed_default_names_a_member_of_its_enum(self):
        enum_typed = {
            key: value for key, value in _PS1_DEFAULT_VARIABLES.items()
            if is_enum(VARIABLE_TYPES.get(key, ''))
        }
        self.assertEqual(
            set(enum_typed),
            {
                'confirmpreference',
                'debugpreference',
                'erroractionpreference',
                'informationpreference',
                'progresspreference',
                'verbosepreference',
                'warningpreference',
            },
        )
        for key, value in enum_typed.items():
            with self.subTest(key):
                self.assertIsNotNone(enum_ordinal(VARIABLE_TYPES[key], value))

    def test_the_confirm_preference_default_is_the_confirm_impact_high(self):
        self.assertEqual(
            self._apply('Write-Host $ConfirmPreference', Ps1ConstantInlining),
            "Write-Host ([System.Management.Automation.ConfirmImpact]'High')")

    def test_every_engine_default_has_a_value_the_domain_spells(self):
        for key, fact in _PS1_DEFAULT_FACTS.items():
            with self.subTest(key):
                self.assertIsNotNone(render(fact))

    def test_an_engine_default_is_inlined_however_often_the_script_reads_it(self):
        self.assertEqual(
            self._apply('\n'.join(['Write-Host $VerbosePreference'] * 8), Ps1ConstantInlining),
            '\n'.join(
                ["Write-Host ([System.Management.Automation.ActionPreference]'SilentlyContinue')"] * 8
            ),
        )


class TestPs1ConstantInliningExtra(TestPs1):

    def test_preference_variable_indexing_is_left_standing_or_folded_to_the_member(self):
        source = 'Write-Output ($VerbosePreference[0] + $VerbosePreference[1])'
        self._assertDeobfuscatesToOneOf(
            source,
            source,
            "Write-Output ([System.Management.Automation.ActionPreference]'SilentlyContinue')",
        )

    @opportunity
    def test_preference_variable_indexing_reads_the_member_and_the_null_beside_it(self):
        self.assertEqual(
            self._deobfuscate('Write-Output ($VerbosePreference[0] + $VerbosePreference[1])'),
            "Write-Output ([System.Management.Automation.ActionPreference]'SilentlyContinue')",
        )

    def test_preference_variable_not_substituted_when_assigned(self):
        result = self._deobfuscate(cleandoc("""
            $VerbosePreference = 'Custom'
            Write-Output $VerbosePreference[1]
        """))
        self.assertIn('$VerbosePreference[1]', result)

    def test_a_write_the_body_performs_on_its_caller_is_not_a_dead_write(self):
        for source, expected in (
            (
                cleandoc("""
                    . {
                      $y = 'q'
                      Write-Host $y
                    }
                    Write-Host $y
                """),
                cleandoc("""
                    . {
                      $y = 'q'
                      Write-Host 'q'
                    }
                    Write-Host $y
                """),
            ),
            (
                cleandoc("""
                    1..3 | % {
                      $x = 'b'
                      Write-Host $x
                    }
                    Write-Host $x
                """),
                cleandoc("""
                    1..3 | % {
                      $x = 'b'
                      Write-Host 'b'
                    }
                    Write-Host $x
                """),
            ),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1ConstantInlining), expected)

    def test_a_write_a_child_scope_performs_is_still_a_dead_write(self):
        self.assertEqual(
            self._apply(cleandoc("""
                & {
                  $y = 'q'
                  Write-Host $y
                }
            """), Ps1ConstantInlining),
            cleandoc("""
                & {
                  Write-Host 'q'
                }
            """))

    def test_a_name_an_assignment_stores_through_is_never_replaced_by_its_value(self):
        for source in (
            cleandoc("""
                $x = @(@('a', 'b'))
                $x[0][1] = 'z'
                Write-Host $x[0][1]
            """),
            cleandoc("""
                $x = 'hello'
                ($x).Length = 5
                Write-Host $x
            """),
            cleandoc("""
                $x = 'hello'
                $x.A.B = 5
                Write-Host $x
            """),
            cleandoc("""
                $x = @('a', 'b')
                $x[0], $x[1] = 'p', 'q'
                Write-Host $x[0]
            """),
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1ConstantInlining)

    def test_a_name_the_engine_maintains_holds_no_value_a_reader_may_be_given(self):
        for source in (
            cleandoc("""
                $Matches = 'nope'
                if ('abc' -match 'b') {
                  Write-Host $Matches
                }
            """),
            cleandoc("""
                $_ = 'a'
                1..3 | % {
                  Write-Host $_
                }
            """),
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1ConstantInlining)

    def test_a_stored_block_dot_sourced_into_a_body_writes_that_body(self):
        self._assertUnchanged(
            cleandoc("""
                $b = {
                  $x = 'INNER'
                }
                . {
                  $x = 'OUTER'
                  . $b
                  Write-Host $x
                }
            """),
            Ps1ConstantInlining)

    def test_a_read_after_a_store_that_may_not_have_finished_gets_no_value(self):
        self._assertUnchanged(
            cleandoc("""
                try {
                  [int]$x = 'abc'
                } catch {}
                Write-Host $x
            """),
            Ps1ConstantInlining)


class TestPs1ConstantInliningAcrossAStoreItCannotSee(TestPs1):

    def test_a_reference_argument_is_not_a_place_a_value_may_be_installed(self):
        self._assertUnchanged(
            cleandoc("""
                $n = 5
                [void][int]::TryParse('7', [ref]$n)
            """), Ps1ConstantInlining)

    def test_a_read_after_a_reference_does_not_observe_the_value_before_it(self):
        self._assertUnchanged(
            cleandoc("""
                $n = 0
                [void][int]::TryParse('7', [ref]$n)
                Write-Host $n
            """), Ps1ConstantInlining)

    def test_a_reference_in_a_body_stores_through_the_binding_the_script_holds(self):
        self._assertUnchanged(
            cleandoc("""
                $n = 0
                function f {
                  [void][int]::TryParse('7', [ref]$n)
                }
                f
                Write-Host $n
            """),
            Ps1ConstantInlining)

    def test_a_splatted_argument_is_not_a_place_a_value_may_be_installed(self):
        self._assertUnchanged(
            cleandoc("""
                $p = @('-Path', 'C:\\')
                Get-Item @p
            """), Ps1ConstantInlining)

    def test_the_assignment_a_reference_stores_into_is_not_removed_as_unread(self):
        self.assertEqual(
            self._apply(
                cleandoc("""
                    $n = 0
                    Write-Host $n
                    [void][int]::TryParse('7', [ref]$n)
                """),
                Ps1ConstantInlining),
            cleandoc("""
                $n = 0
                Write-Host 0
                [void][int]::TryParse('7', [ref]$n)
            """))


class TestPs1ConstantInliningAroundUnreachableCode(TestPs1):

    def test_a_dead_tail_does_not_block_the_fold_at_the_statement_after_it(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = 'a'
                if ($c) { exit; $y = 'q' }
                Write-Host $x
            """), Ps1ConstantInlining),
            cleandoc("""
                if ($c) {
                  exit
                  $y = 'q'
                }
                Write-Host 'a'
            """))

    def test_a_read_no_path_reaches_observes_no_definition(self):
        self._assertUnchanged(
            cleandoc("""
                $x = 'a'
                exit
                while ($true) {
                  Write-Host $x
                }
            """), Ps1ConstantInlining)

    def test_two_writes_neither_of_which_can_run_first_do_not_pick_a_winner(self):
        self._assertUnchanged(
            cleandoc("""
                if ($c) {
                  $x = 'a'
                } else {
                  $x = 'b'
                }
                exit
                while ($true) {
                  Write-Host $x
                }
            """),
            Ps1ConstantInlining)


class TestPs1ConstantInliningAcrossNamedWrites(TestPs1):

    def test_a_read_after_an_out_variable_does_not_observe_the_value_before_it(self):
        self._assertUnchanged(
            cleandoc("""
                $x = 'calc'
                Get-Process -OutVariable x
                Write-Host $x
            """), Ps1ConstantInlining)

    def test_a_read_after_an_unbinding_does_not_observe_the_value_before_it(self):
        self._assertUnchanged(
            cleandoc("""
                $a = 'x'
                Remove-Variable a
                Write-Host $a
            """), Ps1ConstantInlining)

    def test_an_environment_write_by_name_displaces_the_ambient_default(self):
        self._assertUnchanged(
            cleandoc("""
                Set-Item Env:ComSpec 'evil.exe'
                Write-Host $env:ComSpec
            """), Ps1ConstantInlining)

    def test_a_write_whose_name_cannot_be_read_holds_the_scope_from_there_on(self):
        self._assertUnchanged(
            cleandoc("""
                $x = 'a'
                Set-Variable $n 'b'
                Write-Host $x
            """), Ps1ConstantInlining)
        self.assertEqual(
            self._apply(
                cleandoc("""
                    $x = 'a'
                    Write-Host $x
                    Set-Variable $n 'b'
                """), Ps1ConstantInlining),
            cleandoc("""
                Write-Host 'a'
                Set-Variable $n 'b'
            """))

    def test_an_unattributable_write_displaces_the_ambient_default_from_there_on(self):
        self._assertUnchanged(cleandoc("""
            iex $c
            Write-Host $env:ComSpec
        """), Ps1ConstantInlining)
        self.assertEqual(
            self._apply(cleandoc("""
                Write-Host $env:ComSpec
                iex $c
            """), Ps1ConstantInlining),
            cleandoc("""
                Write-Host 'C:\\WINDOWS\\system32\\cmd.exe'
                iex $c
            """))

    def test_a_named_write_in_a_body_does_not_reach_the_scope_around_it(self):
        self.assertEqual(
            self._apply(
                cleandoc("""
                    $x = 'a'
                    function f { Set-Variable x 'b' }
                    Write-Host $x
                """), Ps1ConstantInlining),
            cleandoc("""
                function f {
                  Set-Variable x 'b'
                }
                Write-Host 'a'
            """))


class TestPs1AConstantInterpolatesAsTheTextItRendersTo(TestPs1):

    def test_a_hexadecimal_numeral_interpolates_as_the_decimal_digits_it_renders_to(self):
        self.assertEqual(self._deobfuscate_iterative('$s = 0xFF; $t = "$s"'), "$t = '255'")

    def test_a_char_interpolates_as_the_character_it_holds(self):
        self.assertEqual(self._deobfuscate_iterative('$c = [char]65; $t = "$c"'), "$t = 'A'")

    def test_a_number_interpolated_beside_a_text_is_the_text_of_both(self):
        self.assertEqual(self._deobfuscate_iterative('$s = 0xFF; $t = "v$s"'), "$t = 'v255'")


class TestPs1ALaunchDependentDefaultIsNotInvented(TestPs1):

    @todo
    def test_the_session_name_depends_on_how_the_script_was_launched(self):
        self._assertUnchanged('Write-Host $env:SessionName', Ps1ConstantInlining)

    @backlog
    def test_a_name_the_host_does_not_define_is_not_given_a_processor_count(self):
        self._assertUnchanged('Write-Host $env:NumberOfProcessors', Ps1ConstantInlining)

    def test_a_read_of_a_script_path_name_passes_through_untouched(self):
        for source in (
            'Write-Host $PSCommandPath',
            'Write-Host $PSScriptRoot',
            'Write-Host "${PSCommandPath}"',
            'Write-Host "${PSScriptRoot}"',
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1ConstantInlining)
                self.assertEqual(self._deobfuscate_iterative(source), source)

    def test_a_default_no_launch_mode_can_change_is_still_inlined(self):
        self.assertEqual(
            self._apply('Write-Host $PSHome', Ps1ConstantInlining),
            "Write-Host 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0'")
        self.assertEqual(
            self._apply('Write-Host "$PSHome"', Ps1ConstantInlining),
            'Write-Host "C:\\Windows\\System32\\WindowsPowerShell\\v1.0"')


class TestPs1AnUnsetReadIsNotNullWhereStrictModeIsArmed(TestPs1):

    def test_a_branch_on_an_unset_name_is_not_resolved_where_strict_mode_is_armed(self):
        result = self._deobfuscate_iterative(cleandoc(
            """
            Set-StrictMode -Version 1
            if ($zzqundefined) {
              Write-Host 'dead'
            } else {
              Write-Host 'live'
            }
            """
        ))
        self.assertIn('$zzqundefined', result)


class TestPs1AnUnsetReadIsNotNullWhereADataCodeLeakCanAssignIt(TestPs1):

    _SCRIPT = cleandoc(
        """
        Invoke-Expression $c
        if ($zzqundefined) {
          Write-Host 'dead'
        } else {
          Write-Host 'live'
        }
        """
    )

    def test_a_branch_on_an_unset_name_is_not_resolved_where_a_leak_precedes_it(self):
        self.assertIn('$zzqundefined', self._deobfuscate_iterative(self._SCRIPT))

    def test_the_e_switch_trusts_the_leak_and_resolves_the_branch(self):
        self.assertEqual(
            self._deobfuscate_iterative(self._SCRIPT, trust_eval=True),
            cleandoc(
                """
                Invoke-Expression $c
                Write-Host 'live'
                """
            ))


class TestPs1AnArrayHandedOnFoldsWhereNothingCanChangeItAfterwards(TestPs1):

    def test_a_buffer_folds_into_the_call_whose_result_is_invoked(self):
        self.assertEqual(
            self._deobfuscate_iterative("$b = 'Write-Host', 'hi'; iex ([string]::Join(' ', $b))"),
            'Write-Host hi',
        )

    def test_a_buffer_folds_into_the_decoder_whose_result_is_invoked(self):
        for source in (
            "$b = [Convert]::FromBase64String('V3JpdGUtSG9zdCAx'); "
            'iex ([Text.Encoding]::ASCII.GetString($b))',
            "$b = [Convert]::FromBase64String('V3JpdGUtSG9zdCAx'); "
            '$s = [Text.Encoding]::UTF8.GetString($b); iex $s',
        ):
            with self.subTest(source):
                self.assertEqual(self._deobfuscate_iterative(source), 'Write-Host 1')

    def test_the_command_intrinsics_of_the_session_state_hold_back_no_fold(self):
        self.assertIn(
            'Write-Host hi',
            self._deobfuscate_iterative(
                "$a = 'Write-'; $b = 'Host'; "
                "$ExecutionContext.SessionState.InvokeCommand.InvokeScript($a + $b + ' hi')"),
        )

    def test_a_store_into_another_array_before_the_call_does_not_hold_the_argument_back(self):
        self.assertIn(
            "Write-Output '1,2,3'",
            self._deobfuscate_iterative(
                "$a = 1, 2, 3; $b = 4, 5, 6; $b[0] = 9; Write-Output ([string]::Join(',', $a))"),
        )

    def test_a_class_definition_does_not_make_write_host_keep_its_argument(self):
        self.assertIn(
            'Write-Output 2',
            self._deobfuscate_iterative(
                'class Q {}; $a = 1, 2, 3; Write-Host $a; $b = 4, 5, 6; $b[0] = 9; '
                'Write-Output $a[1]'),
        )


class TestPs1AStoreThatCannotReachAHandedOnArrayDoesNotHoldItBack(TestPs1):

    def test_a_store_into_a_fresh_buffer_after_the_call_does_not_hold_back_its_argument(self):
        self.assertIn(
            "Write-Output 'Hi'",
            self._deobfuscate_iterative(
                '$bytes = 72, 105; $s = [Text.Encoding]::ASCII.GetString($bytes); '
                'Write-Output $s; $buf = 0, 0; $buf[0] = 7'),
        )

    def test_a_decoder_storing_into_its_own_buffer_does_not_hold_back_the_key(self):
        self.assertNotIn(
            '$key',
            self._deobfuscate_iterative(
                'function dec($d, $k) { $o = @(0) * $d.Length; '
                'for ($i = 0; $i -lt $d.Length; $i++) { '
                '$o[$i] = $d[$i] -bxor $k[$i % $k.Length] }; '
                '$o }; $key = 1, 2, 3; Write-Output (dec (4, 5, 6) $key)'),
        )


class TestPs1AStoreIntoAnArrayMadeElsewhereDoesNotHoldBackAFold(TestPs1):

    def test_a_store_into_a_buffer_either_arm_made_does_not_hold_back_an_array_in_a_table(self):
        self.assertIn(
            'Write-Output (1, 2, 3)',
            self._deobfuscate_iterative(
                '$k = 1, 2, 3; $h = @{ k = $k }; '
                'if ((Get-Random -Maximum 1) -eq 0) { $buf = 0, 0 } else { $buf = 1, 1 }; '
                '$buf[0] = 7; Write-Output $k'),
        )

    def test_the_loader_folds_beside_an_unrelated_store_and_a_later_payload(self):
        output = self._deobfuscate_iterative(
            "$b = 'Write-Host', 'hi'; $z = 0, 0; $z[0] = 1; iex ([string]::Join(' ', $b)); "
            "$n = @('Write-Host $b')[(Get-Random -Maximum 1)]; iex $n")
        self.assertIn('Write-Host hi', output)
        self.assertIn("$b = 'Write-Host', 'hi'", output)


class TestPs1AProductByACountOtherThanOneIsANewArray(TestPs1):

    def test_a_store_into_the_product_does_not_hold_back_the_operand(self):
        self.assertIn(
            'Write-Output (1, 2)',
            self._deobfuscate_iterative('$y = 1, 2; $z = $y * 2; $z[0] = 9; Write-Output $y'),
        )


class TestPs1ASecondNameIsNotACopyWhereUnreadableCodeRunsAfterIt(TestPs1):

    def test_the_hand_off_before_an_invoke_expression_keeps_the_name(self):
        self.assertIn(
            '$y = $x',
            self._deobfuscate('$x = 1, 2, 3; $y = $x; Invoke-Expression $c; Write-Output $x'),
        )


class TestPs1TheEnvironmentDriveHoldsTextOnlyWhereEveryHostAgreesOnIt(TestPs1):

    _SOURCE = cleandoc("""
        $env:Q = 'x'
        if ($env:Q) { Write-Output 'y' }
    """)

    def test_the_folding_model_inlines_the_read_and_drops_the_store(self):
        ast = Ps1Parser(self._SOURCE).parse()
        Ps1ConstantInlining().visit(ast)
        self.assertEqual(Ps1Synthesizer().convert(ast), cleandoc("""
            if ('x') {
              Write-Output 'y'
            }
        """))

    def test_the_preserving_model_keeps_the_store_and_the_read(self):
        ast = Ps1Parser(self._SOURCE).parse()
        transform = Ps1ConstantInlining()
        transform.options = Ps1DeobfuscationOptions(preserve_environment=True)
        transform.visit(ast)
        self.assertEqual(Ps1Synthesizer().convert(ast), cleandoc("""
            $env:Q = 'x'
            if ($env:Q) {
              Write-Output 'y'
            }
        """))

    def test_a_store_of_a_type_whose_text_depends_on_the_host_keeps_the_read(self):
        ast = Ps1Parser('$env:Q = 5.5; Write-Output ($env:Q + 1)').parse()
        Ps1ConstantInlining().visit(ast)
        self.assertEqual(Ps1Synthesizer().convert(ast), cleandoc("""
            $env:Q = 5.5
            Write-Output ($env:Q + 1)
        """))
