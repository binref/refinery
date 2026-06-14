from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1


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

    def test_compound_assignment_disqualifies(self):
        result = self._deobfuscate("$x = 'a'; $x += 'b'; Write-Output $x")
        self.assertIn('$x', result)

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
        self.assertIn("'val'", result)

    def test_foreach_variable_not_candidate(self):
        result = self._deobfuscate(
            "foreach ($item in @('a','b')) { Write-Output $item }")
        self.assertIn('$item', result)

    def test_param_variable_not_candidate(self):
        result = self._deobfuscate(
            "param($x); Write-Output $x")
        self.assertIn('$x', result)

    def test_assignment_removed_when_all_refs_substituted(self):
        result = self._deobfuscate("$x = 'hello'; Write-Output $x")
        self.assertNotIn("$x = 'hello'", result)
        self.assertNotIn('$x', result)

    def test_assignment_kept_when_some_refs_remain(self):
        result = self._deobfuscate(
            "$a = @('x','y'); Write-Output $a[0]; Write-Output $a[$i]")
        self.assertIn('$a', result)
        self.assertIn("'x'", result)
        self.assertIn('$i', result)

    def test_case_insensitive_matching(self):
        result = self._deobfuscate("$Foo = 'bar'; Write-Output $foo")
        self.assertIn("'bar'", result)
        self.assertNotIn('$foo', result)
        self.assertNotIn('$Foo', result)

    def test_scoped_variable_not_inlined(self):
        result = self._deobfuscate("$script:x = 'val'; Write-Output $script:x")
        self.assertIn('$script:x', result)

    def test_increment_not_inlined(self):
        result = self._deobfuscate("$i = 0; $i++; Write-Output $i")
        self.assertIn('$i', result)
        self.assertNotIn('0++', result)

    def test_nonconst_value_not_inlined(self):
        result = self._deobfuscate("$x = Get-Date; Write-Output $x")
        self.assertIn('$x', result)

    def test_env_comspec_inlined(self):
        result = self._deobfuscate("$x = $env:ComSpec[4]")
        self.assertNotIn('ComSpec', result)
        self.assertIn("'I'", result)

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


class TestPs1DeadBranchInlining(TestPs1):

    def test_conditional_only_variable_not_inlined(self):
        result = self._deobfuscate_iterative(
            '$x = 1\n'
            'if (0 -GE 1) { $x = 999 }\n'
            'Write-Host $x'
        )
        self.assertIn('1', result)
        self.assertNotIn('999', result)

    def test_dead_branch_arithmetic_not_evaluated(self):
        result = self._deobfuscate_iterative(
            'if (0 -GT 1) { $a = 500 }\n'
            '$b = $a - 200\n'
            '$c = [Char][int]$b'
        )
        self.assertNotIn('[Char][int]-', result)

    def test_unconditional_assignment_still_inlined(self):
        result = self._deobfuscate_iterative(
            '$x = 42\n'
            'if (1 -GT 0) { $x = 42 }\n'
            'Write-Host $x'
        )
        self.assertIn('42', result)

    def test_conditional_only_not_inlined_nonconstant_condition(self):
        result = self._deobfuscate_iterative(
            'if ($env:OS -eq "Windows_NT") { $x = 42 }\n'
            'Write-Host $x'
        )
        self.assertIn('$x', result)

    def test_char_cast_no_negative(self):
        result = self._deobfuscate_iterative(
            'if ($y -GE 100) { $a = 500 }\n'
            '$b = $a - 700\n'
            '$c = [Char][int]$b\n'
            'Write-Host $c'
        )
        self.assertNotIn('$y', result)
        self.assertNotIn('$a', result)
        self.assertIn('-700', result)


class TestPs1NullVariableInlining(TestPs1):

    def test_null_arithmetic(self):
        result = self._deobfuscate_iterative(
            '$x = 5 + $unset\n'
            'Write-Host $x'
        )
        self.assertIn('5', result)
        self.assertNotIn('$unset', result)

    def test_null_if_branch_elimination(self):
        result = self._deobfuscate_iterative(
            'if ($undefined) {\n'
            "    Write-Host 'dead'\n"
            '} else {\n'
            "    Write-Host 'live'\n"
            '}'
        )
        self.assertIn('live', result)
        self.assertNotIn('dead', result)

    def test_null_complex_arithmetic(self):
        result = self._deobfuscate_iterative(
            '$x = (10 - $a + 3)\n'
            'Write-Host $x'
        )
        self.assertIn('13', result)
        self.assertNotIn('$a', result)

    def test_no_inlining_for_assigned_variable(self):
        result = self._deobfuscate_iterative(
            '$y = 5\n'
            '$x = $y + 1\n'
            'Write-Host $x'
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
            'function f {\n'
            '    Param($x)\n'
            '    $x + 1\n'
            '}'
        )
        self.assertIn('$x', result)

    def test_no_inlining_for_foreach_variable(self):
        result = self._deobfuscate_iterative(
            'foreach ($item in @(1, 2, 3)) {\n'
            '    $item\n'
            '}'
        )
        self.assertIn('$item', result)

    def test_no_inlining_for_typed_assignment(self):
        result = self._deobfuscate_iterative(
            '[Byte[]]$data = Get-Content -Encoding Byte "test.bin"\n'
            'Write-Host $data.Length'
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
        self.assertIn('(1, 2, 3)', result)

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

    def test_non_constant_reassignment_blocks_later_region(self):
        result = self._deobfuscate(
            "$x='hello'; Write-Host $x; $x=$y; Write-Host $x"
        )
        self.assertIn('hello', result)
        self.assertNotIn("$x = 'hello'", result)

    def test_dead_assignment_removed(self):
        result = self._deobfuscate(
            "$x='hello'; Write-Host $x; $x='world'; Write-Host $x"
        )
        self.assertNotIn("$x='hello'", result)
        self.assertNotIn("$x='world'", result)
        self.assertNotIn("$x = 'hello'", result)
        self.assertNotIn("$x = 'world'", result)

    def test_constant_before_nonconst_inlined(self):
        result = self._deobfuscate(
            "$x='hello'; Write-Host $x; $x=$y; Write-Host $x"
        )
        self.assertIn('hello', result)
        self.assertNotIn("$x = 'hello'", result)

    def test_nested_nonconst_blocks_outer_reference(self):
        code = '\n'.join([
            "$s = 'initial'",
            'if ($script:cond) { $s = $script:dynamic }',
            'Write-Host $s',
        ])
        result = self._deobfuscate(code)
        self.assertIn('$s', result)

    def test_seal_point_rhs_inlined(self):
        result = self._deobfuscate("$x = 39\n$x = [char]($x)\nWrite-Host $x")
        self.assertNotIn('$x', result)
        self.assertIn("'", result)

    def test_seal_point_string_rhs_inlined(self):
        result = self._deobfuscate(
            "$x = 'hello'\n$x = $x + ' world'\nWrite-Host $x"
        )
        self.assertNotIn('$x', result)
        self.assertIn('hello world', result)

    def test_seal_point_multiple_rhs_refs_inlined(self):
        result = self._deobfuscate("$x = 10\n$x = $x + $x\nWrite-Host $x")
        self.assertNotIn('$x', result)
        self.assertIn('20', result)

    def test_seal_point_does_not_affect_later_ref(self):
        result = self._deobfuscate(
            "$x = 39\n$x = [char]($x)\n$y = $x + 'test'"
        )
        self.assertNotIn('$x', result)
        self.assertIn('test', result)

    def test_seal_point_index_rhs_inlined(self):
        result = self._deobfuscate("$x = 'abc'\n$x = $x[0]\nWrite-Host $x")
        self.assertNotIn('$x', result)
        self.assertIn('a', result)

    def test_seal_point_array_index_rhs_inlined(self):
        result = self._deobfuscate(
            "$x = @('a','b','c')\n$x = $x[1]\nWrite-Host $x"
        )
        self.assertNotIn('$x', result)
        self.assertIn('b', result)

    def test_seal_point_index_in_loop_not_inlined(self):
        result = self._deobfuscate(
            "$x = 'hello'\nwhile ($true) { $x = $x[0] }"
        )
        self.assertIn('$x', result)

    def test_self_ref_in_loop_not_inlined(self):
        code = "$s = 0\nwhile ($s -ne 10) {\n  $s = $s + 1\n}"
        result = self._deobfuscate(code)
        self.assertIn('$s', result)

    def test_index_assign_rejects_candidate(self):
        result = self._deobfuscate(
            "$x = @('a','b','c')\n$x[0] = 'z'\nWrite-Host $x[0]"
        )
        self.assertIn('$x', result)

    def test_member_assign_rejects_candidate(self):
        result = self._deobfuscate(
            "$x = 'hello'\n$x.Length = 5\nWrite-Host $x"
        )
        self.assertIn('$x', result)

    def test_switch_array_self_ref_not_inlined(self):
        result = self._deobfuscate(
            "$x = 0\nswitch (1, 2, 3) {\n  default { $x = $x + 1 }\n}"
        )
        self.assertIn('$x', result)

    def test_constant_re_established_after_seal(self):
        code = '\n'.join([
            "$x = 'first'",
            'if ($script:c) { $x = $script:d }',
            "$x = 'second'",
            'Write-Host $x',
        ])
        result = self._deobfuscate(code)
        self.assertIn('second', result)
        self.assertNotIn('$x', result)

    def test_both_branches_seal(self):
        code = '\n'.join([
            "$x = 'const'",
            'if ($script:c) { $x = $script:d } else { $x = $script:e }',
            'Write-Host $x',
        ])
        result = self._deobfuscate(code)
        self.assertIn('$x', result)

    def test_inline_before_seal_preserves_after(self):
        code = '\n'.join([
            "$x = 'hello'",
            'Write-Host $x',
            'if ($script:c) { $x = $script:d }',
            'Write-Host $x',
        ])
        result = self._deobfuscate(code)
        self.assertIn('hello', result)
        self.assertIn('$x', result)

    def test_self_ref_in_do_while_not_inlined(self):
        code = "$x = 0\ndo { $x = $x + 1 } while ($x -lt 10)"
        result = self._deobfuscate(code)
        self.assertIn('$x', result)

    def test_self_ref_in_for_loop_not_inlined(self):
        code = "$x = ''\nfor ($i = 0; $i -lt 3; $i++) { $x = $x + 'a' }"
        result = self._deobfuscate(code)
        self.assertIn('$x', result)

    def test_foreach_rejects_candidate(self):
        result = self._deobfuscate(
            "$x = 'const'\nforeach ($x in @(1, 2, 3)) { Write-Host $x }"
        )
        self.assertIn('$x', result)

    def test_seal_rhs_then_new_constant(self):
        code = "$x = 10\n$x = $x * 2\n$x = 'done'\nWrite-Host $x"
        result = self._deobfuscate(code)
        self.assertIn('done', result)
        self.assertNotIn('$x', result)

    def test_augmented_assignment_rejects(self):
        result = self._deobfuscate(
            "$x = 'hello'\n$x += ' world'\nWrite-Host $x"
        )
        self.assertIn('$x', result)

    def test_same_stmt_assign_does_not_dominate_earlier_ref(self):
        result = self._deobfuscate(
            "$x = 'old'\nWrite-Host $x ($x = 'new')"
        )
        self.assertIn('old', result)

    def test_same_stmt_binary_assign_does_not_dominate(self):
        result = self._deobfuscate(
            "$x = 'old'\n$y = $x + ($x = 'new')"
        )
        self.assertIn('old', result)

    def test_nested_assign_seal_exclusion(self):
        result = self._deobfuscate(
            "$x = 'hello'\n$x = ($y = $x)\nWrite-Host $y"
        )
        self.assertIn('hello', result)
        self.assertNotIn('$x', result)

    def test_deeply_nested_assign_seal_exclusion(self):
        result = self._deobfuscate(
            "$x = 'deep'\n$x = ($y = ($z = $x))\nWrite-Host $z"
        )
        self.assertIn('deep', result)
        self.assertNotIn('$x', result)


class TestPs1ConstantInliningExtra(TestPs1):

    def test_preference_variable_indexing(self):
        result = self._deobfuscate("Write-Output ($VerbosePreference[0] + $VerbosePreference[1])")
        self.assertNotIn('VerbosePreference', result)

    def test_preference_variable_not_substituted_when_assigned(self):
        result = self._deobfuscate("$VerbosePreference = 'Custom'\nWrite-Output $VerbosePreference[1]")
        self.assertIn("$VerbosePreference", result)
