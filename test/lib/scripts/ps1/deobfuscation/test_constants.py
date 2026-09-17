from __future__ import annotations

import unittest

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.analysis.values import render
from refinery.lib.scripts.ps1.data import VARIABLE_TYPES, enum_ordinal, is_enum
from refinery.lib.scripts.ps1.deobfuscation import Ps1ConstantInlining
from refinery.lib.scripts.ps1.deobfuscation.constants import (
    _PS1_DEFAULT_FACTS,
    _PS1_DEFAULT_VARIABLES,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


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

    def test_compound_assignment_folds(self):
        result = self._deobfuscate("$x = 'a'; $x += 'b'; Write-Output $x")
        self.assertEqual(result, "Write-Output 'ab'")

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

    def test_increment_folds(self):
        result = self._deobfuscate("$i = 0; $i++; Write-Output $i")
        self.assertEqual(result, 'Write-Output 1')

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

    def test_multiassign_target_not_inlined(self):
        # A constant assigned to `$x` must never be inlined into a subsequent multi-assignment
        # target `$x, $y, $z = ...`, which would corrupt it into `509, $y, $z = ...` (invalid).
        from refinery.lib.scripts.ps1.model import (
            Ps1ArrayLiteral,
            Ps1AssignmentExpression,
            Ps1Variable,
        )
        source = '$x = 509\n$x, $y, $z = 1, 2, 3\nWrite-Output $x'
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
            'if ($env:UserInput -eq "yes") { $x = 42 }\n'
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
        self.assertEqual(
            self._deobfuscate("$x = 39\n$x = [char]($x)\nWrite-Host $x"),
            'Write-Host ([char]39)')

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
            "$x.'a-b'('::')\nWrite-Output 'a-b!'",
        )

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

    def test_self_ref_in_a_parameter_default_inside_a_loop_not_inlined(self):
        """
        The default is evaluated once per invocation of the block, and the block is invoked once per
        iteration, so `$x` accumulates. No control-flow node stands for a parameter default, and an
        element the graphs do not place is not an element proven to run once.
        """
        code = (
            "$x = 'a'\n"
            "foreach ($i in $args) { & { param($p = ($x = $x + 'b')) $p } }\n"
            'Write-Host $x'
        )
        result = self._deobfuscate(code)
        self.assertIn("$x + 'b'", result)

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

    def test_augmented_assignment_folds(self):
        result = self._deobfuscate(
            "$x = 'hello'\n$x += ' world'\nWrite-Host $x"
        )
        self.assertEqual(result, "Write-Host 'hello world'")

    def test_same_stmt_assign_does_not_dominate_earlier_ref(self):
        """
        Asserted as exact output because the source itself contains `old`: an `assertIn` here passes
        on a script nothing was done to, and passes just as well on one where the argument was folded
        to `'new'` and the assignment left standing.
        """
        self.assertEqual(
            self._deobfuscate("$x = 'old'\nWrite-Host $x ($x = 'new')"),
            "Write-Host 'old' ($x = 'new')")

    def test_same_stmt_binary_assign_does_not_dominate(self):
        self.assertEqual(
            self._deobfuscate("$x = 'old'\n$y = $x + ($x = 'new')"),
            "$y = 'old' + ($x = 'new')")

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


class TestPs1ConstantInliningAcrossControlFlow(TestPs1):
    """
    Scripts whose meaning this pass can change, each asserted as exact output against the pass
    alone. The full pipeline is the wrong instrument for them: it removes the dead branch of the
    first and unrolls the loop of the last, so a corruption this pass commits is repaired by another
    one and the test attributes the fix to the wrong place.

    Every expectation is what PowerShell prints for the input, not what the pass happens to produce.
    """

    def test_a_write_in_a_branch_is_not_ignored_because_its_value_is_constant(self):
        """
        `if ($c) { $x = 'b' }` and `if ($c) { $x = $y }` are the same statement in the same position,
        differing only in whether the branch write is constant, which is no reason to fold it.
        """
        self.assertEqual(
            self._apply("$x = 'a'; if ($c) { $x = 'b' }; Write-Host $x", Ps1ConstantInlining),
            "$x = 'a'\nif ($c) {\n  $x = 'b'\n}\nWrite-Host $x")

    def test_a_dotted_block_writes_the_scope_that_invokes_it(self):
        self.assertEqual(
            self._apply("$x = 'a'; . { $x = 'b' }; Write-Host $x", Ps1ConstantInlining),
            "$x = 'a'\n. {\n  $x = 'b'\n}\nWrite-Host $x")

    def test_an_ampersand_block_writes_a_scope_of_its_own(self):
        """
        The floor under the case above, and the reason the two cannot share an answer: `&` opens a
        child scope, so PowerShell prints `a` here and folding it is correct.
        """
        self.assertEqual(
            self._apply("$x = 'a'; & { $x = 'b' }; Write-Host $x", Ps1ConstantInlining),
            "& {\n  $x = 'b'\n}\nWrite-Host 'a'")

    def test_a_body_that_writes_its_caller_writes_the_names_it_only_spells_as_strings(self):
        """
        Each of these leaves `$x` holding something other than `'a'` — nothing at all after
        `Remove-Variable` and `Remove-Item`, `'b'` after `Set-Variable`, `$null` after
        `Clear-Variable` — so folding `'a'` into the read is a corruption. No `$x` occurrence
        anywhere records the write, which is what let the fold through.
        """
        for source in (
            "$x = 'a'\n. {\n  Remove-Variable x\n}\nWrite-Host $x",
            "$x = 'a'\n. {\n  Set-Variable x 'b'\n}\nWrite-Host $x",
            "$x = 'a'\n. {\n  Remove-Item Variable:x\n}\nWrite-Host $x",
            "$x = 'a'\n1 | ForEach-Object {\n  Clear-Variable x\n}\nWrite-Host $x",
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1ConstantInlining)

    def test_a_child_scope_that_writes_a_name_as_a_string_leaves_the_caller_value_standing(self):
        """
        The floor under the case above: `&` opens a child scope and a bare `Set-Variable` lands in
        it, so PowerShell prints `a` and folding it is correct.
        """
        self.assertEqual(
            self._apply("$x = 'a'; & { Set-Variable x 'b' }; Write-Host $x", Ps1ConstantInlining),
            "& {\n  Set-Variable x 'b'\n}\nWrite-Host 'a'")

    def test_a_body_that_writes_its_caller_still_leaves_names_it_does_not_write_standing(self):
        """
        The other floor: declining wherever a variable cmdlet sits in a body that writes its caller
        passes the case above and folds nothing anywhere.
        """
        for source, expected in (
            (
                "$x = 'a'; . { Get-Variable x }; Write-Host $x",
                "$x = 'a'\n. {\n  Get-Variable x\n}\nWrite-Host 'a'",
            ),
            (
                "$x = 'a'; . { Remove-Variable y }; Write-Host $x",
                ". {\n  Remove-Variable y\n}\nWrite-Host 'a'",
            ),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1ConstantInlining), expected)

    def test_a_read_inside_a_stored_block_is_not_ordered_against_the_script_holding_it(self):
        """
        `$b` runs where it is invoked, not where it is written, so by the time the block runs `$x` is
        `'b'`. Asserted as exact output: `assertIn('$x', ...)` is satisfied by the assignment target
        alone while the read inside the block is already folded to the wrong value.
        """
        self._assertUnchanged(
            "$x = 'a'\n$b = {\n  Write-Host $x\n}\n$x = 'b'\n& $b", Ps1ConstantInlining)

    def test_a_read_inside_a_function_body_keeps_the_assignment_it_observes(self):
        """
        A reference this pass never walked is still a reference. Counting only its own substitutions
        let it conclude that the one reference it saw was the last one and delete the assignment `f`
        reads — while the substitution itself was correct and stays.
        """
        self.assertEqual(
            self._apply(
                "$x = 'a'; function f { Write-Host $x }; Write-Host $x; f", Ps1ConstantInlining),
            "$x = 'a'\nfunction f {\n  Write-Host $x\n}\nWrite-Host 'a'\nf")

    def test_a_body_a_cmdlet_runs_per_input_object_is_not_a_single_visit(self):
        self._assertUnchanged(
            "$x = 5\n1..3 | % {\n  $x = $x + 1\n}\nWrite-Host $x", Ps1ConstantInlining)

    def test_a_write_that_observes_the_previous_value_keeps_the_write_before_it(self):
        """
        `$x += 'b'` reads `$x` as much as it writes it, so the store it reads cannot be deleted for
        having no readers left. The existing `$i = 0; $i++` test asserts only that `$i` appears,
        which the `$i` inside `$i++` satisfies with the store already gone.
        """
        for source, expected in [
            ("$x = 'a'; Write-Host $x; $x += 'b'", "$x = 'a'\nWrite-Host 'a'\n$x += 'b'"),
            ('$x = 1; Write-Host $x; $x++', '$x = 1\nWrite-Host 1\n$x++'),
        ]:
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1ConstantInlining), expected)

    def test_a_default_the_engine_supplies_is_not_a_value_the_script_overwrote(self):
        """
        `. { }` performs its writes on the caller, so `$ErrorActionPreference` no longer holds the
        default the engine gave it. The write binds inside the block and the read resolves outside,
        so neither is an occurrence of the other's binding and only the untouched-name rule sees it.
        """
        self._assertUnchanged(
            ". {\n  $ErrorActionPreference = 'Stop'\n}\nWrite-Host $ErrorActionPreference",
            Ps1ConstantInlining)
        self.assertEqual(
            self._apply('Write-Host $ErrorActionPreference', Ps1ConstantInlining),
            "Write-Host ([System.Management.Automation.ActionPreference]'Continue')")

    def test_a_branch_that_writes_nothing_still_leaves_the_value_standing(self):
        """
        The floor under the branch rule: refusing on the presence of a branch at all passes the first
        test here and inlines nothing anywhere.
        """
        self.assertEqual(
            self._apply("$x = 'a'; if ($c) { Write-Host 1 }; Write-Host $x", Ps1ConstantInlining),
            "if ($c) {\n  Write-Host 1\n}\nWrite-Host 'a'")

    def test_a_loop_that_only_reads_still_leaves_the_value_standing(self):
        self.assertEqual(
            self._apply("$x = 'a'; while ($c) { Write-Host $x }", Ps1ConstantInlining),
            "while ($c) {\n  Write-Host 'a'\n}")


class TestPs1AnEngineDefaultIsAMemberOfTheTypeTheVariableHolds(TestPs1):
    """
    The capture types every preference variable as an enum, and the default table spells each
    default as a member's name. The two tables are kept apart, so the name the one records has to
    be a member of the enum the other records, or the inlined cast would throw where 5.1 reads the
    default.
    """

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

    def test_preference_variable_indexing_is_left_standing(self):
        """
        `$VerbosePreference` holds an enum member and not the name it prints, so an index into it
        is not an index into that name. Nothing computes an index over the member, and the read is
        left standing rather than substituted.
        """
        source = 'Write-Output ($VerbosePreference[0] + $VerbosePreference[1])'
        self.assertEqual(self._deobfuscate(source), source)

    @unittest.expectedFailure
    def test_preference_variable_indexing_reads_the_member_and_the_null_beside_it(self):
        """
        5.1 indexes a scalar as a collection of one, so `[0]` is the member itself and `[1]` is
        `$null`, and a `+` whose right operand is `$null` is its left operand.
        """
        self.assertEqual(
            self._deobfuscate('Write-Output ($VerbosePreference[0] + $VerbosePreference[1])'),
            "Write-Output ([System.Management.Automation.ActionPreference]'SilentlyContinue')",
        )

    def test_preference_variable_not_substituted_when_assigned(self):
        result = self._deobfuscate("$VerbosePreference = 'Custom'\nWrite-Output $VerbosePreference[1]")
        self.assertIn("$VerbosePreference", result)

    def test_a_write_the_body_performs_on_its_caller_is_not_a_dead_write(self):
        """
        `Ps1SemanticModel` binds the bare write inside a `. { }` or a `ForEach-Object` body to that
        block, but the block performs it on whoever runs it, so `Binding.reads` is not the whole
        list of readers and substituting all of them does not make the write dead.
        """
        for source, expected in (
            (
                ". {\n  $y = 'q'\n  Write-Host $y\n}\nWrite-Host $y",
                ". {\n  $y = 'q'\n  Write-Host 'q'\n}\nWrite-Host $y",
            ),
            (
                "1..3 | % {\n  $x = 'b'\n  Write-Host $x\n}\nWrite-Host $x",
                "1..3 | % {\n  $x = 'b'\n  Write-Host 'b'\n}\nWrite-Host $x",
            ),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1ConstantInlining), expected)

    def test_a_write_a_child_scope_performs_is_still_a_dead_write(self):
        """
        The floor under the test above: `&` opens a fresh scope, so nothing the block assigns
        outlives it and refusing there would keep every write of every block.
        """
        self.assertEqual(
            self._apply("& {\n  $y = 'q'\n  Write-Host $y\n}", Ps1ConstantInlining),
            "& {\n  Write-Host 'q'\n}")

    def test_a_name_an_assignment_stores_through_is_never_replaced_by_its_value(self):
        """
        `$x[0]` in target position names a place, not a value. A constant installed there is an
        assignment to a literal, which is output that no longer parses.
        """
        for source in (
            "$x = @(@('a', 'b'))\n$x[0][1] = 'z'\nWrite-Host $x[0][1]",
            "$x = 'hello'\n($x).Length = 5\nWrite-Host $x",
            "$x = 'hello'\n$x.A.B = 5\nWrite-Host $x",
            "$x = @('a', 'b')\n$x[0], $x[1] = 'p', 'q'\nWrite-Host $x[0]",
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1ConstantInlining)

    def test_a_name_the_engine_maintains_holds_no_value_a_reader_may_be_given(self):
        """
        `-match` rewrites `$Matches` and the pipeline rebinds `$_` per object, so what the script
        last assigned to one of these is not what the next read of it sees.
        """
        for source in (
            "$Matches = 'nope'\nif ('abc' -match 'b') {\n  Write-Host $Matches\n}",
            "$_ = 'a'\n1..3 | % {\n  Write-Host $_\n}",
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1ConstantInlining)

    def test_a_stored_block_dot_sourced_into_a_body_writes_that_body(self):
        """
        `. $b` performs the block's bare writes on whoever dot-sources it, so a block written at the
        root reaches a binding local to a body it is not written inside.
        """
        self._assertUnchanged(
            "$b = {\n  $x = 'INNER'\n}\n. {\n  $x = 'OUTER'\n  . $b\n  Write-Host $x\n}",
            Ps1ConstantInlining)

    def test_a_read_after_a_store_that_may_not_have_finished_gets_no_value(self):
        """
        The handler is entered on exactly the run in which the cast raised and `$x` was never
        stored, and the statement after the whole `try` is reached that way too.
        """
        self._assertUnchanged(
            "try {\n  [int]$x = 'abc'\n} catch {}\nWrite-Host $x",
            Ps1ConstantInlining)


class TestPs1ConstantInliningAcrossAStoreItCannotSee(TestPs1):
    """
    Positions that observe a value without being a place a value may be put, and writes performed by
    something other than an assignment. Each was read as a plain read by every predicate this pass
    consulted, so each folded a value across a store or installed a literal where the syntax means
    something else.

    Every expectation is what PowerShell does with the input, not what the pass happens to produce.
    """

    def test_a_reference_argument_is_not_a_place_a_value_may_be_installed(self):
        """
        `[ref]5` is a reference to nothing. Whatever the callee stores through it is lost, and the
        statement then looks pure enough for a later pass to delete outright.
        """
        self._assertUnchanged(
            "$n = 5\n[void][int]::TryParse('7', [ref]$n)", Ps1ConstantInlining)

    def test_a_read_after_a_reference_does_not_observe_the_value_before_it(self):
        """
        `[Int]::TryParse` assigns `$n` through the reference, so PowerShell prints `7` here. The
        store happens inside the callee and no assignment in the script records it.
        """
        self._assertUnchanged(
            "$n = 0\n[void][int]::TryParse('7', [ref]$n)\nWrite-Host $n", Ps1ConstantInlining)

    def test_a_reference_in_a_body_stores_through_the_binding_the_script_holds(self):
        self._assertUnchanged(
            "$n = 0\nfunction f {\n  [void][int]::TryParse('7', [ref]$n)\n}\nf\nWrite-Host $n",
            Ps1ConstantInlining)

    def test_a_splatted_argument_is_not_a_place_a_value_may_be_installed(self):
        """
        `Get-Item @p` with `$p` holding `'-Path', 'C:\\'` binds `-Path`; `Get-Item ('-Path', 'C:\\')`
        hands the array to the first positional parameter instead, which is a different command.
        """
        self._assertUnchanged(
            "$p = @('-Path', 'C:\\')\nGet-Item @p", Ps1ConstantInlining)

    def test_the_assignment_a_reference_stores_into_is_not_removed_as_unread(self):
        """
        The read before the call is substituted, so every occurrence in `Binding.reads` is
        accounted for and the removal is reached — and must still decline, because the reference
        observes the value too. The fold of the read itself is correct and stays: it runs before the
        call.
        """
        self.assertEqual(
            self._apply(
                "$n = 0\nWrite-Host $n\n[void][int]::TryParse('7', [ref]$n)",
                Ps1ConstantInlining),
            "$n = 0\nWrite-Host 0\n[void][int]::TryParse('7', [ref]$n)")


class TestPs1ConstantInliningAroundUnreachableCode(TestPs1):
    """
    Code no path reaches orders nothing, in either direction: it neither blocks a fold between two
    statements that do run, nor lets a value into a region that never runs.
    """

    def test_a_dead_tail_does_not_block_the_fold_at_the_statement_after_it(self):
        """
        `$y = 'q'` cannot run, but it is still what the branch falls out of into the statement after
        it, and `$x = 'a'` runs before that statement on every path there is. PowerShell prints `a`.
        """
        self.assertEqual(
            self._apply("$x = 'a'\nif ($c) { exit; $y = 'q' }\nWrite-Host $x", Ps1ConstantInlining),
            "if ($c) {\n  exit\n  $y = 'q'\n}\nWrite-Host 'a'")

    def test_a_read_no_path_reaches_observes_no_definition(self):
        """
        Nothing enters the loop after `exit`, so no assignment is ordered against the read inside it
        — not even the one a reachable read in the same place would observe.
        """
        self._assertUnchanged(
            "$x = 'a'\nexit\nwhile ($true) {\n  Write-Host $x\n}", Ps1ConstantInlining)

    def test_two_writes_neither_of_which_can_run_first_do_not_pick_a_winner(self):
        """
        Both arms precede the loop in the source and neither precedes it in the graph, so any rule
        other than refusing returns whichever of the two was enumerated first.
        """
        self._assertUnchanged(
            "if ($c) {\n  $x = 'a'\n} else {\n  $x = 'b'\n}\nexit\n"
            "while ($true) {\n  Write-Host $x\n}",
            Ps1ConstantInlining)


class TestPs1ConstantInliningAcrossNamedWrites(TestPs1):
    """
    Commands that address a variable by its *name* rather than through a `$` occurrence. Nothing in
    the script mentions the variable at the point the value changes, so every layer that reasons
    about occurrences saw a value that never moved and folded straight across the command.

    Every expectation is what PowerShell 5.1 does, measured — see `temp/ps1/census_measurements.md`.
    """

    def test_a_read_after_an_out_variable_does_not_observe_the_value_before_it(self):
        """
        `Get-Process -OutVariable x` fills `$x` with the process list, so the read that follows sees
        that and not `calc`.
        """
        self._assertUnchanged(
            "$x = 'calc'\nGet-Process -OutVariable x\nWrite-Host $x", Ps1ConstantInlining)

    def test_a_read_after_an_unbinding_does_not_observe_the_value_before_it(self):
        """
        Measured: after `Remove-Variable a` the name is gone and the read is empty, where folding
        it to `'x'` prints the value the script deliberately removed.
        """
        self._assertUnchanged(
            "$a = 'x'\nRemove-Variable a\nWrite-Host $a", Ps1ConstantInlining)

    def test_an_environment_write_by_name_displaces_the_ambient_default(self):
        """
        The ambient table answers `$env:ComSpec` with the system default for a script that never
        writes it. This one writes it, and by a spelling that contains no `$env:ComSpec` occurrence.
        """
        self._assertUnchanged(
            "Set-Item Env:ComSpec 'evil.exe'\nWrite-Host $env:ComSpec", Ps1ConstantInlining)

    def test_a_write_whose_name_cannot_be_read_holds_the_scope_from_there_on(self):
        """
        `Set-Variable $n 'b'` may write any name in the scope, `$x` included, so no value in it
        survives the command — and every value before it does, since when the command runs is not
        in doubt at all.
        """
        self._assertUnchanged(
            "$x = 'a'\nSet-Variable $n 'b'\nWrite-Host $x", Ps1ConstantInlining)
        self.assertEqual(
            self._apply(
                "$x = 'a'\nWrite-Host $x\nSet-Variable $n 'b'", Ps1ConstantInlining),
            "Write-Host 'a'\nSet-Variable $n 'b'")

    def test_an_unattributable_write_displaces_the_ambient_default_from_there_on(self):
        """
        An ambient default is the value the engine established before the script ran — a definition
        at the script's entry — so a call that may have replaced it is ordered against it like any
        other write. Suppressing every default for the whole script instead was measured and costs
        the `$PSHome` arithmetic an obfuscated loader's first stage is built out of.
        """
        self._assertUnchanged("iex $c\nWrite-Host $env:ComSpec", Ps1ConstantInlining)
        self.assertEqual(
            self._apply("Write-Host $env:ComSpec\niex $c", Ps1ConstantInlining),
            "Write-Host 'C:\\WINDOWS\\system32\\cmd.exe'\niex $c")

    def test_a_named_write_in_a_body_does_not_reach_the_scope_around_it(self):
        """
        The floor under the case above: a bare `Set-Variable` writes its own scope, so the script's
        `$x` is untouched by one inside a function and folding it is correct.
        """
        self.assertEqual(
            self._apply(
                "$x = 'a'\nfunction f { Set-Variable x 'b' }\nWrite-Host $x", Ps1ConstantInlining),
            "function f {\n  Set-Variable x 'b'\n}\nWrite-Host 'a'")


class TestPs1AConstantInterpolatesAsTheTextItRendersTo(TestPs1):
    """
    An expandable string writes what a variable renders to and not the way the source wrote it.
    Measured, `$s = 0xFF; "$s"` is the String `255`, and `$c = [char]65; "$c"` is `A`.
    """

    def test_a_hexadecimal_numeral_interpolates_as_the_decimal_digits_it_renders_to(self):
        self.assertEqual(self._deobfuscate_iterative('$s = 0xFF; $t = "$s"'), "$t = '255'")

    def test_a_char_interpolates_as_the_character_it_holds(self):
        self.assertEqual(self._deobfuscate_iterative('$c = [char]65; $t = "$c"'), "$t = 'A'")

    def test_a_number_interpolated_beside_a_text_is_the_text_of_both(self):
        self.assertEqual(self._deobfuscate_iterative('$s = 0xFF; $t = "v$s"'), "$t = 'v255'")


class TestPs1ALaunchDependentDefaultIsNotInvented(TestPs1):
    """
    `$PSCommandPath` and `$PSScriptRoot` have no single default: both are empty at an interactive
    prompt and hold the script's own path when the script runs from a file, so inlining either
    launch mode's value changes what the script prints under the other one. Reads of them pass
    through untouched, where a name whose default no launch mode can change is still inlined.
    """

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
    """
    `Set-StrictMode` turns a read of a never-assigned variable into a statement-terminating error, so
    the name is not worth `$null` and giving it that value decides a branch the script never takes.
    Windows PowerShell 5.1 raises for the script below and runs neither body, printing nothing.
    """

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
    """
    `Invoke-Expression`, a dot-sourced file and an opaque dispatch run code this analysis cannot read
    in the calling scope, so a name never assigned in the tree may hold a value one of them wrote.
    Windows PowerShell 5.1 runs `iex '$zzqundefined = 5'` before the `if` and then takes the `dead`
    branch, so the read is not worth `$null` and resolving the branch on it would drop a body 5.1
    runs. `Ps1NullVariableInlining` stands down under such a leak, the write-side dual of the
    read-leak the cleanup passes and the sub-expression fold refuse on, and the sibling of the
    strict-mode stand-down above. The `-e` switch trusts such code and restores the fold.
    """

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
