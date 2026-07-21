from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import (
    Ps1DeadCodeElimination,
    Ps1JunkStatementRemoval,
)


class TestPs1DeadCodeElimination(TestPs1):

    def test_while_false_removed(self):
        result = self._deobfuscate("while ($False) { Write-Host 'dead' }; Write-Host 'live'")
        self.assertNotIn('dead', result)
        self.assertIn('live', result)

    def test_if_true_keeps_then(self):
        result = self._deobfuscate("if ($True) { Write-Host 'yes' } else { Write-Host 'no' }")
        self.assertIn('yes', result)
        self.assertNotIn("'no'", result)

    def test_if_false_keeps_else(self):
        result = self._deobfuscate("if ($False) { Write-Host 'a' } else { Write-Host 'b' }")
        self.assertNotIn("'a'", result)
        self.assertIn('b', result)

    def test_if_false_then_true_elseif(self):
        result = self._deobfuscate("if ($False) {} elseif ($True) { Write-Host 'second' }")
        self.assertIn('second', result)

    def test_all_false_keeps_else(self):
        result = self._deobfuscate("if ($False) {} elseif ($False) {} else { Write-Host 'else' }")
        self.assertIn('else', result)

    def test_non_static_stops_pruning(self):
        result = self._deobfuscate("$x = $env:V\nif ($False) {} elseif ($x) { Write-Host 'kept' }")
        self.assertNotIn('$False', result)
        self.assertIn('$x', result)
        self.assertIn('kept', result)

    def test_switch_constant_match(self):
        result = self._deobfuscate("switch (5) { 3 { 'a' } 5 { 'b' } default { 'c' } }")
        self.assertIn('b', result)
        self.assertNotIn("'a'", result)
        self.assertNotIn("'c'", result)

    def test_switch_constant_default(self):
        result = self._deobfuscate("switch (99) { 1 { 'a' } default { 'd' } }")
        self.assertIn('d', result)
        self.assertNotIn("'a'", result)

    def test_switch_constant_no_match(self):
        result = self._deobfuscate("switch (99) { 1 { 'a' } 2 { 'b' } }")
        self.assertNotIn("'a'", result)
        self.assertNotIn("'b'", result)

    def test_do_while_false_executes_once(self):
        result = self._deobfuscate("do { Write-Host 'once' } while ($False)")
        self.assertIn('once', result)
        self.assertNotIn('while', result.lower())

    def test_if_false_no_else_removed(self):
        result = self._deobfuscate("if ($False) { Write-Host 'dead' }")
        self.assertNotIn('dead', result)

    def test_if_true_empty_then(self):
        result = self._deobfuscate("if ($True) {} else { Write-Host 'dead' }")
        self.assertNotIn('dead', result)

    def test_if_nonzero_integer_truthy(self):
        result = self._deobfuscate("if (99) { Write-Host 'yes' } else { Write-Host 'no' }")
        self.assertIn('yes', result)
        self.assertNotIn("'no'", result)

    def test_if_zero_integer_falsy(self):
        result = self._deobfuscate("if (0) { Write-Host 'dead' } else { Write-Host 'live' }")
        self.assertNotIn('dead', result)
        self.assertIn('live', result)

    def test_while_zero_removed(self):
        result = self._deobfuscate("while (0) { Write-Host 'dead' }; Write-Host 'live'")
        self.assertNotIn('dead', result)
        self.assertIn('live', result)

    def test_if_nonempty_string_truthy(self):
        result = self._deobfuscate("if ('x') { Write-Host 'yes' }")
        self.assertIn('yes', result)
        self.assertNotIn('if', result.lower().split('write')[0])

    def test_if_empty_string_falsy(self):
        result = self._deobfuscate("if ('') { Write-Host 'dead' }")
        self.assertNotIn('dead', result)

    def test_if_negative_integer_truthy(self):
        result = self._deobfuscate("if (-12) { Write-Host 'yes' }")
        self.assertIn('yes', result)
        self.assertNotIn('-12', result)

    def test_if_null_falsy(self):
        result = self._deobfuscate("if ($Null) { Write-Host 'dead' }")
        self.assertNotIn('dead', result)

    def test_if_zero_real_falsy(self):
        result = self._deobfuscate("if (0.0) { Write-Host 'dead' }")
        self.assertNotIn('dead', result)

    def test_if_nonzero_real_truthy(self):
        result = self._deobfuscate("if (3.14) { Write-Host 'yes' }")
        self.assertIn('yes', result)
        self.assertNotIn('3.14', result)

    def test_dead_for_loop_false_eq(self):
        result = self._deobfuscate(
            "for($x=175;$x-Eq437;$x++){Write-Host 'hi'}")
        self.assertIn('$x', result)
        self.assertIn('175', result)
        self.assertNotIn('for', result.lower())
        self.assertNotIn('Write-Host', result)

    def test_dead_for_loop_true_condition(self):
        result = self._deobfuscate(
            "for($x=10;$x-Eq10;$x++){Write-Host 'hi'}")
        self.assertIn('for', result.lower())

    def test_dead_for_loop_no_initializer(self):
        result = self._deobfuscate(
            "for(;$False;){Write-Host 'hi'}")
        self.assertNotIn('Write-Host', result)

    def test_for_break_unrolled(self):
        result = self._deobfuscate(
            "for($i=0;$i -lt 10;$i++){$x = 1; $y = 2; break}")
        self.assertNotIn('for', result.lower())
        self.assertNotIn('break', result.lower())
        self.assertIn('$x', result)
        self.assertIn('$y', result)
        self.assertIn('$i', result)

    def test_for_break_labeled_preserved(self):
        result = self._deobfuscate(
            ":outer for($i=0;$i -lt 5;$i++){$x = 1; break :outer}")
        self.assertIn('for', result.lower())

    def test_for_break_with_continue_preserved(self):
        result = self._deobfuscate(
            "for($i=0;$i -lt 5;$i++){if($i -eq 3){continue}; $x = 1; break}")
        self.assertIn('for', result.lower())

    def test_for_break_not_last_preserved(self):
        result = self._deobfuscate(
            "for($i=0;$i -lt 5;$i++){break; Write-Host done}")
        self.assertIn('for', result.lower())

    def test_for_break_only(self):
        result = self._deobfuscate(
            "for($i=0;$i -lt 5;$i++){break}")
        self.assertNotIn('for', result.lower())
        self.assertIn('$i', result)

    def test_while_break_unrolled(self):
        result = self._deobfuscate(
            "while($True){$x = 42; break}")
        self.assertNotIn('while', result.lower())
        self.assertNotIn('break', result.lower())
        self.assertIn('42', result)

    def test_do_while_break_unrolled(self):
        result = self._deobfuscate(
            "do{$x = 42; break}while($True)")
        self.assertNotIn('do', result.lower())
        self.assertNotIn('break', result.lower())
        self.assertIn('42', result)

    def test_do_until_break_unrolled(self):
        result = self._deobfuscate(
            "do{$x = 42; break}until($False)")
        self.assertNotIn('until', result.lower())
        self.assertNotIn('break', result.lower())
        self.assertIn('42', result)

    def test_while_break_false_condition_removed(self):
        result = self._deobfuscate_iterative(
            "while($False){$x = 42; break}")
        self.assertNotIn('42', result)

    def test_while_break_unknown_condition_guarded(self):
        result = self._deobfuscate(
            "while(Get-Random){Write-Host 42; break}")
        self.assertNotIn('while', result.lower())
        self.assertNotIn('break', result.lower())
        self.assertIn('if', result.lower())
        self.assertIn('42', result)

    def test_for_break_false_condition_preserves_init(self):
        result = self._deobfuscate_iterative(
            "for($i=0; $False; $i++){$x = 42; break}")
        self.assertNotIn('42', result)
        self.assertIn('$i', result)

    def test_while_dead_loop_no_incorrect_inline(self):
        result = self._deobfuscate_iterative(
            '$a = 10\n'
            'while((-9 + $a) -GE (44)) { $b = $a; break }\n'
            '$c = $b - 200\n'
            '$d = [Char][int]$c'
        )
        self.assertNotIn('[Char]-', result.lower())

    def test_bare_integer_statements_pruned(self):
        result = self._deobfuscate_iterative(
            '$x = Get-Process\n'
            '42\n'
            'Write-Host $x\n'
            '(-7)\n'
        )
        self.assertNotIn('42', result)
        self.assertNotIn('-7', result)
        self.assertIn('Get-Process', result)

    def test_bare_integer_only_script_preserved(self):
        result = self._deobfuscate('42')
        self.assertIn('42', result)

    def test_string_statement_preserved(self):
        result = self._deobfuscate_iterative(
            '$x = Get-Process\n'
            "'hello'\n"
            'Write-Host $x\n',
            remove_junk=False,
        )
        self.assertIn('hello', result)

    def test_constant_in_switch_case_pruned(self):
        result = self._deobfuscate_iterative(
            'switch ($action) {\n'
            '  1 { 99 }\n'
            '  2 { Write-Host "ok" }\n'
            '}\n'
        )
        self.assertNotIn('99', result)
        self.assertIn('Write-Host', result)

    def test_constant_in_subexpression_preserved(self):
        result = self._deobfuscate('"prefix$( 1 + 2 )suffix"')
        self.assertIn('prefix', result)
        self.assertIn('suffix', result)
        self.assertNotIn('prefix""suffix', result.replace(' ', ''))

    def test_scriptblock_body_constant_preserved(self):
        result = self._deobfuscate('$x = & { $True }')
        self.assertIn('$True', result)

    def test_scriptblock_body_numeric_preserved(self):
        result = self._deobfuscate('$x = & { 42 }')
        self.assertIn('42', result)


class TestPs1DeadCodeExtra(TestPs1):

    def test_value_producing_if_assignment_keeps_branches(self):
        # The branch outputs of an assignment-RHS `if` are observable, so dead-code and junk
        # removal must leave the `if` untouched.
        result = self._apply(
            "$x = if ($c) { 'aaa' } else { 'bbb' }",
            Ps1DeadCodeElimination, Ps1JunkStatementRemoval)
        self.assertEqual(result, cleandoc("""
            $x = if ($c) {
              'aaa'
            } else {
              'bbb'
            }
        """))

    def test_switch_executes_all_matching_clauses(self):
        result = self._apply(
            "switch (1) { 1 { Write-Host 'A' } 1 { Write-Host 'B' } }", Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc("""
            Write-Host 'A'
            Write-Host 'B'
        """))

    def test_switch_case_sensitive_match(self):
        result = self._apply(
            "switch -CaseSensitive ('Foo') { 'foo' { Write-Host 'A' } 'Foo' { Write-Host 'B' } }",
            Ps1DeadCodeElimination)
        self.assertEqual(result, "Write-Host 'B'")

    def test_empty_try_catch_removed(self):
        result = self._apply('try {} catch {}', Ps1DeadCodeElimination)
        self.assertEqual(result, '')

    def test_empty_try_catch_finally_hoists_finally(self):
        result = self._apply(
            "try {} catch {} finally { Write-Host 'f' }", Ps1DeadCodeElimination)
        self.assertEqual(result, "Write-Host 'f'")

    def test_nonempty_try_kept(self):
        result = self._apply(
            "try { Get-Item x } catch { Write-Host 'err' }", Ps1DeadCodeElimination)
        self.assertIn('Get-Item', result)
        self.assertIn('catch', result.lower())

    def test_trap_continue_removed(self):
        result = self._apply('trap { continue }', Ps1DeadCodeElimination)
        self.assertEqual(result, '')

    def test_trap_break_removed(self):
        result = self._apply('trap { break }', Ps1DeadCodeElimination)
        self.assertEqual(result, '')

    def test_trap_empty_removed(self):
        result = self._apply('trap {}', Ps1DeadCodeElimination)
        self.assertEqual(result, '')

    def test_trap_typed_empty_removed(self):
        result = self._apply('trap [Exception] { continue }', Ps1DeadCodeElimination)
        self.assertEqual(result, '')

    def test_trap_with_output_kept(self):
        result = self._apply("trap { Write-Host 'log' }", Ps1DeadCodeElimination)
        self.assertIn('trap', result.lower())
        self.assertIn('Write-Host', result)

    def test_trap_labeled_break_kept(self):
        result = self._apply('trap { break :outer }', Ps1DeadCodeElimination)
        self.assertIn('trap', result.lower())

    def test_empty_for_counter_terminal(self):
        result = self._apply(
            'for ($i = 0; $i -LT 41; $i++) {}', Ps1DeadCodeElimination)
        self.assertEqual(result, '$i = 41')

    def test_empty_for_decrement_terminal(self):
        result = self._apply(
            'for ($i = 10; $i -GT 0; $i--) {}', Ps1DeadCodeElimination)
        self.assertEqual(result, '$i = 0')

    def test_empty_for_zero_iteration_keeps_init(self):
        result = self._apply(
            'for ($i = 5; $i -LT 0; $i++) {}', Ps1DeadCodeElimination)
        self.assertEqual(result, '$i = 5')

    def test_empty_for_infinite_kept(self):
        result = self._apply('for (;;) {}', Ps1DeadCodeElimination)
        self.assertIn('for', result.lower())

    def test_empty_for_nonconstant_bound_kept(self):
        result = self._apply(
            'for ($i = 0; $i -LT $n; $i++) {}', Ps1DeadCodeElimination)
        self.assertIn('for', result.lower())

    def test_empty_while_true_kept(self):
        result = self._apply('while ($True) {}', Ps1DeadCodeElimination)
        self.assertIn('while', result.lower())

    def test_function_body_return_value_preserved(self):
        result = self._apply(
            "function f { $Null = 915; 42 }\n$x = f\nWrite-Host $x",
            Ps1DeadCodeElimination)
        self.assertIn('42', result)

    def test_try_bareword_assign_removed(self):
        result = self._apply(
            "try { foo =5 } catch {}\nWrite-Host 'keep'", Ps1DeadCodeElimination)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_try_multiple_bareword_assigns_removed(self):
        result = self._apply(
            "try {\n  abc =1\n  def =2\n} catch {}\nWrite-Host 'keep'", Ps1DeadCodeElimination)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_try_bareword_with_finally_hoists(self):
        result = self._apply(
            "try { foo =5 } catch {} finally { Write-Host 'f' }", Ps1DeadCodeElimination)
        self.assertEqual(result, "Write-Host 'f'")

    def test_try_pure_body_removed(self):
        result = self._apply(
            "try { [Math]::Sqrt(9) } catch {}\nWrite-Host 'keep'", Ps1DeadCodeElimination)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_try_side_effect_command_kept(self):
        result = self._apply(
            "try { Remove-Item foo } catch {}\nWrite-Host 'keep'", Ps1DeadCodeElimination)
        self.assertIn('Remove-Item', result)

    def test_try_nonempty_catch_kept(self):
        result = self._apply(
            "try { foo =5 } catch { Write-Host 'err' }\nWrite-Host 'keep'",
            Ps1DeadCodeElimination)
        self.assertIn('foo', result)
        self.assertIn('err', result)

    def test_try_path_command_kept(self):
        result = self._apply(
            "try { ./script.ps1 } catch {}\nWrite-Host 'keep'", Ps1DeadCodeElimination)
        self.assertIn('script', result)

    def test_try_exe_command_kept(self):
        result = self._apply(
            "try { notepad.exe } catch {}\nWrite-Host 'keep'", Ps1DeadCodeElimination)
        self.assertIn('notepad', result)
