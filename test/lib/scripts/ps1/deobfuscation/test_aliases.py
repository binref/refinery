from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1


class TestPs1AliasInlining(TestPs1):

    def test_a_default_alias_beats_a_same_named_function_body(self):
        # `R` is the default alias of Invoke-History, and a default alias beats a same-named script
        # function, so the bare call runs the alias; the function body never reverses `'olleH'` into
        # `'Hello'`. Verified against Windows PowerShell 5.1.
        data = (
            "Function R ([String]$s){"
            "$r = '';"
            "ForEach($c in $s.ToCharArray()){$r = $c + $r};"
            "$r;}"
            "$x = R 'olleH'\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('Invoke-History', result)
        self.assertNotIn('Hello', result)

    def test_a_default_alias_beats_a_same_named_function_case_insensitively(self):
        # `gc` is the default alias of Get-Content, matched case-insensitively, and a default alias
        # beats a same-named script function, so the bare call resolves to the cmdlet and the body
        # `'test'` never runs. Verified against Windows PowerShell 5.1.
        result = self._deobfuscate("Function gc { 'test' }\ngc")
        self.assertEqual(result, 'Get-Content')

    def test_digit_starting_alias_inlined(self):
        data = "Set-Alias 1abc Invoke-Expression\n1abc 'Write-Host hello'"
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('1abc', result.split('\n')[-1])

    def test_obfuscated_alias_target_resolved_after_folding(self):
        data = (
            "Set-Alias myalias $([char]73+[char]69+[char]88)\n"
            "myalias 'Write-Host hi'"
        )
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('myalias', result.split('\n')[-1])

    def test_self_alias_terminates(self):
        # A self-resolving alias must reach a fixpoint (no infinite mark_changed loop) and leave
        # the script unchanged.
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo foo
            foo bar
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo foo
            foo bar
        """))

    def test_an_alias_cycle_terminates_and_is_left_intact(self):
        # Each name in the cycle denotes nothing (5.1 raises CommandNotFoundException), so the call
        # is left as written and resolution terminates rather than rewriting forever.
        result = self._deobfuscate('Set-Alias aq bq; Set-Alias bq aq; aq')
        self.assertEqual(result, 'Set-Alias aq bq\nSet-Alias bq aq\naq')

    def test_a_wildcard_target_alias_is_left_intact(self):
        # A wildcard alias target matches no single command, so the alias denotes nothing (5.1
        # raises CommandNotFoundException) and the call is left as written.
        result = self._deobfuscate('Set-Alias wq i*x; wq')
        self.assertEqual(result, 'Set-Alias wq i*x\nwq')

    def test_a_use_before_its_alias_definition_is_left_intact(self):
        # The definition does not dominate the earlier use, so the use denotes nothing (5.1 raises
        # CommandNotFoundException) and is left as written.
        result = self._deobfuscate('wq\nSet-Alias wq Write-Output')
        self.assertEqual(result, 'wq\nSet-Alias wq Write-Output')

    def test_an_alias_defined_in_a_function_body_does_not_resolve_a_use_outside_it(self):
        # The definition lives in the function's own scope, so the outer use denotes nothing (5.1
        # raises CommandNotFoundException) and the call is left as written.
        result = self._deobfuscate("function f { Set-Alias zx Write-Output }\nzx 'hi'")
        self.assertEqual(result, "function f {\n  Set-Alias zx Write-Output\n}\nzx 'hi'")

    def test_a_parameter_left_without_its_argument_binds_nothing_and_is_left_intact(self):
        # `-Value` is followed by another parameter rather than by its argument, so 5.1 fails the
        # binding with MissingArgument: the command never runs, no alias named `zzq` is created,
        # and the call below denotes nothing.
        script = cleandoc("""
            Set-Alias -Value -Name zzq Write-Output
            zzq 'hi'
        """)
        self.assertEqual(self._deobfuscate(script), script)


class TestPs1AliasDefinitionRemoval(TestPs1):

    def test_a_definition_whose_only_use_the_rewrite_took_is_removed(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            foo 'hi'
        """))
        self.assertEqual(result, "Write-Output 'hi'")

    def test_a_definition_no_use_ever_named_is_removed(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            Write-Host done
        """))
        self.assertEqual(result, 'Write-Host done')

    def test_a_use_the_definition_does_not_reach_keeps_it(self):
        result = self._deobfuscate(cleandoc("""
            foo 'a'
            Set-Alias foo Write-Output
            foo 'b'
        """))
        self.assertEqual(result, cleandoc("""
            foo 'a'
            Set-Alias foo Write-Output
            Write-Output 'b'
        """))

    def test_a_read_of_the_alias_table_keeps_the_definition_it_names(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            foo 'hi'
            Get-Alias foo
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo Write-Output
            Write-Output 'hi'
            Get-Alias foo
        """))

    def test_a_read_of_the_help_for_a_name_keeps_the_definition_it_names(self):
        # `help` is the 5.1 function that reports a command's help and `man` is its default alias,
        # so either spelling reads the alias table for the name it is handed.
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            foo 'hi'
            help foo
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo Write-Output
            Write-Output 'hi'
            help foo
        """))
        under_its_alias = self._deobfuscate(cleandoc("""
            Set-Alias bar Write-Output
            bar 'hi'
            man bar
        """))
        self.assertEqual(under_its_alias, cleandoc("""
            Set-Alias bar Write-Output
            Write-Output 'hi'
            help bar
        """))

    def test_a_read_through_the_alias_namespace_keeps_the_definition(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            foo 'hi'
            ${alias:foo}
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo Write-Output
            Write-Output 'hi'
            $alias:foo
        """))

    def test_a_command_that_opens_the_world_keeps_the_definition(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            foo 'hi'
            Invoke-Expression $z
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo Write-Output
            Write-Output 'hi'
            Invoke-Expression $z
        """))

    def test_an_identity_command_this_batch_is_not_taking_keeps_the_definition(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            foo 'hi'
            Import-Alias aliases.csv
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo Write-Output
            Write-Output 'hi'
            Import-Alias aliases.csv
        """))

    def test_a_read_of_the_command_success_variable_keeps_the_definition(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            foo 'hi'
            Write-Host $?
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo Write-Output
            Write-Output 'hi'
            Write-Host $?
        """))

    def test_a_new_alias_definition_is_inlined_but_not_removed(self):
        result = self._deobfuscate(cleandoc("""
            New-Alias foo Write-Output
            foo 'hi'
        """))
        self.assertEqual(result, cleandoc("""
            New-Alias foo Write-Output
            Write-Output 'hi'
        """))

    def test_a_definition_rebinding_a_default_alias_is_kept_with_its_use(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias gci Write-Output
            gci 'hi'
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias gci Write-Output
            gci 'hi'
        """))

    def test_one_definition_that_must_stay_keeps_the_removable_one_beside_it(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            foo 'a'
            Set-Alias bar Write-Output
            bar 'b'
            Get-Alias bar
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo Write-Output
            Write-Output 'a'
            Set-Alias bar Write-Output
            Write-Output 'b'
            Get-Alias bar
        """))

    def test_a_definition_inside_a_block_kept_as_a_value_is_not_removed(self):
        # A scriptblock renders as the source text between its braces, so the statement is written
        # out rather than run. Measured on 5.1, `Write-Output { Set-Alias zq Get-Date }` prints
        # ` Set-Alias zq Get-Date ` and binds nothing, so removing it changes what the script says.
        printed = cleandoc("""
            Write-Output {
              Set-Alias zq Get-Date
            }
        """)
        stored = cleandoc("""
            $sb = {
              Set-Alias zq Get-Date
            }
        """)
        self.assertEqual(self._deobfuscate(printed), printed)
        self.assertEqual(self._deobfuscate(stored), stored)


class TestPs1AliasRemovalInsideAProtectedBody(TestPs1):

    def test_an_acting_handler_keeps_the_protected_definition_and_the_batch_with_it(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias zq Write-Output
            try {
              Set-Alias zr Write-Output
              Write-Host 'body'
            } catch {
              Write-Host 'caught'
            }
            zq 'hi'
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias zq Write-Output
            try {
              Set-Alias zr Write-Output
              Write-Host 'body'
            } catch {
              Write-Host 'caught'
            }
            Write-Output 'hi'
        """))

    def test_an_empty_handler_leaves_the_protected_definition_removable(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias zq Write-Output
            try {
              Set-Alias zr Write-Output
              Write-Host 'body'
            } catch {
            }
            zq 'hi'
        """))
        self.assertEqual(result, cleandoc("""
            try {
              Write-Host 'body'
            } catch {}
            Write-Output 'hi'
        """))


class TestPs1AliasShadowing(TestPs1):

    def test_the_emulator_does_not_fold_a_call_a_default_alias_shadows(self):
        # `echo` is the default alias of Write-Output and a reaching `Set-Alias` also names it, so
        # the bare call runs the alias and not the function body. Folding it to the body value
        # would substitute a value 5.1 never produces; measured on 5.1 the call prints `y`.
        result = self._deobfuscate(
            "Set-Alias echo Write-Error\nfunction echo { 'from-function' }\necho 'y'")
        self.assertEqual(
            result, "Set-Alias echo Write-Error\nfunction echo {\n  'from-function'\n}\necho 'y'")

    def test_a_provably_dead_alias_shadowed_function_is_removed_only_in_a_closed_world(self):
        # `gci` is the default alias of Get-ChildItem, which beats a same-named function, so
        # `function global:gci { ... }` is never reached by the bare call and is provably dead.
        # Removing it is correct dead-code elimination in a closed world; an `iex` opens the world,
        # where off-tree code could reach it, so it must be kept. Verified against 5.1: with the
        # function defined, `gci` still runs Get-ChildItem.
        closed = self._deobfuscate(cleandoc("""
            function global:gci { Start-Process calc }
            gci
            Write-Host done
        """))
        self.assertEqual(closed, 'Get-ChildItem\nWrite-Host done')
        open_world = self._deobfuscate(cleandoc("""
            function global:gci { Start-Process calc }
            iex $x
            gci
            Write-Host done
        """))
        self.assertIn('Start-Process calc', open_world)
