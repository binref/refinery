from __future__ import annotations

from inspect import cleandoc

from test import backlog, opportunity, todo, wontfix
from test.lib.scripts.ps1.deobfuscation import TestPs1


class TestPs1AliasInlining(TestPs1):

    def test_a_default_alias_beats_a_same_named_function_body(self):
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
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo foo
            foo bar
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo foo
            foo bar
        """))

    def test_an_alias_cycle_terminates_and_is_left_intact(self):
        result = self._deobfuscate('Set-Alias aq bq; Set-Alias bq aq; aq')
        self.assertEqual(result, 'Set-Alias aq bq\nSet-Alias bq aq\naq')

    def test_a_wildcard_target_alias_is_left_intact(self):
        result = self._deobfuscate('Set-Alias wq i*x; wq')
        self.assertEqual(result, 'Set-Alias wq i*x\nwq')

    def test_a_use_before_its_alias_definition_is_left_intact(self):
        result = self._deobfuscate('wq\nSet-Alias wq Write-Output')
        self.assertEqual(result, 'wq\nSet-Alias wq Write-Output')

    def test_an_alias_defined_in_a_function_body_does_not_resolve_a_use_outside_it(self):
        result = self._deobfuscate("function f { Set-Alias zx Write-Output }\nzx 'hi'")
        self.assertEqual(result, "function f {\n  Set-Alias zx Write-Output\n}\nzx 'hi'")

    def test_a_use_before_a_rebinding_takes_the_binding_that_reaches_it(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            foo 'a'
            Set-Alias foo Write-Host
            foo 'b'
        """))
        self.assertEqual(result, cleandoc("""
            Write-Output 'a'
            Write-Host 'b'
        """))

    def test_a_definition_reached_under_a_script_alias_is_inlined_and_removed(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias zsa Set-Alias
            zsa foo Write-Output
            foo 'hi'
        """))
        self.assertEqual(result, "Write-Output 'hi'")

    def test_a_parameter_left_without_its_argument_binds_nothing_and_is_left_intact(self):
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
            Write-Host ${alias:foo}
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo Write-Output
            Write-Output 'hi'
            Write-Host $alias:foo
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

    def test_a_command_whose_own_name_is_a_variable_keeps_the_definition(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            foo 'hi'
            & $env:C
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo Write-Output
            Write-Output 'hi'
            & $env:C
        """))

    def test_a_later_unbind_of_the_name_keeps_the_definition(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            foo 'hi'
            Remove-Item alias:foo
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo Write-Output
            Write-Output 'hi'
            Remove-Item alias:foo
        """))

    def test_a_later_import_of_aliases_keeps_the_definition(self):
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

    @opportunity
    def test_a_success_read_after_another_command_removes_the_definition(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            foo 'hi'
            Write-Host $?
        """))
        self.assertEqual(result, cleandoc("""
            Write-Output 'hi'
            Write-Host $?
        """))

    def test_a_success_read_after_another_command_resolves_the_call(self):
        self._assertDeobfuscatesToOneOf(
            """
                Set-Alias foo Write-Output
                foo 'hi'
                Write-Host $?
            """,
            """
                Set-Alias foo Write-Output
                Write-Output 'hi'
                Write-Host $?
            """,
            """
                Write-Output 'hi'
                Write-Host $?
            """,
        )

    @opportunity
    def test_a_new_alias_definition_whose_only_use_the_rewrite_took_is_removed(self):
        result = self._deobfuscate(cleandoc("""
            New-Alias foo Write-Output
            foo 'hi'
        """))
        self.assertEqual(result, "Write-Output 'hi'")

    def test_a_new_alias_definition_has_its_use_resolved(self):
        self._assertDeobfuscatesToOneOf(
            """
                New-Alias foo Write-Output
                foo 'hi'
            """,
            """
                New-Alias foo Write-Output
                Write-Output 'hi'
            """,
            "Write-Output 'hi'",
        )

    def test_a_failing_rebinding_of_a_read_only_alias_stays_and_does_not_rebind_its_use(self):
        script = cleandoc("""
            Set-Alias gci Write-Output
            gci 'hi'
        """)
        self._assertDeobfuscatesToOneOf(
            script,
            script,
            "Set-Alias gci Write-Output\nGet-ChildItem 'hi'",
        )

    @opportunity
    def test_a_definition_that_must_stay_does_not_keep_the_removable_one_beside_it(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo Write-Output
            foo 'a'
            Set-Alias bar Write-Output
            bar 'b'
            Get-Alias bar
        """))
        self.assertEqual(result, cleandoc("""
            Write-Output 'a'
            Set-Alias bar Write-Output
            Write-Output 'b'
            Get-Alias bar
        """))

    def test_two_definitions_beside_a_read_of_one_have_their_uses_resolved(self):
        self._assertDeobfuscatesToOneOf(
            """
                Set-Alias foo Write-Output
                foo 'a'
                Set-Alias bar Write-Output
                bar 'b'
                Get-Alias bar
            """,
            """
                Set-Alias foo Write-Output
                Write-Output 'a'
                Set-Alias bar Write-Output
                Write-Output 'b'
                Get-Alias bar
            """,
            """
                Write-Output 'a'
                Set-Alias bar Write-Output
                Write-Output 'b'
                Get-Alias bar
            """,
        )

    def test_a_definition_inside_a_block_kept_as_a_value_is_not_removed(self):
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

    @opportunity
    def test_an_acting_handler_does_not_keep_a_protected_definition_that_cannot_fail(self):
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
            try {
              Write-Host 'body'
            } catch {
              Write-Host 'caught'
            }
            Write-Output 'hi'
        """))

    def test_an_acting_handler_around_a_definition_has_the_use_below_resolved(self):
        self._assertDeobfuscatesToOneOf(
            """
                Set-Alias zq Write-Output
                try {
                  Set-Alias zr Write-Output
                  Write-Host 'body'
                } catch {
                  Write-Host 'caught'
                }
                zq 'hi'
            """,
            """
                Set-Alias zq Write-Output
                try {
                  Set-Alias zr Write-Output
                  Write-Host 'body'
                } catch {
                  Write-Host 'caught'
                }
                Write-Output 'hi'
            """,
            """
                try {
                  Write-Host 'body'
                } catch {
                  Write-Host 'caught'
                }
                Write-Output 'hi'
            """,
        )

    @opportunity
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

    def test_a_failing_rebinding_of_an_all_scope_alias_stays_and_its_call_runs_the_alias(self):
        # 5.1 creates `echo` with the `AllScope` option, so a `Set-Alias` of it without that option
        # fails and the bare call still runs Write-Output.
        result = self._deobfuscate(cleandoc("""
            Set-Alias echo Write-Error
            function echo { 'from-function' }
            echo 'y'
        """))
        lines = result.splitlines()
        self.assertEqual(lines[0], 'Set-Alias echo Write-Error')
        self.assertIn(lines[-1], ("echo 'y'", "Write-Output 'y'"))

    def test_a_provably_dead_alias_shadowed_function_is_removed_only_in_a_closed_world(self):
        closed = self._deobfuscate(cleandoc("""
            function global:gci { Start-Process calc }
            Write-Host (gci)
            Write-Host done
        """))
        self.assertEqual(closed, 'Write-Host (Get-ChildItem)\nWrite-Host done')
        open_world = self._deobfuscate(cleandoc("""
            function global:gci { Start-Process calc }
            iex $x
            Write-Host (gci)
            Write-Host done
        """))
        self.assertIn('Start-Process calc', open_world)


class TestPs1AliasRebindingTheToolCannotRead(TestPs1):

    @backlog
    def test_a_read_below_a_forced_alias_of_invoke_expression_is_not_answered_from_above(self):
        source = cleandoc("""
            Set-Alias e Invoke-Expression -Force
            $x = 'a'
            e $payload
            Write-Host $x
        """)
        self._assertDeobfuscatesToOneOf(
            source,
            source,
            source.replace('e $payload', 'Invoke-Expression $payload'),
        )

    @opportunity
    def test_a_rebinding_reached_under_a_script_alias_removes_the_script_alias(self):
        result = self._deobfuscate(cleandoc("""
            Set-Alias zsa Set-Alias
            Set-Alias foo Write-Output
            zsa -Name $env:N -Value Write-Warning
            foo 'hi'
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo Write-Output
            Set-Alias -Name $env:N -Value Write-Warning
            foo 'hi'
        """))

    def test_a_rebinding_reached_under_a_script_alias_keeps_the_later_use(self):
        script = cleandoc("""
            Set-Alias zsa Set-Alias
            Set-Alias foo Write-Output
            zsa -Name $env:N -Value Write-Warning
            foo 'hi'
        """)
        self._assertDeobfuscatesToOneOf(
            script,
            script,
            """
                Set-Alias zsa Set-Alias
                Set-Alias foo Write-Output
                Set-Alias -Name $env:N -Value Write-Warning
                foo 'hi'
            """,
            """
                Set-Alias foo Write-Output
                Set-Alias -Name $env:N -Value Write-Warning
                foo 'hi'
            """,
        )

    def test_a_rebinding_whose_name_is_a_variable_keeps_the_later_use(self):
        script = cleandoc("""
            Set-Alias foo Write-Output
            Set-Alias $env:N Write-Warning
            foo 'hi'
        """)
        self.assertEqual(self._deobfuscate(script), script)

    def test_a_rebinding_dispatched_through_a_variable_command_keeps_the_later_use(self):
        script = cleandoc("""
            Set-Alias foo Write-Output
            & $env:C foo Write-Warning
            foo 'hi'
        """)
        self.assertEqual(self._deobfuscate(script), script)

    def test_a_write_into_the_alias_drive_ends_the_earlier_binding(self):
        script = cleandoc("""
            Set-Alias foo Write-Output
            Set-Item alias:foo Write-Warning
            foo 'hi'
        """)
        self._assertDeobfuscatesToOneOf(script, script, "Write-Warning 'hi'")

    def test_an_unbind_through_the_alias_drive_ends_the_earlier_binding(self):
        script = cleandoc("""
            Set-Alias foo Write-Output
            Remove-Item alias:foo
            foo 'hi'
        """)
        self._assertDeobfuscatesToOneOf(script, script, "foo 'hi'")

    def test_an_assignment_into_the_alias_namespace_ends_the_earlier_binding(self):
        script = cleandoc("""
            Set-Alias foo Write-Output
            $alias:foo = 'Write-Warning'
            foo 'hi'
        """)
        self._assertDeobfuscatesToOneOf(script, script, "Write-Warning 'hi'")


class TestPs1AliasDefiningCommandShadowing(TestPs1):

    def test_a_script_function_named_set_alias_beats_the_cmdlet_and_binds_nothing(self):
        script = cleandoc("""
            function Set-Alias {
              Write-Host 'shadowed'
            }
            Set-Alias foo Write-Output
            foo 'hi'
        """)
        self.assertEqual(self._deobfuscate(script), script)

    def test_a_call_of_a_function_named_set_alias_is_not_removed_as_an_unused_definition(self):
        script = cleandoc("""
            function Set-Alias {
              Write-Host 'shadowed'
            }
            Set-Alias foo Write-Output
            Write-Host done
        """)
        self.assertEqual(self._deobfuscate(script), script)

    def test_a_default_alias_for_set_alias_beats_a_script_function_of_that_name(self):
        result = self._deobfuscate(cleandoc("""
            function sal { Write-Host 'shadowed' }
            sal foo Write-Output
            foo 'hi'
        """))
        self.assertEqual(result, "Write-Output 'hi'")


class TestPs1ARenameOfACommandTheEngineInvokesIsNotUnused(TestPs1):

    #: The shipped functions `cd..` and `more` call `Set-Location` and `Get-Content`, and displaying
    #: the error record of the last script runs `Set-StrictMode`.
    _REACHED_WITHOUT_BEING_NAMED = (
        cleandoc("""
            Set-Alias Get-Help Write-Error
            Write-Output -?
        """),
        cleandoc("""
            Set-Alias Set-Location Write-Error
            cd..
        """),
        cleandoc("""
            Set-Alias Get-Content Write-Error
            more 'C:/Windows/win.ini'
        """),
        cleandoc("""
            Set-Alias Set-StrictMode Write-Error
            Get-Item 'C:/zzqnope/missing'
        """),
    )

    @wontfix(
        'no obfuscator or script rebinds a command it never names, such as Get-Help, and reaches '
        'it only through -? or a built-in function like more'
    )
    def test_the_rename_survives(self):
        for script in self._REACHED_WITHOUT_BEING_NAMED:
            with self.subTest(script):
                self._assertKept(script)


class TestPs1AnAliasTheScriptRebindsIsNotSpelledAsItsDefaultTarget(TestPs1):

    @todo
    def test_a_rebound_shorthand_keeps_its_own_spelling(self):
        result = self._deobfuscate(cleandoc(
            """
            function Keep { param($s) $script:store = $s }
            Set-Alias -Force -Option AllScope % Keep
            1..2 | % { Write-Output 'x' }
            & $script:store
            """
        ))
        self.assertNotIn('ForEach-Object', result)


class TestPs1AScopeQualifiedCallDoesNotRunAPlainAlias(TestPs1):

    @wontfix(
        'no obfuscator or script calls an alias it just defined through a scope prefix such as '
        'global:, which 5.1 does not resolve to that alias'
    )
    def test_a_bare_scope_qualified_call_of_a_plain_alias_is_not_rewritten(self):
        result = self._deobfuscate("Set-Alias zzq Write-Output\nglobal:zzq 'qualified'")
        self.assertNotIn("Write-Output 'qualified'", result)

    @wontfix(
        'no obfuscator or script calls an alias it just defined through a quoted global: name, '
        'which 5.1 does not resolve to that alias'
    )
    def test_a_call_operator_on_a_global_scoped_plain_alias_is_not_rewritten(self):
        result = self._deobfuscate("Set-Alias zzq Write-Output\n& 'global:zzq' 'qualified'")
        self.assertNotIn("Write-Output 'qualified'", result)

    @wontfix(
        'no obfuscator or script calls an alias it just defined through a quoted script: name, '
        'which 5.1 does not resolve to that alias'
    )
    def test_a_call_operator_on_a_script_scoped_plain_alias_is_not_rewritten(self):
        result = self._deobfuscate("Set-Alias zzq Write-Output\n& 'script:zzq' 'qualified'")
        self.assertNotIn("Write-Output 'qualified'", result)


class TestPs1AScriptThatRedefinesForEachObjectDoesNotRunTheCmdlet(TestPs1):

    def test_a_pipeline_over_a_redefined_iterator_is_not_folded(self):
        result = self._deobfuscate(cleandoc(
            """
            function ForEach-Object { 'HIJACK' }
            $r = 1, 2 | ForEach-Object { $_ * 2 }
            Write-Host ('r=' + $r)
            """
        ))
        self.assertIn('ForEach-Object', result)
        self.assertIn('$_ * 2', result)
        self.assertNotIn('2, 4', result)

    def test_a_pipeline_over_a_function_drive_rebinding_is_not_folded(self):
        result = self._deobfuscate(cleandoc(
            """
            ${function:ForEach-Object} = { 'HIJACK' }
            $r = 1, 2 | ForEach-Object { $_ * 2 }
            Write-Host ('r=' + $r)
            """
        ))
        self.assertIn('$_ * 2', result)
        self.assertNotIn('2, 4', result)

    def test_a_pipeline_over_a_set_item_function_drive_is_not_folded(self):
        result = self._deobfuscate(cleandoc(
            """
            Set-Item function:ForEach-Object { 'HIJACK' }
            $r = 1, 2 | % { $_ * 2 }
            Write-Host ('r=' + $r)
            """
        ))
        self.assertIn('$_ * 2', result)

    _REBOUND_ITERATOR_FORMS_5_1_RUNS = (
        "New-Item -Path function: -Name ForEach-Object -Value { 'HIJACK' }",
        "function tmp { 'HIJACK' }\nRename-Item function:tmp ForEach-Object",
        "Set-Item function:ForEach-Object,function:Where-Object { 'HIJACK' }",
        "Set-Item function:/ForEach-Object { 'HIJACK' }",
    )

    @wontfix(
        'no obfuscator or script hijacks ForEach-Object through indirect writes to the function '
        'drive'
    )
    def test_a_rebinding_the_path_extractor_cannot_read_is_still_folded(self):
        for rebinding in self._REBOUND_ITERATOR_FORMS_5_1_RUNS:
            with self.subTest(rebinding):
                result = self._deobfuscate(
                    rebinding + "\n$r = 1, 2 | % { $_ * 2 }\nWrite-Host ('r=' + $r)")
                self.assertIn('$_ * 2', result)

    @wontfix(
        'no obfuscator or script redefines ForEach-Object by writing content to the function '
        'drive'
    )
    def test_a_content_cmdlet_writing_the_function_provider_is_still_folded(self):
        result = self._deobfuscate(cleandoc(
            """
            Set-Content function:ForEach-Object -Value { 'HIJACK' }
            $r = 1, 2 | % { $_ * 2 }
            Write-Host ('r=' + $r)
            """
        ))
        self.assertIn('$_ * 2', result)
