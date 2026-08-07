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
