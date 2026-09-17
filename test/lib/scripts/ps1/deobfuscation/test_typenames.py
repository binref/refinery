from __future__ import annotations

import unittest

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import Ps1TypeSystemSimplifications


class TestPs1TypeSystemSimplifications(TestPs1):

    def test_get_member_index_name_resolved(self):
        result = self._deobfuscate('($ExecutionContext | Get-Member)[6].Name')
        self.assertIn('InvokeCommand', result)
        self.assertNotIn('[6]', result)

    def test_get_member_index_unknown_type_preserved(self):
        result = self._deobfuscate('($unknown | Get-Member)[6].Name')
        self.assertIn('[6].Name', result)

    def test_get_member_index_out_of_range_preserved(self):
        result = self._deobfuscate('($ExecutionContext | Get-Member)[999].Name')
        self.assertIn('[999].Name', result)

    def test_get_member_over_an_enum_value_is_left_standing(self):
        """
        `Get-Member` on a value of an enum lists the instance surface of `System.Enum`, not the
        enum's values, so the index is not resolved against the values.
        """
        source = "Write-Host ([System.ConsoleColor]'Red' | Get-Member)[0].Name"
        self.assertEqual(self._deobfuscate(source), source)

    def test_get_member_over_a_preference_variable_is_left_standing(self):
        self.assertEqual(
            self._deobfuscate('Write-Host ($VerbosePreference | Get-Member)[0].Name'),
            "Write-Host ([System.Management.Automation.ActionPreference]'SilentlyContinue'"
            ' | Get-Member)[0].Name',
        )

    def test_get_member_filtered_by_a_wildcard_over_a_preference_variable_is_left_standing(self):
        self.assertEqual(
            self._deobfuscate(
                "Write-Host (($VerbosePreference | Get-Member | Where-Object { $_.Name -like 'Su*' }).Name)"),
            cleandoc("""
                Write-Host (([System.Management.Automation.ActionPreference]'SilentlyContinue' | Get-Member | Where-Object {
                  $_.Name -Like 'Su*'
                }).Name)
            """),
        )

    @unittest.expectedFailure
    def test_get_member_over_a_preference_variable_lists_the_enum_instance_members(self):
        self.assertEqual(
            self._deobfuscate('Write-Host ($VerbosePreference | Get-Member)[0].Name'),
            "Write-Host 'CompareTo'",
        )

    def test_name_on_string_literal_stripped(self):
        result = self._deobfuscate("$x.('GetCmdlets'.Name)('*w-*ct')")
        self.assertNotIn('.Name', result)
        self.assertIn('New-Object', result)


class TestPs1MemberFoldsFollowTheWriteAReadObserves(TestPs1):
    """
    Which write a name's type is taken from, at the pass that spells members out. A name is not a
    variable: the same spelling in two bodies is two of them, and a read outside the body that
    writes it observes nothing that body did.
    """

    def test_a_function_bodys_write_does_not_fold_a_get_member_index_outside_it(self):
        """
        Nothing says `f` was ever called, so the top-level `$q` holds `$null` and `Get-Member` over
        `$null` is an error rather than a member list.
        """
        self._assertUnchanged(cleandoc("""
            function f {
              $q = New-Object Net.WebClient
            }
            ($q | Get-Member)[0].Name
        """), Ps1TypeSystemSimplifications)

    def test_each_function_body_spells_its_members_from_its_own_write(self):
        result = self._apply(cleandoc("""
            function f {
              $q = New-Object Net.WebClient
              $q.downloadstring('u')
            }
            function g {
              $q = New-Object Text.StringBuilder
              $q.tostring()
            }
        """), Ps1TypeSystemSimplifications)
        self.assertEqual(result, cleandoc("""
            function f {
              $q = New-Object Net.WebClient
              $q.DownloadString('u')
            }
            function g {
              $q = New-Object Text.StringBuilder
              $q.ToString()
            }
        """))

    def test_a_store_through_a_member_leaves_the_member_spelling_resolvable(self):
        result = self._apply(cleandoc("""
            $q = New-Object Net.WebClient
            $q.Proxy = $null
            $q.downloadstring('u')
        """), Ps1TypeSystemSimplifications)
        self.assertEqual(result, cleandoc("""
            $q = New-Object Net.WebClient
            $q.Proxy = $null
            $q.DownloadString('u')
        """))

    def test_a_write_and_a_read_inside_one_subexpression_resolve(self):
        result = self._apply(
            "$($q = New-Object Net.WebClient; $q.downloadstring('u'))",
            Ps1TypeSystemSimplifications,
        )
        self.assertEqual(result, cleandoc("""
            $($q = New-Object Net.WebClient
            $q.DownloadString('u'))
        """))

    def test_a_get_member_index_before_every_write_of_the_name_is_left_alone(self):
        """
        The name holds what it held before the script ran, and `Get-Member` over that `$null` is an
        error rather than a member list, so no index into it names a member.
        """
        self._assertUnchanged(cleandoc("""
            ($q | Get-Member)[0].Name
            $q = New-Object Net.WebClient
        """), Ps1TypeSystemSimplifications)

    def test_a_read_at_the_top_of_a_loop_body_is_left_alone(self):
        self._assertUnchanged(cleandoc("""
            while ($c) {
              $q.downloadstring('u')
              $q = New-Object Net.WebClient
            }
        """), Ps1TypeSystemSimplifications)

    def test_a_loop_body_read_resolves_once_a_write_before_the_loop_reaches_it(self):
        result = self._apply(cleandoc("""
            $q = New-Object Net.WebClient
            while ($c) {
              $q.downloadstring('u')
              $q = New-Object Net.WebClient
            }
        """), Ps1TypeSystemSimplifications)
        self.assertEqual(result, cleandoc("""
            $q = New-Object Net.WebClient
            while ($c) {
              $q.DownloadString('u')
              $q = New-Object Net.WebClient
            }
        """))

    def test_a_write_on_one_branch_only_does_not_fold_the_read_after_the_branch(self):
        self._assertUnchanged(cleandoc("""
            if ($c) {
              $q = New-Object Net.WebClient
            }
            ($q | Get-Member)[0].Name
        """), Ps1TypeSystemSimplifications)

    def test_a_write_before_the_branch_folds_the_read_after_it(self):
        result = self._apply(cleandoc("""
            $q = New-Object Net.WebClient
            if ($c) {
              $q = New-Object Net.WebClient
            }
            ($q | Get-Member)[0].Name
        """), Ps1TypeSystemSimplifications)
        self.assertEqual(result, cleandoc("""
            $q = New-Object Net.WebClient
            if ($c) {
              $q = New-Object Net.WebClient
            }
            'CancelAsync'
        """))

    def test_a_qualified_write_inside_a_body_does_not_fold_a_top_level_read(self):
        self._assertUnchanged(cleandoc("""
            function f {
              $script:q = New-Object Net.WebClient
            }
            ($q | Get-Member)[0].Name
        """), Ps1TypeSystemSimplifications)

    def test_a_qualified_write_folds_the_reads_that_follow_it_in_its_own_body(self):
        result = self._apply(cleandoc("""
            function f {
              $script:q = New-Object Net.WebClient
              ($q | Get-Member)[0].Name
            }
        """), Ps1TypeSystemSimplifications)
        self.assertEqual(result, cleandoc("""
            function f {
              $script:q = New-Object Net.WebClient
              'CancelAsync'
            }
        """))

    def test_a_read_between_two_writes_of_different_types_reads_the_first(self):
        result = self._apply(cleandoc("""
            $q = New-Object Net.WebClient
            $q.downloadstring('u')
            $q = New-Object Text.StringBuilder
            $q.tostring()
        """), Ps1TypeSystemSimplifications)
        self.assertEqual(result, cleandoc("""
            $q = New-Object Net.WebClient
            $q.DownloadString('u')
            $q = New-Object Text.StringBuilder
            $q.ToString()
        """))

    def test_a_read_two_writes_of_different_types_reach_is_left_alone(self):
        self._assertUnchanged(cleandoc("""
            $q = New-Object Net.WebClient
            if ($c) {
              $q = New-Object Text.StringBuilder
            }
            $q.tostring()
        """), Ps1TypeSystemSimplifications)

    def test_an_unattributable_write_before_the_read_leaves_the_member_alone(self):
        self._assertUnchanged(cleandoc("""
            $q = New-Object Net.WebClient
            Invoke-Expression $code
            $q.downloadstring('u')
        """), Ps1TypeSystemSimplifications)

    def test_an_unattributable_write_after_the_read_leaves_the_member_resolvable(self):
        result = self._apply(cleandoc("""
            $q = New-Object Net.WebClient
            $q.downloadstring('u')
            Invoke-Expression $code
        """), Ps1TypeSystemSimplifications)
        self.assertEqual(result, cleandoc("""
            $q = New-Object Net.WebClient
            $q.DownloadString('u')
            Invoke-Expression $code
        """))

    def test_a_read_through_a_scope_qualifier_leaves_the_member_alone(self):
        self._assertUnchanged(cleandoc("""
            $global:q = New-Object Net.WebClient
            $global:q.downloadstring('u')
        """), Ps1TypeSystemSimplifications)

    def test_a_foreach_over_a_string_spells_a_string_member(self):
        """
        `Substring` is a member of the string itself; the characters `foreach` is often assumed to
        yield have no such member at all.
        """
        result = self._apply(cleandoc("""
            foreach ($s in 'abc') {
              $s.substring(0, 1)
            }
        """), Ps1TypeSystemSimplifications)
        self.assertEqual(result, cleandoc("""
            foreach ($s in 'abc') {
              $s.Substring(0, 1)
            }
        """))


class TestPs1AMemberIsNotSpelledFromAStoreThatMayNotHaveCompleted(TestPs1):
    """
    A handler runs on the run where its `try` body threw. Measured on 5.1 the name is `$null` at
    that read and at the statement after the whole `try`, and `Get-Member` over `$null` reports
    `You must specify an object for the Get-Member cmdlet`, so an index into it names no member of
    anything.
    """

    def test_a_handler_does_not_spell_a_member_from_its_try_bodys_write(self):
        self._assertUnchanged(cleandoc("""
            try {
              $q = New-Object Net.WebClient
            } catch {
              ($q | Get-Member)[0].Name
            }
        """), Ps1TypeSystemSimplifications)

    def test_a_read_after_the_whole_try_does_not_spell_a_member_from_the_write_inside_it(self):
        self._assertUnchanged(cleandoc("""
            try {
              $q = New-Object Net.WebClient
            } catch {}
            ($q | Get-Member)[0].Name
        """), Ps1TypeSystemSimplifications)

    def test_a_read_only_the_completing_body_reaches_still_resolves(self):
        result = self._apply(cleandoc("""
            try {
              $q = New-Object Net.WebClient
              $q.downloadstring('u')
            } catch {}
        """), Ps1TypeSystemSimplifications)
        self.assertEqual(result, cleandoc("""
            try {
              $q = New-Object Net.WebClient
              $q.DownloadString('u')
            } catch {}
        """))


class TestPs1NoMemberIsSpelledInsideATrapBody(TestPs1):
    """
    The hole `refinery.lib.scripts.ps1.analysis.variable_types` carries, seen from the pass that
    spells members: no read inside a `trap` body is typed, so none of them is spelled. For the write
    standing below the trap that is 5.1's answer, since a throw from above it leaves the name
    `$null`; for a write that cannot throw it is not, and the same read written outside the trap
    does resolve. What is pinned is the refusal rather than the completed-store rule.
    """

    def test_a_write_standing_below_the_trap_does_not_spell_a_member_inside_it(self):
        self._assertUnchanged(cleandoc("""
            trap {
              ($q | Get-Member)[0].Name
            }
            $q = New-Object Net.WebClient
        """), Ps1TypeSystemSimplifications)

    def test_a_write_that_cannot_throw_does_not_spell_one_inside_the_trap_either(self):
        self._assertUnchanged(cleandoc("""
            $q = 'abc'
            trap {
              $q.substring(0, 1)
            }
        """), Ps1TypeSystemSimplifications)
        self.assertEqual(self._apply(cleandoc("""
            $q = 'abc'
            $q.substring(0, 1)
        """), Ps1TypeSystemSimplifications), cleandoc("""
            $q = 'abc'
            $q.Substring(0, 1)
        """))


class TestPs1AMemberIsNotSpelledPastABlockThatWritesItsCallersName(TestPs1):
    """
    Measured on 5.1: `. { $q = New-Object Net.WebClient }` and a `ForEach-Object` or `Where-Object`
    body store into the caller's `$q`, so `($q | Get-Member)[0].Name` answers `Disposed` after one
    of them where the String written above it would answer `Clone`, and `CompareTo` where the
    WebClient written above it would answer `Disposed`. A `&` block writes a scope of its own.
    """

    def test_a_write_a_caller_scope_block_replaces_does_not_spell_the_members(self):
        for source in [
            cleandoc("""
                $q = 'abc'
                . {
                  $q = New-Object Net.WebClient
                }
                ($q | Get-Member)[0].Name
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                . {
                  $q = 5
                }
                ($q | Get-Member)[0].Name
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | ForEach-Object {
                  $q = 5
                }
                $q.downloadstring('u')
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | Where-Object {
                  $q = 5
                }
                $q.downloadstring('u')
            """),
        ]:
            with self.subTest(source):
                self._assertUnchanged(source, Ps1TypeSystemSimplifications)

    def test_a_block_that_writes_no_such_name_leaves_the_members_resolvable(self):
        result = self._apply(cleandoc("""
            $q = 'abc'
            . { $z = 5 }
            ($q | Get-Member)[0].Name
        """), Ps1TypeSystemSimplifications)
        self.assertEqual(result, cleandoc("""
            $q = 'abc'
            . {
              $z = 5
            }
            'Clone'
        """))

    def test_a_block_opening_a_scope_of_its_own_leaves_the_members_resolvable(self):
        result = self._apply(cleandoc("""
            $q = New-Object Net.WebClient
            & { $q = 5 }
            $q.downloadstring('u')
        """), Ps1TypeSystemSimplifications)
        self.assertEqual(result, cleandoc("""
            $q = New-Object Net.WebClient
            & {
              $q = 5
            }
            $q.DownloadString('u')
        """))


class TestPs1AMemberIsNotSpelledAcrossACallThatMayHaveRewrittenTheName(TestPs1):
    """
    Measured on 5.1: with `Invoke-Expression '$q = New-Object Text.StringBuilder'` between them, the
    read carries a StringBuilder rather than the WebClient the script wrote, and it does so whether
    the read stands at the top level, inside `1..3 | %{ }` or inside `& { }`. Writing the read into
    a block that runs right there is therefore no way around the call.
    """

    def test_a_read_inside_a_block_the_call_precedes_leaves_the_member_alone(self):
        for source in [
            cleandoc("""
                $q = New-Object Net.WebClient
                Invoke-Expression $code
                1..3 | % {
                  $q.downloadstring('u')
                }
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                Invoke-Expression $code
                & {
                  $q.downloadstring('u')
                }
            """),
        ]:
            with self.subTest(source):
                self._assertUnchanged(source, Ps1TypeSystemSimplifications)

    def test_a_read_inside_a_block_the_call_follows_still_resolves(self):
        for source, expected in [
            (
                cleandoc("""
                    $q = New-Object Net.WebClient
                    1..3 | % {
                      $q.downloadstring('u')
                    }
                    Invoke-Expression $code
                """),
                cleandoc("""
                    $q = New-Object Net.WebClient
                    1..3 | % {
                      $q.DownloadString('u')
                    }
                    Invoke-Expression $code
                """),
            ),
            (
                cleandoc("""
                    $q = New-Object Net.WebClient
                    & {
                      $q.downloadstring('u')
                    }
                    Invoke-Expression $code
                """),
                cleandoc("""
                    $q = New-Object Net.WebClient
                    & {
                      $q.DownloadString('u')
                    }
                    Invoke-Expression $code
                """),
            ),
        ]:
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1TypeSystemSimplifications), expected)
