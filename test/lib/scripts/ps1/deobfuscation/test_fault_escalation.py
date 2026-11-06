from __future__ import annotations

import inspect
import itertools

from test import backlog, opportunity
from test.lib.scripts.ps1.deobfuscation import TestPs1

_RAISE = "$Null = [Int]'abc'"

_CAST_RAISE = "Write-Host ([int]'a')"

_MATCHING = '[System.Management.Automation.RuntimeException]'

_DIFFERENT = '[System.IO.IOException]'

_FOLLOWER = "Write-Host 'FOLLOWER_RAN'"

_HANDLER = "Write-Host 'HANDLER_RAN'"

_OUTER_HANDLER = "Write-Host 'OUTER_HANDLER_RAN'"

_ANCHOR = "Write-Host 'ANCHOR_SURVIVES'"

_OPAQUE = '$args'

_STOPPING_RAISE = 'Get-Item nope -ErrorAction Stop'

_ACTING_STOPPING_RAISE = F'Write-Host ({_STOPPING_RAISE})'

_UNSPECIFIED_RAISE = 'Write-Host (Get-Item nope)'

_BINDING_FAILURE_RAISE = 'Get-Item -BogusParam foo'

_STRICT_MEMBER_RAISE = '$Null.Nonexistent'

_STRICT_UNSET_VAR_RAISE = '$ThisVarWasNeverSet'


class _Ps1FaultEscalation(TestPs1):

    def _assertKeptButFor(self, source: str, *removable: str) -> None:
        source = inspect.cleandoc(source)
        spans: list[tuple[int, int]] = []
        for statement in removable:
            self.assertIn(statement, source)
            start = source.find(statement)
            while start >= 0:
                spans.append((start, start + len(statement)))
                start = source.find(statement, start + len(statement))
        spans.sort()

        def without(removed: tuple[tuple[int, int], ...]) -> str:
            pieces: list[str] = []
            end = 0
            for start, stop in removed:
                pieces.append(source[end:start])
                end = stop
            pieces.append(source[end:])
            return ''.join(pieces)

        acceptable = [
            without(tuple(span for span, cut in zip(spans, cuts) if cut))
            for cuts in itertools.product((False, True), repeat=len(spans))
        ]
        self._assertDeobfuscatesToOneOf(source, *acceptable)

    def _assertTheTrapStaysWhileTheCastDoes(self, source: str) -> None:
        source = inspect.cleandoc(source)
        without_the_cast = source.replace(_CAST_RAISE, '')
        self._assertDeobfuscatesToOneOf(
            source,
            source,
            without_the_cast,
            without_the_cast.replace('trap { continue }', ''),
        )


class TestPs1AStopPreferenceMakesTheRaiseEndTheScript(_Ps1FaultEscalation):

    def test_a_raising_cast_under_a_stop_preference_is_kept(self):
        self._assertKeptButFor(F"""
            $ErrorActionPreference = 'Stop'
            {_RAISE}
            {_FOLLOWER}
        """, _FOLLOWER)

    def test_a_raising_cast_in_a_branch_under_a_stop_preference_is_kept(self):
        self._assertKept(F"""
            $ErrorActionPreference = 'Stop'
            if ({_OPAQUE}) {{
              {_RAISE}
            }}
            {_FOLLOWER}
        """)


class TestPs1APreferenceThatResumesLeavesTheRaiseRemovable(_Ps1FaultEscalation):

    def test_a_raising_cast_under_a_continue_preference_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            $ErrorActionPreference = 'Continue'
            {_RAISE}
            {_ANCHOR}
        """, F"""
            $ErrorActionPreference = 'Continue'
            {_ANCHOR}
        """)

    def test_a_raising_cast_under_a_silently_continue_preference_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            $ErrorActionPreference = 'SilentlyContinue'
            {_RAISE}
            {_ANCHOR}
        """, F"""
            $ErrorActionPreference = 'SilentlyContinue'
            {_ANCHOR}
        """)

    def test_a_raising_cast_under_a_preference_copied_from_another_preference_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            $ErrorActionPreference = $VerbosePreference
            {_RAISE}
            {_ANCHOR}
        """, F"""
            $ErrorActionPreference = [System.Management.Automation.ActionPreference]'SilentlyContinue'
            {_ANCHOR}
        """)


class TestPs1ATrapWhoseTypeFilterMissesTheErrorEndsTheScript(_Ps1FaultEscalation):

    def test_a_raising_cast_under_an_empty_trap_whose_filter_misses_is_kept(self):
        self._assertKeptButFor(F"""
            trap {_DIFFERENT} {{ }}
            {_RAISE}
            {_FOLLOWER}
        """, _FOLLOWER)

    def test_a_raising_cast_under_a_live_trap_whose_filter_misses_is_kept(self):
        self._assertKeptButFor(F"""
            trap {_DIFFERENT} {{ {_HANDLER} }}
            {_RAISE}
            {_FOLLOWER}
        """, _HANDLER, _FOLLOWER)


class TestPs1ATrapBodyThatReachesBreakEndsTheScript(_Ps1FaultEscalation):

    def test_a_raising_cast_under_a_trap_that_breaks_is_kept(self):
        self._assertKeptButFor(F"""
            trap {{ break }}
            {_RAISE}
            {_FOLLOWER}
        """, _FOLLOWER)

    def test_a_raising_cast_under_a_trap_that_writes_then_breaks_is_kept(self):
        self._assertKeptButFor(F"""
            trap {{
              {_HANDLER}
              break
            }}
            {_RAISE}
            {_FOLLOWER}
        """, _FOLLOWER)


class TestPs1ATrapThatTakesTheErrorAndSwallowsLeavesTheRaiseRemovable(_Ps1FaultEscalation):

    def test_a_raising_cast_under_a_matching_trap_that_continues_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {_MATCHING} {{ continue }}
            {_RAISE}
            {_FOLLOWER}
        """, _FOLLOWER)

    def test_a_raising_cast_under_an_untyped_trap_that_continues_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            {_RAISE}
            {_FOLLOWER}
        """, _FOLLOWER)

    def test_a_raising_cast_a_continuing_trap_takes_from_a_missing_filter_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {_DIFFERENT} {{ }}
            trap {{ continue }}
            {_RAISE}
            {_FOLLOWER}
        """, _FOLLOWER)


class TestPs1ACatchWhoseTypeFilterMissesLeavesTheRaiseRemovable(_Ps1FaultEscalation):

    def test_a_raising_cast_under_an_empty_catch_whose_filter_misses_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{ {_RAISE} }} catch {_DIFFERENT} {{ }}
            {_FOLLOWER}
        """, _FOLLOWER)


class TestPs1ATypedCatchThatMissesDoesNotShieldAnEnclosingCatch(_Ps1FaultEscalation):

    def test_a_raising_cast_a_missing_filter_passes_to_a_live_outer_catch_runs_that_catch(self):
        source = F"""
            try {{
              try {{ {_RAISE} }} catch {_DIFFERENT} {{ }}
            }} catch {{
              {_HANDLER}
            }}
        """
        self._assertDeobfuscatesToOneOf(source, source, _HANDLER)

    def test_a_noise_bareword_past_a_missing_filter_runs_the_live_outer_catch(self):
        source = F"""
            try {{
              try {{ zzqq0 =5 }} catch {_DIFFERENT} {{ }}
              {_FOLLOWER}
            }} catch {{
              {_HANDLER}
            }}
        """
        self._assertDeobfuscatesToOneOf(source, source, _HANDLER)


class TestPs1ATypedCatchThatMatchesShieldsAnEnclosingCatch(_Ps1FaultEscalation):

    def test_a_raising_cast_an_empty_matching_filter_swallows_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              try {{ {_RAISE} }} catch {_MATCHING} {{ }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, F"""
            try {{
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)


class TestPs1AnEmptyCatchDoesNotCoverWhatFollowsTheRaiseInItsBlock(_Ps1FaultEscalation):

    def test_a_proven_raise_before_a_dead_tail_folds_the_construct_away(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              {_RAISE}
              {_FOLLOWER}
            }} catch {{ }}
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1AProvenThrowFoldsTheTryConstruct(_Ps1FaultEscalation):

    def test_a_proven_raise_under_an_empty_catch_folds_to_nothing(self):
        self._assertDeobfuscatesTo(F"try {{ {_RAISE} }} catch {{ }}", '')

    def test_a_throw_lifts_the_body_of_the_catch_that_takes_it(self):
        self._assertDeobfuscatesTo(F"try {{ throw 'x' }} catch {{ {_HANDLER} }}", _HANDLER)

    def test_a_proven_cast_lifts_the_body_of_a_bare_catch(self):
        self._assertDeobfuscatesTo(F"try {{ {_RAISE} }} catch {{ {_HANDLER} }}", _HANDLER)

    def test_a_dead_tail_after_the_throw_goes_while_the_handler_body_is_lifted(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              {_RAISE}
              {_FOLLOWER}
            }} catch {{ {_HANDLER} }}
        """, _HANDLER)

    def test_a_universally_typed_catch_takes_the_throw_and_lifts_its_body(self):
        self._assertDeobfuscatesTo(
            F"try {{ {_RAISE} }} catch [System.Exception] {{ {_HANDLER} }}", _HANDLER)

    def test_an_empty_catch_beside_a_finally_folds_to_the_finally(self):
        self._assertDeobfuscatesTo(
            F"try {{ {_RAISE} }} catch {{ }} finally {{ {_HANDLER} }}", _HANDLER)

    def test_a_catch_body_beside_a_finally_is_kept_or_lifted_before_the_finally(self):
        source = F'try {{ {_RAISE} }} catch {{ {_HANDLER} }} finally {{ {_OUTER_HANDLER} }}'
        self._assertDeobfuscatesToOneOf(source, source, F"""
            {_HANDLER}
            {_OUTER_HANDLER}
        """)

    @opportunity
    def test_a_catch_body_beside_a_finally_lifts_both_bodies_in_order(self):
        self._assertDeobfuscatesTo(F"""
            try {{ {_RAISE} }} catch {{ {_HANDLER} }} finally {{ {_OUTER_HANDLER} }}
        """, F"""
            {_HANDLER}
            {_OUTER_HANDLER}
        """)

    def test_a_throw_of_a_command_argument_is_kept_or_lifted_with_the_command_first(self):
        source = F"try {{ throw (Write-Host 'a') }} catch {{ {_HANDLER} }}"
        self._assertDeobfuscatesToOneOf(source, source, F"""
            Write-Host 'a'
            {_HANDLER}
        """)

    def test_a_throw_of_an_assignment_argument_still_assigns_what_a_later_line_writes(self):
        source = F"""
            try {{ throw ($script:x = 5) }} catch {{ {_HANDLER} }}
            Write-Host $x
        """
        self._assertDeobfuscatesToOneOf(source, source, F"""
            $script:x = 5
            {_HANDLER}
            Write-Host $x
        """, F"""
            {_HANDLER}
            Write-Host 5
        """)

    @opportunity
    def test_a_throw_of_a_command_argument_lifts_the_command_before_the_catch_body(self):
        self._assertDeobfuscatesTo(F"""
            try {{ throw (Write-Host 'a') }} catch {{ {_HANDLER} }}
        """, F"""
            Write-Host 'a'
            {_HANDLER}
        """)


class TestPs1AProvenThrowIsNotFoldedWhereTheLiftWouldChangeWhatRuns(_Ps1FaultEscalation):

    def test_a_catch_that_reads_the_error_variable_is_not_folded(self):
        self._assertKept(F"try {{ {_RAISE} }} catch {{ Write-Host $_ }}")

    def test_a_catch_that_reads_the_error_item_is_not_folded(self):
        self._assertKept(F"try {{ {_RAISE} }} catch {{ Write-Host $PSItem }}")

    def test_a_later_read_of_the_error_record_stops_the_fold(self):
        self._assertKept(F"""
            try {{ throw 'x' }} catch {{ }}
            Write-Host $Error.Count
        """)

    def test_a_catch_body_that_throws_beside_a_finally_never_skips_the_finally(self):
        source = F"try {{ {_RAISE} }} catch {{ throw 'y' }} finally {{ {_OUTER_HANDLER} }}"
        self._assertDeobfuscatesToOneOf(source, source, F"""
            {_OUTER_HANDLER}
            throw 'y'
        """)


class TestPs1ATrapInTheTryBodyTakesTheThrowBeforeTheCatch(_Ps1FaultEscalation):

    def test_a_resuming_trap_after_the_throw_keeps_the_construct(self):
        self._assertKept(F"try {{ throw 'x'; trap {{ continue }} }} catch {{ {_HANDLER} }}")

    def test_a_resuming_trap_before_the_throw_keeps_the_construct(self):
        self._assertKept(F"try {{ trap {{ continue }}; throw 'x' }} catch {{ {_HANDLER} }}")


class TestPs1AnEmptyCatchCoversARaiseThatIsLastInItsBlock(_Ps1FaultEscalation):

    def test_a_raising_cast_after_every_other_statement_of_its_try_block_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              {_FOLLOWER}
              {_RAISE}
            }} catch {{ }}
            {_ANCHOR}
        """, F"""
            try {{
              {_FOLLOWER}
            }} catch {{ }}
            {_ANCHOR}
        """)


class TestPs1ASoftFaultBeforeALiveTailInAnEmptyCatchIsKept(_Ps1FaultEscalation):

    def test_a_possible_division_by_zero_before_a_live_tail_is_kept(self):
        self._assertKept(F"""
            try {{
              $Null = (1 / $env:FOO)
              {_FOLLOWER}
            }} catch {{ }}
        """)

    def test_a_bitwise_operator_over_a_string_before_a_live_tail_is_kept(self):
        self.assertEqual(
            self._deobfuscate(inspect.cleandoc(F"""
                try {{
                  $Null = ($PSCommandPath -bxor 3)
                  {_FOLLOWER}
                }} catch {{ }}
            """)),
            "try {\n  $Null = ($PSCommandPath -BXor 3)\n  Write-Host 'FOLLOWER_RAN'\n} catch {}",
        )

    def test_a_command_discard_before_a_live_tail_under_a_stop_preference_is_kept(self):
        self._assertKept(F"""
            $ErrorActionPreference = 'Stop'
            try {{
              $Null = (Get-ChildItem 'Z:\\nope')
              {_FOLLOWER}
            }} catch {{ }}
        """)

    @opportunity
    def test_a_command_discard_before_a_live_tail_with_no_stop_preference_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              $Null = (Get-ChildItem 'Z:\\nope')
              {_FOLLOWER}
            }} catch {{ }}
        """, F"""
            try {{
              {_FOLLOWER}
            }} catch {{ }}
        """)


class TestPs1ATrapGuardsTheBlockItIsWrittenIn(_Ps1FaultEscalation):

    def test_a_raising_cast_beside_a_live_trap_in_the_same_nested_block_is_kept(self):
        self._assertKept(F"""
            if ({_OPAQUE}) {{
              trap {{ {_HANDLER} }}
              {_RAISE}
            }}
            {_ANCHOR}
        """)

    def test_a_raising_cast_beside_the_innermost_of_two_live_traps_is_kept(self):
        self._assertKept(F"""
            trap {{ {_FOLLOWER} }}
            if ({_OPAQUE}) {{
              trap {{ {_HANDLER} }}
              {_RAISE}
            }}
            {_ANCHOR}
        """)


class TestPs1ATrapTheRaisingBlockDoesNotReachLeavesItRemovable(_Ps1FaultEscalation):

    def test_a_raising_cast_outside_the_block_that_declares_the_trap_is_removed(self):
        self._assertDeobfuscatesToOneOf(F"""
            if ({_OPAQUE}) {{
              trap {{ {_HANDLER} }}
            }}
            {_RAISE}
            {_ANCHOR}
        """, F"""
            if ({_OPAQUE}) {{
              trap {{ {_HANDLER} }}
            }}
            {_ANCHOR}
        """, _ANCHOR)

    def test_a_raising_cast_whose_innermost_trap_continues_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ {_HANDLER} }}
            if ({_OPAQUE}) {{
              trap {{ continue }}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_ANCHOR}
        """, F"""
            trap {{ {_HANDLER} }}
            if ({_OPAQUE}) {{
              trap {{ continue }}
              {_FOLLOWER}
            }}
            {_ANCHOR}
        """)


class TestPs1ATrapInATryBlockRunsInsteadOfTheCatch(_Ps1FaultEscalation):

    def test_a_raising_cast_beside_a_live_trap_inside_a_guarded_try_block_is_kept(self):
        self._assertKept(F"""
            try {{
              trap {{ {_HANDLER} }}
              {_RAISE}
            }} catch {{
              {_FOLLOWER}
            }}
            {_ANCHOR}
        """)


class TestPs1ATrapInATryBlockThatSwallowsLeavesTheRaiseRemovable(_Ps1FaultEscalation):

    @staticmethod
    def _guarded(trap: str) -> str:
        return F"""
            try {{
              {trap}
              {_RAISE}
            }} catch {{
              {_HANDLER}
            }}
            {_ANCHOR}
        """

    @staticmethod
    def _shell(trap: str) -> str:
        return F"""
            try {{
              {trap}
            }} catch {{
              {_HANDLER}
            }}
            {_ANCHOR}
        """

    def test_a_raising_cast_a_continuing_trap_takes_before_a_live_catch_is_removed(self):
        trap = 'trap { continue }'
        self._assertDeobfuscatesToOneOf(self._guarded(trap), self._shell(trap), _ANCHOR)

    def test_a_raising_cast_an_empty_trap_takes_before_a_live_catch_is_removed(self):
        trap = 'trap { }'
        self._assertDeobfuscatesToOneOf(self._guarded(trap), self._shell(trap), _ANCHOR)

    @opportunity
    def test_a_try_left_with_only_a_continuing_trap_dissolves(self):
        self._assertDeobfuscatesTo(self._guarded('trap { continue }'), _ANCHOR)

    @opportunity
    def test_a_try_left_with_only_an_empty_trap_dissolves(self):
        self._assertDeobfuscatesTo(self._guarded('trap { }'), _ANCHOR)


class TestPs1ATrapBodyThatOnlyProducesAValueIsAsInertAsAnEmptyOne(_Ps1FaultEscalation):

    @opportunity
    def test_a_raising_cast_under_a_trap_whose_body_is_a_bare_value_goes_with_it(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ 5 }}
            {_RAISE}
            {_ANCHOR}
        """, _ANCHOR)

    @opportunity
    def test_a_trap_whose_body_is_a_bare_value_goes_above_a_command(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ 5 }}
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1ATrapBodyThatProducesAValueIsLiveWhenOutputIsKept(_Ps1FaultEscalation):

    def test_a_trap_whose_body_is_a_bare_value_still_writes_it_before_the_next_command(self):
        source = F"""
            trap {{ 5 }}
            {_RAISE}
            Write-Host 'A'
        """
        lifted = """
            5
            Write-Host 'A'
        """
        self._assertDeobfuscatesToOneOf(source, source, lifted, preserve_bare_output=True)


class TestPs1ATrapWithAnEmptyBodyLeavesTheRaiseRemovable(_Ps1FaultEscalation):

    def test_a_raising_cast_under_a_trap_whose_body_is_empty_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ }}
            {_RAISE}
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1ATrapInASubexpressionKeepsItsWholeGuardedBracket(_Ps1FaultEscalation):

    def test_a_trap_beside_a_raising_cast_inside_a_subexpression_is_kept(self):
        self._assertKept("$x = $(trap { 'h' }; [int]'a')")


class TestPs1AReadOfErrorObservesARaiseNoHandlerTook(_Ps1FaultEscalation):

    def test_a_raising_cast_a_later_count_of_error_observes_is_kept(self):
        self._assertKept(F"""
            {_RAISE}
            if ($Error.Count) {{
              {_HANDLER}
            }}
            {_ANCHOR}
        """)

    def test_a_raising_cast_a_later_read_of_its_error_record_observes_is_kept(self):
        self._assertKept(F"""
            {_RAISE}
            Write-Host $Error[0].Exception.Message
        """)

    def test_a_stacktrace_read_after_the_raise_observes_it_and_keeps_it(self):
        self._assertKept(F"""
            {_RAISE}
            Write-Host $StackTrace
        """)

    def test_a_named_reference_read_of_error_after_the_raise_keeps_it(self):
        self._assertDeobfuscatesTo(F"""
            {_RAISE}
            Write-Host (Get-Variable Error).Value.Count
        """, F"""
            {_RAISE}
            Write-Host $Error.Count
        """)

    def test_a_splatted_read_of_the_error_record_after_the_raise_keeps_it(self):
        self._assertKept(F"""
            {_RAISE}
            Write-Output @Error
        """)

    def test_the_identical_error_read_moved_before_the_raise_leaves_it_removable(self):
        self._assertDeobfuscatesTo(F"""
            Write-Host $Error[0].Exception.Message
            {_RAISE}
            {_ANCHOR}
        """, F"""
            Write-Host $Error[0].Exception.Message
            {_ANCHOR}
        """)


class TestPs1AReadOfErrorInASeparateBodyIsAKnownInterproceduralGap(_Ps1FaultEscalation):

    @backlog
    def test_a_raise_before_a_call_whose_body_reads_error_is_kept(self):
        self._assertKept(F"""
            function Show-Count {{ Write-Host ($Error.Count) }}
            {_RAISE}
            Show-Count
        """)

    @backlog
    def test_a_raise_before_a_pipeline_scriptblock_that_reads_error_is_kept(self):
        source = F"""
            {_RAISE}
            1..3 | ForEach-Object {{ Write-Host ($Error.Count) }}
        """
        self._assertDeobfuscatesToOneOf(source, source, F"""
            {_RAISE}
            1, 2, 3 | ForEach-Object {{ Write-Host ($Error.Count) }}
        """)

    @backlog
    def test_a_raise_before_a_dot_sourced_block_that_reads_error_is_kept(self):
        self._assertKept(F"""
            {_RAISE}
            . {{ Write-Host ($Error.Count) }}
        """)


class TestPs1ARaiseNoReadOfErrorFollowsIsRemovable(_Ps1FaultEscalation):

    def test_a_raising_cast_after_the_only_read_of_error_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            if ($Error.Count) {{
              {_HANDLER}
            }}
            {_RAISE}
            {_ANCHOR}
        """, F"""
            if ($Error.Count) {{
              {_HANDLER}
            }}
            {_ANCHOR}
        """)


class TestPs1ARaiseInATrapBodyEndsThatBody(_Ps1FaultEscalation):

    def test_a_raising_cast_before_another_statement_of_the_same_trap_body_is_kept(self):
        self._assertKeptButFor(F"""
            trap {{
              {_HANDLER}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_RAISE}
            {_ANCHOR}
        """, _FOLLOWER, _ANCHOR)

    def test_a_raising_cast_in_the_trap_body_of_a_function_is_kept(self):
        self._assertKeptButFor(F"""
            function Invoke-Thing {{
              trap {{
                {_HANDLER}
                {_RAISE}
                {_FOLLOWER}
              }}
              {_RAISE}
            }}
            Invoke-Thing
            {_ANCHOR}
        """, _FOLLOWER)

    def test_a_raising_cast_in_a_nested_block_of_a_firing_trap_body_is_kept(self):
        self._assertKeptButFor(F"""
            trap {{
              {_HANDLER}
              foreach ($i in 1) {{
                {_RAISE}
              }}
              {_FOLLOWER}
            }}
            {_RAISE}
            {_ANCHOR}
        """, _FOLLOWER, _ANCHOR)

    def test_a_trap_body_raise_a_stopping_command_fires_is_kept(self):
        self._assertKeptButFor(F"""
            trap {{
              {_HANDLER}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_STOPPING_RAISE}
            {_ANCHOR}
        """, _FOLLOWER, _ANCHOR)

    def test_a_raising_cast_in_a_trap_body_an_enclosing_catch_takes_is_kept(self):
        self._assertKeptButFor(F"""
            try {{
              trap {{
                {_HANDLER}
                {_RAISE}
                {_FOLLOWER}
              }}
              {_RAISE}
            }} catch {{
              {_OUTER_HANDLER}
            }}
            {_ANCHOR}
        """, _FOLLOWER)

    def test_a_raising_cast_in_a_trap_body_an_enclosing_trap_takes_is_kept(self):
        self._assertKeptButFor(F"""
            trap {{ {_OUTER_HANDLER} }}
            if ({_OPAQUE}) {{
              trap {{
                {_HANDLER}
                {_RAISE}
                {_FOLLOWER}
              }}
              {_RAISE}
            }}
            {_ANCHOR}
        """, _FOLLOWER)


class TestPs1ATrapBodyNothingTriggersLeavesTheRaiseInItRemovable(_Ps1FaultEscalation):

    def test_a_raising_cast_in_the_body_of_a_trap_no_raise_triggers_is_removed(self):
        self._assertDeobfuscatesToOneOf(F"""
            trap {{
              {_HANDLER}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_ANCHOR}
        """, F"""
            trap {{
              {_HANDLER}
              {_FOLLOWER}
            }}
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1ATrapBodyBesideLinesThatCannotFailLeavesTheRaiseInItRemovable(_Ps1FaultEscalation):

    @opportunity
    def test_a_raising_cast_in_the_body_of_a_trap_beside_a_store_is_removed(self):
        self._assertDeobfuscatesToOneOf(F"""
            $s = $env:COMPUTERNAME
            trap {{
              Write-Host $s
              {_RAISE}
              {_FOLLOWER}
            }}
        """, F"""
            $s = $env:ComputerName
            trap {{
              Write-Host $s
              {_FOLLOWER}
            }}
        """, '$s = $env:ComputerName')

    def test_a_raising_cast_in_the_body_of_a_trap_beside_a_function_definition_is_removed(self):
        self._assertDeobfuscatesToOneOf(F"""
            function Invoke-Thing {{
              {_HANDLER}
            }}
            trap {{
              Invoke-Thing
              {_RAISE}
              {_FOLLOWER}
            }}
        """, F"""
            function Invoke-Thing {{
              {_HANDLER}
            }}
            trap {{
              Invoke-Thing
              {_FOLLOWER}
            }}
        """, F"""
            function Invoke-Thing {{
              {_HANDLER}
            }}
        """)

    def test_a_raising_cast_in_the_body_of_a_trap_beside_a_return_is_removed(self):
        self._assertDeobfuscatesToOneOf(F"""
            function Invoke-Thing {{
              trap {{
                {_HANDLER}
                {_RAISE}
                {_FOLLOWER}
              }}
              return
            }}
            Invoke-Thing
        """, F"""
            function Invoke-Thing {{
              trap {{
                {_HANDLER}
                {_FOLLOWER}
              }}
              return
            }}
            Invoke-Thing
        """, """
            function Invoke-Thing {
              return
            }
            Invoke-Thing
        """, '')


class TestPs1AFiringTrapBodyRaiseDependsOnWhichBlockFiresTheTrap(_Ps1FaultEscalation):

    def test_a_process_block_trap_body_raise_a_process_raiser_fires_is_kept(self):
        self._assertKeptButFor(F"""
            function Invoke-Thing {{
              process {{
                trap {{
                  {_HANDLER}
                  {_RAISE}
                  {_FOLLOWER}
                }}
                {_STOPPING_RAISE}
              }}
            }}
            Invoke-Thing
        """, _FOLLOWER)

    def test_a_process_block_trap_body_raise_a_begin_raiser_never_fires_is_removed(self):
        self._assertDeobfuscatesToOneOf(F"""
            function Invoke-Thing {{
              begin {{
                {_STOPPING_RAISE}
              }}
              process {{
                trap {{
                  {_HANDLER}
                  {_RAISE}
                  {_FOLLOWER}
                }}
              }}
            }}
            Invoke-Thing
        """, F"""
            function Invoke-Thing {{
              begin {{
                {_STOPPING_RAISE}
              }}
              process {{
                trap {{
                  {_HANDLER}
                  {_FOLLOWER}
                }}
              }}
            }}
            Invoke-Thing
        """, F"""
            function Invoke-Thing {{
              begin {{
                {_STOPPING_RAISE}
              }}
              process {{
              }}
            }}
            Invoke-Thing
        """, F"""
            function Invoke-Thing {{
              begin {{
                {_STOPPING_RAISE}
              }}
            }}
            Invoke-Thing
        """)


class TestPs1ATrapBodyRaiseABindingFailureFiresIsKept(_Ps1FaultEscalation):

    def test_a_trap_body_raise_a_binding_failure_fires_is_kept(self):
        self._assertKeptButFor(F"""
            trap {{
              {_HANDLER}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_BINDING_FAILURE_RAISE}
            {_ANCHOR}
        """, _FOLLOWER, _ANCHOR)


class TestPs1ATrapBodyRaiseAStrictModeMemberFiresIsKept(_Ps1FaultEscalation):

    def test_a_trap_body_raise_a_strict_mode_member_fires_is_kept(self):
        self._assertKeptButFor(F"""
            Set-StrictMode -Version Latest
            trap {{
              {_HANDLER}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_STRICT_MEMBER_RAISE}
            {_ANCHOR}
        """, _FOLLOWER, _ANCHOR)


class TestPs1ATrapBodyRaiseAStrictModeUnsetReadFiresIsKept(_Ps1FaultEscalation):

    def test_a_trap_body_raise_a_strict_mode_unset_variable_read_fires_is_kept(self):
        self._assertKeptButFor(F"""
            Set-StrictMode -Version Latest
            trap {{
              {_HANDLER}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_STRICT_UNSET_VAR_RAISE}
            {_ANCHOR}
        """, _FOLLOWER, _ANCHOR)


class TestPs1ATrapTakesTheErrorsOfTheNamedBlockItIsWrittenIn(_Ps1FaultEscalation):

    def test_a_raising_cast_beside_a_live_trap_in_the_same_process_block_is_kept(self):
        self._assertKept(F"""
            function Invoke-Thing {{
              process {{
                trap {{ {_HANDLER} }}
                {_RAISE}
                {_FOLLOWER}
              }}
            }}
            Invoke-Thing
        """)

    def test_a_raising_cast_beside_a_live_trap_in_the_same_begin_block_is_kept(self):
        self._assertKept(F"""
            function Invoke-Thing {{
              begin {{
                trap {{ {_HANDLER} }}
                {_RAISE}
                {_FOLLOWER}
              }}
              process {{
                {_ANCHOR}
              }}
            }}
            Invoke-Thing
        """)


class TestPs1ATrapInAnotherNamedBlockLeavesTheRaiseRemovable(_Ps1FaultEscalation):

    def test_a_raising_cast_in_the_process_block_a_begin_block_trap_never_sees_is_removed(self):
        self._assertDeobfuscatesToOneOf(F"""
            function Invoke-Thing {{
              begin {{
                trap {{ {_HANDLER} }}
              }}
              process {{
                {_RAISE}
                {_FOLLOWER}
              }}
            }}
            Invoke-Thing
        """, F"""
            function Invoke-Thing {{
              begin {{
                trap {{ {_HANDLER} }}
              }}
              process {{
                {_FOLLOWER}
              }}
            }}
            Invoke-Thing
        """, F"""
            function Invoke-Thing {{
              begin {{
              }}
              process {{
                {_FOLLOWER}
              }}
            }}
            Invoke-Thing
        """, F"""
            function Invoke-Thing {{
              process {{
                {_FOLLOWER}
              }}
            }}
            Invoke-Thing
        """)


class TestPs1ATrapInAFunctionOutlivesTheRaiseWhereAHandlerMayGuardTheCall(_Ps1FaultEscalation):

    def test_a_trap_in_a_function_a_guarded_call_reaches_is_kept(self):
        self._assertDeobfuscatesTo(F"""
            function Invoke-Thing {{
              trap {{ continue }}
              {_RAISE}
              {_FOLLOWER}
            }}
            try {{
              Invoke-Thing
            }} catch {{
              {_HANDLER}
            }}
        """, F"""
            function Invoke-Thing {{
              trap {{ continue }}
              {_FOLLOWER}
            }}
            try {{
              Invoke-Thing
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_the_same_trap_is_removed_where_the_script_holds_no_handler_at_all(self):
        self._assertDeobfuscatesTo(F"""
            function Invoke-Thing {{
              trap {{ continue }}
              {_RAISE}
              {_FOLLOWER}
            }}
            Invoke-Thing
            {_ANCHOR}
        """, F"""
            function Invoke-Thing {{
              {_FOLLOWER}
            }}
            Invoke-Thing
            {_ANCHOR}
        """)


class TestPs1ACommandToldToStopMakesItsErrorEndTheScript(_Ps1FaultEscalation):

    def test_a_trap_that_continues_over_a_command_told_to_stop_is_kept(self):
        self._assertKept(F"""
            trap {{ continue }}
            {_ACTING_STOPPING_RAISE}
            {_FOLLOWER}
        """)

    def test_an_empty_trap_over_a_command_told_to_stop_is_kept(self):
        self._assertKept(F"""
            trap {{}}
            {_ACTING_STOPPING_RAISE}
            {_FOLLOWER}
        """)

    def test_a_trap_over_a_command_told_to_stop_inside_a_branch_is_kept(self):
        self._assertKept(F"""
            trap {{ continue }}
            if ({_OPAQUE}) {{
              {_ACTING_STOPPING_RAISE}
            }}
            {_FOLLOWER}
        """)

    def test_a_trap_over_a_command_told_to_continue_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            Write-Host (Get-Item nope -ErrorAction Continue)
            {_FOLLOWER}
        """, F"""
            Write-Host (Get-Item nope -ErrorAction Continue)
            {_FOLLOWER}
        """)


class TestPs1ADiscardedCommandToldToStopIsKeptWithNoHandler(_Ps1FaultEscalation):

    def test_a_discarded_command_told_to_stop_with_no_handler_is_kept(self):
        self._assertKept(F"""
            $Null = {_STOPPING_RAISE}
            {_FOLLOWER}
        """)

    def test_a_discarded_command_told_to_continue_with_no_handler_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            $Null = Get-Item nope -ErrorAction Continue
            {_FOLLOWER}
        """, _FOLLOWER)


class TestPs1AnExitIsNoRaiseAnyTrapDisposesOf(_Ps1FaultEscalation):

    def test_a_trap_over_an_exit_in_a_branch_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            if ({_OPAQUE}) {{
              exit 3
            }}
            {_FOLLOWER}
        """, F"""
            if ({_OPAQUE}) {{
              exit 3
            }}
            {_FOLLOWER}
        """)


class TestPs1AStopPreferenceMakesEveryTrapLoadBearing(_Ps1FaultEscalation):

    def test_a_trap_under_a_stop_preference_outlives_the_raise_it_guards(self):
        self._assertDeobfuscatesTo(F"""
            $ErrorActionPreference = 'Stop'
            trap {{ continue }}
            {_RAISE}
            {_FOLLOWER}
        """, F"""
            $ErrorActionPreference = 'Stop'
            trap {{ continue }}
            {_FOLLOWER}
        """)


class TestPs1EverySpellingOfTheStopActionMakesTheTrapOverItLoadBearing(_Ps1FaultEscalation):

    def _assertTheTrapOverTheActionIsKept(self, action: str) -> None:
        def guarded(argument: str) -> str:
            return F"""
                trap {{ continue }}
                Write-Host (Get-Item nope -ErrorAction {argument})
                {_FOLLOWER}
            """
        self._assertDeobfuscatesToOneOf(
            guarded(action),
            guarded(action),
            guarded('Stop'),
            guarded("'Stop'"),
        )

    def test_the_member_name_selects_stop_however_it_is_cased_or_quoted(self):
        for action in ['Stop', 'stop', 'STOP', "'Stop'", '"Stop"']:
            with self.subTest(action):
                self._assertTheTrapOverTheActionIsKept(action)

    def test_an_abbreviation_no_other_member_answers_to_selects_stop(self):
        for action in ['St', 'Sto']:
            with self.subTest(action):
                self._assertTheTrapOverTheActionIsKept(action)

    def test_the_ordinal_of_stop_selects_it_however_the_integer_is_spelled(self):
        for action in ['1', '01', '0x1']:
            with self.subTest(action):
                self._assertTheTrapOverTheActionIsKept(action)


class TestPs1EverySpellingOfTheErrorActionParameterCarriesTheStopItIsGiven(_Ps1FaultEscalation):

    def _assertTheTrapOverTheCommandIsKept(self, command: str, expected: str) -> None:
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            {command}
            {_FOLLOWER}
        """, F"""
            trap {{ continue }}
            {expected}
            {_FOLLOWER}
        """)

    def _assertTheTrapOverTheParameterIsKept(self, parameter: str) -> None:
        self._assertTheTrapOverTheCommandIsKept(
            F'Write-Host (Get-Item nope {parameter} Stop)',
            'Write-Host (Get-Item nope -ErrorAction Stop)',
        )

    def test_a_prefix_no_other_parameter_answers_to_binds_the_action(self):
        for parameter in ['-ErrorAction', '-erroraction', '-ErrorActio', '-ErrorAc', '-ErrorA']:
            with self.subTest(parameter):
                self._assertTheTrapOverTheParameterIsKept(parameter)

    def test_the_documented_alias_of_the_parameter_binds_the_action(self):
        for parameter in ['-EA', '-ea']:
            with self.subTest(parameter):
                self._assertTheTrapOverTheParameterIsKept(parameter)

    def test_an_action_attached_to_the_parameter_with_a_colon_binds_it(self):
        for command in [
            'Write-Host (Get-Item nope -ErrorAction:Stop)',
            'Write-Host (Get-Item nope -EA:Stop)',
        ]:
            with self.subTest(command):
                self._assertTheTrapOverTheCommandIsKept(
                    command, 'Write-Host (Get-Item nope -ErrorAction:Stop)',
                )


class TestPs1EverySpellingOfAnActionOtherThanStopLeavesTheTrapRemovable(_Ps1FaultEscalation):

    def _assertTheTrapOverTheCommandIsRemoved(self, command: str, expected: str) -> None:
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            {command}
            {_FOLLOWER}
        """, F"""
            {expected}
            {_FOLLOWER}
        """)

    def _assertTheTrapOverTheActionIsRemoved(self, action: str, member: str) -> None:
        def unguarded(argument: str) -> str:
            return F"""
                Write-Host (Get-Item nope -ErrorAction {argument})
                {_FOLLOWER}
            """
        self._assertDeobfuscatesToOneOf(F"""
            trap {{ continue }}
            Write-Host (Get-Item nope -ErrorAction {action})
            {_FOLLOWER}
        """, *(unguarded(argument) for argument in (action, member, F"'{member}'")))

    def test_a_member_name_other_than_stop_leaves_the_trap_removable(self):
        for action in ['Continue', 'SilentlyContinue', 'Ignore']:
            with self.subTest(action):
                self._assertTheTrapOverTheActionIsRemoved(action, action)

    def test_an_abbreviation_of_a_member_other_than_stop_leaves_the_trap_removable(self):
        for action, member in [
            ('Cont', 'Continue'),
            ('Sil', 'SilentlyContinue'),
            ('Ig', 'Ignore'),
        ]:
            with self.subTest(action):
                self._assertTheTrapOverTheActionIsRemoved(action, member)

    def test_the_ordinal_of_a_member_other_than_stop_leaves_the_trap_removable(self):
        for action, member in [
            ('0', 'SilentlyContinue'),
            ('2', 'Continue'),
            ('4', 'Ignore'),
            ('0x2', 'Continue'),
        ]:
            with self.subTest(action):
                self._assertTheTrapOverTheActionIsRemoved(action, member)

    def test_a_member_other_than_stop_attached_with_a_colon_leaves_the_trap_removable(self):
        commands = [
            'Write-Host (Get-Item nope -ErrorAction:Continue)',
            'Write-Host (Get-Item nope -EA:SilentlyContinue)',
        ]
        expected = [
            'Write-Host (Get-Item nope -ErrorAction:Continue)',
            'Write-Host (Get-Item nope -ErrorAction:SilentlyContinue)',
        ]
        for command, spelled in zip(commands, expected):
            with self.subTest(command):
                self._assertTheTrapOverTheCommandIsRemoved(command, spelled)


class TestPs1AnActionThatArrivesBySplattingIsTheActionTheCommandRunsUnder(_Ps1FaultEscalation):

    def test_a_table_that_carries_stop_makes_the_trap_load_bearing(self):
        self._assertKept(F"""
            trap {{ continue }}
            $p = @{{ErrorAction = 'Stop'}}
            Write-Host (Get-Item nope @p)
            {_FOLLOWER}
        """)

    @opportunity
    def test_a_table_that_carries_continue_leaves_the_trap_removable(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            $p = @{{ErrorAction = 'Continue'}}
            Write-Host (Get-Item nope @p)
            {_FOLLOWER}
        """, F"""
            $p = @{{ErrorAction = 'Continue'}}
            Write-Host (Get-Item nope @p)
            {_FOLLOWER}
        """)


class TestPs1EverySpellingOfTheStopPreferenceMakesTheTrapUnderItLoadBearing(_Ps1FaultEscalation):

    def _assertTheTrapUnderTheWriteIsKept(self, assignment: str) -> None:
        guarded = self._apply(inspect.cleandoc(F"""
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """))
        output = self._deobfuscate(inspect.cleandoc(F"""
            {assignment}
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """))
        self.assertTrue(output.endswith(guarded), output)
        self.assertIn('ErrorActionPreference', output.removesuffix(guarded))

    def test_a_plain_write_of_the_preference_arms_every_error(self):
        self._assertTheTrapUnderTheWriteIsKept("$ErrorActionPreference = 'Stop'")

    def test_a_type_constrained_write_of_the_preference_arms_every_error(self):
        self._assertTheTrapUnderTheWriteIsKept("[string]$ErrorActionPreference = 'Stop'")

    def test_a_parenthesized_write_of_the_preference_arms_every_error(self):
        self._assertTheTrapUnderTheWriteIsKept("($ErrorActionPreference) = 'Stop'")

    def test_a_multiple_assignment_that_names_the_preference_arms_every_error(self):
        self._assertTheTrapUnderTheWriteIsKept("$a, $ErrorActionPreference = 1, 'Stop'")

    def test_a_scope_qualified_write_of_the_preference_arms_every_error(self):
        self._assertTheTrapUnderTheWriteIsKept("$global:ErrorActionPreference = 'Stop'")

    def test_the_ordinal_of_stop_written_to_the_preference_arms_every_error(self):
        self._assertTheTrapUnderTheWriteIsKept('$ErrorActionPreference = 1')


class TestPs1AWriteThatArmsNoStopLeavesTheTrapRemovable(_Ps1FaultEscalation):

    def _assertTheTrapUnderTheWriteIsRemoved(self, assignment: str) -> None:
        self._assertDeobfuscatesTo(F"""
            {assignment}
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """, F"""
            {assignment}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)

    def test_a_trap_over_a_command_no_write_arms_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """, F"""
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)

    def test_a_preference_set_to_continue_arms_nothing(self):
        self._assertTheTrapUnderTheWriteIsRemoved("$ErrorActionPreference = 'Continue'")

    def test_a_preference_set_to_the_ordinal_of_continue_arms_nothing(self):
        self._assertTheTrapUnderTheWriteIsRemoved('$ErrorActionPreference = 2')


class TestPs1ATerminatingErrorReachedThroughACallIsHandedToTheCaller(_Ps1FaultEscalation):

    def test_a_trap_over_a_call_to_a_function_that_throws_stays_while_the_call_does(self):
        source = F"""
            function Invoke-Raise {{
              throw 'e'
            }}
            function Invoke-Wrapper {{
              trap {{ continue }}
              Invoke-Raise
              {_FOLLOWER}
            }}
            Invoke-Wrapper
            {_ANCHOR}
        """
        self._assertDeobfuscatesToOneOf(source, source, F"""
            function Invoke-Wrapper {{
              {_FOLLOWER}
            }}
            Invoke-Wrapper
            {_ANCHOR}
        """)


class TestPs1ATerminatingErrorInsideAStringThatIsRunIsInvisible(_Ps1FaultEscalation):

    def test_a_trap_over_a_string_that_is_run_and_throws_stays_while_the_throw_does(self):
        source = F"""
            trap {{ continue }}
            iex 'throw 1'
            {_FOLLOWER}
        """
        self._assertDeobfuscatesToOneOf(source, source, F"""
            trap {{ continue }}
            throw 1
            {_FOLLOWER}
        """, _FOLLOWER)


class TestPs1AStopPreferenceACmdletArmsMakesEveryErrorTerminating(_Ps1FaultEscalation):

    def test_a_preference_a_cmdlet_arms_keeps_the_trap_while_the_cast_stays(self):
        self._assertTheTrapStaysWhileTheCastDoes(F"""
            New-Variable ErrorActionPreference Stop -Force
            trap {{ continue }}
            {_CAST_RAISE}
            {_FOLLOWER}
        """)

    def test_a_cmdlet_that_writes_a_member_other_than_stop_leaves_the_trap_removable(self):
        self._assertDeobfuscatesTo(F"""
            New-Variable ErrorActionPreference Continue -Force
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """, F"""
            New-Variable ErrorActionPreference Continue -Force
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)


class TestPs1AStopBoundThroughDefaultParameterValuesMakesCommandsTerminating(_Ps1FaultEscalation):

    def _assertTheTrapUnderTheDefaultIsKept(self, write: str) -> None:
        self._assertKept(F"""
            {write}
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)

    def test_an_index_assignment_of_stop_binds_the_action(self):
        self._assertTheTrapUnderTheDefaultIsKept(
            "$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'")

    def test_a_command_scoped_key_binds_the_action(self):
        self._assertTheTrapUnderTheDefaultIsKept(
            "$PSDefaultParameterValues['Get-Item:ErrorAction'] = 'Stop'")

    def test_the_add_mutation_of_stop_binds_the_action(self):
        self._assertTheTrapUnderTheDefaultIsKept(
            "$PSDefaultParameterValues.Add('*:ErrorAction', 'Stop')")

    def test_an_alias_key_binds_the_action(self):
        self._assertTheTrapUnderTheDefaultIsKept(
            "$PSDefaultParameterValues['*:ea'] = 'Stop'")

    def test_a_member_assignment_of_stop_binds_the_action(self):
        self._assertTheTrapUnderTheDefaultIsKept(
            "$PSDefaultParameterValues.'*:ErrorAction' = 'Stop'")

    def test_a_default_that_binds_a_member_other_than_stop_leaves_the_trap_removable(self):
        self._assertDeobfuscatesTo(F"""
            $PSDefaultParameterValues['*:ErrorAction'] = 'Continue'
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """, F"""
            $PSDefaultParameterValues['*:ErrorAction'] = 'Continue'
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)


class TestPs1AStopArmingTheRemovalGateStillMisses(_Ps1FaultEscalation):

    @backlog
    def test_a_splatted_write_of_the_preference_keeps_the_trap_while_the_cast_stays(self):
        self._assertTheTrapStaysWhileTheCastDoes(F"""
            $t = @{{ Name = 'ErrorActionPreference'; Value = 'Stop' }}
            Set-Variable @t
            & {{
              trap {{ continue }}
              {_CAST_RAISE}
              {_FOLLOWER}
            }}
        """)

    def test_a_literal_path_write_of_the_preference_keeps_the_trap_while_the_cast_stays(self):
        self._assertTheTrapStaysWhileTheCastDoes(F"""
            Set-Item -LiteralPath Variable:ErrorActionPreference Stop
            trap {{ continue }}
            {_CAST_RAISE}
            {_FOLLOWER}
        """)

    def test_a_whole_table_replacement_that_binds_the_action_keeps_the_trap(self):
        self._assertKept(F"""
            $PSDefaultParameterValues = @{{ '*:ErrorAction' = 'Stop' }}
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)

    @backlog
    def test_an_aliased_table_that_binds_the_action_keeps_the_trap(self):
        self._assertKept(F"""
            $x = $PSDefaultParameterValues
            $x['*:ErrorAction'] = 'Stop'
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)


class TestPs1AComputedMemberCallOnTheDefaultTableMayArmAStop(_Ps1FaultEscalation):

    def test_a_computed_member_mutation_of_the_default_table_keeps_the_trap(self):
        guarded = self._apply(inspect.cleandoc(F"""
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """))
        output = self._deobfuscate(inspect.cleandoc(F"""
            $n = 'Add'
            $PSDefaultParameterValues.$n('*:ErrorAction', 'Stop')
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """))
        self.assertTrue(output.endswith(guarded), output)
        self.assertIn('$PSDefaultParameterValues.', output.removesuffix(guarded))
        self.assertIn("('*:ErrorAction', 'Stop')", output.removesuffix(guarded))


class TestPs1AnAmbiguousActionPrefixKeepsTheTrapOverIt(_Ps1FaultEscalation):

    @opportunity
    def test_a_trap_over_a_command_whose_action_prefix_is_ambiguous_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            Write-Host (Get-Item nope -ErrorAction S)
            {_FOLLOWER}
        """, F"""
            Write-Host (Get-Item nope -ErrorAction S)
            {_FOLLOWER}
        """)


class TestPs1AThrowInsideAnUninvokedBlockLeavesTheTrapBesideItRemovable(_Ps1FaultEscalation):

    def test_a_trap_beside_a_stored_block_that_throws_is_removed(self):
        self._assertDeobfuscatesToOneOf(F"""
            trap {{ continue }}
            $s = {{ throw 'x' }}
            {_RAISE}
            {_FOLLOWER}
        """, F"""
            $Null = {{ throw 'x' }}
            {_FOLLOWER}
        """, _FOLLOWER)
