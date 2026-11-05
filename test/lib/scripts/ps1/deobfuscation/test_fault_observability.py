from __future__ import annotations

import inspect

from unittest.mock import patch

from refinery.lib.scripts.ps1.analysis import faults

from test import opportunity, todo
from test.lib.scripts.ps1.deobfuscation import TestPs1

_RAISE = "$Null = [Int]'abc'"

_RAISE_DIV = '$Null = 1/0'

_MAY_RAISE = '$Null = [Int]$env:FOO'
_MAY_RAISE_DIV = '$Null = 1 / $env:FOO'

_QUIET_CAST = "$Null = [Int]'42'"
_QUIET_DIVISION = '$Null = 1/1'
_QUIET_PRODUCT = '$Null = 6 * 7'
_QUIET_LENGTH = "$Null = 'abcdef'.Length"
_QUIET_REMAINDER = '$Null = 10 % 3'
_QUIET_CHAR = '$Null = [Char]65'
_QUIET_CONCATENATION = "$Null = 'ab' + 'cd'"
_QUIET_STRING = '$Null = [String]12'
_QUIET_CONJUNCTION = '$Null = 3 -Band 1'
_QUIET_NEGATION = '$Null = -Not $True'
_QUIET_BOOL = "$Null = [Bool]'x'"
_QUIET_COUNT = '$Null = @(1, 2, 3).Count'

_ANCHOR = "Write-Host 'ANCHOR_SURVIVES'"

_HANDLER = "Write-Host 'HANDLER_RAN'"

_CLEANUP = "Write-Host 'CLEANUP_RAN'"

_OPAQUE = '$args'

_UNSET_READ = '[void]$zzqunset'

_UNSET_OUTPUT = '$zzqbare'

_UNSET_PIPELINE = '$zzqunset | ForEach-Object { [void]$_ }'

_STRICT = 'Set-StrictMode -Version 1'

_STRICT_PSDEBUG = 'Set-PSDebug -Strict'

_STRICT_IN_A_STRING = "Invoke-Expression 'Set-StrictMode -Version 1'"

_UNREADABLE = 'Invoke-Expression $env:ZZQPAYLOAD'

_REQUEST = 'Invoke-WebRequest $u'


class TestPs1ARaisingStatementDirectlyInAGuardedTryBlockIsKept(TestPs1):

    def test_a_raising_cast_directly_in_the_try_block_is_kept(self):
        self._assertKept(F"""
            try {{
              {_MAY_RAISE}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_raising_division_directly_in_the_try_block_is_kept(self):
        self._assertKept(F"""
            try {{
              {_MAY_RAISE_DIV}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)


class TestPs1AStatementNestedInAGuardedTryBlock(TestPs1):

    def _assertRemovedWithOrWithoutItsConstruct(
        self,
        source: str,
        statement: str,
        construct: str,
    ) -> None:
        source = inspect.cleandoc(source)
        self.assertIn(construct, source)
        self.assertIn(statement, construct)
        self._assertDeobfuscatesToOneOf(
            source,
            source.replace(statement, ''),
            source.replace(construct, ''),
        )

    def test_a_raising_cast_in_a_nested_if_body_is_kept(self):
        self._assertKept(F"""
            try {{
              if ({_OPAQUE}) {{ {_RAISE} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_quiet_cast_in_a_nested_if_body_is_removed(self):
        self._assertRemovedWithOrWithoutItsConstruct(F"""
            try {{
              if ({_OPAQUE}) {{ {_QUIET_CAST} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _QUIET_CAST, F'if ({_OPAQUE}) {{ {_QUIET_CAST} }}')

    def test_a_raising_cast_in_a_nested_foreach_body_is_kept(self):
        self._assertKept(F"""
            try {{
              foreach ($i in {_OPAQUE}) {{ {_RAISE} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_quiet_product_in_a_nested_foreach_body_is_removed(self):
        self._assertRemovedWithOrWithoutItsConstruct(F"""
            try {{
              foreach ($i in {_OPAQUE}) {{ {_QUIET_PRODUCT} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _QUIET_PRODUCT, F'foreach ($i in {_OPAQUE}) {{ {_QUIET_PRODUCT} }}')

    def test_a_raising_cast_in_a_nested_while_body_is_kept(self):
        self._assertKept(F"""
            try {{
              while ({_OPAQUE}) {{ {_RAISE} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_quiet_length_in_a_nested_while_body_is_removed(self):
        self._assertRemoved(F"""
            try {{
              while ({_OPAQUE}) {{ {_QUIET_LENGTH} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _QUIET_LENGTH)

    def test_a_raising_cast_in_a_nested_switch_case_body_is_kept(self):
        self._assertKept(F"""
            try {{
              switch ({_OPAQUE}) {{ 1 {{ {_RAISE} }} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_quiet_remainder_in_a_nested_switch_case_body_is_removed(self):
        self._assertRemovedWithOrWithoutItsConstruct(F"""
            try {{
              switch ({_OPAQUE}) {{ 1 {{ {_QUIET_REMAINDER} }} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _QUIET_REMAINDER, F'switch ({_OPAQUE}) {{ 1 {{ {_QUIET_REMAINDER} }} }}')

    def test_a_raising_cast_in_a_scriptblock_invoked_in_place_runs_the_catch(self):
        source = inspect.cleandoc(F"""
            try {{
              & {{ {_RAISE} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)
        self._assertDeobfuscatesToOneOf(source, source, source.replace(_ANCHOR, ''), _HANDLER)

    def test_a_quiet_char_in_a_scriptblock_invoked_in_place_is_removed(self):
        self._assertRemovedWithOrWithoutItsConstruct(F"""
            try {{
              & {{ {_QUIET_CHAR} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _QUIET_CHAR, F'& {{ {_QUIET_CHAR} }}')

    def test_a_raising_division_in_a_nested_if_body_is_kept(self):
        self._assertKept(F"""
            try {{
              if ({_OPAQUE}) {{ {_RAISE_DIV} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_quiet_division_in_a_nested_if_body_is_removed(self):
        self._assertRemovedWithOrWithoutItsConstruct(F"""
            try {{
              if ({_OPAQUE}) {{ {_QUIET_DIVISION} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _QUIET_DIVISION, F'if ({_OPAQUE}) {{ {_QUIET_DIVISION} }}')


class TestPs1AStatementInAFunctionAGuardedTryBlockCalls(TestPs1):

    def test_a_raising_cast_in_a_function_the_try_block_calls_runs_the_catch(self):
        source = inspect.cleandoc(F"""
            function Invoke-Thing {{
              {_RAISE}
            }}
            try {{
              Invoke-Thing
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)
        self._assertDeobfuscatesToOneOf(source, source, source.replace(_ANCHOR, ''), _HANDLER)

    def test_a_quiet_concatenation_in_a_function_the_try_block_calls_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            function Invoke-Thing {{
              {_QUIET_CONCATENATION}
            }}
            try {{
              Invoke-Thing
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


class TestPs1AnEmptyCatchSwallowsSoTheRaisingStatementIsRemovable(TestPs1):

    def test_a_raising_cast_guarded_only_by_an_empty_catch_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{ {_RAISE} }} catch {{ }}
            {_ANCHOR}
        """, _ANCHOR)

    def test_a_raising_cast_an_empty_inner_catch_shields_from_a_live_outer_catch_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              try {{ {_RAISE} }} catch {{ }}
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

    def test_a_raising_cast_under_an_empty_catch_beside_a_live_catch_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{ {_RAISE} }} catch {{ }}
            try {{ {_REQUEST} }} catch {{ {_HANDLER} }}
            {_ANCHOR}
        """, F"""
            try {{ {_REQUEST} }} catch {{ {_HANDLER} }}
            {_ANCHOR}
        """)


class TestPs1AFinallyAloneDoesNotGuardTheRaisingStatement(TestPs1):

    def test_a_raising_cast_in_a_try_whose_only_clause_is_a_finally_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{ {_RAISE} }} finally {{ {_CLEANUP} }}
            {_ANCHOR}
        """, F"""
            {_CLEANUP}
            {_ANCHOR}
        """)


class TestPs1AnInnerFinallyDoesNotShieldAnOuterCatch(TestPs1):

    def test_a_raising_cast_under_an_inner_finally_runs_the_finally_then_the_outer_catch(self):
        source = inspect.cleandoc(F"""
            try {{
              try {{ {_RAISE} }} finally {{ {_CLEANUP} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)
        self._assertDeobfuscatesToOneOf(
            source,
            source,
            source.replace(_ANCHOR, ''),
            F"""
                {_CLEANUP}
                {_HANDLER}
            """,
        )

    def test_a_quiet_string_under_an_inner_finally_inside_a_live_outer_catch_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              try {{ {_QUIET_STRING} }} finally {{ {_CLEANUP} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, F"""
            try {{
              {_CLEANUP}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)


class TestPs1ALiveTrapGuardsItsWholeScope(TestPs1):

    def test_a_raising_cast_below_a_live_trap_in_the_same_scope_is_kept(self):
        self._assertKept(F"""
            trap {{ {_HANDLER} }}
            {_RAISE}
            {_ANCHOR}
        """)

    def test_a_quiet_conjunction_below_a_live_trap_in_the_same_scope_is_removed(self):
        self._assertRemoved(F"""
            trap {{ {_HANDLER} }}
            {_QUIET_CONJUNCTION}
            {_ANCHOR}
        """, _QUIET_CONJUNCTION)

    def test_a_raising_cast_above_a_live_trap_in_the_same_scope_is_kept(self):
        self._assertKept(F"""
            {_RAISE}
            trap {{ {_HANDLER} }}
            {_ANCHOR}
        """)

    def test_a_quiet_negation_above_a_live_trap_in_the_same_scope_is_removed(self):
        self._assertRemoved(F"""
            {_QUIET_NEGATION}
            trap {{ {_HANDLER} }}
            {_ANCHOR}
        """, _QUIET_NEGATION)

    def test_a_raising_cast_nested_in_a_scope_a_live_trap_guards_is_kept(self):
        self._assertKept(F"""
            trap {{ {_HANDLER} }}
            if ({_OPAQUE}) {{
              {_RAISE}
              {_ANCHOR}
            }}
        """)

    def test_a_quiet_bool_nested_in_a_scope_a_live_trap_guards_is_removed(self):
        self._assertRemoved(F"""
            trap {{ {_HANDLER} }}
            if ({_OPAQUE}) {{
              {_QUIET_BOOL}
              {_ANCHOR}
            }}
        """, _QUIET_BOOL)

    def test_a_raising_cast_in_a_function_scope_a_live_trap_guards_is_kept(self):
        self._assertKept(F"""
            function Invoke-Thing {{
              trap {{ {_HANDLER} }}
              {_RAISE}
            }}
            Invoke-Thing
            {_ANCHOR}
        """)

    def test_a_quiet_count_in_a_function_scope_a_live_trap_guards_is_removed(self):
        self._assertRemoved(F"""
            function Invoke-Thing {{
              trap {{ {_HANDLER} }}
              {_QUIET_COUNT}
            }}
            Invoke-Thing
            {_ANCHOR}
        """, _QUIET_COUNT)


class TestPs1ATrapOutOfScopeLeavesTheStatementRemovable(TestPs1):

    def test_a_raising_cast_outside_the_scope_of_a_live_trap_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            function Invoke-Thing {{
              trap {{ {_HANDLER} }}
              {_REQUEST}
            }}
            Invoke-Thing
            {_RAISE}
            {_ANCHOR}
        """, F"""
            function Invoke-Thing {{
              trap {{ {_HANDLER} }}
              {_REQUEST}
            }}
            Invoke-Thing
            {_ANCHOR}
        """)


class TestPs1AStatementTerminatingRaiseAboveAStatementIsRemovable(TestPs1):

    def test_a_raising_cast_above_a_statement_at_script_scope_is_removed(self):
        self._assertRemoved(F"""
            {_RAISE}
            {_ANCHOR}
        """, _RAISE)

    def test_a_raising_division_above_a_statement_at_script_scope_is_removed(self):
        self._assertRemoved(F"""
            {_RAISE_DIV}
            {_ANCHOR}
        """, _RAISE_DIV)

    def test_a_raising_cast_in_a_called_function_leaves_only_the_statement_below(self):
        self._assertDeobfuscatesTo(F"""
            function Invoke-Thing {{ {_RAISE} }}
            Invoke-Thing
            {_ANCHOR}
        """, _ANCHOR)

    def test_a_raising_cast_above_a_statement_in_the_same_branch_body_is_removed(self):
        self._assertRemoved(F"""
            if ({_OPAQUE}) {{
              {_RAISE}
              Write-Host 'BRANCH_RUNS'
            }}
            {_ANCHOR}
        """, _RAISE)

    def test_a_quiet_cast_above_a_statement_at_script_scope_is_removed(self):
        self._assertRemoved(F"""
            {_QUIET_CAST}
            {_ANCHOR}
        """, _QUIET_CAST)


class TestPs1AReadOfAnUnsetVariableRaisesOnlyWhereStrictModeIsArmed(TestPs1):

    def test_a_discarded_unset_read_in_a_guarded_try_block_is_removed(self):
        self._assertRemoved(F"""
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _UNSET_READ)

    def test_the_same_read_written_as_bare_output_is_removed_alike(self):
        self._assertRemoved(F"""
            try {{
              {_UNSET_OUTPUT}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _UNSET_OUTPUT)

    def test_a_discarded_unset_read_under_a_trap_that_acts_is_removed(self):
        self._assertRemoved(F"""
            trap {{ {_HANDLER} }}
            {_UNSET_READ}
            {_ANCHOR}
        """, _UNSET_READ)

    def test_a_discarded_pipeline_over_an_unset_read_is_removed(self):
        self._assertRemoved(F"""
            {_UNSET_PIPELINE}
            try {{
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _UNSET_PIPELINE)

    def test_the_pipeline_is_removed_beside_a_handler_that_does_not_stand_over_it(self):
        self._assertRemoved(F"""
            {_STRICT}
            {_UNSET_PIPELINE}
            try {{
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _UNSET_PIPELINE)

    def test_the_discard_and_the_output_are_both_kept_where_strict_mode_is_armed(self):
        self._assertKept(F"""
            {_STRICT}
            try {{
              {_UNSET_READ}
              {_UNSET_OUTPUT}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)


    def test_the_discard_and_the_output_are_both_kept_where_the_other_command_arms_it(self):
        self._assertKept(F"""
            {_STRICT_PSDEBUG}
            try {{
              {_UNSET_READ}
              {_UNSET_OUTPUT}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_the_pipeline_is_removed_where_the_other_command_arms_it(self):
        self._assertRemoved(F"""
            {_STRICT_PSDEBUG}
            {_UNSET_PIPELINE}
            try {{
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _UNSET_PIPELINE)

    def test_the_discard_under_a_trap_is_kept_where_the_other_command_arms_it(self):
        self._assertKept(F"""
            trap {{ {_HANDLER} }}
            {_STRICT_PSDEBUG}
            {_UNSET_READ}
            {_ANCHOR}
        """)

    def test_the_arming_is_seen_where_it_is_written_as_a_string(self):
        self._assertDeobfuscatesTo(F"""
            {_STRICT_IN_A_STRING}
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, F"""
            {_STRICT}
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)


class TestPs1AnUnreadablePayloadMayArmStrictModeWithoutSpellingIt(TestPs1):

    def test_a_discarded_unset_read_below_an_unreadable_payload_is_kept(self):
        self._assertKept(F"""
            {_UNREADABLE}
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_discarded_pipeline_below_an_unreadable_payload_is_kept(self):
        self._assertKept(F"""
            {_UNREADABLE}
            {_UNSET_PIPELINE}
            try {{
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_the_same_read_above_that_payload_is_removed(self):
        self._assertRemoved(F"""
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
            {_UNREADABLE}
        """, _UNSET_READ)

    @todo
    def test_a_bare_unset_read_below_an_unreadable_payload_with_no_handler_is_kept(self):
        # The payload may arm strict mode and set `$ErrorActionPreference` to `Stop`; the read then
        # ends the script before the anchor runs.
        self._assertKept(F"""
            {_UNREADABLE}
            {_UNSET_OUTPUT}
            {_ANCHOR}
        """)

    @todo
    def test_a_discarded_unset_read_below_an_unreadable_payload_with_no_handler_is_kept(self):
        self._assertKept(F"""
            {_UNREADABLE}
            {_UNSET_READ}
            {_ANCHOR}
        """)


class TestPs1OnlyABareNameIsGrantedTheStrictModeReading(TestPs1):

    def _assertKeptInAGuardedBlock(self, statement: str) -> None:
        self._assertKept(F"""
            try {{
              {statement}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_discarded_member_read_is_kept(self):
        self._assertKeptInAGuardedBlock('[void]$zzqunset.Foo')

    def test_a_discarded_index_read_is_kept(self):
        self._assertKeptInAGuardedBlock('[void]$zzqunset[0]')


class TestPs1AQualifiedReadRaisesNothingWhereStrictModeIsOff(TestPs1):

    def _assertRemovedFromAGuardedBlock(self, statement: str) -> None:
        self._assertRemoved(F"""
            try {{
              {statement}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, statement)

    @opportunity
    def test_a_discarded_environment_read_is_removed(self):
        self._assertRemovedFromAGuardedBlock('[void]$env:ZZQUNSET')

    @opportunity
    def test_a_discarded_scope_qualified_read_is_removed(self):
        self._assertRemovedFromAGuardedBlock('[void]$global:zzqunset')


#: Code that each of these runs may call `Set-PSDebug -Strict`, which 5.1 applies to the global
#: scope and so to the caller, where `Set-StrictMode` in that code applies only to its own scope.
_RUNS_UNREADABLE_CODE = (
    'using module Zzqfoo',
    'Invoke-History',
    'Add-PSSnapin Zzqfoo',
    'Import-PSSession $s',
    'Register-EngineEvent -SourceIdentifier z -Action $sb',
    'Zzqunknowncommand',
)

class TestPs1ACommandThatRunsUnreadableCodeIsNotAlwaysAWorldOpener(TestPs1):

    def _assertReadSurvivesBelow(self, command: str) -> None:
        self._assertKept(F"""
            {command}
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    @todo
    def test_a_module_loaded_by_the_using_statement_keeps_the_read(self):
        self._assertReadSurvivesBelow(_RUNS_UNREADABLE_CODE[0])

    @todo
    def test_a_replayed_history_entry_keeps_the_read(self):
        self._assertReadSurvivesBelow(_RUNS_UNREADABLE_CODE[1])

    @todo
    def test_a_loaded_snapin_keeps_the_read(self):
        self._assertReadSurvivesBelow(_RUNS_UNREADABLE_CODE[2])

    @todo
    def test_an_imported_session_keeps_the_read(self):
        self._assertReadSurvivesBelow(_RUNS_UNREADABLE_CODE[3])

    @todo
    def test_an_event_action_keeps_the_read(self):
        self._assertReadSurvivesBelow(_RUNS_UNREADABLE_CODE[4])

    @todo
    def test_a_command_this_analysis_cannot_resolve_keeps_the_read(self):
        self._assertReadSurvivesBelow(_RUNS_UNREADABLE_CODE[5])

    def test_the_two_spellings_the_world_does_count_keep_it_today(self):
        for command in ('Import-Module Zzqfoo', _UNREADABLE):
            with self.subTest(command):
                self._assertReadSurvivesBelow(command)


class TestPs1TheGrantAssumesTheEntryScopeRunsDefaultSemantics(TestPs1):

    @todo
    def test_the_discarded_read_survives_when_the_caller_says_this_is_a_fragment(self):
        self._assertKept(F"""
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, preserve_bare_output=True)

    def test_the_bare_output_read_survives_there_today(self):
        self._assertKept(F"""
            try {{
              {_UNSET_OUTPUT}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, preserve_bare_output=True)


class TestPs1AFunctionBodyIsNotWeighedAtItsDefinitionsPosition(TestPs1):

    def test_a_body_read_is_kept_where_the_call_below_a_payload_is_guarded(self):
        self._assertKept(F"""
            function Zzqf {{
              {_UNSET_READ}
            }}
            {_UNREADABLE}
            try {{
              Zzqf
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_the_same_body_read_goes_where_nothing_unreadable_runs_at_all(self):
        self._assertDeobfuscatesTo(F"""
            function Zzqf {{
              {_UNSET_READ}
            }}
            try {{
              Zzqf
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


class TestPs1TheStrictModeScanStaysLinearInTheSizeOfTheScript(TestPs1):

    def _armings_asked(self, statements: int) -> int:
        source = '\n'.join([
            F"trap {{ {_HANDLER} }}",
            *(F'[void]$zzq{index}' for index in range(statements)),
            _ANCHOR,
        ])
        asked = 0
        real = faults._arms_strict_mode

        def counted(node):
            nonlocal asked
            asked += 1
            return real(node)

        with patch.object(faults, '_arms_strict_mode', counted):
            self._deobfuscate(source)
        return asked

    def test_the_walk_is_taken_a_bounded_number_of_times(self):
        self.assertLess(self._armings_asked(320), 5000)

    def test_doubling_the_script_does_not_square_the_walking(self):
        counts = {size: self._armings_asked(size) for size in (40, 320)}
        self.assertLess(counts[320], 12 * counts[40])
