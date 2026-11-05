from __future__ import annotations

from test import opportunity
from test.lib.scripts.ps1.deobfuscation import TestPs1

_PAYLOAD = "Write-Host 'PAYLOAD'"

_OTHER = "Write-Host 'OTHER'"

_TAIL = "Write-Host 'TAIL'"

_SUCCEEDS = "Write-Host 'FIRST'"

_FAILS = 'Get-Item nope -ErrorAction SilentlyContinue | Write-Host'

_FAULTS = "$Null = [Int]'abc'"

_UNSET = '$somethingTheScriptNeverSets'


class _Ps1AutomaticVariables(TestPs1):

    def _assertRunsTheSameStatements(self, source: str, *decided: str) -> None:
        self._assertDeobfuscatesToOneOf(source, source, *decided)


class TestPs1TheSuccessFlagIsTrueUntilSomethingFails(_Ps1AutomaticVariables):

    def test_the_success_flag_at_the_top_of_a_script_takes_the_then_branch(self):
        self._assertDeobfuscatesTo(F'if ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_the_success_flag_after_a_command_that_succeeds_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F'{_SUCCEEDS}\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', F'{_SUCCEEDS}\n{_PAYLOAD}'
        )

    def test_the_negated_success_flag_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(F'if (-not $?) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD)

    def test_the_success_flag_under_a_bang_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(F'if (!$?) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD)

    def test_the_success_flag_compared_to_true_takes_the_then_branch(self):
        self._assertDeobfuscatesTo(
            F'if ($? -eq $true) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD
        )

    def test_the_success_flag_guarding_a_branch_without_an_else_keeps_the_body(self):
        self._assertDeobfuscatesTo(F'if ($?) {{ {_PAYLOAD} }}\n{_TAIL}', F'{_PAYLOAD}\n{_TAIL}')

    def test_the_success_flag_copied_into_a_variable_takes_the_then_branch(self):
        self._assertDeobfuscatesTo(
            F'$q = $?\nif ($q) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD
        )

    def test_an_unconditional_break_reduces_a_while_the_success_flag_guards_to_its_body(self):
        self._assertDeobfuscatesTo(F"""
            while ($?) {{
              {_PAYLOAD}
              break
            }}
        """, _PAYLOAD)

    def test_a_while_loop_the_success_flag_guards_without_a_break_stays_a_loop(self):
        self._assertRunsTheSameStatements(F"""
            while ($?) {{
              {_PAYLOAD}
            }}
        """, F"""
            while ($True) {{
              {_PAYLOAD}
            }}
        """)

    def test_the_success_flag_read_inside_a_called_function_is_kept(self):
        self._assertKept(F"""
            function Invoke-Thing {{
              if ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}
            }}
            Invoke-Thing
        """)


class TestPs1TheSuccessFlagIsFalseAfterAFailure(_Ps1AutomaticVariables):

    def test_the_success_flag_after_a_command_whose_suppressed_failure_is_unprovable_is_kept(self):
        self._assertKept(F'{_FAILS}\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}')

    def test_the_negated_success_flag_after_a_command_whose_failure_is_unprovable_is_kept(self):
        self._assertKept(F'{_FAILS}\nif (!$?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}')

    def test_the_success_flag_after_a_conversion_that_raises_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(
            F'{_FAULTS}\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER
        )


class TestPs1AnEngineStringTheToolSupplies(_Ps1AutomaticVariables):

    def test_the_edition_name_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F'if ($PSEdition) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_the_edition_name_compared_to_desktop_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F"if ($PSEdition -eq 'Desktop') {{ {_PAYLOAD} }} else {{ {_OTHER} }}", _PAYLOAD)

    def test_the_error_view_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F'if ($ErrorView) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_the_error_view_compared_to_normal_view_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F"if ($ErrorView -eq 'NormalView') {{ {_PAYLOAD} }} else {{ {_OTHER} }}", _PAYLOAD)

    def test_the_error_view_guarding_a_branch_without_an_else_keeps_the_body(self):
        self._assertRunsTheSameStatements(
            F'if ($ErrorView) {{ {_PAYLOAD} }}\n{_TAIL}', F'{_PAYLOAD}\n{_TAIL}')


class TestPs1APreferenceVariableIsAnEnumAndNotTheNameItPrints(_Ps1AutomaticVariables):

    def test_the_verbose_preference_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(
            F'if ($VerbosePreference) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD
        )

    def test_the_debug_preference_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(
            F'if ($DebugPreference) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD
        )

    def test_the_information_preference_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(
            F'if ($InformationPreference) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD
        )

    def test_the_error_action_preference_takes_the_then_branch(self):
        self._assertDeobfuscatesTo(
            F'if ($ErrorActionPreference) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD
        )

    def test_eight_guards_on_the_verbose_preference_each_take_the_else_branch(self):
        guard = F'if ($VerbosePreference) {{ {_OTHER} }} else {{ {_PAYLOAD} }}'
        self._assertDeobfuscatesTo('\n'.join([guard] * 8), '\n'.join([_PAYLOAD] * 8))


class TestPs1AGuardComparingAPreferenceToAMemberNameIsDecided(_Ps1AutomaticVariables):

    @opportunity
    def test_a_preference_equal_to_its_member_name_takes_the_then_branch(self):
        self._assertDeobfuscatesTo(
            F"if ($VerbosePreference -eq 'SilentlyContinue') {{ {_PAYLOAD} }} else {{ {_OTHER} }}",
            _PAYLOAD,
        )

    @opportunity
    def test_a_preference_unequal_to_another_member_name_takes_the_then_branch(self):
        self._assertDeobfuscatesTo(
            F"if ($ErrorActionPreference -ne 'Stop') {{ {_PAYLOAD} }} else {{ {_OTHER} }}",
            _PAYLOAD,
        )

    @opportunity
    def test_a_switch_over_a_preference_takes_the_clause_naming_its_member(self):
        self._assertDeobfuscatesTo(
            F"switch ($ErrorActionPreference) {{ 'Continue' {{ {_PAYLOAD} }} default {{ {_OTHER} }} }}",
            _PAYLOAD,
        )


class TestPs1ADeadStoreOfAnEngineDefaultAfterTheWorldOpens(_Ps1AutomaticVariables):

    def test_a_dead_store_of_a_string_default_is_deleted(self):
        self._assertDeobfuscatesTo(
            F'Add-Type -TypeDefinition $code\n$u = $PSEdition\n{_TAIL}',
            F'Add-Type -TypeDefinition $code\n{_TAIL}',
        )

    @opportunity
    def test_a_dead_store_of_a_preference_is_deleted(self):
        self._assertDeobfuscatesTo(
            F'Add-Type -TypeDefinition $code\n$u = $VerbosePreference\n{_TAIL}',
            F'Add-Type -TypeDefinition $code\n{_TAIL}',
        )


class TestPs1AStatementThatRaisesIsVisibleInTheErrorRecord(_Ps1AutomaticVariables):

    def test_a_raising_statement_before_a_read_of_the_error_count_is_kept(self):
        self._assertKept(F'{_FAULTS}\nWrite-Host ($Error.Count)')

    def test_a_raising_statement_before_a_guard_on_the_error_count_is_kept(self):
        self._assertKept(F'{_FAULTS}\nif ($Error.Count) {{ {_PAYLOAD} }} else {{ {_OTHER} }}')

    def test_a_success_flag_read_after_the_raise_does_not_keep_it(self):
        self._assertDeobfuscatesToOneOf(
            F'{_FAULTS}\n{_SUCCEEDS}\nWrite-Host $?',
            F'{_SUCCEEDS}\nWrite-Host $?',
            F'{_SUCCEEDS}\nWrite-Host $True',
        )

    def test_a_success_flag_read_immediately_after_the_raise_freezes_it_to_false(self):
        self._assertDeobfuscatesTo(F'{_FAULTS}\nWrite-Host $?', 'Write-Host $False')


class TestPs1ARaiseSwallowedByAHandlerStaysVisibleToTheSuccessFlag(_Ps1AutomaticVariables):

    def test_a_success_flag_after_a_swallowed_certain_raise_does_not_take_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F'try {{ {_FAULTS} }} catch {{ }}\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER)


class TestPs1AWriteALiveSuccessFlagReadObservesIsKept(_Ps1AutomaticVariables):

    def test_a_guard_on_the_success_flag_after_a_dead_store_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F'{_FAILS}\n$junk = 5\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}',
            F'{_FAILS}\n{_PAYLOAD}',
        )

    def test_a_guard_on_the_success_flag_after_a_discard_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F'{_FAILS}\n$Null = 5\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}',
            F'{_FAILS}\n{_PAYLOAD}',
        )

    def test_a_guard_on_the_success_flag_after_a_store_and_an_empty_if_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F'{_FAILS}\n$junk = 5\nif ($zzz) {{ }}\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}',
            F'{_FAILS}\n$junk = 5\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}',
            F'{_FAILS}\n{_PAYLOAD}',
        )

    def test_the_success_flag_after_a_store_and_an_empty_foreach_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F'{_FAILS}\n$junk = 5\nforeach ($i in $zzz) {{ }}\n'
            F'if ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}',
            F'{_FAILS}\n$junk = 5\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}',
            F'{_FAILS}\n{_PAYLOAD}',
        )

    def test_a_constant_store_inlines_and_the_success_flag_after_it_reads_true(self):
        self._assertDeobfuscatesToOneOf(
            F'{_FAILS}\n$x = 5\nWrite-Host $?\nWrite-Host $x',
            F'{_FAILS}\n$x = 5\nWrite-Host $?\nWrite-Host 5',
            F'{_FAILS}\nWrite-Host $True\nWrite-Host 5',
        )

    def test_the_success_flag_read_right_after_a_dead_store_reads_true(self):
        self._assertRunsTheSameStatements(
            F'{_FAILS}\n$junk = 5\nWrite-Host $?', F'{_FAILS}\nWrite-Host $True'
        )


class TestPs1TheSuccessFlagGuardingALoopIsNotFoldedFromItsOwnBody(_Ps1AutomaticVariables):

    def test_a_while_guard_whose_body_certainly_raises_keeps_the_loop(self):
        self._assertKept(F'while ($?) {{ {_PAYLOAD}\n{_FAULTS} }}\n{_TAIL}')


class TestPs1TheSuccessFlagAtTheTopOfARerunningBlockIsNotAFreshStart(_Ps1AutomaticVariables):

    def test_the_success_flag_at_the_top_of_an_end_block_takes_the_then_branch(self):
        self._assertDeobfuscatesTo(
            F'end {{ if ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }} }}',
            F'end {{ {_PAYLOAD} }}',
        )

    def test_the_success_flag_at_the_top_of_a_process_block_is_kept(self):
        self._assertKept(F'process {{ if ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }} }}')

    def test_a_success_flag_writer_observed_only_across_a_process_reentry_is_kept(self):
        self._assertKept(
            F'process {{ if ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}\n{_FAULTS} }}')


class TestPs1TheTokenVariablesStayEmptyForTheWholeOfAScript(_Ps1AutomaticVariables):

    def test_the_first_token_variable_at_the_top_of_a_script_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(F'if ($^) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER)

    def test_the_last_token_variable_at_the_top_of_a_script_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(F'if ($$) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER)

    def test_the_first_token_variable_after_a_command_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(
            F'{_SUCCEEDS}\nif ($^) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', F'{_SUCCEEDS}\n{_OTHER}'
        )

    def test_the_last_token_variable_after_a_command_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(
            F'{_SUCCEEDS}\nif ($$) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', F'{_SUCCEEDS}\n{_OTHER}'
        )


class TestPs1ANameTheScriptNeverAssignsIsNull(_Ps1AutomaticVariables):

    def test_a_name_the_script_never_assigns_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(F'if ({_UNSET}) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER)

    def test_a_negated_name_the_script_never_assigns_takes_the_then_branch(self):
        self._assertDeobfuscatesTo(
            F'if (-not {_UNSET}) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD
        )


class TestPs1AnEngineVariableWithAKnownValueStaysFolded(_Ps1AutomaticVariables):

    def test_the_true_literal_takes_the_then_branch(self):
        self._assertDeobfuscatesTo(F'if ($true) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_the_false_literal_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(F'if ($false) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER)

    def test_the_confirm_preference_takes_the_then_branch(self):
        self._assertDeobfuscatesTo(
            F'if ($ConfirmPreference) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD
        )

    def test_the_culture_name_takes_the_then_branch(self):
        self._assertDeobfuscatesTo(
            F'if ($PSCulture) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD
        )

    def test_the_shell_identifier_takes_the_then_branch(self):
        self._assertDeobfuscatesTo(F'if ($ShellID) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_the_console_file_name_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(
            F'if ($ConsoleFileName) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER
        )

    def test_the_mail_server_name_takes_the_else_branch(self):
        self._assertDeobfuscatesTo(
            F'if ($PSEmailServer) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER
        )
