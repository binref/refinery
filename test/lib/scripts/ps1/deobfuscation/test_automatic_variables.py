from __future__ import annotations

import inspect
import unittest

from test.lib.scripts.ps1.deobfuscation import TestPs1

#: The body of the branch each script below is written to reach. `Write-Host` is never a removal
#: candidate, so it goes missing from the output only because the branch holding it was folded away.
_PAYLOAD = "Write-Host 'PAYLOAD'"

#: The body of the other branch, so that every script prints exactly one of two lines and the output
#: names the branch the analysis decided for.
_OTHER = "Write-Host 'OTHER'"

#: A statement after the guarded construct, so that a script whose guard carries no `else` still has
#: something left to print once the guard is decided.
_TAIL = "Write-Host 'TAIL'"

#: A command that runs and succeeds. Windows PowerShell 5.1 leaves `$?` at `$true` after it.
_SUCCEEDS = "Write-Host 'FIRST'"

#: A command that fails and whose error `-ErrorAction SilentlyContinue` suppresses. 5.1 sets `$?` to
#: `$false` after it, so a suppressed error is still an observable one.
_FAILS = r'Get-Item C:\missing -ErrorAction SilentlyContinue'

#: A discarded conversion 5.1 answers with a terminating error. It sets `$?` to `$false` and appends
#: a record to `$Error`, and the script runs on to the next statement.
_FAULTS = "$Null = [Int]'abc'"

#: A name no statement of the script ever assigns, which 5.1 reads as `$null`.
_UNSET = '$somethingTheScriptNeverSets'


class _Ps1AutomaticVariables(TestPs1):

    def _assertRunsTheSameStatements(self, source: str, decided: str) -> None:
        """
        A guard the analysis cannot settle survives into the output with both bodies, and one it
        settles the way 5.1 settles it leaves behind the statements 5.1 runs. Those two whole
        programs are the only ones that preserve what the script does, so the assertion admits
        exactly them: an output that is neither has changed which statements run.
        """
        self.assertIn(
            self._deobfuscate(inspect.cleandoc(source)),
            (
                self._apply(inspect.cleandoc(source)),
                self._apply(inspect.cleandoc(decided)),
            ),
        )

    def _assertDecidesTo(self, source: str, expected: str) -> None:
        """
        Both arguments are written as ordinary indented PowerShell, and `expected` is rendered
        through the synthesizer before the comparison, so that brace layout cannot be mistaken for a
        branch having been removed.
        """
        self.assertEqual(
            self._deobfuscate(inspect.cleandoc(source)),
            self._apply(inspect.cleandoc(expected)),
        )

    def _assertKept(self, source: str) -> None:
        self._assertDecidesTo(source, source)


class TestPs1TheSuccessFlagIsTrueUntilSomethingFails(_Ps1AutomaticVariables):
    """
    `$?` reports whether the last statement succeeded. Windows PowerShell 5.1 starts a script with
    it at `$true` and leaves it there until something fails, so a branch guarded by it at the top of
    a script is one the script takes. The deobfuscator resolves `$?` from its position: at the top
    of the script it is `$true`, and the guard folds to the branch 5.1 runs.

    Where the position cannot settle the flag the read is left in place and the guard is kept: a
    command whose success the analysis cannot prove leaves `$?` undecided, and so does a `$?` read
    inside a called function's body, whose value belongs to the caller.
    """

    def test_the_success_flag_at_the_top_of_a_script_takes_the_then_branch(self):
        self._assertDecidesTo(
            F'if ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_the_success_flag_after_a_command_whose_success_is_unprovable_is_kept(self):
        self._assertKept(F'{_SUCCEEDS}\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}')

    def test_the_negated_success_flag_takes_the_else_branch(self):
        self._assertDecidesTo(
            F'if (-not $?) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD)

    def test_the_success_flag_under_a_bang_takes_the_else_branch(self):
        self._assertDecidesTo(
            F'if (!$?) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD)

    def test_the_success_flag_compared_to_true_takes_the_then_branch(self):
        self._assertDecidesTo(
            F'if ($? -eq $true) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_the_success_flag_guarding_a_branch_without_an_else_keeps_the_body(self):
        self._assertDecidesTo(
            F'if ($?) {{ {_PAYLOAD} }}\n{_TAIL}', F'{_PAYLOAD}\n{_TAIL}')

    def test_the_success_flag_copied_into_a_variable_takes_the_then_branch(self):
        self._assertDecidesTo(
            F'$q = $?\nif ($q) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_an_unconditional_break_reduces_a_while_the_success_flag_guards_to_its_body(self):
        self._assertDecidesTo(F"""
            while ($?) {{
              {_PAYLOAD}
              break
            }}
        """, _PAYLOAD)

    def test_a_while_loop_the_success_flag_guards_without_a_break_is_kept(self):
        self._assertKept(F"""
            while ($?) {{
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
    """
    5.1 sets `$?` to `$false` after a statement that fails, so a guard reading it takes the other
    branch. The deobfuscator settles the flag to `$false` only where it can prove the failure — a
    conversion that certainly raises — and folds the guard the way 5.1 does. A command whose error
    `-ErrorAction SilentlyContinue` suppresses fails on 5.1 too, but the analysis cannot prove that,
    so it leaves `$?` undecided and keeps the guard rather than fold from a value it cannot stand on.
    """

    def test_the_success_flag_after_a_command_whose_suppressed_failure_is_unprovable_is_kept(self):
        self._assertKept(F'{_FAILS}\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}')

    def test_the_negated_success_flag_after_a_command_whose_failure_is_unprovable_is_kept(self):
        self._assertKept(F'{_FAILS}\nif (!$?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}')

    def test_the_success_flag_after_a_conversion_that_raises_takes_the_else_branch(self):
        self._assertDecidesTo(
            F'{_FAULTS}\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER)


class TestPs1AnEngineStringTheToolSupplies(_Ps1AutomaticVariables):
    """
    5.1 hands a script `$PSEdition` as `Desktop` and `$ErrorView` as `NormalView`, each a plain
    string. `$ErrorView` is a bare string in 5.1 and only became an `ErrorView` enum in a later
    edition, so its truth is a non-empty string's truth and not an enum member's numeric value.
    Neither name is ever empty, so a guard reading one is a guard the script passes, whether it
    tests the name for truth or compares it against the value the engine supplies.
    """

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
    """
    `$VerbosePreference`, `$DebugPreference` and `$InformationPreference` each hold the
    `ActionPreference` member `SilentlyContinue`, whose numeric value is zero. 5.1 reads that as
    false, so a guard on one of these takes the `else` branch — even though the name prints as a
    non-empty string. `$ErrorActionPreference` holds `Continue`, whose value is two, and a guard on
    it takes the `then` branch for that value and not because its name is non-empty.
    """

    def test_the_verbose_preference_takes_the_else_branch(self):
        self._assertDecidesTo(
            F'if ($VerbosePreference) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD)

    def test_the_debug_preference_takes_the_else_branch(self):
        self._assertDecidesTo(
            F'if ($DebugPreference) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD)

    def test_the_information_preference_takes_the_else_branch(self):
        self._assertDecidesTo(
            F'if ($InformationPreference) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD)

    def test_the_error_action_preference_takes_the_then_branch(self):
        self._assertDecidesTo(
            F'if ($ErrorActionPreference) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_eight_guards_on_the_verbose_preference_each_take_the_else_branch(self):
        """
        An engine default is inlined at every read. Its spelling is bounded by the tables the
        inlining pass keeps, so the expansion budget that withholds a large constant the script
        defines does not withhold it, and the eighth guard is decided like the first.
        """
        guard = F'if ($VerbosePreference) {{ {_OTHER} }} else {{ {_PAYLOAD} }}'
        self._assertDecidesTo('\n'.join([guard] * 8), '\n'.join([_PAYLOAD] * 8))


class TestPs1AGuardComparingAPreferenceToAMemberNameIsDecided(_Ps1AutomaticVariables):
    """
    5.1 compares a preference variable to a String by converting the String to the member it
    names, so `$VerbosePreference -eq 'SilentlyContinue'` is `$true` and a `switch` over
    `$ErrorActionPreference` takes its `'Continue'` clause. The domain computes no comparison over
    an enum — the binary grid has no row for one — so each of these guards, decided before the
    preference variables became enum members, is left standing with both branches; each is the
    fold to recover.
    """

    @unittest.expectedFailure
    def test_a_preference_equal_to_its_member_name_takes_the_then_branch(self):
        self._assertDecidesTo(
            F"if ($VerbosePreference -eq 'SilentlyContinue') {{ {_PAYLOAD} }} else {{ {_OTHER} }}",
            _PAYLOAD,
        )

    @unittest.expectedFailure
    def test_a_preference_unequal_to_another_member_name_takes_the_then_branch(self):
        self._assertDecidesTo(
            F"if ($ErrorActionPreference -ne 'Stop') {{ {_PAYLOAD} }} else {{ {_OTHER} }}",
            _PAYLOAD,
        )

    @unittest.expectedFailure
    def test_a_switch_over_a_preference_takes_the_clause_naming_its_member(self):
        self._assertDecidesTo(
            F"switch ($ErrorActionPreference) {{ 'Continue' {{ {_PAYLOAD} }} default {{ {_OTHER} }} }}",
            _PAYLOAD,
        )


class TestPs1ADeadStoreOfAnEngineDefaultAfterTheWorldOpens(_Ps1AutomaticVariables):
    """
    `Add-Type` opens the command world, after which the effect model calls no cast pure: a type
    the script adds may carry a converter. A preference variable's value arrives as the cast of
    its member name, so a dead store of one after `Add-Type` is kept as a discard where the same
    store of a String-valued default is deleted. 5.1 runs neither, and the member's store is the
    deletion to recover.
    """

    def test_a_dead_store_of_a_string_default_is_deleted(self):
        self._assertDecidesTo(
            F'Add-Type -TypeDefinition $code\n$u = $PSEdition\n{_TAIL}',
            F'Add-Type -TypeDefinition $code\n{_TAIL}',
        )

    @unittest.expectedFailure
    def test_a_dead_store_of_a_preference_is_deleted(self):
        self._assertDecidesTo(
            F'Add-Type -TypeDefinition $code\n$u = $VerbosePreference\n{_TAIL}',
            F'Add-Type -TypeDefinition $code\n{_TAIL}',
        )


class TestPs1AStatementThatRaisesIsVisibleInTheErrorRecord(_Ps1AutomaticVariables):
    """
    `$Error` collects a record for every error the engine reports, so a script that raises before
    reading `$Error.Count` sees one where a script that does not raise sees zero. The raising
    statement is what makes that difference, and a read of `$Error` reachable after it observes the
    difference, so the raising statement — which prints nothing and assigns nothing, and which a
    removal weighing handlers alone would delete as junk — is kept.
    """

    def test_a_raising_statement_before_a_read_of_the_error_count_is_kept(self):
        self._assertKept(F'{_FAULTS}\nWrite-Host ($Error.Count)')

    def test_a_raising_statement_before_a_guard_on_the_error_count_is_kept(self):
        self._assertKept(F'{_FAULTS}\nif ($Error.Count) {{ {_PAYLOAD} }} else {{ {_OTHER} }}')

    def test_a_success_flag_read_after_the_raise_does_not_keep_it(self):
        """
        `$?` is a different automatic variable from the error record, and every statement resets it,
        so a `$?` read after the raise does not observe it. The raise is removed although a `$?` read
        follows it.
        """
        self._assertDeobfuscatesTo(
            F'{_FAULTS}\n{_SUCCEEDS}\nWrite-Host $?',
            F'{_SUCCEEDS}\nWrite-Host $?')

    def test_a_success_flag_read_immediately_after_the_raise_freezes_it_to_false(self):
        """
        With nothing between the raise and the `$?` read to reset it, `$?` reports the raise: 5.1
        prints `$false`. The reset-aware `$?` channel proves that — the raise is the read's
        immediate predecessor and certainly throws — so the read is frozen to `$False`, and the
        raiser, which now has no observer, is removed. The output prints `$false` exactly as 5.1
        does, with the raise gone.
        """
        self._assertDeobfuscatesTo(F'{_FAULTS}\nWrite-Host $?', 'Write-Host $False')


class TestPs1ARaiseSwallowedByAHandlerStaysVisibleToTheSuccessFlag(_Ps1AutomaticVariables):
    """
    A raise an empty `catch` swallows still fails the statement, so 5.1 leaves `$?` at `$false` after
    the whole `try`/`catch` — measured on the host: `$?` read after `try { $Null = [Int]'abc' } catch
    { }` is `$false`, and a guard on it takes the else branch.

    The raiser and the guard survive the passes that dissolve the handler, so by the time a removal
    reaches the top-level raiser the reset-aware `$?` channel places a live read after it and the veto
    keeps it. The guard then folds against a raiser still standing before it — to the else branch the
    host takes — rather than reading as the top of a script the removal emptied.
    """

    def test_a_success_flag_after_a_swallowed_certain_raise_does_not_take_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F'try {{ {_FAULTS} }} catch {{ }}\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER)


class TestPs1AWriteALiveSuccessFlagReadObservesIsKept(_Ps1AutomaticVariables):
    """
    Every leaf statement resets `$?`, so removing one a later `$?` read observes changes the value
    that read sees — a success command before a dead store makes the store's success the flag the
    guard reads, and dropping the store lets the earlier failure through. The removal veto keeps such
    a write whatever the statement's own output is worth, because the flag is engine state the script
    reads back.

    A `$?`-transparent statement between the write and the read — an empty or never-entered `if` or
    `foreach` — does not break the observation: the reaching-definition walk steps through it, so the
    store is still kept. A no-op that runs nothing may itself be dropped, but the write it stood
    between survives and the guard still reads the store's success.
    """

    def test_a_dead_store_before_a_success_flag_read_is_kept(self):
        self._assertKept(
            F'{_FAILS}\n$junk = 5\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}')

    def test_a_discard_before_a_success_flag_read_is_kept(self):
        self._assertKept(
            F'{_FAILS}\n$Null = 5\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}')

    def test_a_store_a_success_flag_read_observes_across_an_empty_if_is_kept(self):
        self._assertRunsTheSameStatements(
            F'{_FAILS}\n$junk = 5\nif ($zzz) {{ }}\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}',
            F'{_FAILS}\n$junk = 5\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}')

    def test_a_store_a_success_flag_read_observes_across_an_empty_foreach_is_kept(self):
        self._assertRunsTheSameStatements(
            F'{_FAILS}\n$junk = 5\nforeach ($i in $zzz) {{ }}\n'
            F'if ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}',
            F'{_FAILS}\n$junk = 5\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}')

    def test_a_constant_store_a_success_flag_read_observes_is_kept_while_its_value_inlines(self):
        self._assertDecidesTo(
            F'{_FAILS}\n$x = 5\nWrite-Host $?\nWrite-Host $x',
            F'{_FAILS}\n$x = 5\nWrite-Host $?\nWrite-Host 5')

    def test_a_store_before_an_immediate_success_flag_read_is_kept(self):
        self._assertKept(F'{_FAILS}\n$junk = 5\nWrite-Host $?')


class TestPs1TheSuccessFlagGuardingALoopIsNotFoldedFromItsOwnBody(_Ps1AutomaticVariables):
    """
    A `$?` read guarding a loop is reached on the first iteration from the top of the script, where
    `$?` is `$true`, as well as from the loop's own body. Where the body certainly raises, folding
    the guard to `$false` would delete a body 5.1 runs once before the raise steps out of the loop,
    so the guard is left in place and the whole loop is kept.
    """

    def test_a_while_guard_whose_body_certainly_raises_keeps_the_loop(self):
        self._assertKept(F'while ($?) {{ {_PAYLOAD}\n{_FAULTS} }}\n{_TAIL}')


class TestPs1TheSuccessFlagAtTheTopOfARerunningBlockIsNotAFreshStart(_Ps1AutomaticVariables):
    """
    5.1 runs `begin`, `end` and the unnamed body once, so a `$?` read at the top of one is a fresh
    `$true` and its guard folds to the branch 5.1 takes. It re-enters `process` once per pipeline
    input and carries `$?` across those entries, so the top of a `process` block is not a fresh start
    and its guard is left in place. The two named-block forms are each other's control: the same
    guard folds under `end` and is kept under `process`.
    """

    def test_the_success_flag_at_the_top_of_an_end_block_takes_the_then_branch(self):
        self._assertDecidesTo(
            F'end {{ if ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }} }}',
            F'end {{ {_PAYLOAD} }}')

    def test_the_success_flag_at_the_top_of_a_process_block_is_kept(self):
        self._assertKept(F'process {{ if ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }} }}')

    @unittest.expectedFailure
    def test_a_success_flag_writer_observed_only_across_a_process_reentry_is_kept(self):
        """
        The trailing raise fails the statement, so 5.1 carries `$?`=`$false` into the next pipeline
        input's top-of-`process` read, which takes the `else` branch there. The control-flow graph
        sequences `process` once and draws no per-input back-edge, so the removal veto does not see
        that read reach the raise and drops it as junk — the same unmodeled-reentry fail-open the
        persistent channel has. Retire this once the graph models the `process` re-entry.
        """
        self._assertKept(
            F'process {{ if ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}\n{_FAULTS} }}')


class TestPs1TheTokenVariablesStayEmptyForTheWholeOfAScript(_Ps1AutomaticVariables):
    """
    `$^` and `$$` hold the first and the last token of the previous command line, which only a host
    reading command lines one at a time ever supplies. A script the engine runs from a file or from
    `-Command` is a single command line, so 5.1 leaves both empty from the first statement to the
    last, and a guard on either takes the `else` branch whether a command has run before it or not.

    These are controls: the deobfuscator answers both names the way 5.1 does and must go on
    answering them, since a file that passed by folding nothing at all would look no different.
    """

    def test_the_first_token_variable_at_the_top_of_a_script_takes_the_else_branch(self):
        self._assertDecidesTo(F'if ($^) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER)

    def test_the_last_token_variable_at_the_top_of_a_script_takes_the_else_branch(self):
        self._assertDecidesTo(F'if ($$) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER)

    def test_the_first_token_variable_after_a_command_takes_the_else_branch(self):
        self._assertDecidesTo(
            F'{_SUCCEEDS}\nif ($^) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', F'{_SUCCEEDS}\n{_OTHER}')

    def test_the_last_token_variable_after_a_command_takes_the_else_branch(self):
        self._assertDecidesTo(
            F'{_SUCCEEDS}\nif ($$) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', F'{_SUCCEEDS}\n{_OTHER}')


class TestPs1ANameTheScriptNeverAssignsIsNull(_Ps1AutomaticVariables):
    """
    A variable no statement writes and the engine does not maintain reads as `$null` in 5.1, which
    is false. Folding its guard away is the deobfuscator doing its job, and it must keep doing it.
    """

    def test_a_name_the_script_never_assigns_takes_the_else_branch(self):
        self._assertDecidesTo(F'if ({_UNSET}) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER)

    def test_a_negated_name_the_script_never_assigns_takes_the_then_branch(self):
        self._assertDecidesTo(F'if (-not {_UNSET}) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)


class TestPs1AnEngineVariableWithAKnownValueStaysFolded(_Ps1AutomaticVariables):
    """
    Controls on both sides of the truth test, for names whose 5.1 value the deobfuscator already
    carries. `$ConfirmPreference` is `High`, `$ErrorActionPreference` is `Continue`, `$PSCulture` is
    a culture name and `$ShellID` is `Microsoft.PowerShell`, all of which 5.1 reads as true;
    `$ConsoleFileName` and `$PSEmailServer` are the empty string, which it reads as false.
    """

    def test_the_true_literal_takes_the_then_branch(self):
        self._assertDecidesTo(F'if ($true) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_the_false_literal_takes_the_else_branch(self):
        self._assertDecidesTo(F'if ($false) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER)

    def test_the_confirm_preference_takes_the_then_branch(self):
        self._assertDecidesTo(
            F'if ($ConfirmPreference) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_the_error_action_preference_takes_the_then_branch(self):
        self._assertDecidesTo(
            F'if ($ErrorActionPreference) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_the_culture_name_takes_the_then_branch(self):
        self._assertDecidesTo(F'if ($PSCulture) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_the_shell_identifier_takes_the_then_branch(self):
        self._assertDecidesTo(F'if ($ShellID) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    def test_the_console_file_name_takes_the_else_branch(self):
        self._assertDecidesTo(F'if ($ConsoleFileName) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER)

    def test_the_mail_server_name_takes_the_else_branch(self):
        self._assertDecidesTo(F'if ($PSEmailServer) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _OTHER)
