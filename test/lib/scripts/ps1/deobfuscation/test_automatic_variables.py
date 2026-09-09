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
    `$?` reports whether the last command succeeded. Windows PowerShell 5.1 starts a script with it
    at `$true` and leaves it there after every command that succeeds, so a branch guarded by it is
    one the script takes.

    The deobfuscator has no value for `$?` and reads it as `$null`. Every guard below therefore
    decides the wrong way, and the branch 5.1 runs is deleted along with everything inside it.
    """

    @unittest.expectedFailure
    def test_the_success_flag_at_the_top_of_a_script_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F'if ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    @unittest.expectedFailure
    def test_the_success_flag_after_a_command_that_succeeds_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F'{_SUCCEEDS}\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}',
            F'{_SUCCEEDS}\n{_PAYLOAD}')

    @unittest.expectedFailure
    def test_the_negated_success_flag_takes_the_else_branch(self):
        self._assertRunsTheSameStatements(
            F'if (-not $?) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD)

    @unittest.expectedFailure
    def test_the_success_flag_under_a_bang_takes_the_else_branch(self):
        self._assertRunsTheSameStatements(
            F'if (!$?) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD)

    @unittest.expectedFailure
    def test_the_success_flag_compared_to_true_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F'if ($? -eq $true) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    @unittest.expectedFailure
    def test_the_success_flag_guarding_a_branch_without_an_else_keeps_the_body(self):
        self._assertRunsTheSameStatements(
            F'if ($?) {{ {_PAYLOAD} }}\n{_TAIL}', F'{_PAYLOAD}\n{_TAIL}')

    @unittest.expectedFailure
    def test_the_success_flag_copied_into_a_variable_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(
            F'$q = $?\nif ($q) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', _PAYLOAD)

    @unittest.expectedFailure
    def test_a_while_loop_the_success_flag_guards_runs_its_body(self):
        self._assertKept(F"""
            while ($?) {{
              {_PAYLOAD}
              break
            }}
        """)

    @unittest.expectedFailure
    def test_the_success_flag_read_inside_a_called_function_takes_the_then_branch(self):
        self._assertRunsTheSameStatements(F"""
            function Invoke-Thing {{
              if ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}
            }}
            Invoke-Thing
        """, F"""
            function Invoke-Thing {{
              {_PAYLOAD}
            }}
            Invoke-Thing
        """)


class TestPs1TheSuccessFlagIsFalseAfterAFailure(_Ps1AutomaticVariables):
    """
    Controls for the pins above, in the direction the deobfuscator already answers correctly. 5.1
    sets `$?` to `$false` after a command that fails and after a conversion that raises, and it
    counts a suppressed error as a failure, so here the guard does take the branch the analysis
    picks for it.
    """

    def test_the_success_flag_after_a_command_that_fails_takes_the_else_branch(self):
        self._assertDecidesTo(
            F'{_FAILS}\nif ($?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}', F'{_FAILS}\n{_OTHER}')

    def test_the_negated_success_flag_after_a_command_that_fails_takes_the_then_branch(self):
        self._assertDecidesTo(
            F'{_FAILS}\nif (-not $?) {{ {_PAYLOAD} }} else {{ {_OTHER} }}',
            F'{_FAILS}\n{_PAYLOAD}')

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
    non-empty string.

    The deobfuscator substitutes the printed spelling and tests that string for truth, which it
    always is. It decides these guards the opposite way and deletes the branch 5.1 runs.
    """

    @unittest.expectedFailure
    def test_the_verbose_preference_takes_the_else_branch(self):
        self._assertRunsTheSameStatements(
            F'if ($VerbosePreference) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD)

    @unittest.expectedFailure
    def test_the_debug_preference_takes_the_else_branch(self):
        self._assertRunsTheSameStatements(
            F'if ($DebugPreference) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD)

    @unittest.expectedFailure
    def test_the_information_preference_takes_the_else_branch(self):
        self._assertRunsTheSameStatements(
            F'if ($InformationPreference) {{ {_OTHER} }} else {{ {_PAYLOAD} }}', _PAYLOAD)


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
        so a read of it is the success channel a later increment adds to this same model — not the
        persistent-error channel this one does. This increment must therefore not keep the raise on
        the strength of a `$?` read, and the raise is removed although a `$?` read follows it.
        """
        self._assertDeobfuscatesTo(
            F'{_FAULTS}\n{_SUCCEEDS}\nWrite-Host $?',
            F'{_SUCCEEDS}\nWrite-Host $?')


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
