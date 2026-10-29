from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import set_body
from refinery.lib.scripts.ps1.analysis.session import Ps1Session, session_of
from refinery.lib.scripts.ps1.parser import Ps1Parser


class TestPs1TheSessionAScriptMaySet(TestBase):
    """
    What a script may set in its session is read the wide way: a spelling the reader cannot tell
    harmless counts as setting it. Each spelling below is measured on 5.1 in `corpus.BEHAVIOURS`
    or named by the rule it follows.
    """

    @staticmethod
    def _session(source: str) -> Ps1Session:
        return session_of(Ps1Parser(source).parse())

    def test_every_spelling_that_may_silence_errors_is_read_as_silencing_them(self):
        for source in (
            "$ErrorActionPreference = 'SilentlyContinue'",
            '$ErrorActionPreference = 0',
            '$ErrorActionPreference = $old',
            "Invoke-Expression '$ErrorActionPreference = 0'",
            "Set-Variable -Name ('Error' + 'ActionPreference') -Value 0",
            "$ExecutionContext.SessionState.PSVariable.Set('ErrorActionPreference', 'SilentlyContinue')",
            "$t = @{ Name = 'ErrorActionPreference'; Value = 0 }; Set-Variable @t",
            'Set-Item -LiteralPath Variable:ErrorActionPreference 0',
            "foreach ($ErrorActionPreference in 'SilentlyContinue') { }",
            '& { param($ErrorActionPreference) } SilentlyContinue',
            'Set-Variable $name 0',
        ):
            with self.subTest(source):
                self.assertTrue(self._session(source).silenced)

    def test_a_preference_read_or_set_to_a_member_that_is_not_silent_silences_nothing(self):
        for source in (
            "$ErrorActionPreference = 'Stop'",
            "Set-Variable ErrorActionPreference Stop",
            '$old = $ErrorActionPreference',
            "Write-Host 'nothing'",
        ):
            with self.subTest(source):
                self.assertFalse(self._session(source).silenced)

    def test_a_call_handed_a_silent_action_silences_the_bodies_it_runs(self):
        for source in ('f -ErrorAction SilentlyContinue', 'f -ea 0', 'f @splat', "$PSDefaultParameterValues['*:ErrorAction'] = 0"):
            with self.subTest(source):
                self.assertTrue(self._session(source).silenced_by_a_call)
        self.assertFalse(self._session('f -ErrorAction Stop').silenced_by_a_call)

    def test_every_mention_of_the_default_table_may_bind_defaults(self):
        for source in (
            "$PSDefaultParameterValues['Get-Random:Maximum'] = 0",
            "$PSDefaultParameterValues = @{ 'Get-Random:Maximum' = 0 }",
            "$ExecutionContext.SessionState.PSVariable.Set('PSDefaultParameterValues', @{})",
            '$table = $PSDefaultParameterValues',
            "Invoke-Expression '$PSDefaultParameterValues = @{}'",
        ):
            with self.subTest(source):
                self.assertTrue(self._session(source).defaults)
        self.assertFalse(self._session('Get-Random').defaults)

    def test_every_spelling_that_may_seed_the_generator_is_read_as_seeding_it(self):
        for source in (
            'Get-Random -SetSeed 7',
            'Get-Random -s 7',
            'Get-Random @splat',
            "Invoke-Expression 'Get-Random -SetSeed 7'",
            "$PSDefaultParameterValues['Get-Random:SetSeed'] = 7",
        ):
            with self.subTest(source):
                self.assertTrue(self._session(source).seeded)
        self.assertFalse(self._session('Get-Random -Maximum 5').seeded)

    def test_a_seed_bound_under_any_command_name_is_read_as_seeding_it(self):
        for source in (
            'random -SetSeed 7',
            'Set-Alias r Get-Random; r -SetSeed 7',
            '& $command -SetSeed 7',
        ):
            with self.subTest(source):
                self.assertTrue(self._session(source).seeded)

    def test_the_session_of_a_script_follows_a_change_to_it(self):
        tree = Ps1Parser('Get-Random -Maximum 5').parse()
        self.assertFalse(session_of(tree).seeded)
        set_body(tree, [*tree.body, *Ps1Parser('Get-Random -SetSeed 7').parse().body])
        self.assertTrue(session_of(tree).seeded)
