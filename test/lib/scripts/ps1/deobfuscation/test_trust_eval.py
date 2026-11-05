from __future__ import annotations

from inspect import cleandoc

from refinery.lib.scripts.ps1.deobfuscation.unused import Ps1JunkStatementRemoval
from refinery.lib.scripts.ps1.options import Ps1DeobfuscationOptions
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer
from test import opportunity
from test.lib.scripts.ps1.deobfuscation import TestPs1

_JUNK = '$Null = [System.Guid]::NewGuid()'


class TestPs1TrustedEvalExcusesTheConstructsThatRunUnreadableCode(TestPs1):

    _RUNS_UNREADABLE_CODE = (
        ('Invoke-Expression $c', ''),
        ('Invoke-Command -ScriptBlock $b', ''),
        ('& $f', ''),
        ('. $f', ''),
        ('. C:/stage2.ps1', ''),
        ('$b = [scriptblock]::Create($s)', 'Write-Host $b'),
        ('$r = $sb.Invoke()', 'Write-Host $r'),
        ('$r = $ExecutionContext.InvokeCommand.InvokeScript($s)', 'Write-Host $r'),
    )

    def _rows(self):
        for opener, tail in self._RUNS_UNREADABLE_CODE:
            yield opener, '\n'.join(line for line in (opener, _JUNK, tail) if line)

    def test_the_junk_below_one_is_kept_by_default(self):
        for opener, script in self._rows():
            with self.subTest(opener):
                self._assertKept(script)

    def test_the_junk_below_one_is_removed_under_the_option(self):
        for opener, script in self._rows():
            with self.subTest(opener):
                self._assertRemoved(F'{script}\n', F'{_JUNK}\n', trust_eval=True)


class TestPs1TrustedEvalDoesNotExcuseAMutationTheScriptWritesDown(TestPs1):

    _RUNS_CODE_IN_PLAIN_SIGHT = (
        'Add-Type -TypeDefinition $src',
        'Import-Module Zzq',
        'New-Module -ScriptBlock $b',
    )

    _MUTATES_IN_PLAIN_SIGHT = (
        *_RUNS_CODE_IN_PLAIN_SIGHT,
        'Update-TypeData -TypeName System.Int32 -MemberName X -Value 1',
        'Add-Member -InputObject $o -MemberType NoteProperty -Name X -Value 1',
        'class Zzq {}',
        cleandoc("""
            enum Zzq {
              A
            }
        """),
        "[PSObject+TypeAccelerators]::Add('zzq', [int])",
        '$o.PSObject.Members.Add($m)',
    )

    def test_a_write_to_the_accelerator_table_found_by_name_is_not_excused_by_the_option(self):
        script = (
            "[psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')::Add('zzq', [int])\n"
            F'{_JUNK}'
        )
        self.assertEqual(self._deobfuscate(script, trust_eval=True), self._deobfuscate(script))

    def test_the_junk_below_one_that_runs_code_is_kept_by_default(self):
        for mutation in self._RUNS_CODE_IN_PLAIN_SIGHT:
            with self.subTest(mutation):
                self._assertKept(F'{mutation}\n{_JUNK}')

    def test_the_option_changes_nothing_below_one(self):
        for mutation in self._MUTATES_IN_PLAIN_SIGHT:
            with self.subTest(mutation):
                script = F'{mutation}\n{_JUNK}'
                self.assertEqual(
                    self._deobfuscate(script, trust_eval=True), self._deobfuscate(script)
                )


class TestPs1TrustedEvalDoesNotExcuseARebindingTheScriptWritesDown(TestPs1):

    _REBINDS_IN_PLAIN_SIGHT = (
        'Set-Item alias:Get-Date Stop-Process',
        'Set-Item function:Get-Date { Stop-Process }',
        'New-Alias Get-Date Stop-Process -Force',
        'Set-Item alias:Get-Date Update-TypeData',
        'Set-Alias -Name Get-Date -Value Stop-Process -Scope Global',
        'Set-Item alias:Get-Date Stop-Process -Force:$True',
        'New-Alias Get-Date Stop-Process -Option ReadOnly, AllScope',
        'New-Alias Get-Date Stop-Process -Description $d',
    )

    _CALL = '$Null = Get-Date'

    def test_a_call_to_the_rebound_name_is_kept_by_default(self):
        for rebinding in self._REBINDS_IN_PLAIN_SIGHT:
            with self.subTest(rebinding):
                self._assertKept(cleandoc(F"""
                    {rebinding}
                    {self._CALL}
                """))

    def test_a_call_to_the_rebound_name_is_kept_under_the_option_too(self):
        for rebinding in self._REBINDS_IN_PLAIN_SIGHT:
            with self.subTest(rebinding):
                self._assertKept(cleandoc(F"""
                    {rebinding}
                    {self._CALL}
                """), trust_eval=True)

    def test_a_definition_the_rebound_name_reaches_is_kept_under_the_option(self):
        self._assertKept(
            cleandoc("""
                Set-Item alias:q Zzq
                function Zzq {
                  Write-Host 'x'
                }
                q
            """),
            trust_eval=True,
        )

    def test_a_bareword_the_rebound_name_reaches_is_kept_under_the_option(self):
        self._assertKept(
            cleandoc("""
                Set-Item alias:certutil Write-Host
                try {
                  certutil =http://h/p.exe
                } catch {}
            """),
            trust_eval=True,
        )

    def test_a_dot_invoked_mutator_is_kept_under_the_option(self):
        self._assertKept(cleandoc(FR"""
            . Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $src
            {_JUNK}
        """), trust_eval=True)


class TestPs1TrustedEvalStillExcusesAnEvalBesideAProviderPathThatBindsNothing(TestPs1):

    _READS_THE_PROVIDER = (
        "Test-Path 'alias:curl'",
        'Write-Host (Get-ChildItem alias:)',
        cleandoc("""
            $q = Get-Item function:more
            Write-Host $q
        """),
        "Write-Host 'alias:x'",
    )

    def test_the_junk_below_an_eval_is_still_removed(self):
        for reader in self._READS_THE_PROVIDER:
            with self.subTest(reader):
                self._assertRemoved(
                    F'Invoke-Expression $c\n{reader}\n{_JUNK}\n',
                    F'{_JUNK}\n',
                    trust_eval=True,
                )


class TestPs1TrustedEvalChangesNothingAboutAScriptThatRunsNoUnreadableCode(TestPs1):

    _CLOSED_WORLD_SCRIPTS = (
        cleandoc("""
            $a = 1 + 1
            $Null = [Math]::Abs(-3)
            Write-Host $a
        """),
        cleandoc("""
            function Zzq {
              'x'
            }
            Zzq
        """),
        cleandoc("""
            $q = 'abc'.Substring(1)
            Write-Output $q
        """),
    )

    _RUNS_NO_CODE_IN_THIS_SESSION = (
        'Start-Job -ScriptBlock $b',
        "Set-Alias Copy-Item 'dI6tW'.Remove(3, 3)",
        "Import-Alias 'C:/a.csv'",
        "$function:zzq = 'Get-Date'",
    )

    def test_both_models_produce_the_same_output(self):
        for script in self._CLOSED_WORLD_SCRIPTS:
            with self.subTest(script):
                self.assertEqual(
                    self._deobfuscate(script),
                    self._deobfuscate(script, trust_eval=True),
                )

    def test_junk_below_a_statement_running_no_code_in_this_session_goes_under_the_option(self):
        for statement in self._RUNS_NO_CODE_IN_THIS_SESSION:
            with self.subTest(statement):
                self._assertRemoved(F"""
                    {statement}
                    {_JUNK}
                """, _JUNK, trust_eval=True)

    @opportunity
    def test_junk_below_a_statement_running_no_code_in_this_session_goes_by_default(self):
        for statement in self._RUNS_NO_CODE_IN_THIS_SESSION:
            with self.subTest(statement):
                self._assertRemoved(F"""
                    {statement}
                    {_JUNK}
                """, _JUNK)


class TestPs1TrustedEvalReachesTheAnswersOnePayloadDispatcherUsedToWithhold(TestPs1):

    def test_a_discarded_construction_below_an_eval_is_removed(self):
        self._assertRemoved(
            'Invoke-Expression $c\n$Null = New-Object System.Object\n',
            '$Null = New-Object System.Object\n',
            trust_eval=True,
        )

    def test_a_command_inside_a_block_below_an_eval_stops_refusing(self):
        self._assertRemoved(
            '$Null = [int[]](1, 2, 3 | ForEach-Object {\n'
            '  Get-Random\n'
            '}) -Join "-"\n'
            'Invoke-Expression $h\n',
            '$Null = [int[]](1, 2, 3 | ForEach-Object {\n'
            '  Get-Random\n'
            '}) -Join "-"\n',
            trust_eval=True,
        )

    def test_a_definition_and_its_only_call_below_an_eval_are_removed(self):
        self._assertDeobfuscatesTo(
            """
            Invoke-Expression $c
            function Zzq {
              $Null = 1
            }
            Zzq
            """,
            'Invoke-Expression $c',
            trust_eval=True,
        )


class TestPs1TrustedEvalReachesATransformThatBuildsItsOwnCache(TestPs1):

    _SCRIPT = cleandoc("""
        Invoke-Expression $c
        $Null = Get-Item 'C:/x'
    """)

    def _run_alone(self, **flags) -> str:
        ast = Ps1Parser(self._SCRIPT).parse()
        for _ in range(10):
            transform = Ps1JunkStatementRemoval()
            transform.options = Ps1DeobfuscationOptions(**flags)
            transform.visit(ast)
            if not transform.changed:
                break
        return Ps1Synthesizer().convert(ast)

    def test_the_pass_keeps_the_junk_without_the_option(self):
        self.assertEqual(self._run_alone(), self._SCRIPT)

    def test_the_pass_removes_the_junk_under_the_option(self):
        self.assertEqual(self._run_alone(trust_eval=True), 'Invoke-Expression $c')


class TestPs1TrustedEvalAlsoAssumesTheUnreadableCodeReadsNothing(TestPs1):

    def test_a_definition_no_statement_calls_is_deleted(self):
        self._assertDeobfuscatesTo(
            """
            Invoke-Expression $c
            function Zzq {
              Stop-Process -Name x
            }
            """,
            'Invoke-Expression $c',
            trust_eval=True,
        )

    def test_a_bare_value_in_a_surviving_body_is_deleted(self):
        self._assertDeobfuscatesTo(
            """
            Invoke-Expression $c
            function Zzq {
              Write-Host 'side'
              'payload'
            }
            Zzq
            """,
            """
            Invoke-Expression $c
            function Zzq {
              Write-Host 'side'
            }
            Zzq
            """,
            trust_eval=True,
        )

    def test_a_bare_variable_read_the_payload_could_fault_is_deleted(self):
        self._assertDeobfuscatesTo(
            """
            Invoke-Expression $c
            $q
            """,
            'Invoke-Expression $c',
            trust_eval=True,
        )

    def test_an_alias_binding_only_the_payload_could_use_is_deleted(self):
        self._assertDeobfuscatesTo(
            """
            $r = $sb.Invoke()
            Set-Alias zzq Get-Date
            Write-Host $r
            """,
            """
            $r = $sb.Invoke()
            Write-Host $r
            """,
            trust_eval=True,
        )

    def test_the_default_keeps_what_the_payload_could_reach(self):
        scripts = (
            'Invoke-Expression $c\nfunction Zzq {\n  Stop-Process -Name x\n}',
            "Invoke-Expression $c\nfunction Zzq {\n  Write-Host 'side'\n  'payload'\n}\nZzq",
            '$r = $sb.Invoke()\nSet-Alias zzq Get-Date\nWrite-Host $r',
        )
        for script in scripts:
            with self.subTest(script):
                self._assertKept(script)
