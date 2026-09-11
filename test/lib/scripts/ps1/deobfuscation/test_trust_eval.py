from __future__ import annotations

from inspect import cleandoc

from refinery.lib.scripts.ps1.deobfuscation.unused import Ps1JunkStatementRemoval
from refinery.lib.scripts.ps1.options import Ps1DeobfuscationOptions
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer
from test.lib.scripts.ps1.deobfuscation import TestPs1

#: A discarded call whose removal needs the .NET type name to still denote what the metadata says,
#: so that every row below is decided by the statement written above it and by nothing else.
_JUNK = '$Null = [System.Guid]::NewGuid()'


class TestPs1TrustedEvalExcusesTheConstructsThatRunUnreadableCode(TestPs1):
    """
    Under `refinery.lib.scripts.ps1.options.Ps1DeobfuscationOptions.trust_eval` a construct that
    runs code this analysis cannot read is assumed to leave the .NET type system and the command
    table as it found them, so junk written below it is removed. Each row is one such construct, and
    each is asserted twice: kept without the option, which is the only sound answer and the default,
    and removed with it.
    """

    #: Each opener is paired with what has to be written under it to keep it alive, so that the one
    #: statement a row measures is the junk and never the opener: a `[scriptblock]::Create` whose
    #: result nothing reads is itself a dead store the option would collect, and such a row would
    #: pass while saying nothing about the junk.
    _RUNS_UNREADABLE_CODE = (
        ('Invoke-Expression $c', ''),
        ('Invoke-Command -ScriptBlock $b', ''),
        ('Start-Job -ScriptBlock $b', ''),
        ('& $f', ''),
        ('. $f', ''),
        ('. C:/stage2.ps1', ''),
        ("Set-Alias Copy-Item 'dI6tW'.Remove(3, 3)", ''),
        ("Import-Alias 'C:/a.csv'", ''),
        ("$function:zzq = 'Get-Date'", ''),
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
    """
    The option is an assumption about code that cannot be read, not a licence to disbelieve a
    statement the walk can see. A mutation of the type system written out in the script opens the
    world under both models, and the junk below it is kept under both.
    """

    _MUTATES_IN_PLAIN_SIGHT = (
        'Add-Type -TypeDefinition $src',
        'Update-TypeData -TypeName System.Int32 -MemberName X -Value 1',
        'Add-Member -InputObject $o -MemberType NoteProperty -Name X -Value 1',
        'Import-Module Zzq',
        'New-Module -ScriptBlock $b',
        'class Zzq {}',
        cleandoc("""
            enum Zzq {
              A
            }
        """),
        "[PSObject+TypeAccelerators]::Add('zzq', [int])",
        '$o.PSObject.Members.Add($m)',
    )

    def test_the_junk_below_one_is_kept_by_default(self):
        for mutation in self._MUTATES_IN_PLAIN_SIGHT:
            with self.subTest(mutation):
                self._assertKept(F'{mutation}\n{_JUNK}')

    def test_the_junk_below_one_is_kept_under_the_option_too(self):
        for mutation in self._MUTATES_IN_PLAIN_SIGHT:
            with self.subTest(mutation):
                self._assertKept(F'{mutation}\n{_JUNK}', trust_eval=True)


class TestPs1TrustedEvalDoesNotExcuseARebindingTheScriptWritesDown(TestPs1):
    """
    A statement that spells out both the command name it takes over and what it binds that name to
    runs no code this analysis cannot read, so the option does not excuse it either. The name it
    rebinds never reaches the shadow set, which is why the world verdict has to keep refusing:
    every row below calls the rebound name, and the call runs whatever the row bound it to.
    """

    #: The last four rows carry a parameter that steers the binding without saying what it is. A
    #: reading that took every argument for part of the binding would call each of them unreadable
    #: and excuse the whole statement, which is the shape a switch alone is enough to reach.
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
    """
    A statement that merely names the `alias:` or `function:` provider is read as an identity
    opener, because the reading cannot tell a path read from a path write. None of the rows below
    writes anything, so none of them may switch the option off for the script it sits in.
    """

    _READS_THE_PROVIDER = (
        "Test-Path 'alias:curl'",
        'Get-ChildItem alias:',
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
    """
    A script with nothing to excuse comes out of both models byte for byte the same, so that the
    option is measured as the one thing it is rather than as a second deobfuscation mode.
    """

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

    def test_both_models_produce_the_same_output(self):
        for script in self._CLOSED_WORLD_SCRIPTS:
            with self.subTest(script):
                self.assertEqual(
                    self._deobfuscate(script),
                    self._deobfuscate(script, trust_eval=True),
                )


class TestPs1TrustedEvalReachesTheAnswersOnePayloadDispatcherUsedToWithhold(TestPs1):
    """
    Three families kept standing, each reduced to the statement that carries it, and none of them
    the discarded static call the classes above measure with.
    """

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
    """
    The option travels on the transformer, so a pass run without the pipeline's shared cache builds
    one that carries it. A cache that defaulted the option instead would answer under a
    configuration the transformer beside it does not hold, which is one run reading two settings.
    """

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
    """
    The four costs the option accepts beyond the type system and the command table, each written
    out so that changing one is a test failure rather than a silent widening. None of them is a
    wrong answer about what the payload *changes*; each is what follows from also assuming that
    nothing outside the file reads what is in it. The default keeps all four.
    """

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

    def test_the_default_keeps_all_four(self):
        scripts = (
            'Invoke-Expression $c\nfunction Zzq {\n  Stop-Process -Name x\n}',
            "Invoke-Expression $c\nfunction Zzq {\n  Write-Host 'side'\n  'payload'\n}\nZzq",
            'Invoke-Expression $c\n$q',
            '$r = $sb.Invoke()\nSet-Alias zzq Get-Date\nWrite-Host $r',
        )
        for script in scripts:
            with self.subTest(script):
                self._assertKept(script)
