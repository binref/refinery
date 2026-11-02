from __future__ import annotations

from inspect import cleandoc

from test import lines_executed
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.analysis import dispatch, faults, raising
from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.model import Ps1TrapStatement
from refinery.lib.scripts.ps1.parser import Ps1Parser


class _Ps1LineFailure(TestPs1):

    def _output(self, source: str, trust_eval: bool = False) -> str:
        return self._deobfuscate_iterative(cleandoc(source), trust_eval=trust_eval)

    def assertKeeps(self, source: str, *lines: str, trust_eval: bool = False) -> None:
        output = self._output(source, trust_eval)
        for line in lines:
            self.assertIn(line, output)

    def assertKeepsATrap(self, source: str, trust_eval: bool = False) -> None:
        output = Ps1Parser(self._output(source, trust_eval)).parse()
        self.assertTrue(any(isinstance(node, Ps1TrapStatement) for node in output.walk()))

    def assertKeepsTheTrapWhileTheLineStays(self, source: str, line: str, trust_eval: bool = False) -> None:
        output = self._output(source, trust_eval)
        if line in output:
            self.assertIn('trap', output)

    def assertDropsEveryTrap(self, source: str, trust_eval: bool = False) -> None:
        output = Ps1Parser(self._output(source, trust_eval)).parse()
        self.assertFalse(any(isinstance(node, Ps1TrapStatement) for node in output.walk()))


class TestPs1AStoreMayFailWhereTheScriptConstrainsTheName(_Ps1LineFailure):
    """
    A plain store into a local cannot fail unless something gave the variable a type, an attribute
    or an option: then storing a value it refuses is a statement-terminating error the `trap` takes.
    """

    def test_a_store_into_a_variable_a_splat_made_read_only_stays(self):
        self.assertKeeps("""
            $o = @{ Name = 'v'; Value = 1; Option = 'ReadOnly' }
            New-Variable @o
            trap { Write-Host 'T'; continue }
            $v = 5
            Write-Host 'after'
        """, '$v = 5')

    def test_a_dead_store_that_types_its_variable_stays_while_the_variable_is_written_again(self):
        self.assertKeeps("""
            [int]$v1 = 1
            if ($args.Count -ge 0) {
              trap { Write-Host 'T'; continue }
              $v1 = 'abc'
            }
            Write-Host 'after'
        """, '[int]$v1', "$v1 = 'abc'")

    def test_a_store_after_a_default_option_for_new_variable_is_not_folded(self):
        self.assertKeeps("""
            $PSDefaultParameterValues['New-Variable:Option'] = 'ReadOnly'
            New-Variable x 1
            trap { Write-Host 'T'; continue }
            $x = 2
            Write-Host $x
        """, 'Write-Host $x')

    def test_a_store_after_a_payload_nobody_can_read_stays_where_code_is_suspected(self):
        self.assertKeeps("""
            iex $args[0]
            trap { Write-Host 'T'; continue }
            $x = 2
            Write-Host 'after'
        """, '$x = 2')


class TestPs1AReadMayFailUnderStrictModeWhereTheNameMayBeRemoved(_Ps1LineFailure):
    """
    Under strict mode a read of a variable that is not set fails, so a read is certain to succeed
    only where a store to it certainly completed and nothing may have removed the variable since.
    """

    _REMOVALS = (
        'Remove-Variable v1',
        "Get-ChildItem variable:v1 | Remove-Item",
        "'variable:v1' | Remove-Item",
        'Remove-Item -LiteralPath variable:v1',
        'Remove-Item Microsoft.PowerShell.Core\\Variable::v1',
        'Move-Item variable:v1 variable:v2',
        'Rename-Item variable:v1 v2',
    )

    def test_a_read_after_every_spelling_of_a_removal_stays(self):
        for removal in self._REMOVALS:
            with self.subTest(removal=removal):
                self.assertKeeps(F"""
                    Set-StrictMode -Version 1
                    $v1 = 1
                    {removal}
                    trap {{ Write-Host 'T'; continue }}
                    $null = $v1
                    Write-Host 'after'
                """, '$v1\n')

    def test_a_read_after_a_payload_nobody_can_read_stays_where_code_is_suspected(self):
        self.assertKeeps("""
            Set-StrictMode -Version 1
            $v1 = 1
            iex $args[0]
            trap { Write-Host 'T'; continue }
            $null = $v1
            Write-Host 'after'
        """, '$v1\n')


class TestPs1ACallFactCoversWhatWasMeasured(_Ps1LineFailure):
    """
    The commands the facts cover cannot fail on the arguments they were measured on, and may fail
    on every other: `Select-Object -First -1` is refused, and `Write-Host` fails where the script
    asks it to stop on what it writes.
    """

    def test_a_negative_count_handed_through_a_variable_keeps_its_line(self):
        self.assertKeeps("""
            $n = -1
            trap { Write-Host 'T'; continue }
            $null = 1, 2 | Select-Object -First $n
            Write-Host 'after'
        """, 'Select-Object')

    def test_a_write_to_the_host_under_a_stopping_information_preference_keeps_the_trap(self):
        self.assertKeepsATrap("""
            $InformationPreference = 'Stop'
            trap { Write-Output 'T'; continue }
            Write-Host 'a'
            Write-Output 'after'
        """)

    def test_a_write_to_the_host_where_a_call_binds_a_stopping_information_action_keeps_the_trap(self):
        for binding in ('-InformationAction Stop', '-infa Stop', '@arguments'):
            with self.subTest(binding=binding):
                self.assertKeepsATrap(F"""
                    function f {{
                      [CmdletBinding()]
                      param()
                      trap {{ Write-Output 'T'; continue }}
                      Write-Host 'a'
                      Write-Output 'after'
                    }}
                    $arguments = @{{ InformationAction = 'Stop' }}
                    f {binding}
                """)

    def test_a_raise_in_the_body_of_a_trap_over_lines_the_facts_clear_goes(self):
        """
        The body of a `trap` runs only where a line of its block fails; the lines the facts clear
        cannot fail, so the body never runs and the cast in it raises nothing anyone sees.
        """
        output = self._output("""
            trap { Write-Host 'T'; $null = [int]'a'; Write-Host 'U'; continue }
            Write-Host 'a'
            $null = 1, 2 | Select-Object -First 1
            'x' | Out-Null
            Get-Process | Out-Null
            Write-Host 'after'
        """)
        self.assertNotIn("[int]'a'", output)


class TestPs1ACallRaisesWhatTheBodyItRunsHandsBack(_Ps1LineFailure):
    """
    Where a `trap` stands over a call, what reaches it is what the called body hands back: an error
    the body reports where nothing passes errors outward, and one it leaves with where something
    does, which ends the body at the failing line.
    """

    def test_a_call_from_another_function_before_the_definition_runs_keeps_the_trap(self):
        self.assertKeeps("""
            function f2 {
              trap { Write-Output 'T'; continue }
              f1
            }
            f2
            function f1 { }
            f2
            Write-Output 'after'
        """, 'trap', '  f1\n')

    def test_a_failing_line_two_calls_down_keeps_the_trap_that_abandons_the_rest(self):
        """
        5.1 writes only `f0`: the error leaves `g1` and `g0` for the `trap` of `f0`. Without the
        `trap` the error is reported and `g0` is written as well, and so it is without the cast.
        """
        self.assertKeeps("""
            $p = $args
            function g1 { $null = [int]$p[0] }
            function g0 { g1; Write-Host 'g0' }
            function f0 { trap { continue }; g0; Write-Host 'f0' }
            f0
        """, 'trap', '[int]$p[0]')

    def test_a_helper_defined_at_the_top_lets_the_trap_of_each_caller_go(self):
        self.assertDropsEveryTrap("""
            function g { Write-Host 'g' }
            function f1 { trap { continue }; g; Write-Host 'f1' }
            function f2 { trap { continue }; g; Write-Host 'f2' }
            f1
            f2
        """)


class TestPs1ABodyHandedOutAsAValueRunsWhereNoCallNamesIt(_Ps1LineFailure):
    """
    A function the script reads as a value, looks up, or reaches as a class method may run under a
    `try` no call names, which passes its error outward and ends the body at the failing line; so
    its `trap` stays, and the function is not dead for want of a call.
    """

    _HANDINGS = (
        'try { 1 | ForEach-Object -Process $function:f1 } catch { Write-Host "c" }',
        'try { & (Get-Command f1).ScriptBlock } catch { Write-Host "c" }',
        'try { & (Get-Item function:f1).ScriptBlock } catch { Write-Host "c" }',
        'class C { [void] M() { f1 } }; try { [C]::new().M() } catch { Write-Host "c" }',
    )

    def test_a_trap_in_a_body_handed_out_stays_in_either_mode(self):
        for handing in self._HANDINGS:
            for trust_eval in (False, True):
                with self.subTest(handing=handing, trust_eval=trust_eval):
                    self.assertKeepsTheTrapWhileTheLineStays(F"""
                        $p = $args
                        function f1 {{ trap {{ continue }}; $null = [int]$p[0]; Write-Host 'm1' }}
                        {handing}
                    """, '[int]$p[0]', trust_eval=trust_eval)

    def test_a_function_used_only_as_a_value_stays(self):
        self.assertKeeps("""
            function f1 { Write-Host 'm1' }
            $b = $function:f1
            & $b
        """, 'function f1')


class TestPs1ACallTheCallGraphCannotAttributeMayRunAnyFunction(_Ps1LineFailure):
    """
    Under trusted eval, a call whose target a later step spells still runs the body under the `try`
    around it, so the body's `trap` stays while its failing line stays. 5.1 writes `m1` for both
    calls; without the `trap` and with the failing line, the second writes `c`.
    """

    _CALLS = (
        "& ('f' + '1')",
        '& $n',
        '. $n',
        "iex 'f1'",
        "Invoke-Expression ('f' + '1')",
        'iex $n',
        "$ExecutionContext.InvokeCommand.InvokeScript('f1')",
        "[ScriptBlock]::Create('f1').Invoke()",
        "[scriptblock]::($m)('f1').Invoke()",
    )

    def test_a_trap_in_a_body_a_computed_call_runs_under_a_try_stays(self):
        for call in self._CALLS:
            with self.subTest(call=call):
                self.assertKeepsTheTrapWhileTheLineStays(F"""
                    $p = $args
                    $n = 'f1'
                    $m = $args[1]
                    function f1 {{ trap {{ continue }}; $null = [int]$p[0]; Write-Host 'm1' }}
                    f1
                    try {{ {call} }} catch {{ Write-Host 'c' }}
                """, '[int]$p[0]', trust_eval=True)


class TestPs1ConstantInliningDecidesEveryReadBeforeItSubstitutes(_Ps1LineFailure):

    def test_both_reads_under_a_kept_trap_are_inlined(self):
        output = self._output("""
            $p = $args
            try {
              trap { continue }
              $null = [int]$p[0]
              $a = 'x'
              $b = 'y'
              Write-Host $a
              Write-Host $b
            } catch {
              Write-Host 'c'
            }
        """)
        self.assertIn("Write-Host 'x'", output)
        self.assertIn("Write-Host 'y'", output)


class TestPs1ANestedGenericTypeNameIsReadWhole(_Ps1LineFailure):

    def test_a_nested_generic_type_name_deobfuscates(self):
        output = self._output("""
            $d = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[int]]'
            Write-Host $d.Count
        """)
        self.assertIn('Write-Host', output)


class TestPs1CallsNobodyCanAttributeCostLinearWork(TestPs1):
    """
    A call nobody can attribute may run every function body, so a script with many of them beside
    many trapped functions pays their product wherever it asks about one per body; and a grant that
    reads the raise model of the tree as it stands rebuilds every model once per substitution.
    """

    @staticmethod
    def _bodies(size: int) -> list[str]:
        return [
            F'function f{index} {{ trap {{ continue }}; $null = [int]$args[0]; Write-Host "t{index}" }}'
            for index in range(size)
        ]

    @staticmethod
    def _work(source: str) -> int:
        tree = Ps1Parser(source).parse()
        return lines_executed(lambda: deobfuscate(tree, trust_eval=True), raising, faults, dispatch)

    def test_functions_each_called_through_a_computed_name_under_a_try(self):
        def work(size: int) -> int:
            lines = [F"$n{index} = 'f{index}'" for index in range(size)]
            lines.extend(self._bodies(size))
            for index in range(size):
                lines.append(F'f{index} $args[0]')
                lines.append(F"try {{ & $n{index} $args[0] }} catch {{ Write-Host 'c{index}' }}")
            return self._work('\n'.join(lines))

        self.assertWorkGrowsLinearly(work, 8)

    def test_unrelated_computed_calls_beside_many_trapped_functions(self):
        def work(size: int) -> int:
            lines = [F'iex $c{index}' for index in range(size)]
            lines.extend(self._bodies(size))
            lines.extend(F'f{index} $args[0]' for index in range(size))
            return self._work('\n'.join(lines))

        self.assertWorkGrowsLinearly(work, 16)

