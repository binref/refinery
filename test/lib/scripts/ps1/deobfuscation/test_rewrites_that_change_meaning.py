from __future__ import annotations

from inspect import cleandoc

from test import lines_executed, wontfix, todo
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.analysis import world
from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


class TestPs1AnAttributeArgumentWithoutAValueIsPrintedAsWritten(TestPs1):

    def test_a_named_attribute_argument_without_a_value_stays_a_name(self):
        source = 'param([Parameter(Mandatory)] $x)'
        self.assertIn('Parameter(Mandatory)', Ps1Synthesizer().convert(Ps1Parser(source).parse()))


class TestPs1AJumpABlockLetsOutReachesTheLoopAroundIt(TestPs1):

    @todo
    def test_a_continue_a_pipeline_block_lets_out_runs_the_iterator_of_the_for_loop(self):
        output = self._deobfuscate_iterative(cleandoc("""
            for ($j = 0; $j -lt 1; $j++) {
              1 | ForEach-Object { continue }
              break
            }
        """))
        self.assertNotIn('$True', output)


class TestPs1ABlockHeldByAPropertyIsInvokedAsABlock(TestPs1):

    @todo
    def test_invoking_a_block_a_property_holds_is_not_rewritten_into_a_method_call(self):
        source = cleandoc("""
            $o = [pscustomobject]@{ B = { Write-Host 'm1' } }
            $o.B.Invoke()
        """)
        self.assertIn(self._deobfuscate_iterative(source), (self._apply(source), "Write-Host 'm1'"))


class TestPs1ADefaultParameterValueMayChangeWhatAVariableCommandDoes(TestPs1):

    @wontfix(
        'no obfuscator or script makes Set-Variable read-only by default through '
        'PSDefaultParameterValues and then stores into the variable it protected'
    )
    def test_a_variable_command_a_default_may_extend_is_not_read_as_a_plain_store(self):
        output = self._deobfuscate_iterative(cleandoc("""
            $PSDefaultParameterValues = @{ 'Set-Variable:Option' = 'ReadOnly' }
            Set-Variable x 1
            $x = 2
            Write-Host $x
        """))
        self.assertNotIn('Write-Host 2', output)


class TestPs1AStoreBehindADispatchThatMayConstrainItIsNotFolded(TestPs1):

    @wontfix(
        'no script receives the command that makes its own variable read-only as its first '
        'argument and then stores into that variable'
    )
    def test_a_store_behind_a_dispatch_nobody_can_read_is_not_folded_where_code_is_suspected(self):
        output = self._deobfuscate_iterative(cleandoc("""
            & $args[0] -Name x -Value 1 -Option ReadOnly
            $x = 2
            Write-Host $x
        """), trust_eval=False)
        self.assertIn('Write-Host $x', output)


class TestPs1InliningEveryPayloadCostsLinearWork(TestPs1):

    @todo
    def test_functions_each_called_through_a_payload_under_a_try(self):
        def work(size: int) -> int:
            lines = [
                F'function f{index} {{ trap {{ continue }}; $null = [int]$args[0]; Write-Host "t{index}" }}'
                for index in range(size)
            ]
            for index in range(size):
                lines.append(F'f{index} $args[0]')
                lines.append(F"try {{ iex 'f{index} $args[0]' }} catch {{ Write-Host 'c{index}' }}")
            tree = Ps1Parser('\n'.join(lines)).parse()
            return lines_executed(lambda: deobfuscate(tree, trust_eval=True), world)

        self.assertWorkGrowsLinearly(work, 8)


class TestPs1AFunctionRunThroughAComputedItemPathIsRun(TestPs1):

    @wontfix(
        'a path computed into an item command may name the function drive; refusing on it would '
        'refuse every script that copies or deletes a file by a variable path'
    )
    def test_a_trap_in_a_function_run_through_a_computed_item_path_stays(self):
        output = self._deobfuscate_iterative(cleandoc("""
            $p = $args
            function f1 { trap { continue }; $null = [int]$p[0]; Write-Host 'm1' }
            try { Get-ChildItem $p[1] | ForEach-Object { & $_.ScriptBlock } } catch { Write-Host 'c' }
        """))
        if '[int]$p[0]' in output:
            self.assertIn('trap', output)


class TestPs1AStoreAVariableRefusesIsNotFoldedIntoItsReads(TestPs1):

    @todo
    def test_a_store_a_validation_attribute_refuses_is_not_folded(self):
        output = self._deobfuscate(cleandoc("""
            [ValidateRange(1,5)][int]$x = 1
            try { $x = 9; Write-Host $x } catch { Write-Host 'caught' }
        """))
        self.assertNotIn('Write-Host 9', output)

    @todo
    def test_a_store_into_a_read_only_variable_is_not_folded(self):
        output = self._deobfuscate(cleandoc("""
            Set-Variable -Name y -Value 1 -Option ReadOnly
            try { $y = 'a'; Write-Host $y } catch { Write-Host 'caught' }
        """))
        self.assertNotIn("Write-Host 'a'", output)


class TestPs1APayloadThatDoesNotParseIsNotInlined(TestPs1):

    @todo
    def test_a_payload_missing_its_closing_parenthesis_stays_a_payload(self):
        self.assertIn("'$x = ('", self._deobfuscate("iex '$x = ('"))
