from __future__ import annotations

import unittest

from inspect import cleandoc

from test import lines_executed, wontfix
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.analysis import world
from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


class TestPs1AnAttributeArgumentWithoutAValueIsPrintedAsWritten(TestPs1):

    @unittest.expectedFailure
    def test_a_named_attribute_argument_without_a_value_stays_a_name(self):
        """
        `Mandatory` names a property of `ParameterAttribute`; written as the string `'Mandatory'`, it
        is a positional argument the attribute does not take.
        """
        source = 'param([Parameter(Mandatory)] $x)'
        self.assertIn('Parameter(Mandatory)', Ps1Synthesizer().convert(Ps1Parser(source).parse()))


class TestPs1ABlockHeldByAPropertyIsInvokedAsABlock(TestPs1):

    @unittest.expectedFailure
    def test_invoking_a_block_a_property_holds_keeps_the_invocation(self):
        """
        `$o.B.Invoke()` runs the block the property `B` holds; `$o.B()` asks for a method named `B`,
        which a custom object does not have.
        """
        output = self._deobfuscate_iterative(cleandoc("""
            $o = [pscustomobject]@{ B = { Write-Host 'm1' } }
            $o.B.Invoke()
        """))
        self.assertIn('.Invoke()', output)


class TestPs1ADefaultParameterValueMayChangeWhatAVariableCommandDoes(TestPs1):

    @unittest.expectedFailure
    def test_a_variable_command_a_default_may_extend_is_not_read_as_a_plain_store(self):
        """
        `$PSDefaultParameterValues` binds `-Option ReadOnly` into every `Set-Variable`, which a plain
        store does not take: the store `$x = 2` below fails, and `Write-Host` prints `1`.
        """
        output = self._deobfuscate_iterative(cleandoc("""
            $PSDefaultParameterValues = @{ 'Set-Variable:Option' = 'ReadOnly' }
            Set-Variable x 1
            $x = 2
            Write-Host $x
        """))
        self.assertNotIn('Write-Host 2', output)


class TestPs1AStoreBehindADispatchThatMayConstrainItIsNotFolded(TestPs1):

    @unittest.expectedFailure
    def test_a_store_behind_a_dispatch_nobody_can_read_is_not_folded_where_code_is_suspected(self):
        """
        The command the first line runs is supplied as data, and may make `$x` read-only, so the
        store `$x = 2` may fail and `Write-Host` print `1`.
        """
        output = self._deobfuscate_iterative(cleandoc("""
            & $args[0] -Name x -Value 1 -Option ReadOnly
            $x = 2
            Write-Host $x
        """), trust_eval=False)
        self.assertIn('Write-Host $x', output)


class TestPs1InliningEveryPayloadCostsLinearWork(TestPs1):

    @unittest.expectedFailure
    def test_functions_each_called_through_a_payload_under_a_try(self):
        """
        Inlining a payload measures the world of the whole script again, so a script of many
        payloads pays their number times its size.
        """
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
    """
    A variable carrying a validation attribute, or made read-only, refuses a store it cannot take,
    and the `catch` around the store runs instead of the read that follows it.
    """

    @unittest.expectedFailure
    def test_a_store_a_validation_attribute_refuses_is_not_folded(self):
        output = self._deobfuscate(cleandoc("""
            [ValidateRange(1,5)][int]$x = 1
            try { $x = 9; Write-Host $x } catch { Write-Host 'caught' }
        """))
        self.assertNotIn('Write-Host 9', output)

    @unittest.expectedFailure
    def test_a_store_into_a_read_only_variable_is_not_folded(self):
        output = self._deobfuscate(cleandoc("""
            Set-Variable -Name y -Value 1 -Option ReadOnly
            try { $y = 'a'; Write-Host $y } catch { Write-Host 'caught' }
        """))
        self.assertNotIn("Write-Host 'a'", output)


class TestPs1APayloadThatDoesNotParseIsNotInlined(TestPs1):

    @unittest.expectedFailure
    def test_a_payload_missing_its_closing_parenthesis_stays_a_payload(self):
        self.assertIn("'$x = ('", self._deobfuscate("iex '$x = ('"))
