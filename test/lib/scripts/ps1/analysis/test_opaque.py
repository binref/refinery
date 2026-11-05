from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.opaque import (
    runs_unreadable_code,
    writes_nobody_can_attribute,
)
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation, Ps1InvokeMember
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _first(source: str, kind: type) -> Node:
    found = [node for node in Ps1Parser(source).parse().walk() if isinstance(node, kind)]
    if not found:
        raise AssertionError(F'no {kind.__name__} in {source!r}')
    return min(found, key=lambda node: sum(1 for _ in _ancestors(node)))


def _ancestors(node: Node):
    cursor = node.parent
    while cursor is not None:
        yield cursor
        cursor = cursor.parent


def _command(source: str) -> Node:
    return _first(source, Ps1CommandInvocation)


class TestPs1UnreadableCode(TestBase):

    def test_invoke_expression_runs_unreadable_code(self):
        for source in ('Invoke-Expression $c', 'iex $c', 'IEX $c'):
            with self.subTest(source):
                self.assertTrue(runs_unreadable_code(_command(source)))

    def test_a_dot_invocation_runs_its_target_in_the_callers_scope(self):
        for source in (". 'stage2.ps1'", '. $sb', '. Writer', '. (Get-Thing)'):
            with self.subTest(source):
                self.assertTrue(runs_unreadable_code(_command(source)))

    def test_a_relative_path_command_is_not_a_dot_invocation(self):
        for source in (r'.\tool.exe', r'./tool.exe', r'.\sub\stage.ps1 -Foo bar'):
            with self.subTest(source):
                self.assertFalse(runs_unreadable_code(_command(source)))

    def test_a_dot_source_of_a_relative_path_is_still_unreadable(self):
        for source in (r'. .\stage2.ps1', r'. ./stage2.ps1'):
            with self.subTest(source):
                self.assertTrue(runs_unreadable_code(_command(source)))

    def test_invoke_command_runs_unreadable_code_only_with_no_new_scope(self):
        for source in (
            'Invoke-Command -NoNewScope -ScriptBlock $sb',
            'Invoke-Command -ScriptBlock $sb -NoNewScope',
            'Invoke-Command -NoNewScope:$true -ScriptBlock $sb',
            'Invoke-Command -NoNewScope:$c -ScriptBlock $sb',
        ):
            with self.subTest(source):
                self.assertTrue(runs_unreadable_code(_command(source)))
        for source in (
            'Invoke-Command -ScriptBlock $sb',
            'Invoke-Command -NoNewScope:$false -ScriptBlock $sb',
        ):
            with self.subTest(source):
                self.assertFalse(runs_unreadable_code(_command(source)))

    def test_a_dot_invoked_inline_block_is_not_unreadable(self):
        self.assertFalse(runs_unreadable_code(_command('. { $x = 1 }')))

    def test_a_call_operator_opens_a_child_scope_and_writes_nothing_outside(self):
        for source in ("& 'stage2.ps1'", '& $sb', '& { $x = 1 }', 'Writer'):
            with self.subTest(source):
                self.assertFalse(runs_unreadable_code(_command(source)))

    def test_an_execution_context_invoke_runs_in_a_scope_of_its_own(self):
        for source in (
            '$ExecutionContext.InvokeCommand.InvokeScript($c)',
            '$ExecutionContext.InvokeCommand.NewScriptBlock($c)',
        ):
            with self.subTest(source):
                self.assertFalse(runs_unreadable_code(_first(source, Ps1InvokeMember)))

    def test_a_command_that_runs_nothing_unreadable_is_not_flagged(self):
        for source in ('Write-Host $x', 'Get-Process', "Set-Content out.txt 'x'"):
            with self.subTest(source):
                self.assertFalse(runs_unreadable_code(_command(source)))


class TestPs1UnattributableWriteSources(TestBase):

    def test_a_computed_name_is_an_unattributable_write(self):
        self.assertTrue(writes_nobody_can_attribute(_command("Set-Variable $n 'v'")))

    def test_unreadable_code_is_an_unattributable_write(self):
        self.assertTrue(writes_nobody_can_attribute(_command('iex $c')))

    def test_a_write_naming_another_scope_is_not_one_this_answers_for(self):
        self.assertFalse(writes_nobody_can_attribute(_command("Set-Variable $n 'v' -Scope Global")))

    def test_a_literal_name_and_an_ordinary_command_are_neither(self):
        for source in ("Set-Variable y 'v'", 'Write-Host $x', '& { iex $c }'):
            with self.subTest(source):
                self.assertFalse(writes_nobody_can_attribute(_command(source)))
