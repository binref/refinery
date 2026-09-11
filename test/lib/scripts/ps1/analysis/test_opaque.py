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
    """
    The outermost node of *kind*, so `& { iex $c }` names the `&` and not the call inside it.
    """
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
    """
    Which calls run code this analysis never sees, in the scope they stand in. A miss performs a
    corruption — the caller folds a value across a call that replaced it — where a spurious hit only
    withholds a fold, so the answers lean towards *unreadable* wherever the language is ambiguous.

    Every expectation is measured on 5.1: each probe sets `$x = 'a'`, runs the construct against
    `$x = 'REPLACED'`, and reads `$x` back — see `temp/ps1/census_measurements.md`.
    """

    def test_invoke_expression_runs_unreadable_code(self):
        for source in ('Invoke-Expression $c', 'iex $c', "IEX 'Write-Host hi'"):
            with self.subTest(source):
                self.assertTrue(runs_unreadable_code(_command(source)))

    def test_a_dot_invocation_runs_its_target_in_the_callers_scope(self):
        """
        Measured: `. Writer` leaves `$x` replaced where `Writer` alone does not, so the operator and
        not the target is what decides the scope — a file, a variable and a plain function name are
        one case here.
        """
        for source in (". 'stage2.ps1'", '. $sb', '. Writer', '. (Get-Thing)'):
            with self.subTest(source):
                self.assertTrue(runs_unreadable_code(_command(source)))

    def test_a_relative_path_command_is_not_a_dot_invocation(self):
        """
        The dot of `.\\tool.exe` opens a path and the program runs in a scope of its own; only a dot
        standing apart from its target dot-sources. Conflating the two would mark every
        relative-path call as an unattributable write it does not make.
        """
        for source in (r'.\tool.exe', r'./tool.exe', r'.\sub\stage.ps1 -Foo bar'):
            with self.subTest(source):
                self.assertFalse(runs_unreadable_code(_command(source)))

    def test_a_dot_source_of_a_relative_path_is_still_unreadable(self):
        for source in (r'. .\stage2.ps1', r'. ./stage2.ps1'):
            with self.subTest(source):
                self.assertTrue(runs_unreadable_code(_command(source)))

    def test_invoke_command_runs_unreadable_code_only_with_no_new_scope(self):
        """
        `Invoke-Command` opens a child scope unless told not to, and `-NoNewScope` with a block this
        analysis never reads is the shape no other layer places: no block node stands at
        `-ScriptBlock $sb`, so `Ps1BlockModel` has nothing to carry out to the caller.
        """
        for source in (
            'Invoke-Command -NoNewScope -ScriptBlock $sb',
            'Invoke-Command -ScriptBlock $sb -NoNewScope',
        ):
            with self.subTest(source):
                self.assertTrue(runs_unreadable_code(_command(source)))
        self.assertFalse(runs_unreadable_code(_command('Invoke-Command -ScriptBlock $sb')))

    def test_a_dot_invoked_inline_block_is_not_unreadable(self):
        """
        Its body is written where it runs, so every layer above already reads it — and
        `Ps1BlockModel` is what carries a write inside it out to the caller.
        """
        self.assertFalse(runs_unreadable_code(_command('. { $x = 1 }')))

    def test_a_call_operator_opens_a_child_scope_and_writes_nothing_outside(self):
        """
        Measured: `& { $x = 'REPLACED' }` and `& stage2.ps1` both leave the caller's `$x` alone. The
        qualified write inside one — `& { iex '$script:x = 1' }` — does reach, and is a stated hole
        rather than a reason to call every `&` a caller-scope write.
        """
        for source in ("& 'stage2.ps1'", '& $sb', '& { $x = 1 }', 'Writer'):
            with self.subTest(source):
                self.assertFalse(runs_unreadable_code(_command(source)))

    def test_an_execution_context_invoke_runs_in_a_scope_of_its_own(self):
        """
        Measured, and against what it looks like: `$ExecutionContext.InvokeCommand.InvokeScript(…)`
        does *not* replace the caller's `$x`, so it belongs with `&` and not with
        `Invoke-Expression`.
        """
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
    """
    The two ways a script writes a name nothing can attribute are one question to a consumer: a
    computed name, and code this analysis never sees.
    """

    def test_a_computed_name_is_an_unattributable_write(self):
        self.assertTrue(writes_nobody_can_attribute(_command("Set-Variable $n 'v'")))

    def test_unreadable_code_is_an_unattributable_write(self):
        self.assertTrue(writes_nobody_can_attribute(_command('iex $c')))

    def test_a_write_naming_another_scope_is_not_one_this_answers_for(self):
        """
        `-Scope Global` reaches the script scope out of any body and at no particular moment, so it
        is not a fact about the point the command stands at — `Scope.writes_unreadable_names` holds
        it instead.
        """
        self.assertFalse(writes_nobody_can_attribute(_command("Set-Variable $n 'v' -Scope Global")))

    def test_a_literal_name_and_an_ordinary_command_are_neither(self):
        for source in ("Set-Variable y 'v'", 'Write-Host $x', '& { iex $c }'):
            with self.subTest(source):
                self.assertFalse(writes_nobody_can_attribute(_command(source)))
