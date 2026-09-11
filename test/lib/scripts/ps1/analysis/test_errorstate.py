from __future__ import annotations

from inspect import cleandoc

from test import TestBase

from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.errorstate import Ps1ErrorStateReach
from refinery.lib.scripts.ps1.model import (
    Ps1CastExpression,
    Ps1Script,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _parse(source: str) -> Ps1Script:
    return Ps1Parser(cleandoc(source)).parse()


def _reach(source: str) -> tuple[Ps1Script, Ps1ErrorStateReach]:
    tree = _parse(source)
    return tree, Ps1ModelCache(tree).error_state


def _raiser(tree: Ps1Script) -> Ps1CastExpression:
    """
    The `[Int]'abc'` cast every fixture raises with. It is nested inside the statement that raises,
    and `persistent_read_observed_after` locates it to that statement, so passing the cast asks the
    query about the raiser wherever it is written — at the top level or inside a branch.
    """
    return next(node for node in tree.walk() if isinstance(node, Ps1CastExpression))


def _success_read(tree: Ps1Script) -> Ps1Variable:
    """
    The single `$?` occurrence of a fixture, wherever it is written. `success_flag_at` locates it to
    the statement that reads it, so passing the variable asks the query about that read's position.
    """
    return next(
        node for node in tree.walk() if isinstance(node, Ps1Variable) and node.name == '?')


class TestPs1PersistentReadObservedAfterAnswersFromReachability(TestBase):

    def test_a_read_reachable_after_the_raiser_is_observed(self):
        tree, reach = _reach("""
            $Null = [Int]'abc'
            $Error.Count
        """)
        self.assertTrue(reach.persistent_read_observed_after(_raiser(tree)))

    def test_a_read_only_before_the_raiser_is_not_observed(self):
        tree, reach = _reach("""
            $Error.Count
            $Null = [Int]'abc'
        """)
        self.assertFalse(reach.persistent_read_observed_after(_raiser(tree)))

    def test_a_read_on_a_branch_the_raiser_cannot_reach_is_not_observed(self):
        tree, reach = _reach("""
            if ($c) {
              $Null = [Int]'abc'
            } else {
              $Error.Count
            }
        """)
        self.assertFalse(reach.persistent_read_observed_after(_raiser(tree)))

    def test_a_stacktrace_read_reachable_after_the_raiser_is_observed(self):
        tree, reach = _reach("""
            $Null = [Int]'abc'
            $StackTrace
        """)
        self.assertTrue(reach.persistent_read_observed_after(_raiser(tree)))

    def test_a_success_flag_read_after_the_raiser_is_not_a_persistent_read(self):
        tree, reach = _reach("""
            $Null = [Int]'abc'
            if (-not $?) { 'x' }
        """)
        self.assertFalse(reach.persistent_read_observed_after(_raiser(tree)))

    def test_a_named_reference_read_of_error_after_the_raiser_is_observed(self):
        tree, reach = _reach("""
            $Null = [Int]'abc'
            Write-Host (Get-Variable Error).Value.Count
        """)
        self.assertTrue(reach.persistent_read_observed_after(_raiser(tree)))

    def test_a_splatted_read_of_the_record_after_the_raiser_is_observed(self):
        tree, reach = _reach("""
            $Null = [Int]'abc'
            Write-Output @Error
        """)
        self.assertTrue(reach.persistent_read_observed_after(_raiser(tree)))


class TestPs1TheErrorReadSitesSplitTheTwoChannels(TestBase):
    """
    The channels a raise writes are told apart where the naming knowledge lives, so the persistent
    query cannot absorb the success flag.
    """

    def test_the_error_record_is_a_persistent_site_and_the_success_flag_a_success_site(self):
        tree = _parse("""
            $Error.Count
            $StackTrace
            if (-not $?) { 'x' }
        """)
        sites = Ps1ModelCache(tree).commands.error_state_read_sites()
        persistent_names = {
            node.name.lower() for node in sites.persistent if isinstance(node, Ps1Variable)}
        success_names = {
            node.name for node in sites.success if isinstance(node, Ps1Variable)}
        self.assertEqual(persistent_names, {'error', 'stacktrace'})
        self.assertEqual(success_names, {'?'})


class TestPs1SuccessFlagAtDecidesFromPosition(TestBase):
    """
    `$?` resets on every statement, so its value is a property of what runs immediately before the
    read. `success_flag_at` decides it from that position: `True` at the top of the root script,
    `False` when the statement before certainly raises, and `None` — leave it in place — wherever the
    position cannot settle it. Each pin carries a same-shape control that moves the verdict, so the
    query is tested by what selects the answer and not by one input's incidental shape.
    """

    def test_a_read_at_the_top_of_the_root_script_is_true(self):
        tree, reach = _reach("if ($?) { 'x' }")
        self.assertIs(reach.success_flag_at(_success_read(tree)), True)

    def test_a_read_after_a_certain_raise_is_false(self):
        tree, reach = _reach("""
            $Null = [Int]'abc'
            if ($?) { 'x' }
        """)
        self.assertIs(reach.success_flag_at(_success_read(tree)), False)

    def test_a_read_after_a_command_whose_failure_is_unprovable_is_undecided(self):
        tree, reach = _reach(r"""
            Get-Item C:\missing
            if ($?) { 'x' }
        """)
        self.assertIsNone(reach.success_flag_at(_success_read(tree)))

    def test_a_read_below_a_param_default_that_can_fail_is_undecided(self):
        tree, reach = _reach(r"""
            param($x = (Get-Item C:\missing))
            if ($?) { 'x' }
        """)
        self.assertIsNone(reach.success_flag_at(_success_read(tree)))

    def test_a_read_in_a_live_loop_condition_is_undecided(self):
        tree, reach = _reach("while ($?) { 'x' }")
        self.assertIsNone(reach.success_flag_at(_success_read(tree)))

    def test_a_while_condition_whose_body_certainly_raises_stays_undecided(self):
        tree, reach = _reach("""
            while ($?) {
              'x'
              $Null = [Int]'abc'
            }
        """)
        self.assertIsNone(reach.success_flag_at(_success_read(tree)))

    def test_a_do_while_condition_after_a_body_that_certainly_raises_is_false(self):
        tree, reach = _reach("""
            do {
              'x'
              $Null = [Int]'abc'
            } while ($?)
        """)
        self.assertIs(reach.success_flag_at(_success_read(tree)), False)

    def test_a_read_at_the_top_of_a_process_block_is_undecided(self):
        tree, reach = _reach("process { if ($?) { 'x' } }")
        self.assertIsNone(reach.success_flag_at(_success_read(tree)))

    def test_a_read_at_the_top_of_an_end_block_is_true(self):
        tree, reach = _reach("end { if ($?) { 'x' } }")
        self.assertIs(reach.success_flag_at(_success_read(tree)), True)

    def test_a_read_after_a_certain_raise_inside_a_function_is_false_inside_that_body(self):
        tree, reach = _reach("""
            function Invoke-Thing {
              $Null = [Int]'abc'
              if ($?) { 'x' }
            }
        """)
        self.assertIs(reach.success_flag_at(_success_read(tree)), False)

    def test_a_read_at_a_function_body_entry_is_undecided(self):
        tree, reach = _reach("""
            function Invoke-Thing {
              if ($?) { 'x' }
            }
        """)
        self.assertIsNone(reach.success_flag_at(_success_read(tree)))

    def test_a_read_at_a_resuming_trap_body_entry_is_undecided(self):
        tree, reach = _reach("""
            trap { $s = $?; continue }
            $Null = [Int]'abc'
        """)
        self.assertIsNone(reach.success_flag_at(_success_read(tree)))

    def test_a_read_after_a_merge_of_a_raising_and_a_plain_arm_is_undecided(self):
        tree, reach = _reach("""
            if ($c) {
              $Null = [Int]'abc'
            } else {
              'plain'
            }
            if ($?) { 'x' }
        """)
        self.assertIsNone(reach.success_flag_at(_success_read(tree)))


class TestPs1WritesSuccessFlagIsTheKillSet(TestBase):
    """
    A leaf expression-statement resets `$?` on every path it takes; a compound statement and a
    function definition each leave it on at least one path, so they are transparent. `writes_success_flag`
    is that measured table — the KILL set the veto's reaching-definition walk blocks on and the gate
    it opens with.
    """

    def test_a_store_is_a_writer(self):
        tree = _parse('$junk = 5')
        self.assertTrue(Ps1ErrorStateReach.writes_success_flag(tree.body[0]))

    def test_a_command_is_a_writer(self):
        tree = _parse("Write-Host 'x'")
        self.assertTrue(Ps1ErrorStateReach.writes_success_flag(tree.body[0]))

    def test_an_assignment_whose_subexpression_runs_no_statement_still_writes(self):
        """
        Measured on Windows PowerShell 5.1: a leaf assignment resets `$?` even when its right-hand
        subexpression runs zero statements. `Get-Item C:\\missing -EA SilentlyContinue; $x =
        $(if ($false) {1}); $?` reads `$true`, and so do `$()`, `@()`, and a bare `$(if ($false)
        {1})` statement. The KILL set is the statement kind, not what the subexpression evaluates, so
        such a statement must never be read as transparent — doing so would free an earlier writer a
        later read still observes.
        """
        tree = _parse('$x = $(if ($false) { 1 })')
        self.assertTrue(Ps1ErrorStateReach.writes_success_flag(tree.body[0]))

    def test_an_empty_if_is_transparent(self):
        tree = _parse('if ($c) { }')
        self.assertFalse(Ps1ErrorStateReach.writes_success_flag(tree.body[0]))

    def test_an_empty_foreach_is_transparent(self):
        tree = _parse('foreach ($i in $c) { }')
        self.assertFalse(Ps1ErrorStateReach.writes_success_flag(tree.body[0]))

    def test_a_function_definition_is_transparent(self):
        tree = _parse('function f { }')
        self.assertFalse(Ps1ErrorStateReach.writes_success_flag(tree.body[0]))

    def test_a_synthetic_node_is_transparent(self):
        self.assertFalse(Ps1ErrorStateReach.writes_success_flag(None))


class TestPs1SuccessFlagWriteObservedIsAReachingDefinition(TestBase):
    """
    Whether removing a `$?` writer would change what a live `$?` read sees — the reaching-definition
    of the reset-on-every-statement flag. A writer is kept when a read is reachable from it over plain
    control flow through only transparent statements, and freed when a later writer overwrites the flag
    first, when the statement is transparent so removing it changes nothing, or when the script reads
    `$?` nowhere. Each pin carries a same-shape control that moves the verdict.
    """

    def test_a_writer_observed_through_a_transparent_no_op_is_kept(self):
        tree, reach = _reach("""
            $junk = 5
            if ($zzz) { }
            Write-Host $?
        """)
        self.assertTrue(reach.success_flag_write_observed(tree.body[0]))

    def test_a_writer_a_later_writer_overwrites_is_freed(self):
        tree, reach = _reach("""
            $junk = 5
            $other = 1
            Write-Host $?
        """)
        self.assertFalse(reach.success_flag_write_observed(tree.body[0]))

    def test_the_later_writer_the_read_observes_is_itself_kept(self):
        tree, reach = _reach("""
            $junk = 5
            $other = 1
            Write-Host $?
        """)
        self.assertTrue(reach.success_flag_write_observed(tree.body[1]))

    def test_a_transparent_statement_is_never_kept_by_this_axis(self):
        tree, reach = _reach("""
            function f { }
            Write-Host $?
        """)
        self.assertFalse(reach.success_flag_write_observed(tree.body[0]))

    def test_a_writer_in_a_script_that_reads_no_success_flag_is_freed(self):
        tree, reach = _reach("""
            $junk = 5
            Write-Host 'x'
        """)
        self.assertFalse(reach.success_flag_write_observed(tree.body[0]))

    def test_a_writer_a_read_observes_across_a_resuming_trap_is_kept(self):
        tree, reach = _reach("""
            trap { continue }
            $junk = 5
            Write-Host $?
        """)
        self.assertTrue(reach.success_flag_write_observed(tree.body[1]))
