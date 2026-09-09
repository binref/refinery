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


class TestPs1TheErrorReadSitesSplitTheTwoChannels(TestBase):
    """
    The channels a raise writes are told apart where the naming knowledge lives, so the persistent
    query cannot absorb the success flag and cluster 4 has the `$?` sites waiting for it.
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
