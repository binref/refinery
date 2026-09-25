from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.handoff import Ps1Handoff
from refinery.lib.scripts.ps1.analysis.objects import Ps1ObjectFlow
from refinery.lib.scripts.ps1.analysis.world import runs_code_it_cannot_read
from refinery.lib.scripts.ps1.model import Ps1Variable
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _occurrences(tree: Node, name: str) -> list[Ps1Variable]:
    return [
        node for node in tree.walk_in_order()
        if isinstance(node, Ps1Variable) and node.name.lower() == name
    ]


def _objects(source: str) -> tuple[Node, Ps1ObjectFlow]:
    tree = Ps1Parser(source).parse()
    return tree, Ps1ModelCache(tree).object_flow


class TestPs1ACodeNobodyCanReadIsAChange(TestBase):
    """
    Code this analysis cannot read may store through any place it can name, whichever scope it runs
    in. Measured on 5.1 in `corpus.BEHAVIOURS`, a payload storing through a table that holds an
    array changes the array when a block made from it is run by `&` or `Invoke-Command`, when
    `InvokeScript` runs it, and when `Invoke-Expression` runs it.
    """

    def test_every_runner_of_code_from_a_string_runs_code_nobody_can_read(self):
        for source in (
            'iex $c',
            '& ([scriptblock]::Create($c))',
            '$ExecutionContext.InvokeCommand.InvokeScript($c)',
            '& $s',
            'Invoke-Command -ScriptBlock $s',
            'function f { iex $c }',
        ):
            with self.subTest(source):
                _, objects = _objects(source)
                self.assertTrue(objects.unreadable_code)

    def test_a_call_of_a_block_the_source_spells_runs_nothing_unreadable(self):
        for source in ('& { $x = 1 }', 'Write-Host hi', '[string]::Join(" ", $b)'):
            with self.subTest(source):
                _, objects = _objects(source)
                self.assertEqual(objects.unreadable_code, ())

    def test_code_run_by_a_created_block_is_unreadable_whatever_the_options_say(self):
        tree = Ps1Parser('& ([scriptblock]::Create($c))').parse()
        self.assertTrue(any(runs_code_it_cannot_read(node) for node in tree.walk()))


class TestPs1AChangeIsOrderedWhereTheNodeIsPlaced(TestBase):
    """
    Whether a change may follow a node is asked in the first graph on the node's way out that
    places the change. Measured on 5.1 in `corpus.BEHAVIOURS`, `$y = & { ,$x }` hands the block the
    array `$x` holds, and a payload run after it that stores through `$y` changes that array.
    """

    def test_a_change_after_the_statement_that_runs_a_block_follows_a_node_in_it(self):
        tree, objects = _objects('$x = 1, 2, 3; $y = & { ,$x }; $y[0] = 9')
        self.assertTrue(objects.change_may_follow(_occurrences(tree, 'x')[1]))

    def test_unreadable_code_after_the_statement_that_runs_a_block_follows_a_node_in_it(self):
        tree, objects = _objects('$x = 1, 2, 3; $y = & { ,$x }; iex $c')
        self.assertTrue(objects.unreadable_code_may_follow(_occurrences(tree, 'x')[1]))

    def test_a_change_before_the_statement_that_runs_a_block_does_not_follow_a_node_in_it(self):
        tree, objects = _objects('$z = 0, 0; $z[0] = 7; $x = 1, 2, 3; $y = & { ,$x }')
        self.assertFalse(objects.change_may_follow(_occurrences(tree, 'x')[1]))

    def test_a_change_in_a_function_body_may_follow_anything(self):
        tree, objects = _objects('function f { $z[0] = 7 }; $x = 1, 2, 3; Write-Output $x')
        self.assertTrue(objects.change_may_follow(_occurrences(tree, 'x')[1]))


class TestPs1AChangeTheObjectMaySeeBetweenAWriteAndARead(TestBase):
    """
    Whether the object a read observes may have been changed since the write through a place no
    occurrence of the name spells. Measured on 5.1 in `corpus.BEHAVIOURS`: a store through a
    table holding the array changes it, and a payload a called function runs through `$y` after
    `$y = $x` changes the array `$x` holds.
    """

    @staticmethod
    def _unseen(source: str) -> Ps1Handoff:
        tree, objects = _objects(source)
        occurrences = _occurrences(tree, 'x')
        return objects.unseen_change(occurrences[0], occurrences[-1])

    def test_a_store_through_a_container_holding_the_array_changes_it(self):
        self.assertIs(
            self._unseen("$x = 1, 2, 3; $h = @{ k = $x }; $h['k'][0] = 9; Write-Output $x"),
            Ps1Handoff.OBJECT,
        )

    def test_a_store_through_a_second_name_is_no_unseen_change(self):
        """
        The semantic model files a store spelled through `$y` against `$x` as well, so the change
        is a write of the name and not one this has to report.
        """
        self.assertIs(
            self._unseen('$x = 1, 2, 3; $y = $x; $y[0] = 9; Write-Output $x'),
            Ps1Handoff.NOWHERE,
        )

    def test_code_nobody_can_read_may_store_through_a_second_name(self):
        self.assertIs(
            self._unseen('$x = 1, 2, 3; $y = $x; function f { iex $c }; f; Write-Output $x'),
            Ps1Handoff.OBJECT,
        )

    def test_a_change_before_the_hand_off_changes_nothing_the_read_observes(self):
        self.assertIs(
            self._unseen("$z = 0, 0; $z[0] = 7; $x = 1, 2, 3; $h = @{ k = $x }; Write-Output $x"),
            Ps1Handoff.NOWHERE,
        )
