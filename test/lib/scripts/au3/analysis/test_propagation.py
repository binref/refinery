"""
The binding walk against its payload bound: a run of assignments that stays within it folds, and
one that leaves it is refused whole — every read the overflowing value flowed from is retracted
from the walk's records, so the run passes through as written instead of half-folded, while a read
that merely consumes a mid-run value keeps the record of the value that stood there.
"""
from __future__ import annotations

import inspect

from test import TestBase

from refinery.lib.scripts.au3.analysis.existence import build_existence_model
from refinery.lib.scripts.au3.analysis.propagation import build_propagation_model
from refinery.lib.scripts.au3.analysis.scopes import build_scope_model
from refinery.lib.scripts.au3.analysis.values import to_string
from refinery.lib.scripts.au3.model import Au3Variable
from refinery.lib.scripts.au3.parser import Au3Parser

_HALF = 'a' * 2048
_OTHER = 'b' * 2048
_TAIL = 'a' * 2049


def _recorded(source: str) -> list[tuple[str, str]]:
    """
    Every read the walk recorded over *source*, in a stable order, as the name read and the printed
    value at the read.
    """
    root = Au3Parser(inspect.cleandoc(source)).parse()
    scopes = build_scope_model(root)
    model = build_propagation_model(root, scopes, build_existence_model(root, scopes))
    return sorted(
        (node.name, to_string(value))
        for node in root.walk()
        if isinstance(node, Au3Variable)
        and (value := model.values.get(node)) is not None
    )


class TestAu3PropagationModel(TestBase):

    def test_a_run_to_exactly_the_bound_folds(self):
        source = F'''
            Global $v = "{_HALF}"
            $v = $v & "{_HALF}"
            $w = $v
            '''
        self.assertEqual(_recorded(source), sorted([('v', _HALF), ('v', 'a' * 4096)]))

    def test_a_run_past_the_bound_is_refused_whole(self):
        """
        The reads the overflowing value flowed from — the read in the overflowing statement itself
        and every read behind the bindings it built on — leave the records, while the consumer read
        between the links keeps the mid-run value that stood there.
        """
        source = F'''
            Global $v = "{_HALF}"
            $v = $v & "{_HALF}"
            $w = $v
            $v = $v & "{_HALF}"
            '''
        self.assertEqual(_recorded(source), [('v', 'a' * 4096)])

    def test_every_shape_that_feeds_an_overflowing_binding_is_retracted(self):
        for value in (
            F'$v & "{_TAIL}"',
            F'"b" & $v & "{_TAIL}"',
            F'$v & $v & "a"',
            F'"c" & $v & "d" & $v',
        ):
            with self.subTest(value=value):
                source = F'''
                    Global $v = "{_HALF}"
                    $u = $v
                    $v = {value}
                    '''
                self.assertEqual(_recorded(source), [('v', _HALF)])

    def test_a_declaration_chain_past_the_bound_is_refused_whole(self):
        source = F'''
            Global $v = "{_HALF}"
            Global $u = $v
            Global $w = $v & "{_TAIL}"
            '''
        self.assertEqual(_recorded(source), [('v', _HALF)])

    def test_a_compound_assignment_past_the_bound_is_refused_whole(self):
        source = F'''
            Global $seed = "{_HALF}"
            Global $v = $seed
            $v &= "{_TAIL}"
            '''
        self.assertEqual(_recorded(source), [])

    def test_a_branch_join_past_the_bound_is_refused_whole(self):
        """
        Both branches bind the same value, so the join keeps it with the lineages of both behind
        it, and an overflow after the join retracts the read in each branch.
        """
        source = F'''
            Global $v = "{_HALF}"
            If $c Then
                $v = $v & "{_HALF}"
            Else
                $v = $v & "{_HALF}"
            EndIf
            $w = $v
            $v = $v & "{_HALF}"
            '''
        self.assertEqual(_recorded(source), [('v', 'a' * 4096)])

    def test_a_run_past_the_bound_under_two_names_is_refused_whole(self):
        source = F'''
            Global $v = "{_HALF}"
            Global $w = "{_OTHER}"
            $v = $v & $w
            $u = $v
            $w = $w & $v
            '''
        self.assertEqual(_recorded(source), [('v', _HALF + _OTHER)])

    def test_a_combination_over_an_unknown_operand_keeps_its_records(self):
        """
        A combination that fails on an unknown operand is a refusal, not an overflow: nothing
        proves the run grows past the bound, so the reads stay recorded exactly as before.
        """
        source = F'''
            Global $v = "{_HALF}"
            $u = $v
            $v = $v & $x
            $w = $v
            '''
        self.assertEqual(_recorded(source), [('v', _HALF), ('v', _HALF)])
