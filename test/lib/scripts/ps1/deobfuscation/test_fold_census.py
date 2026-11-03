from __future__ import annotations

import unittest
import unittest.mock

from refinery.lib.scripts.ps1.deobfuscation import _folds, deobfuscate
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer

from test.lib.scripts.ps1.corpus import oracle_corpus
from test.lib.scripts.ps1.deobfuscation.fold_census import FOLDS
from test.lib.scripts.ps1.deobfuscation.fold_contribution import CONTRIBUTION, Contribution


def census() -> dict[str, str]:
    """
    Every corpus row the deobfuscator rewrites, with what it rewrites it to. A row whose output
    equals its canonical input is absent rather than mapped to itself, so the population of this
    dictionary is the set of folds the tool takes.
    """
    folded = {}
    for row in oracle_corpus():
        ast = Ps1Parser(row).parse()
        before = Ps1Synthesizer().convert(ast)
        deobfuscate(ast)
        after = Ps1Synthesizer().convert(ast)
        if after != before:
            folded[row] = after
    return folded


class TestPs1FoldCensus(unittest.TestCase):
    """
    Which folds the deobfuscator takes over the whole corpus, held against a recorded baseline.

    A change that refuses more than it used to still passes every test that asserts an answer is
    correct, because a refusal is not a wrong answer — it only stops being an answer. Here it is a
    key that went missing.
    """

    def test_every_fold_the_corpus_takes_is_the_one_recorded(self):
        self.assertEqual(census(), FOLDS)

    def test_a_neutered_pass_moves_only_the_folds_recorded_for_it(self):
        """
        The census can only be trusted to catch a lost fold if a lost fold moves it. The rows
        themselves are pinned, so that a pass which drops one fold and picks up another has to say
        which. A fold that appears only when a pass is disabled may mean the passes are fighting,
        and the census would then record whichever won the race, so every such fold is recorded
        with the reason it is not one.
        """
        baseline = census()
        for transformer in _folds:
            with self.subTest(neutered=transformer.__name__):
                with unittest.mock.patch.object(transformer, 'visit', lambda self, node: None):
                    without = census()
                measured = Contribution(
                    lost=tuple(sorted(set(baseline) - set(without))),
                    changed=tuple(sorted(
                        row for row in set(baseline) & set(without)
                        if baseline[row] != without[row]
                    )),
                    added=tuple(sorted(set(without) - set(baseline))),
                )
                recorded = CONTRIBUTION[transformer.__name__]
                with self.subTest(law='the folds it takes away are the recorded ones'):
                    self.assertEqual(measured.lost, recorded.lost)
                    self.assertEqual(measured.changed, recorded.changed)
                with self.subTest(law='the folds it adds are the recorded ones'):
                    self.assertEqual(measured.added, recorded.added)
