from __future__ import annotations

import unittest

from test import TestBase

from test.lib.scripts.js.analysis.analysis_check import (
    generate_probe,
    model_view,
    observed_changes,
    unsound_misses,
)
from test.lib.scripts.js.analysis.differential import node_executable


class TestAnalysisCheckGenerator(TestBase):

    def test_generation_is_deterministic(self):
        for seed in range(256):
            self.assertEqual(generate_probe(seed).source, generate_probe(seed).source)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestMutationAnalysisIsSound(TestBase):

    def test_mutated_bindings_covers_runtime_mutations(self):
        observed_total = 0
        for seed in range(96):
            probe = generate_probe(seed)
            observed = observed_changes(probe)
            observed_total += len(observed)
            missed = unsound_misses(probe, observed, model_view(probe))
            self.assertEqual(
                set(),
                missed,
                F'seed {seed}: f rebound {sorted(missed)} at runtime but mutated_bindings omitted them\n'
                F'{probe.source}',
            )
        self.assertGreater(
            observed_total,
            96,
            'the generator produced too few runtime mutations for a meaningful soundness sweep',
        )
