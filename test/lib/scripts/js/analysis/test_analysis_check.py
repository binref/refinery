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
    """
    The probe generator must be a pure function of its seed, so a failure in the soundness sweep below
    reproduces from its seed. Generation needs no Node.js and is checked here; the runtime invariant
    that requires an engine lives in the Node-gated class.
    """

    def test_generation_is_deterministic(self):
        for seed in range(256):
            self.assertEqual(generate_probe(seed).source, generate_probe(seed).source)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestMutationAnalysisIsSound(TestBase):
    """
    The runtime ground-truth gate for `EffectModel.mutated_bindings`: for each generated program, run
    its function in Node.js, record which outer variables it actually rebinds, and assert the model
    reported every one it could observe. This catches an under-reporting mutation analysis directly —
    on a tiny program, with no deobfuscation pass needed to expose it — the failure mode behind three
    of the bugs the binding-resolved effect lift introduced (a confined-but-read write dropped from the
    set, and a redeclared callee whose effect went unattributed). Only the safe direction is asserted:
    the model may name a binding that did not change on a given run, but it must never miss one. Node is
    the oracle; the model, never this test, is what is under scrutiny.
    """

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
