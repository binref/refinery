from __future__ import annotations

import unittest

from test import TestBase

from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.analysis.jsgen import generate


class TestFuzzGenerator(TestBase):
    """
    Self-validation for the seeded program generator that feeds the differential fuzzer. A
    divergence between a program and its deobfuscation is only trustworthy as a deobfuscator bug
    when the program is itself sound, so these tests pin the generator's invariants rather than any
    deobfuscation behavior. Generation being a pure function of the seed needs no Node.js and is
    checked here; the runtime invariants that require an engine live in the Node-gated class below.
    """

    def test_generation_is_deterministic(self):
        for seed in range(256):
            self.assertEqual(generate(seed), generate(seed))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestFuzzGeneratorRunsInNode(TestBase):
    """
    A generated program is a sound oracle input only if Node.js runs it without an uncaught
    exception, so a future divergence cannot be a spurious `SyntaxError` or `ReferenceError`, and
    only if it is deterministic, so comparing an original against its deobfuscation is meaningful. A
    failure here is a generator regression to fix before the fuzzer can be trusted, never a
    deobfuscator bug.
    """

    def test_generated_programs_run_cleanly_and_deterministically(self):
        for seed in range(64):
            source = generate(seed)
            first = behavior(source)
            self.assertIsNone(
                first[1],
                F'seed {seed} did not run cleanly in node:\n{source}',
            )
            self.assertEqual(
                first,
                behavior(source),
                F'seed {seed} is not deterministic in node:\n{source}',
            )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationFuzzSweep(TestBase):
    """
    The differential sweep itself: over a fixed seed range, a generated program and its deobfuscation
    must behave identically in Node.js, and deobfuscation must not raise. Node is the oracle — no
    expected output is asserted. This is the permanent regression gate that keeps the three fixed
    semantics-preservation P0s closed (an effectful `if` test, negative zero, and an effectful call
    dropped with a dead store). Generator soundness is the precondition checked above, so a failure
    here is a deobfuscator bug, not a spurious input.
    """

    def test_deobfuscation_preserves_behavior_across_seeds(self):
        for seed in range(64):
            source = generate(seed)
            original = behavior(source)
            self.assertIsNone(
                original[1],
                F'seed {seed} did not run cleanly in node:\n{source}',
            )
            deobfuscated = deobfuscate_source(source)
            self.assertEqual(
                original,
                behavior(deobfuscated),
                F'seed {seed}: deobfuscation changed observable behavior\n'
                F'--- source ---\n{source}\n--- deobfuscated ---\n{deobfuscated}',
            )
