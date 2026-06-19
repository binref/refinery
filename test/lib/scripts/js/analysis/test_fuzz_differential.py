from __future__ import annotations

import unittest

from test import TestBase

from test.lib.scripts.js.analysis.differential import behavior, node_executable
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
