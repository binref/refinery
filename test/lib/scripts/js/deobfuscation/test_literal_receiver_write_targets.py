from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    node_executable,
)


@unittest.skipUnless(node_executable() is not None, 'node.js is required')
class TestLiteralReceiverWriteTargets(TestBase):

    def _preserves(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_assignment_targets_preserve_behavior(self):
        for source in [
            'console.log([1, 2, 3][0] = 9);',
            'console.log("abc"[0] = "x");',
            'console.log([1, 2, 3].length = 1);',
            'console.log([10, 20, 30][1] += 5);',
            'console.log("abc"[1] += "z");',
            'console.log([1, 2, 3].length += 2);',
        ]:
            with self.subTest(source=source):
                self._preserves(source)

    def test_increment_and_decrement_targets_preserve_behavior(self):
        for source in [
            'console.log([1, 2, 3][2]++);',
            'console.log(--[9, 8, 7][1]);',
            'console.log([1, 2, 3].length++);',
            'console.log("abc"[0]++);',
            'console.log(--"abc"[2]);',
        ]:
            with self.subTest(source=source):
                self._preserves(source)

    def test_delete_targets_preserve_behavior(self):
        for source in [
            'console.log(delete [1, 2, 3][0]);',
            'console.log(delete "abc"[0]);',
            'console.log(delete [1, 2, 3].length);',
        ]:
            with self.subTest(source=source):
                self._preserves(source)
