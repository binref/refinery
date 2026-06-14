from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    make_string_literal,
    switch_matches,
)
from refinery.lib.scripts.ps1.model import (
    Ps1HereString,
    Ps1StringLiteral,
)


class TestPs1Helpers(TestPs1):

    def test_multiline_string_emitted_as_here_string(self):
        node = make_string_literal('line1\nline2')
        self.assertIsInstance(node, Ps1HereString)
        self.assertEqual(node.value, 'line1\nline2')
        self.assertIn("@'\n", node.raw)
        node2 = make_string_literal('no newlines')
        self.assertIsInstance(node2, Ps1StringLiteral)

    def test_switch_matches_bool_int_coercion(self):
        # PowerShell coerces between bool and int in switch/`-eq` comparisons, so a `$true` label
        # matches the integer 1 and `$false` matches 0.
        self.assertTrue(switch_matches(1, True))
        self.assertTrue(switch_matches(0, False))
        self.assertFalse(switch_matches(2, True))

    def test_make_string_literal_avoids_herestring_breakout(self):
        # A value with a line beginning with the here-string terminator `'@` must not be emitted as
        # a here-string, or it would close the string early; a safe multi-line value still may.
        unsafe = make_string_literal("a\n'@\nb")
        self.assertNotIsInstance(unsafe, Ps1HereString)
        safe = make_string_literal('a\nb')
        self.assertIsInstance(safe, Ps1HereString)
