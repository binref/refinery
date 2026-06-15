from __future__ import annotations

from test.lib.scripts.vba.deobfuscation import TestVba

from refinery.lib.scripts.vba.deobfuscation.names import text_compare_safe


class TestVbaNames(TestVba):

    def test_text_compare_safe_predicate(self):
        # Case folding is locale-independent only for ASCII digits and ASCII letters other than the
        # Turkic-sensitive I/i; symbols and non-ASCII are unsafe.
        self.assertTrue(text_compare_safe(''))
        self.assertTrue(text_compare_safe('AB12'))
        self.assertFalse(text_compare_safe('FILE'))
        self.assertFalse(text_compare_safe('file'))
        self.assertFalse(text_compare_safe('a-b'))
        self.assertFalse(text_compare_safe('\xe9'))
