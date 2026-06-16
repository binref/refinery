from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.helpers import (
    has_remaining_references,
    make_string_literal,
)
from refinery.lib.scripts.js.parser import JsParser


class TestDeobfuscationHelpers(TestJsDeobfuscator):

    def test_make_string_literal_escapes_control_chars(self):
        self.assertEqual(make_string_literal('a\nb').raw, "'a\\nb'")
        self.assertEqual(make_string_literal('x\ry').raw, "'x\\ry'")
        self.assertEqual(make_string_literal('p\tq').raw, "'p\\tq'")
        self.assertEqual(make_string_literal('m\0n').raw, "'m\\0n'")

    def test_shadowed_param_does_not_prevent_table_cleanup(self):
        source = inspect.cleandoc(
            """
            function uses_table_param(table) { return table.length; }
            uses_table_param([1, 2, 3]);
            """
        )
        ast = JsParser(source).parse()
        result = has_remaining_references(ast, 'table', check_shadowing=True)
        self.assertFalse(result,
            'all occurrences of table are shadowed by function parameters')
