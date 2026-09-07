from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import is_well_formed
from refinery.lib.scripts.js.model import JsErrorNode
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


def _read_and_printed(source: str) -> tuple[bool, str, int]:
    ast = JsParser(source).parse()
    return is_well_formed(ast), JsSynthesizer().convert(ast), len(ast.body)


def _unread(source: str) -> list[tuple[str, str]]:
    return [
        (node.text, node.message)
        for node in JsParser(source).parse().walk_in_order()
        if isinstance(node, JsErrorNode)
    ]


class TestAConditionalMissingItsColonStopsAtItsBoundary(TestBase):
    """
    A conditional expression whose colon is absent may not be finished by stepping over the token
    that stands where the colon was expected. Where that token closes the statement or the block,
    stepping over it reads the next statement as the conditional's alternate and folds the whole
    tail of the block into one expression. Node rejects every colon-less source here; what is
    pinned is that the parser keeps the conditional as the text it stands in, up to the token
    that closes it and never past it, so that the statements after it are read as themselves.
    """

    def test_the_statement_after_a_colonless_conditional_is_kept(self):
        _, printed, count = _read_and_printed('f(); a ? b; g();')
        self.assertEqual(printed, 'f();\na ? b;\ng();')
        self.assertEqual(count, 3)
        self.assertEqual(_unread('f(); a ? b; g();'), [('a ? b;', 'expected :')])

    def test_a_colonless_conditional_stops_at_the_token_that_closes_it(self):
        expected = {
            'end_of_file': ('a ? b', 'a ? b'),
            'closing_brace': ('{ a ? b }', '{\n  a ? b\n}'),
            'closing_paren': ('h(a ? b)', 'h(a ? b);'),
        }
        for name, (source, printed) in expected.items():
            with self.subTest(name):
                self.assertEqual(JsSynthesizer().convert(JsParser(source).parse()), printed)
                self.assertEqual(_unread(source), [('a ? b', 'expected :')])

    def test_a_colonless_conditional_is_not_a_well_formed_program(self):
        for source in ('f(); a ? b; g();', 'a ? b', '{ a ? b }', 'h(a ? b)'):
            with self.subTest(source):
                self.assertEqual(is_well_formed(JsParser(source).parse()), False)

    def test_a_conditional_that_has_its_colon_is_left_alone(self):
        well_formed, printed, count = _read_and_printed('f(); a ? b : c; g();')
        self.assertEqual(printed, 'f();\na ? b : c;\ng();')
        self.assertEqual(well_formed, True)
        self.assertEqual(count, 3)
