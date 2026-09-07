from __future__ import annotations

from test import TestBase
from test.lib.scripts.js.test_parser_recovery import A_CONSTRUCT_NESTED

from refinery.lib.scripts import canonical, is_well_formed
from refinery.lib.scripts.js.parser import JsParser


_A_DEPTH_THE_PARSER_READS = 150
"""
A nesting depth below the parser's own limit, so that every shape in `A_CONSTRUCT_NESTED` is read
whole rather than answered with the text it refused, and one that costs more interpreter frames than
the default recursion limit of a thousand provides, so that a tree this deep is comparable only when
the comparison raises that limit for itself.
"""


class TestADeepTreeIsComparedRatherThanExhaustingTheStack(TestBase):
    """
    `refinery.lib.scripts.canonical` decides which program a tree spells by descending every one of
    its nodes, so how deep a tree it answers for is decided by the parser's nesting limit and not by
    how many interpreter frames the process happens to run under. Whitespace around a program is one
    of the things the answer is defined to ignore, which makes a pair that differs only in leading
    and trailing newlines the same program at every depth the parser accepts.
    """

    def test_every_construct_is_read_whole_at_that_depth(self):
        self.assertEqual(
            {
                name: is_well_formed(JsParser(shape(_A_DEPTH_THE_PARSER_READS)).parse())
                for name, shape in A_CONSTRUCT_NESTED.items()
            },
            {name: True for name in A_CONSTRUCT_NESTED},
        )

    def test_surrounding_whitespace_is_the_same_program_at_that_depth(self):
        for name, shape in A_CONSTRUCT_NESTED.items():
            with self.subTest(name):
                source = shape(_A_DEPTH_THE_PARSER_READS)
                self.assertEqual(
                    canonical(JsParser(source).parse()),
                    canonical(JsParser(F'\n{source}\n').parse()),
                )

    def test_the_constructs_remain_distinct_programs_at_that_depth(self):
        self.assertEqual(
            len({
                canonical(JsParser(shape(_A_DEPTH_THE_PARSER_READS)).parse())
                for shape in A_CONSTRUCT_NESTED.values()
            }),
            len(A_CONSTRUCT_NESTED),
        )
