from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import canonical, is_well_formed
from refinery.lib.scripts.js.model import JsConditionalExpression, JsMemberExpression
from refinery.lib.scripts.js.parser import JsParser


_SPLIT_AND_TIGHT = {
    'computed_member': ("o ? .['k']", "o?.['k']"),
    'dotted_member': ('o ? .k', 'o?.k'),
    'optional_call': ('f ? .(1)', 'f?.(1)'),
    'chain_after_an_index': ("o['a'] ? .['b']", "o['a']?.['b']"),
}
"""
Each key names a shape of optional chain; the pair is that chain with the two characters of its `?.`
operator split by a space, and the same chain written tight. Node rejects every split spelling and
accepts every tight one, and a space is the only difference between the members of a pair.
"""


class TestASplitOptionalChainOperatorRecoversToTheChain(TestBase):

    def test_a_split_operator_is_the_same_program_as_the_tight_operator(self):
        for name, (split, tight) in _SPLIT_AND_TIGHT.items():
            with self.subTest(name):
                self.assertEqual(
                    canonical(JsParser(split).parse()),
                    canonical(JsParser(tight).parse()),
                )

    def test_the_split_spelling_is_flagged_repaired_and_the_tight_one_is_not(self):
        for name, (split, tight) in _SPLIT_AND_TIGHT.items():
            with self.subTest(name):
                self.assertEqual(is_well_formed(JsParser(split).parse()), False)
                self.assertEqual(is_well_formed(JsParser(tight).parse()), True)

    def test_a_dot_after_a_question_that_opens_a_number_stays_a_conditional(self):
        for source in ('x ? .5 : y', 'a ? b.c : d'):
            with self.subTest(source):
                ast = JsParser(source).parse()
                nodes = list(ast.walk())
                self.assertEqual(is_well_formed(ast), True)
                self.assertEqual(any(isinstance(n, JsConditionalExpression) for n in nodes), True)
                self.assertEqual(
                    any(isinstance(n, JsMemberExpression) and n.optional for n in nodes), False)
