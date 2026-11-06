"""
SECURITY: the snippets here are hand-authored and benign, and `node --check` only parses them, never
running one. Nothing from `samples` may ever be fed to this.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    node_executable,
    node_reads_as_a_program,
)
from test.lib.scripts.js.ledger import printed, well_formed

from refinery.lib.scripts.js.model import JsBigIntLiteral, JsNumericLiteral, JsProperty
from refinery.lib.scripts.js.parser import JsParser


A_PROPERTY_KEY = {
    'x = { a: 1 };': True,
    'x = { if: 1 };': True,
    "x = { 'a b': 1 };": True,
    'x = { 1: 1 };': True,
    'x = { .5: 1 };': True,
    'x = { 08: 1 };': True,
    'x = { 1_0: 1 };': True,
    'x = { 1n: 1 };': True,
    'x = { [k]: 1 };': True,
    'x = { +: 1 };': False,
    'x = { ,: 1 };': False,
    'x = { ;: 1 };': False,
    'x = { ): 1 };': False,
    'x = { %: 1 };': False,
    'x = { ++: 1 };': False,
    'x = { =>: 1 };': False,
    'x = { @: 1 };': False,
    'x = { #a: 1 };': False,
    'x = { +() {} };': False,
    'class C { +() {} }': False,
}


def _sole_property(source: str) -> JsProperty:
    return [
        node for node in JsParser(source).parse().walk()
        if isinstance(node, JsProperty)
    ][0]


def _canonical(text: str) -> str:
    return ''.join(text.split())


class TestAPropertyKeyIsSpelledByAName(TestBase):
    def test_a_key_that_spells_no_property_name_is_not_a_well_formed_program(self):
        self.assertEqual(
            {source: well_formed(source) for source in A_PROPERTY_KEY},
            A_PROPERTY_KEY,
        )

    def test_a_numeral_in_a_key_position_is_the_numeral_it_is_anywhere_else(self):
        self.assertEqual(
            (
                type(_sole_property('x = { 1n: 1 };').key),
                type(_sole_property('x = { 1: 1 };').key),
            ),
            (JsBigIntLiteral, JsNumericLiteral),
        )

    def test_a_key_the_rule_refuses_still_prints_back_as_it_was_written(self):
        self.assertEqual(
            {source: _canonical(printed(source)) for source in A_PROPERTY_KEY},
            {source: _canonical(source) for source in A_PROPERTY_KEY},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheEngineReadsEachKeyAsTheCorpusRecords(TestBase):

    def test_node_reads_each_key_as_the_corpus_records_it(self):
        self.assertEqual(
            {source: node_reads_as_a_program(source) for source in A_PROPERTY_KEY},
            A_PROPERTY_KEY,
        )
