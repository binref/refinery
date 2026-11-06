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


A_DECLARATION_AS_A_STATEMENT = {
    'var x;': True,
    'let x;': True,
    'const x;': False,
    'var [a];': False,
    'var {a};': False,
    'let [a];': False,
    'let {a};': False,
    'const [a];': False,
    'const {a};': False,
}


def _in_the_iterating_heads() -> dict[str, bool]:
    return {
        F'for ({keyword} {target} {word} o) {{}}': True
        for keyword in ('var', 'let', 'const')
        for target in ('x', '[a]', '{a}')
        for word in ('in', 'of')
    }


A_DECLARATION_IN_A_FOR_HEAD = {
    **_in_the_iterating_heads(),
    'for (var x;;) {}': True,
    'for (let x;;) {}': True,
    'for (const x;;) {}': False,
    'for (var [a];;) {}': False,
    'for (var {a};;) {}': False,
    'for (let [a];;) {}': False,
    'for (let {a};;) {}': False,
    'for (const [a];;) {}': False,
    'for (const {a};;) {}': False,
}

A_DECLARATION_WHEREVER_IT_STANDS = {
    **A_DECLARATION_AS_A_STATEMENT,
    **A_DECLARATION_IN_A_FOR_HEAD,
}


def _canonical(text: str) -> str:
    return ''.join(text.split())


class TestADeclarationIsWrittenWithAnInitializerAsItsKeywordAndTargetDecide(TestBase):
    def test_a_statement_declaration_may_omit_the_initializer_only_for_a_named_var_or_let(self):
        self.assertEqual(
            {source: well_formed(source) for source in A_DECLARATION_AS_A_STATEMENT},
            A_DECLARATION_AS_A_STATEMENT,
        )

    def test_a_for_head_lifts_the_requirement_only_where_it_iterates(self):
        self.assertEqual(
            {source: well_formed(source) for source in A_DECLARATION_IN_A_FOR_HEAD},
            A_DECLARATION_IN_A_FOR_HEAD,
        )

    def test_a_declaration_the_rule_refuses_still_prints_back_as_it_was_written(self):
        self.assertEqual(
            {source: _canonical(printed(source)) for source in A_DECLARATION_WHEREVER_IT_STANDS},
            {source: _canonical(source) for source in A_DECLARATION_WHEREVER_IT_STANDS},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheEngineReadsEachDeclarationAsTheCorpusRecords(TestBase):

    def test_node_reads_each_declaration_as_the_corpus_records_it(self):
        self.assertEqual(
            {
                source: node_reads_as_a_program(source)
                for source in A_DECLARATION_WHEREVER_IT_STANDS
            },
            A_DECLARATION_WHEREVER_IT_STANDS,
        )
