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
from test.lib.scripts.js.ledger import well_formed


#: Each expression an update is written against, mapped to whether V8 reads it as a well-formed
#: operand. The specification forbids a call there, but V8 accepts `f()++` in every mode and throws
#: a `ReferenceError` only when it runs.
AN_UPDATE_OPERAND = {
    'a': True,
    'a.b': True,
    'a[b]': True,
    'a.b.c': True,
    'f()': True,
    'f().b': True,
    'a.b()': True,
    '(a)': True,
    '(a.b)': True,
    'new a().b': True,
    'a?.b': False,
    'a?.b.c': False,
    'a.b?.c': False,
    'this': False,
    '1': False,
    '[a]': False,
    '(a, b)': False,
    'new a': False,
    'a => {}': False,
    'function () {}': False,
    'class {}': False,
    '(a?.b)': False,
}


A_FILE_WRITING_AN_UPDATE = {
    **{
        source: reference
        for operand, reference in AN_UPDATE_OPERAND.items()
        for source in (F'{operand}++;', F'++{operand};')
    },
    'f = a => {}++': False,
    'f = function () {}++': False,
}


class TestAnUpdateWritesBackToAReference(TestBase):
    def test_an_update_against_something_that_is_no_reference_is_no_program(self):
        self.assertEqual(
            {source: well_formed(source) for source in A_FILE_WRITING_AN_UPDATE},
            A_FILE_WRITING_AN_UPDATE,
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheEngineReadsEachUpdateAsTheCorpusRecords(TestBase):

    def test_node_reads_each_update_as_the_corpus_records_it(self):
        self.assertEqual(
            {source: node_reads_as_a_program(source) for source in A_FILE_WRITING_AN_UPDATE},
            A_FILE_WRITING_AN_UPDATE,
        )
