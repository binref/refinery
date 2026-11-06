"""
SECURITY: Node runs only the snippets this file writes. Nothing from `samples` may ever be handed to
the engine.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.ledger import printed, well_formed

from refinery.lib.scripts.js.analysis.model import is_use_position
from refinery.lib.scripts.js.model import JsIdentifier
from refinery.lib.scripts.js.parser import JsParser


A_MODULE_DECLARATION_CARRYING_ATTRIBUTES = (
    "import d from './x.json' with { type: 'json' };",
    "import * as ns from './x.json' with { type: 'json' };",
    "import { a } from './x.json' with { type: 'json' };",
    "export { a as b } from './x.json' with { type: 'json' };",
    "export * from './x.json' with { type: 'json' };",
    "export * as ns from './x.json' with { type: 'json' };",
)

A_CLAUSE_OF_MORE_THAN_ONE_ATTRIBUTE = (
    "export * from './x.json' with { type: 'json', hint: 'eager' };"
)

A_RE_EXPORT_CARRYING_NO_CLAUSE = (
    "export { a } from 'm';",
    "export * from 'm';",
    "export * as ns from 'm';",
)

A_CLAUSE_WITH_NO_FROM_TO_FOLLOW = (
    "import x with { type: 'json' };",
    "export * with { type: 'json' };",
    "export { default as j } with { type: 'json' };",
)


def _reads_a_binding_named(source: str, name: str) -> int:
    tree = JsParser(source).parse()
    return sum(
        is_use_position(node) for node in tree.walk()
        if isinstance(node, JsIdentifier) and node.name == name
    )


class TestAModuleDeclarationCarriesTheAttributesItWasWrittenWith(TestBase):

    def test_each_clause_is_a_well_formed_program_that_reads_no_binding(self):
        rows = A_MODULE_DECLARATION_CARRYING_ATTRIBUTES
        self.assertEqual(
            {source: (well_formed(source), _reads_a_binding_named(source, 'type')) for source in rows},
            {source: (True, 0) for source in rows},
        )

    def test_each_clause_prints_back_exactly_as_it_was_written(self):
        rows = A_MODULE_DECLARATION_CARRYING_ATTRIBUTES
        self.assertEqual(
            {source: printed(source) for source in rows},
            {source: source for source in rows},
        )

    def test_a_clause_of_more_than_one_attribute_survives_the_print(self):
        source = A_CLAUSE_OF_MORE_THAN_ONE_ATTRIBUTE
        self.assertEqual(
            (
                well_formed(source),
                printed(source),
                _reads_a_binding_named(source, 'type'),
                _reads_a_binding_named(source, 'hint'),
            ),
            (True, source, 0, 0),
        )

    def test_a_re_export_with_no_clause_prints_none(self):
        rows = A_RE_EXPORT_CARRYING_NO_CLAUSE
        self.assertEqual(
            {source: printed(source) for source in rows},
            {source: source for source in rows},
        )

    def test_a_clause_with_no_from_to_follow_is_no_program(self):
        rows = A_CLAUSE_WITH_NO_FROM_TO_FOLLOW
        self.assertEqual(
            {source: well_formed(source) for source in rows},
            {source: False for source in rows},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodeReadsEachClauseAndRefusesOneWithNoFrom(TestBase):

    def test_node_parses_each_clause_and_refuses_a_clause_with_no_from(self):
        """
        Node fails to find the absent module `./x.json` for every declaration that carries a clause,
        an error reported as `ERROR`, and fails to parse every clause that no `from` precedes.
        """
        carried = A_MODULE_DECLARATION_CARRYING_ATTRIBUTES + (A_CLAUSE_OF_MORE_THAN_ONE_ATTRIBUTE,)
        no_from = A_CLAUSE_WITH_NO_FROM_TO_FOLLOW
        self.assertEqual(
            {source: behavior(source, module=True)[1] for source in carried + no_from},
            {
                **{source: 'ERROR' for source in carried},
                **{source: 'SyntaxError' for source in no_from},
            },
        )
