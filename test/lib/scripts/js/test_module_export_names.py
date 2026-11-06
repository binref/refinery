"""
An import or export list may name the far side of the module boundary with a string literal, as in
`export { x as 'a b' }`, and the name is the text the string denotes.

Every JavaScript escape here is assembled from `chr(92)`, because one typed into a Python string is
resolved by Python and reaches the parser and Node as the character it names. Every table holding
escapes is checked for the backslash its escaped rows carry.

SECURITY: Node runs only the modules this file writes. Nothing from `samples` may ever be handed to
the engine.
"""
from __future__ import annotations

import unittest

from collections.abc import Iterable, Mapping

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    module_graph_behavior,
    node_executable,
)
from test.lib.scripts.js.ledger import printed, well_formed

from refinery.lib.scripts.js.model import (
    JsExportAllDeclaration,
    JsExportSpecifier,
    JsImportSpecifier,
    JsStringLiteral,
)
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser


def _an_escape(code: int) -> str:
    return F'{chr(92)}u{code:04X}'


ESCAPED_B = _an_escape(0x62)
ESCAPED_LINE_FEED = F'{chr(92)}n'


def _a_graph(middle: str, entry: str) -> dict[str, str]:
    return {
        'src.mjs': 'export var a = 1;\n',
        'mid.mjs': F'{middle}\n',
        'main.mjs': F'{entry}\n',
    }


def _the_module_export_name(source: str) -> str | None:
    for node in JsParser(source).parse().walk_in_order():
        if isinstance(node, JsImportSpecifier):
            written = node.imported
        elif isinstance(node, (JsExportSpecifier, JsExportAllDeclaration)):
            written = node.exported
        else:
            continue
        return written.value if isinstance(written, JsStringLiteral) else None
    return None


def _deobfuscated(files: Mapping[str, str]) -> dict[str, str]:
    return {
        name: deobfuscate_source(text, execution=ExecutionModel.module)
        for name, text in files.items()
    }


def _unspelled(sources: Iterable[str]) -> list[str]:
    return [source for source in sources if chr(92) not in source]


A_SPECIFIER_NAMING_THE_BOUNDARY_WITH_A_STRING = {
    "export { a as 'b c' } from 'm';": 'b c',
    "import { 'b c' as v } from 'm';": 'b c',
    "export * as 'b c' from 'm';": 'b c',
    'var a = 1; export { a as ' + F"'{ESCAPED_B} c' }};": 'b c',
    'import { ' + F"'{ESCAPED_B} c'" + " as v } from 'm';": 'b c',
    'export * as ' + F"'{ESCAPED_B} c'" + " from 'm';": 'b c',
}


A_NAME_THE_TWO_SIDES_SPELL_DIFFERENTLY = {
    (
        "export { a as 'b c' } from './src.mjs';",
        "import { 'b c' as v } from './mid.mjs';\nconsole.log(v);",
    ): ('1\n', None),
    (
        'export { a as ' + F"'{ESCAPED_B} c'" + " } from './src.mjs';",
        "import { 'b c' as v } from './mid.mjs';\nconsole.log(v);",
    ): ('1\n', None),
    (
        "export { a as 'b c' } from './src.mjs';",
        'import { ' + F"'{ESCAPED_B} c'"
        + " as v } from './mid.mjs';\nconsole.log(v);",
    ): ('1\n', None),
    (
        'export * as ' + F"'{ESCAPED_B} c'" + " from './src.mjs';",
        "import { 'b c' as ns } from './mid.mjs';\nconsole.log(ns.a);",
    ): ('1\n', None),
    (
        'export { a as ' + F"'x{ESCAPED_LINE_FEED}y'" + " } from './src.mjs';",
        'import { ' + F"'x{ESCAPED_LINE_FEED}y'"
        + " as v } from './mid.mjs';\nconsole.log(v);",
    ): ('1\n', None),
    (
        'function a() { return 1; }\nexport { a as ' + F"'{ESCAPED_B} c'" + ' };',
        "import { 'b c' as v } from './mid.mjs';\nconsole.log(v());",
    ): ('1\n', None),
    (
        "export { a as 'b c' } from './src.mjs';",
        'import { "' + "'b c'" + '" as v } from ' + "'./mid.mjs';\nconsole.log(v);",
    ): ('', 'SyntaxError'),
}


A_SPECIFIER_HALF_NO_NAME_IS_READ_FROM = (
    "import { a as if } from './src.mjs';",
    'import { a as ' + _an_escape(0x69) + "f } from './src.mjs';",
    'import { a as ' + F'{chr(92)}u{{110000}}' + " } from './src.mjs';",
)


class TestANameWrittenAsAStringIsTheTextThatStringDenotes(TestBase):

    def test_a_name_written_as_a_string_is_the_text_that_string_denotes(self):
        rows = A_SPECIFIER_NAMING_THE_BOUNDARY_WITH_A_STRING
        self.assertEqual(_unspelled(list(rows)[3:]), [])
        self.assertEqual({source: _the_module_export_name(source) for source in rows}, rows)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAModuleReachesTheNameItsStringDenotesAndNotItsSpelling(TestBase):

    def test_two_spellings_of_one_name_reach_each_other_across_the_boundary(self):
        rows = A_NAME_THE_TWO_SIDES_SPELL_DIFFERENTLY
        self.assertEqual(_unspelled(F'{middle}{entry}' for middle, entry in list(rows)[1:6]), [])
        self.assertEqual(
            {row: module_graph_behavior(_a_graph(*row), 'main.mjs') for row in rows},
            rows,
        )

    def test_the_tool_leaves_every_module_of_the_graph_saying_what_it_said(self):
        rows = A_NAME_THE_TWO_SIDES_SPELL_DIFFERENTLY
        self.assertEqual(
            {
                row: module_graph_behavior(_deobfuscated(_a_graph(*row)), 'main.mjs')
                for row in rows
            },
            rows,
        )


class TestASpecifierHalfNoNameIsReadFromIsPrintedAsItWasWritten(TestBase):

    def test_a_declaration_the_parser_could_not_read_whole_comes_back_whole(self):
        rows = A_SPECIFIER_HALF_NO_NAME_IS_READ_FROM
        self.assertEqual(_unspelled(rows[1:]), [])
        self.assertEqual(
            {source: (printed(source), well_formed(source)) for source in rows},
            {source: (source, False) for source in rows},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAProgramNodeRefusesIsNotAnsweredWithOneThatRuns(TestBase):

    def test_a_declaration_no_engine_reads_is_answered_with_one_no_engine_reads(self):
        rows = {
            source: _a_graph('export var b = 2;', F'{source}\nconsole.log(1);')
            for source in A_SPECIFIER_HALF_NO_NAME_IS_READ_FROM
        }
        self.assertEqual(
            {
                source: (
                    module_graph_behavior(files, 'main.mjs'),
                    module_graph_behavior(_deobfuscated(files), 'main.mjs'),
                )
                for source, files in rows.items()
            },
            {source: (('', 'SyntaxError'), ('', 'SyntaxError')) for source in rows},
        )


#: A string where a specifier names the local binding it creates, which no string may name, mapped
#: to the smallest edit that moves the same string to the far side of the boundary: a `from` clause
#: makes an export a re-export, and an `as` clause gives an import its local name.
A_STRING_WHERE_A_LOCAL_BINDING_BELONGS = {
    "export { 'a' };": "export { 'a' } from 'm';",
    "export { 'a' as b };": "export { 'a' as b } from 'm';",
    "import { 'a' } from 'm';": "import { 'a' as b } from 'm';",
}


#: A boundary name written as a string holding a lone surrogate, mapped to the same declaration with
#: the surrogate paired: a string naming the boundary must be well-formed UTF-16.
A_LONE_SURROGATE = _an_escape(0xD800)
A_LONE_LOW_SURROGATE = _an_escape(0xDC00)
A_SURROGATE_PAIR = A_LONE_SURROGATE + A_LONE_LOW_SURROGATE
A_BOUNDARY_NAME_HOLDING_A_LONE_SURROGATE = {
    F"export {{ a as '{A_LONE_SURROGATE}' }} from 'm';":
        F"export {{ a as '{A_SURROGATE_PAIR}' }} from 'm';",
    F"import {{ '{A_LONE_LOW_SURROGATE}' as v }} from 'm';":
        F"import {{ '{A_SURROGATE_PAIR}' as v }} from 'm';",
    F"export * as '{A_LONE_SURROGATE}' from 'm';":
        F"export * as '{A_SURROGATE_PAIR}' from 'm';",
}


class TestAStringNamesTheBoundaryAndOnlyAWellFormedOne(TestBase):

    def test_a_string_naming_a_local_binding_is_no_program_and_its_boundary_twin_is(self):
        rows = A_STRING_WHERE_A_LOCAL_BINDING_BELONGS
        self.assertEqual(
            {source: well_formed(source) for source in rows},
            {source: False for source in rows},
        )
        self.assertEqual(
            {twin: well_formed(twin) for twin in rows.values()},
            {twin: True for twin in rows.values()},
        )
        self.assertEqual(
            {source: printed(source) for source in rows},
            {source: source for source in rows},
        )

    def test_a_boundary_name_with_a_lone_surrogate_is_no_program_and_its_paired_twin_is(self):
        rows = A_BOUNDARY_NAME_HOLDING_A_LONE_SURROGATE
        self.assertEqual(_unspelled(list(rows) + list(rows.values())), [])
        self.assertEqual(
            {source: well_formed(source) for source in rows},
            {source: False for source in rows},
        )
        self.assertEqual(
            {twin: well_formed(twin) for twin in rows.values()},
            {twin: True for twin in rows.values()},
        )
        self.assertEqual(
            {source: printed(source) for source in rows},
            {source: source for source in rows},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodeRefusesAStringOutOfPositionAndParsesItsTwin(TestBase):
    """
    Node refuses every left side of the two tables at parse with a `SyntaxError`, and parses every
    right side, which then fails at the link only because no module `m` exists.
    """

    def test_node_refuses_each_out_of_position_string_and_parses_its_twin(self):
        banned = (
            list(A_STRING_WHERE_A_LOCAL_BINDING_BELONGS)
            + list(A_BOUNDARY_NAME_HOLDING_A_LONE_SURROGATE)
        )
        twins = (
            list(A_STRING_WHERE_A_LOCAL_BINDING_BELONGS.values())
            + list(A_BOUNDARY_NAME_HOLDING_A_LONE_SURROGATE.values())
        )
        self.assertEqual(
            {source: behavior(source, module=True)[1] for source in banned},
            {source: 'SyntaxError' for source in banned},
        )
        self.assertEqual(
            {twin: behavior(twin, module=True)[1] for twin in twins},
            {twin: 'ERROR' for twin in twins},
        )
