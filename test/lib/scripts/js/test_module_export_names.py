"""
The name an import or export list gives the far side of the module boundary, and what a tool writes
for a specifier half it could not read.

That position holds a word or a string literal, and the two are separate productions rather than
two spellings of one thing. A string names the text it denotes: `export { x as 'a b' }` reaches a
name no word spells, an escape between the quotes stands for the character it names, and the quotes
themselves are how the text was written and no part of it — which is what a module asking for the
name `"'a b'"` is refused for.

The other half of a specifier names a binding the file creates, and a text no name is read from
leaves the position holding the span that was written. The span is what comes back out: a
declaration printed without the `as` clause it was written with is a different declaration and not
a repair, whatever the parser made of the half it could not read.

Every answer here is Node's over a graph of `.mjs` files, since a module is the only kind of code
these declarations appear in and what one of them reaches is the linker's answer rather than the
parser's.

The hazard this module is written against is its own: a unicode escape typed into a Python string is
resolved by Python and reaches JavaScript as the character it names, so every escape here is
assembled from `chr(92)` and every table is checked for the backslash it must carry.

SECURITY: every module below is written out by this file and Node runs only those. Nothing from
`samples` may ever be handed to the engine.
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
    """
    The JavaScript unicode escape naming the code point *code*.

    The backslash is assembled from `chr(92)` and never typed into this file. An escape Python
    resolved is the character it named by the time anything here reads it, and a case that lost its
    escape asks nothing.
    """
    return F'{chr(92)}u{code:04X}'


#: The letter `b` written as an escape, and a line feed written as one. A name carrying either is a
#: name whose spelling and whose text are different strings, which is the whole of what these
#: declarations are read wrongly over.
ESCAPED_B = _an_escape(0x62)
ESCAPED_LINE_FEED = F'{chr(92)}n'


def _a_graph(middle: str, entry: str) -> dict[str, str]:
    """
    The three modules of a graph: one exporting `a`, a middle one written as *middle* that passes a
    name on, and the entry written as *entry* that prints what it reached.
    """
    return {
        'src.mjs': 'export var a = 1;\n',
        'mid.mjs': F'{middle}\n',
        'main.mjs': F'{entry}\n',
    }


def _the_module_export_name(source: str) -> str | None:
    """
    The name the one specifier of *source* reaches across the module boundary with, which is the
    text denoted by the string literal written in that position. A position holding anything other
    than a string literal denotes no text at all, and nothing is what that is reported as.
    """
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
    """
    The sources among *sources* holding no backslash, which is the whole of what tells a case
    written with a JavaScript escape from one Python resolved before Node or the parser saw it.
    """
    return [source for source in sources if chr(92) not in source]


#: Every declaration the grammar lets a string literal name the boundary in, mapped to the text it
#: denotes. Each writes the same name, `b c`, which no word spells and which the last three write
#: with an escape.
A_SPECIFIER_NAMING_THE_BOUNDARY_WITH_A_STRING = {
    "export { a as 'b c' } from 'm';": 'b c',
    "import { 'b c' as v } from 'm';": 'b c',
    "export * as 'b c' from 'm';": 'b c',
    'var a = 1; export { a as ' + F"'{ESCAPED_B} c' }};": 'b c',
    'import { ' + F"'{ESCAPED_B} c'" + " as v } from 'm';": 'b c',
    'export * as ' + F"'{ESCAPED_B} c'" + " from 'm';": 'b c',
}


#: The declaration written in the middle module and the one written in the entry, mapped to what
#: Node prints for the graph they stand in and what it throws. The two sides of each row spell the
#: name differently, so what matches them is the text the literals denote and not the way either was
#: written.
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


#: A declaration whose local binding is named by a text the parser reads no name from: a word the
#: language reserves, an escape spelling one, and an escape naming no code point at all. Node
#: refuses each of the three.
A_SPECIFIER_HALF_NO_NAME_IS_READ_FROM = (
    "import { a as if } from './src.mjs';",
    'import { a as ' + _an_escape(0x69) + "f } from './src.mjs';",
    'import { a as ' + F'{chr(92)}u{{110000}}' + " } from './src.mjs';",
)


class TestANameWrittenAsAStringIsTheTextThatStringDenotes(TestBase):
    """
    A string literal standing where an import or export list names the boundary is read as the
    literal it is, and the name it gives is the text it denotes. Reading it as a word instead asks a
    name reader for a text that opens with a quote, which leaves the tree holding a name no module
    has and, where the text carries an escape, leaves no name at all.
    """

    def test_a_name_written_as_a_string_is_the_text_that_string_denotes(self):
        """
        Each of the six declarations of `A_SPECIFIER_NAMING_THE_BOUNDARY_WITH_A_STRING` names `b c`,
        three of them writing the `b` as an escape. A reading that kept the raw spelling would
        answer with the quotes still on it, and one that took the position for a word would answer
        with nothing at all.
        """
        rows = A_SPECIFIER_NAMING_THE_BOUNDARY_WITH_A_STRING
        self.assertEqual(_unspelled(list(rows)[3:]), [])
        self.assertEqual({source: _the_module_export_name(source) for source in rows}, rows)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAModuleReachesTheNameItsStringDenotesAndNotItsSpelling(TestBase):
    """
    What a module exports under and what another module imports by are matched as text. Two
    spellings denoting one text are one name, and the quotes a literal was written with are no part
    of it — so a graph whose two sides disagree only in spelling links, and one asking for the
    quoted text does not link at all.

    The tool has to leave every module of such a graph meaning what it meant. A rewrite that drops
    an `as` clause, or that changes the text a literal denotes, is invisible in the file it stands
    in and is a link error in the file that reads it.
    """

    def test_two_spellings_of_one_name_reach_each_other_across_the_boundary(self):
        """
        Node prints `1` for six of the seven graphs of `A_NAME_THE_TWO_SIDES_SPELL_DIFFERENTLY`,
        which spell the name plainly on both sides, with an escape on the export side, with one on
        the import side, through a namespace re-export, with a line feed inside the name, and off a
        local binding. The seventh asks for the name `'b c'` with the quotes taken for part of it,
        and Node refuses it: the requested module provides no export of that name.
        """
        rows = A_NAME_THE_TWO_SIDES_SPELL_DIFFERENTLY
        self.assertEqual(_unspelled(F'{middle}{entry}' for middle, entry in list(rows)[1:6]), [])
        self.assertEqual(
            {row: module_graph_behavior(_a_graph(*row), 'main.mjs') for row in rows},
            rows,
        )

    def test_the_tool_leaves_every_module_of_the_graph_saying_what_it_said(self):
        """
        Every module of each graph of `A_NAME_THE_TWO_SIDES_SPELL_DIFFERENTLY` deobfuscated, run
        together, answers what the graph answered before: the six that print `1` still print it, and
        the one Node refuses is still refused.
        """
        rows = A_NAME_THE_TWO_SIDES_SPELL_DIFFERENTLY
        self.assertEqual(
            {
                row: module_graph_behavior(_deobfuscated(_a_graph(*row)), 'main.mjs')
                for row in rows
            },
            rows,
        )


class TestASpecifierHalfNoNameIsReadFromIsPrintedAsItWasWritten(TestBase):
    """
    A local binding a specifier names with a word the language reserves is refused, and so is one
    named by an escape spelling such a word or by an escape naming no code point. The position then
    holds the span that was written rather than a name, and printing has one thing to do with it,
    which is to write it back: a file that comes back declaring a different import than the one it
    was given says the tool read something it did not.
    """

    def test_a_declaration_the_parser_could_not_read_whole_comes_back_whole(self):
        """
        Each of the three declarations of `A_SPECIFIER_HALF_NO_NAME_IS_READ_FROM` prints back as the
        text it was written as, and each is a tree
        `refinery.lib.scripts.is_well_formed` answers `False` for, the position holding a span and
        not a name.
        """
        rows = A_SPECIFIER_HALF_NO_NAME_IS_READ_FROM
        self.assertEqual(_unspelled(rows[1:]), [])
        self.assertEqual(
            {source: (printed(source), well_formed(source)) for source in rows},
            {source: (source, False) for source in rows},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAProgramNodeRefusesIsNotAnsweredWithOneThatRuns(TestBase):
    """
    The three declarations no name is read from are three files no engine reads, and the answer the
    tool gives for one has to be refused as well. A file that links and runs where the original
    never could is the one answer that tells an analyst something the program never did.
    """

    def test_a_declaration_no_engine_reads_is_answered_with_one_no_engine_reads(self):
        """
        Node refuses each graph of `A_SPECIFIER_HALF_NO_NAME_IS_READ_FROM` with a `SyntaxError` and
        prints nothing, from the source and from whatever the tool writes for it alike.
        """
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


#: A string standing where a specifier names the local binding it creates rather than the far side of
#: the boundary, mapped to the smallest edit that lets the same string stand. A `from` clause makes a
#: named export a re-export, whose near side is a boundary name and not a local; an `as` clause moves
#: the string off the import binding onto the boundary. A local binding is a name the file refers to
#: and no string spells one, so Node refuses every left side at parse and reads every right one.
A_STRING_WHERE_A_LOCAL_BINDING_BELONGS = {
    "export { 'a' };": "export { 'a' } from 'm';",
    "export { 'a' as b };": "export { 'a' as b } from 'm';",
    "import { 'a' } from 'm';": "import { 'a' as b } from 'm';",
}


#: A boundary name written as a string that carries a lone surrogate, mapped to the same declaration
#: with that surrogate paired. A lone surrogate — a high one no low one follows, or a low one on its
#: own — is a code unit spelling no character a name may hold, so Node refuses every left side at
#: parse and reads every right one. Each surrogate is a JavaScript escape assembled from `chr(92)`,
#: so the code unit it names is the parser's to resolve and never Python's.
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
    """
    A string may name what a specifier reaches across the boundary, and there alone. The near side of
    a specifier names a binding the file creates, which no string spells, and a boundary name a
    string does spell must denote a well-formed run of code units. A declaration written against
    either rule is read with the repair recorded, so `refinery.lib.scripts.is_well_formed` answers
    `False` for it, while the smallest edit obeying the rule is a program the same reader admits.

    Nothing is answered wrongly: each refused declaration prints back as the text it was written as,
    the position holding the string that was there and not a name.
    """

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
    Every left side of the two tables is a file Node refuses at parse with a `SyntaxError`, and every
    right side is one it parses and turns away only at the link, for the module `m` none of them
    provides. The parse clearing on the right is what makes the refusal on the left about where the
    string stands and how it is spelled, and not about a string standing in a specifier at all.
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
