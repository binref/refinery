from __future__ import annotations

import random
import unittest

from typing import NamedTuple

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.test_comment_carriers import every_program_holding_a_comment
from test.lib.scripts.js.deobfuscation.test_escaped_identifiers import (
    AN_ESCAPED_ACCESSOR_TERMINAL,
    AN_ESCAPED_ASYNC_TERMINAL,
    AN_ESCAPED_KEYWORD_OPERATOR,
    AN_ESCAPED_STATIC_TERMINAL,
)
from test.lib.scripts.js.ledger import (
    before_and_after,
    dropped_source_characters,
    printed,
    well_formed,
)

from refinery.lib.scripts import is_well_formed
from refinery.lib.scripts.js.model import (
    JsCallExpression,
    JsDoWhileStatement,
    JsErrorNode,
    JsExpressionStatement,
    JsIfStatement,
    JsRegExpLiteral,
    JsScript,
    JsSwitchCase,
    JsSwitchStatement,
    Node,
    file_ended_inside,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.units.sinks.ppjscript import ppjscript


def unread_spans(tree: Node) -> list[str]:
    """
    The text every `refinery.lib.scripts.js.model.JsErrorNode` of *tree* keeps, in the order the
    file writes them.
    """
    return [node.text for node in tree.walk_in_order() if isinstance(node, JsErrorNode)]


def spans_written_in_order(text: str, spans: list[str]) -> bool:
    """
    Whether *text* writes each of *spans* verbatim, one behind the other in the order given.
    """
    cursor = 0
    for span in spans:
        found = text.find(span, cursor)
        if found < 0:
            return False
        cursor = found + len(span)
    return True


def a_span_the_parser_kept(node: object) -> tuple[type, str]:
    """
    The kind of *node*, and the text it keeps where it is a span no parser could read.
    """
    return type(node), node.text if isinstance(node, JsErrorNode) else ''


_HEAD = 'const registry = {};\nconst names = Object.keys(registry);\n'
"""
The two statements every source below starts with. A recovery that swallowed what stood before the
position it could not read would show up in the printed text rather than hide in a one-token file,
and the printer writes these two back character for character, which is why every expectation here
is spelled as this text followed by the tail the broken construct contributes.
"""


class Stop(NamedTuple):
    """
    A source that stops where the language still requires something, together with the text that
    would have finished it. `cut` is what the tool is handed and `whole` is the file it was cut
    from, so the text the cut took is the whole of the difference between the two. Node rejects
    every `cut` here and accepts every `whole`.
    """
    opened: str
    closing: str

    @property
    def cut(self) -> str:
        return F'{_HEAD}{self.opened}'

    @property
    def whole(self) -> str:
        return F'{_HEAD}{self.opened}{self.closing}'


_STOPS = {
    'var_with_no_name': Stop(
        'var', ' handler = registry;\n'),
    'const_with_no_name': Stop(
        'const', ' handler = registry;\n'),
    'member_access_with_no_name': Stop(
        'registry.', 'alpha;\n'),
    'optional_member_access_with_no_name': Stop(
        'registry?.', 'alpha;\n'),
    'chained_member_access_with_no_name': Stop(
        'registry.alpha.', 'beta;\n'),
    'new_meta_property_with_no_name': Stop(
        'function build() { new.', 'target; }\n'),
    'object_getter_with_no_name': Stop(
        'const o = { get', ' alpha() { return 1; } };\n'),
    'object_setter_with_no_name': Stop(
        'const o = { set', ' alpha(v) { registry.v = v; } };\n'),
    'object_async_method_with_no_name': Stop(
        'const o = { async', ' alpha() {} };\n'),
    'catch_parameter_with_no_name': Stop(
        'try { names.pop(); } catch (', 'err) { registry.e = err; }\n'),
    'label_with_no_statement': Stop(
        'outer:', ' while (names.pop()) break outer;\n'),
    'super_member_with_no_name': Stop(
        'class Foo extends Object { m() { super.', 'toString(); } }\n'),
    'class_heritage_with_no_name': Stop(
        'class Foo extends', ' Object {}\n'),
    'export_default_with_no_value': Stop(
        'export default', ' registry;\n'),
    'computed_member_with_no_key': Stop(
        'registry[', "'alpha'];\n"),
    'spread_with_no_argument': Stop(
        'const o = { ...', 'registry };\n'),
    'for_head_with_no_binding': Stop(
        'for (const', ' x of names) registry[x] = 1;\n'),
    'switch_case_with_no_test': Stop(
        'switch (names.length) { case', ' 1: break; }\n'),
    'arrow_with_no_body': Stop(
        'const f = () =>', ' registry;\n'),
    'member_access_in_a_template_with_no_name': Stop(
        'String(`a${registry.', 'alpha}b`);\n'),
}


_MALFORMED = {
    'doubled_dot': 'registry..alpha;\n',
    'dot_before_a_semicolon': 'registry.;\n',
    'dot_before_a_bracket': 'registry.];\n',
    'dot_before_a_string': "registry.'alpha';\n",
    'new_dot_before_a_string': "function f() { new.'target'; }\n",
    'label_before_a_closing_brace': 'function f() { outer: }\n',
}
"""
Sources that stop nowhere and are simply wrong: a name position holding something that is not a
name. Node rejects each of them, and unlike a cut file no completion turns one into a program, so
what the tool does with them is pinned on its own.
"""


class TestParserRecoveryAlwaysPrints(TestBase):
    """
    `refinery.lib.scripts.js.parser.JsParser` never raises, so every question about a broken file is
    answered by the tree it recovers. A construct the parser cannot finish reading is kept as the
    text it stands in: a `refinery.lib.scripts.js.model.JsErrorNode` reading, verbatim, the
    statement or list item the construct began at up to where the file stopped, and nothing is
    written that the file did not hold. What is pinned here is that the text comes back, that
    printing it again writes the same text, which span is the one kept, and that the tree says it
    is not a program. Node refuses every print here, since none of the cuts was made whole.
    """

    def _print(self, source: str) -> str:
        return JsSynthesizer().convert(JsParser(source).parse())

    def _errors(self, source: str) -> list[tuple[str, str]]:
        return [
            (node.text, node.message)
            for node in JsParser(source).parse().walk_in_order()
            if isinstance(node, JsErrorNode)
        ]

    def test_a_source_that_stops_mid_construct_prints_the_text_it_read(self):
        expected = {
            'var_with_no_name': 'var',
            'const_with_no_name': 'const',
            'member_access_with_no_name': 'registry.',
            'optional_member_access_with_no_name': 'registry?.',
            'chained_member_access_with_no_name': 'registry.alpha.',
            'new_meta_property_with_no_name': 'function build() {\n  new.',
            'object_getter_with_no_name': 'const o = { get',
            'object_setter_with_no_name': 'const o = { set',
            'object_async_method_with_no_name': 'const o = { async',
            'catch_parameter_with_no_name': 'try { names.pop(); } catch (',
            'label_with_no_statement': 'outer:',
            'super_member_with_no_name': 'class Foo extends Object {\n  m() {\n    super.',
            'class_heritage_with_no_name': 'class Foo extends',
            'export_default_with_no_value': 'export default',
            'computed_member_with_no_key': 'registry[',
            'spread_with_no_argument': 'const o = { ...',
            'for_head_with_no_binding': 'for (const',
            'switch_case_with_no_test': 'switch (names.length) {\n  case',
            'arrow_with_no_body': 'const f = () =>',
            'member_access_in_a_template_with_no_name': 'String(`a${registry.',
        }
        self.assertEqual(
            {name: self._print(_STOPS[name].cut) for name in expected},
            {name: F'{_HEAD}{tail}' for name, tail in expected.items()},
        )

    def test_a_source_that_stops_mid_construct_is_not_a_well_formed_program(self):
        self.assertEqual(
            {name: is_well_formed(JsParser(stop.cut).parse()) for name, stop in _STOPS.items()},
            {name: False for name in _STOPS},
        )

    def test_the_construct_a_source_stops_inside_is_kept_as_an_error_node(self):
        """
        The span kept begins where the statement or list item the construct belongs to began: a
        member access keeps the object it hangs off, a method body keeps only the statement inside
        it, and a `case` keeps only its clause, since a switch is a list the parser reads clause by
        clause. A bracketed list the file ends inside is kept as the list it is, so what an object
        literal contributes is the member the file stopped inside and not the literal around it.
        """
        expected = {
            'var_with_no_name': [('var', 'expected a name')],
            'const_with_no_name': [('const', 'expected a name')],
            'member_access_with_no_name': [('registry.', 'expected a property name')],
            'optional_member_access_with_no_name': [('registry?.', 'expected a property name')],
            'chained_member_access_with_no_name': [('registry.alpha.', 'expected a property name')],
            'new_meta_property_with_no_name': [('new.', 'expected a property name')],
            'object_getter_with_no_name': [('get', 'expected a property name')],
            'object_setter_with_no_name': [('set', 'expected a property name')],
            'object_async_method_with_no_name': [('async', 'expected a property name')],
            'catch_parameter_with_no_name': [('try { names.pop(); } catch (', 'expected a name')],
            'label_with_no_statement': [('outer:', 'unexpected token')],
            'super_member_with_no_name': [('super.', 'expected a property name')],
            'class_heritage_with_no_name': [('class Foo extends', 'unexpected token')],
            'export_default_with_no_value': [('export default', 'unexpected token')],
            'computed_member_with_no_key': [('registry[', 'unexpected token')],
            'spread_with_no_argument': [('...', 'unexpected token')],
            'for_head_with_no_binding': [('for (const', 'expected a name')],
            'switch_case_with_no_test': [('case', 'unexpected token')],
            'arrow_with_no_body': [('const f = () =>', 'unexpected token')],
            'member_access_in_a_template_with_no_name':
                [('registry.', 'expected a property name')],
        }
        self.assertEqual({name: self._errors(_STOPS[name].cut) for name in expected}, expected)

    def test_writing_the_text_the_cut_took_yields_a_program_that_prints(self):
        expected = {
            'var_with_no_name': 'var handler = registry;',
            'const_with_no_name': 'const handler = registry;',
            'member_access_with_no_name': 'registry.alpha;',
            'optional_member_access_with_no_name': 'registry?.alpha;',
            'chained_member_access_with_no_name': 'registry.alpha.beta;',
            'new_meta_property_with_no_name': 'function build() {\n  new.target;\n}',
            'object_getter_with_no_name': 'const o = { get alpha() {\n  return 1;\n} };',
            'object_setter_with_no_name': 'const o = { set alpha(v) {\n  registry.v = v;\n} };',
            'object_async_method_with_no_name': 'const o = { async alpha() {} };',
            'catch_parameter_with_no_name':
                'try {\n  names.pop();\n} catch (err) {\n  registry.e = err;\n}',
            'label_with_no_statement': 'outer: while (names.pop()) {\n  break outer;\n}',
            'super_member_with_no_name':
                'class Foo extends Object {\n  m() {\n    super.toString();\n  }\n}',
            'class_heritage_with_no_name': 'class Foo extends Object {}',
            'export_default_with_no_value': 'export default registry;',
            'computed_member_with_no_key': "registry['alpha'];",
            'spread_with_no_argument': 'const o = { ...registry };',
            'for_head_with_no_binding': 'for (const x of names) {\n  registry[x] = 1;\n}',
            'switch_case_with_no_test': 'switch (names.length) {\n  case 1:\n    break;\n}',
            'arrow_with_no_body': 'const f = () => registry;',
            'member_access_in_a_template_with_no_name': 'String(`a${registry.alpha}b`);',
        }
        for name, tail in expected.items():
            with self.subTest(name):
                whole = _STOPS[name].whole
                self.assertEqual(is_well_formed(JsParser(whole).parse()), True)
                self.assertEqual(self._print(whole), F'{_HEAD}{tail}')

    def test_printing_what_was_printed_for_a_source_that_stops_mid_construct_writes_it_again(self):
        """
        The output of a recovery is itself input to the tool, and the text an error node keeps is
        read back as that same text: a print that changed on the second pass would be a tool that
        reads its own output as something other than what it wrote.
        """
        once = {name: self._print(stop.cut) for name, stop in _STOPS.items()}
        self.assertEqual({name: self._print(text) for name, text in once.items()}, once)

    def test_ppjscript_prints_a_source_that_stops_mid_construct(self):
        expected = {
            'var_with_no_name': 'var',
            'const_with_no_name': 'const',
            'member_access_with_no_name': 'registry.',
            'optional_member_access_with_no_name': 'registry?.',
            'chained_member_access_with_no_name': 'registry.alpha.',
            'new_meta_property_with_no_name': 'function build() {\n    new.',
            'object_getter_with_no_name': 'const o = { get',
            'object_setter_with_no_name': 'const o = { set',
            'object_async_method_with_no_name': 'const o = { async',
            'catch_parameter_with_no_name': 'try { names.pop(); } catch (',
            'label_with_no_statement': 'outer:',
            'super_member_with_no_name': 'class Foo extends Object {\n    m() {\n        super.',
            'class_heritage_with_no_name': 'class Foo extends',
            'export_default_with_no_value': 'export default',
            'computed_member_with_no_key': 'registry[',
            'spread_with_no_argument': 'const o = { ...',
            'for_head_with_no_binding': 'for (const',
            'switch_case_with_no_test': 'switch (names.length) {\n    case',
            'arrow_with_no_body': 'const f = () =>',
            'member_access_in_a_template_with_no_name': 'String(`a${registry.',
        }
        self.assertEqual(
            {name: _STOPS[name].cut.encode('utf8') | ppjscript() | str for name in expected},
            {name: F'{_HEAD}{tail}' for name, tail in expected.items()},
        )


class TestParserRecoveryOverAMalformedNamePosition(TestBase):
    """
    The same law where a name position holds a token that is not a name. Nothing was cut off here,
    so the statement holding the position is kept whole, up to the semicolon or the closing brace
    that ends it: the token that was not a name stays where it stood, inside the text that comes
    back, and a brace that closes the enclosing block is the block's and never the text's.
    """

    def _print(self, source: str) -> str:
        return JsSynthesizer().convert(JsParser(source).parse())

    def test_a_malformed_name_position_prints_the_text_it_read(self):
        expected = {
            'doubled_dot': 'registry..alpha;',
            'dot_before_a_semicolon': 'registry.;',
            'dot_before_a_bracket': 'registry.];',
            'dot_before_a_string': "registry.'alpha';",
            'new_dot_before_a_string': "function f() {\n  new.'target';\n}",
            'label_before_a_closing_brace': 'function f() {\n  outer:\n}',
        }
        self.assertEqual(
            {name: self._print(F'{_HEAD}{_MALFORMED[name]}') for name in expected},
            {name: F'{_HEAD}{tail}' for name, tail in expected.items()},
        )

    def test_a_malformed_name_position_is_not_a_well_formed_program(self):
        self.assertEqual(
            {name: is_well_formed(JsParser(F'{_HEAD}{tail}').parse()) for name, tail in _MALFORMED.items()},
            {name: False for name in _MALFORMED},
        )

    def test_the_statement_holding_the_token_that_was_not_a_name_is_kept_as_an_error_node(self):
        expected = {
            'doubled_dot': [('registry..alpha;', 'expected a property name')],
            'dot_before_a_semicolon': [('registry.;', 'expected a property name')],
            'dot_before_a_bracket': [('registry.];', 'expected a property name')],
            'dot_before_a_string': [("registry.'alpha';", 'expected a property name')],
            'new_dot_before_a_string': [("new.'target';", 'expected a property name')],
            'label_before_a_closing_brace': [('outer:', 'unexpected token')],
        }
        self.assertEqual(
            {
                name: [
                    (node.text, node.message)
                    for node in JsParser(F'{_HEAD}{_MALFORMED[name]}').parse().walk_in_order()
                    if isinstance(node, JsErrorNode)
                ]
                for name in expected
            },
            expected,
        )

    def test_printing_what_was_printed_for_a_malformed_name_position_writes_it_again(self):
        once = {name: self._print(F'{_HEAD}{tail}') for name, tail in _MALFORMED.items()}
        self.assertEqual({name: self._print(text) for name, text in once.items()}, once)

    def test_ppjscript_prints_a_malformed_name_position(self):
        expected = {
            'doubled_dot': 'registry..alpha;',
            'dot_before_a_semicolon': 'registry.;',
            'dot_before_a_bracket': 'registry.];',
            'dot_before_a_string': "registry.'alpha';",
            'new_dot_before_a_string': "function f() {\n    new.'target';\n}",
            'label_before_a_closing_brace': 'function f() {\n    outer:\n}',
        }
        self.assertEqual(
            {name: F'{_HEAD}{_MALFORMED[name]}'.encode('utf8') | ppjscript() | str for name in expected},
            {name: F'{_HEAD}{tail}' for name, tail in expected.items()},
        )


#: Module declarations that stop before the specifier they read from. A module host refuses every
#: one of them: `new vm.SourceTextModule` under `node --experimental-vm-modules` answers
#: `SyntaxError: Unexpected end of input`, and `Unexpected token ','` for `import a,`.
MODULE_DECLARATIONS_CUT_BEFORE_THEIR_SPECIFIER = (
    'import',
    'import a',
    'import a from',
    'import a,',
    'import a, {',
    'import a, { b',
    'import {',
    'import { a',
    'import { a as b } from',
    'import * as ns from',
    'export *',
    'export * from',
)

#: Module declarations that name the module they read from, which the same host accepts. It answers
#: for `export { a as b };` alone, and for a name rather than for a spelling: `Export 'a' is not
#: defined in module`, where `var a; export { a as b };` is accepted.
MODULE_DECLARATIONS_THAT_NAME_THEIR_SPECIFIER = (
    'import a from "m";',
    'import "m";',
    'import { a as b } from "m";',
    'import * as ns from "m";',
    'import a, { b } from "m";',
    'import a from "m" with { type: "json" };',
    'export * from "m";',
    'export * as ns from "m";',
    'export { a as b } from "m";',
    'export { a as b };',
)


class TestAModuleDeclarationIsReadOnlyWhereItsSpecifierIsWritten(TestBase):
    """
    A module declaration names the module it reads from with a string literal, and a file that
    stops before that literal was written holds no declaration at all. Such a span is kept as a
    `refinery.lib.scripts.js.model.JsErrorNode` reading the text verbatim, so the tree reports that
    the file is not a program and what is printed for it is what was handed over.

    This was an entry of this ledger until the parser stopped answering such a file with a
    declaration carrying a specifier that no text spells, and it stays as the regression test that
    entry became.
    """

    @staticmethod
    def _well_formed(source: str) -> bool:
        return is_well_formed(JsParser(source).parse())

    @staticmethod
    def _printed(source: str) -> str:
        return JsSynthesizer().convert(JsParser(source).parse())

    def test_a_declaration_cut_before_its_specifier_is_not_a_well_formed_program(self):
        sources = MODULE_DECLARATIONS_CUT_BEFORE_THEIR_SPECIFIER
        self.assertEqual(
            {source: self._well_formed(source) for source in sources},
            {source: False for source in sources},
        )

    def test_a_declaration_cut_before_its_specifier_is_printed_as_the_source_wrote_it(self):
        sources = MODULE_DECLARATIONS_CUT_BEFORE_THEIR_SPECIFIER
        self.assertEqual(
            {source: self._printed(source) for source in sources},
            {source: source for source in sources},
        )

    def test_printing_a_declaration_cut_before_its_specifier_twice_writes_the_source_again(self):
        sources = MODULE_DECLARATIONS_CUT_BEFORE_THEIR_SPECIFIER
        self.assertEqual(
            {source: self._printed(self._printed(source)) for source in sources},
            {source: source for source in sources},
        )

    def test_a_declaration_that_names_its_specifier_is_a_program_printed_as_it_was_written(self):
        sources = MODULE_DECLARATIONS_THAT_NAME_THEIR_SPECIFIER
        self.assertEqual(
            {source: (self._well_formed(source), self._printed(source)) for source in sources},
            {source: (True, source) for source in sources},
        )


#: Files that stop in the middle of a construct, grouped by the construct each one stops inside of.
#: No engine reads any of them, and the law below is quantified over all of them at once: the group
#: a row is in is only what the parser would have had to finish writing in order to answer with a
#: program at all.
SOURCES_THAT_STOP_INSIDE_A_CONSTRUCT = {
    'a function': (
        'function',
        'function f',
        'function f(',
        'function f(a, b',
        'function f() {',
        'function f() { g();',
        'function* g() {',
        'async function h() {',
        'x = function (',
        'x = () => {',
    ),
    'a class': (
        'class',
        'class Foo',
        'class Foo {',
        'class Foo extends Bar {',
        'class Foo { m(',
        'class Foo { m() {',
        'class Foo { m() { g();',
        'class Foo { static {',
        'x = class {',
    ),
    'a statement': (
        'if (a) {',
        'if (a) { f();',
        'while (a) {',
        'for (;;) {',
        'for (const v of a) {',
        'with (o) {',
        'label: {',
        'try {',
        'try { f();',
        'try {} catch',
        'try {} catch (e',
        'try {} catch (e) {',
        'try { f(); } catch (e) { g();',
        'try {} finally',
        'switch (x',
        'switch (x) {',
        'switch (x) { case 1:',
        'switch (x) { case 1: f();',
        'switch (x) { default:',
    ),
    'a bracketed expression': (
        'x = (1 + 2',
        'x = { a',
        'x = { a: 1',
        'x = { a: 1, b: 2',
        'x = [1, 2',
        'x = [1, 2, 3',
        'x = f(1, 2',
        'x = f(g(1), 2',
        'x = a.b(',
        'x = new C(',
    ),
    'a binding pattern': (
        'const {',
        'const { a',
        'const { a, b',
        'const [',
        'const [a, b',
        'const { a: { b',
        'const [a, [b',
        'try {} catch ({ a',
    ),
    'an export declaration': (
        'export {',
        'export { a',
        'export function f() {',
        'export default function () {',
    ),
}


class TestAFileThatStopsInsideAConstructIsNotAProgram(TestBase):
    """
    A file cut in the middle of a construct still has to be answered with a tree. The parser keeps
    what it could not finish reading as the text it stands in, and a block, a class body or a
    switch the file ends inside keeps the statements it holds and records that nothing closed it,
    so what comes back is what was handed over — `x = f(1, 2` prints as `x = f(1, 2` and
    `try {} catch` as `try {} catch` — and the tree says it is not a program.

    No engine reads any of these. `new vm.Script` refuses every row but the export declarations,
    each with `SyntaxError: Unexpected end of input` except `x = f(1, 2` and `x = f(g(1), 2`, which
    it refuses with `missing ) after argument list`. The export declarations are put to `new
    vm.SourceTextModule` under `node --experimental-vm-modules`, because `vm.Script` refuses them
    for a reason of its own, `Unexpected token 'export'`; that host refuses all four with
    `Unexpected end of input` and accepts `export {};`, `var a; export { a };`, `export function
    f() {}` and `export default function () {}`, so what it refuses is the cut and not the keyword.

    This was an entry of `test.lib.scripts.js.test_release_blockers` until the parser began
    recording the repair, and it stays as the regression test that entry became.
    """

    @staticmethod
    def _well_formed(source: str) -> bool:
        return is_well_formed(JsParser(source).parse())

    @staticmethod
    def _printed(source: str) -> str:
        return JsSynthesizer().convert(JsParser(source).parse())

    @staticmethod
    def _sources() -> list[str]:
        return [
            source
            for group in SOURCES_THAT_STOP_INSIDE_A_CONSTRUCT.values()
            for source in group
        ]

    def test_a_file_that_stops_inside_a_construct_is_not_a_well_formed_program(self):
        sources = self._sources()
        self.assertEqual(
            {source: self._well_formed(source) for source in sources},
            {source: False for source in sources},
        )

    def test_a_file_that_stops_inside_a_construct_drops_no_character_and_prints_to_itself(self):
        """
        Layout is the printer's: `for (;;) {` comes back as `for (; ; ) {`. What may not change is
        the characters the file holds, and the print of the print.
        """
        sources = self._sources()
        printed = {source: self._printed(source) for source in sources}
        self.assertEqual(
            {
                source: (dropped_source_characters(source, text), self._printed(text) == text)
                for source, text in printed.items()
            },
            {source: ('', True) for source in sources},
        )

    def test_a_bracket_the_file_closes_with_something_else_is_not_a_well_formed_program(self):
        """
        Node refuses `var x = (1 + 2; g(x);` with `SyntaxError: Unexpected token ';'`. The file does
        not stop anywhere — it runs to its end — and the declaration is kept as the text it is:
        a bracket it opened and never closed holds everything behind it, the `;` and the call
        included, so the text runs to the end of the file.
        """
        source = 'var x = (1 + 2; g(x);'
        self.assertEqual(
            (self._well_formed(source), self._printed(source)),
            (False, 'var x = (1 + 2; g(x);'),
        )


#: Names a module may bind. `node --check` on a `.mjs` file accepts every one of them in every
#: position of `A_POSITION_NAMING_A_BINDING_THE_FILE_CREATES` and in every position of
#: `A_POSITION_NAMING_THE_FAR_SIDE_OF_THE_BOUNDARY`.
A_NAME_A_MODULE_MAY_BIND = (
    'alpha',
    'as',
    'from',
    'of',
    'get',
    'set',
    'async',
    'target',
    'meta',
)

#: Words that same host refuses in every position of
#: `A_POSITION_NAMING_A_BINDING_THE_FILE_CREATES`, each with a `SyntaxError`: `Unexpected token
#: 'class'` and its like for a word the language reserves anywhere, `Unexpected reserved word` for
#: `enum` and for `await`, which only module code reserves, `Unexpected strict mode reserved word`
#: for the words only strict code reserves, and `Unexpected eval or arguments in strict mode` for
#: the two names strict code refuses to bind. It accepts every one of them in every position of
#: `A_POSITION_NAMING_THE_FAR_SIDE_OF_THE_BOUNDARY`.
A_WORD_NO_MODULE_MAY_BIND = (
    'default',
    'class',
    'new',
    'function',
    'var',
    'if',
    'in',
    'this',
    'typeof',
    'void',
    'return',
    'super',
    'import',
    'export',
    'null',
    'true',
    'enum',
    'await',
    'yield',
    'let',
    'static',
    'implements',
    'interface',
    'package',
    'private',
    'protected',
    'public',
    'eval',
    'arguments',
)

#: The positions of an `import` or `export` declaration that name a binding the file creates, each
#: as the declaration that writes a name there.
A_POSITION_NAMING_A_BINDING_THE_FILE_CREATES = {
    'a default import'     : 'import {name} from "m";',
    'a namespace import'   : 'import * as {name} from "m";',
    'a renamed import'     : 'import {{ remote as {name} }} from "m";',
    'a plain import'       : 'import {{ {name} }} from "m";',
    'an export of a local' : 'var {name};\nexport {{ {name} }};',
}

#: The positions of an `import` or `export` declaration that name something on the far side of the
#: module boundary, where the grammar takes an IdentifierName rather than a name the file binds.
A_POSITION_NAMING_THE_FAR_SIDE_OF_THE_BOUNDARY = {
    'an import'              : 'import {{ {name} as local }} from "m";',
    'a re-export'            : 'export {{ {name} }} from "m";',
    'a renamed re-export'    : 'export {{ {name} as local }} from "m";',
    'the name it exports as' : 'export {{ local as {name} }} from "m";',
    'a namespace re-export'  : 'export * as {name} from "m";',
    'an export of a local'   : 'var local;\nexport {{ local as {name} }};',
}


class TestAModuleTakesAWiderNameAcrossItsBoundaryThanItBinds(TestBase):
    """
    An `import` or `export` declaration writes names in two kinds of position. One names a binding
    the file creates, and takes an ordinary name: `node --check` on a `.mjs` file refuses every
    word of `A_WORD_NO_MODULE_MAY_BIND` there. The other names something on the far side of the
    module boundary, and takes an IdentifierName, which is the wider set — the same host accepts
    every one of those words there. `import { default as local } from "m";` is a module and
    `import { default } from "m";` is not, and the two differ in nothing but which position the
    reserved word stands in.

    What is pinned is the accepting half of that: every spelling the host reads is read here
    without a repair, and printed back as the file wrote it; and the one spelling that is both
    positions at once, the shorthand import, which binds.
    """

    @staticmethod
    def _read_and_printed(source: str) -> tuple[bool, str]:
        tree = JsParser(source).parse()
        return is_well_formed(tree), JsSynthesizer().convert(tree)

    def test_a_name_a_module_binds_is_a_program_printed_as_it_was_written(self):
        for position, template in A_POSITION_NAMING_A_BINDING_THE_FILE_CREATES.items():
            sources = [
                template.format(name=name)
                for name in A_NAME_A_MODULE_MAY_BIND
            ]
            with self.subTest(position=position):
                self.assertEqual(
                    {source: self._read_and_printed(source) for source in sources},
                    {source: (True, source) for source in sources},
                )

    def test_a_name_across_the_module_boundary_is_a_program_printed_as_it_was_written(self):
        words = (*A_NAME_A_MODULE_MAY_BIND, *A_WORD_NO_MODULE_MAY_BIND)
        for position, template in A_POSITION_NAMING_THE_FAR_SIDE_OF_THE_BOUNDARY.items():
            sources = [
                template.format(name=word)
                for word in words
            ]
            with self.subTest(position=position):
                self.assertEqual(
                    {source: self._read_and_printed(source) for source in sources},
                    {source: (True, source) for source in sources},
                )

    def test_the_shorthand_import_binds_the_word_the_shorthand_re_export_only_passes_on(self):
        """
        The word in `import { yield } from "m";` names a binding as well as the far side of the
        boundary, and the word in `export { yield } from "m";` names the far side twice over, which
        is why the host refuses the first and reads the second.
        """
        self.assertEqual(
            {
                source: is_well_formed(JsParser(source).parse())
                for source in ['import { yield } from "m";', 'export { yield } from "m";']
            },
            {'import { yield } from "m";': False, 'export { yield } from "m";': True},
        )


#: Files no engine reads, each mapped to the text the parser could not read and its reason. Node
#: refuses every one of them: `Unexpected end of input` for the ones that stop short, `Invalid
#: regular expression: missing /` for the lone slash, `Unexpected token ')'` for `x = ()`, for
#: `x = (a,)` and for the two files holding a stray closer, `Unexpected token '...'` for
#: `x = (...a)`, `Unexpected identifier 'b'` for the three with two names pressed together,
#: `missing ) after argument list` for the two argument lists, `Unexpected string` for the catch
#: parameter, `Unexpected token 'break'` for the case clause, `Missing } in template expression`
#: for the three templates, `Unexpected token '}'` for the three clause bodies and for
#: `{ throw }`, `Illegal newline after throw` for the three files breaking the line behind
#: `throw`, `Malformed arrow function parameter list` for the two arrows behind `new`, and
#: `Invalid or unexpected token` for the six files whose line ends inside a string. The import
#: declaration is module code, which `node --check` on a `.mjs` file refuses with `Unexpected
#: identifier 'c'`.
A_FILE_THE_PARSER_REFUSES = {
    'x = /': ('x = /', 'unexpected token'),
    'var': ('var', 'expected a name'),
    'var a = 1,': ('var a = 1,', 'expected a name'),
    'x = y.': ('x = y.', 'expected a property name'),
    'x = a?.': ('x = a?.', 'expected a property name'),
    'delete a.': ('delete a.', 'expected a property name'),
    'x = { get': ('get', 'expected a property name'),
    'x = ()': ('x = ()', 'a parameter list with no arrow behind it'),
    'x = (a,)': ('x = (a,)', 'a parameter list with no arrow behind it'),
    'x = (...a)': ('x = (...a)', 'a parameter list with no arrow behind it'),
    'x = new': ('x = new', 'unexpected token'),
    'throw new': ('throw new', 'unexpected token'),
    'if (a)': ('if (a)', 'unexpected token'),
    'while (a)': ('while (a)', 'unexpected token'),
    'with (o)': ('with (o)', 'unexpected token'),
    'for (const v of a)': ('for (const v of a)', 'unexpected token'),
    'if (a) { f(); } else': ('if (a) { f(); } else', 'unexpected token'),
    'class D extends': ('class D extends', 'unexpected token'),
    'x = y[a b]': ('x = y[a b]', 'expected RBRACKET'),
    "f('alpha' 'beta');": ("'alpha' 'beta'", 'expected COMMA'),
    "x = new C('alpha' 'beta');": ("'alpha' 'beta'", 'expected COMMA'),
    'function f(a b) { return a; }': ('a b', 'expected COMMA'),
    'class C { m(a b) {} }': ('a b', 'expected COMMA'),
    "try { f(); } catch (e 'beta') {}": ("try { f(); } catch (e 'beta') {}", 'expected RPAREN'),
    'switch (x) { case 1 break; }': ('case 1 break;', 'expected COLON'),
    'import a, { b c, d } from "m";': ('b c', 'expected COMMA'),
    'f(`${`a}`); g();': ('`${`a}`', 'expected the template to resume'),
    '[`${`a}`, b]; g();': ('`${`a}`, b', 'expected the template to resume'),
    'f(`${a`b}`, c); g();': ('`${a`b}`, c', 'expected the template to resume'),
    'if (a) foo(});': ('}', 'unexpected token'),
    'while (a) foo(});': ('}', 'unexpected token'),
    'if (a) var x = f(});': ('}', 'unexpected token'),
    '{ throw }': ('throw', 'unexpected token'),
    'throw\n1;': ('throw', 'no line terminator may follow throw'),
    'throw\n': ('throw', 'no line terminator may follow throw'),
    'function f() { throw\n  new Error("x"); }':
        ('throw', 'no line terminator may follow throw'),
    'new x => y;': ('new x => y;', 'an arrow function as an operand'),
    'new (x) => y;': ('new (x) => y;', 'an arrow function as an operand'),
    'f([a ) b], c); g=1; h=2;': ('a ) b', 'expected COMMA'),
    'x = ([a, )]); y = 1;': (')', 'unexpected token'),
    'x = "abc\n': ('x = "abc\n', 'a string literal the line ends inside'),
    'x = "abc\r\ny;': ('x = "abc\r\n', 'a string literal the line ends inside'),
    'x = "abc\rz;': ('x = "abc\r', 'a string literal the line ends inside'),
    'x = "abc\nz;': ('x = "abc\n', 'a string literal the line ends inside'),
    'while (a) "b;\nc();': ('"b;\n', 'a string literal the line ends inside'),
    'f("abc\n, 1);': ('"abc\n', 'a string literal the line ends inside'),
}


class TestAFileTheParserRefusesComesBackAsItWasWritten(TestBase):
    """
    `refinery.lib.scripts.js.model.JsErrorNode` promises that a span no parser could read is kept
    verbatim, so that what an analyst gets back still contains what was written; and printing a
    parse and parsing that print reaches a fixed point, including for a source no engine accepts,
    because a tool that reads its own output otherwise changes a file every pass. The span kept
    is the statement or list item the refused token stood in: a whole statement for most of these,
    the two elements pressed together for an argument or parameter list, and the one clause for
    the switch. A span ending in a string a line terminator ended takes the terminator with it:
    `x = "abc` at the end of a file is a string the file ended inside, which is a different tree,
    and a print that put the span last would otherwise read back as that.

    None of these prints reads as a program either: a print that did would answer a file no engine
    reads with one an engine runs.
    """

    def test_no_character_of_the_file_is_dropped(self):
        rows = A_FILE_THE_PARSER_REFUSES
        self.assertEqual(
            {source: dropped_source_characters(source, printed(source)) for source in rows},
            {source: '' for source in rows},
        )

    def test_printing_the_print_writes_it_again(self):
        once = {source: printed(source) for source in A_FILE_THE_PARSER_REFUSES}
        self.assertEqual({source: printed(text) for source, text in once.items()}, once)

    def test_the_text_the_parser_could_not_read_is_kept_as_an_error_node(self):
        self.assertEqual(
            {
                source: [
                    (node.text, node.message)
                    for node in JsParser(source).parse().walk_in_order()
                    if isinstance(node, JsErrorNode)
                ]
                for source in A_FILE_THE_PARSER_REFUSES
            },
            {source: [span] for source, span in A_FILE_THE_PARSER_REFUSES.items()},
        )

    def test_none_of_them_is_a_well_formed_program(self):
        rows = A_FILE_THE_PARSER_REFUSES
        self.assertEqual({source: well_formed(source) for source in rows}, {source: False for source in rows})

    def test_none_of_them_prints_a_well_formed_program(self):
        rows = A_FILE_THE_PARSER_REFUSES
        self.assertEqual(
            {source: well_formed(printed(source)) for source in rows},
            {source: False for source in rows},
        )

    def test_a_clause_body_holding_unread_text_is_written_without_a_block(self):
        """
        A clause takes one statement and the braces a printer adds around it are a block, which is
        a statement the source did not write. Where the body is text no parser could read, those
        braces close the text off from what follows and the print reads back as a different file.
        """
        sources = [
            'if (a) foo(});',
            'while (a) foo(});',
            'if (a) var x = f(});',
            'if (a) foo(}); else if (b) foo(});',
        ]
        self.assertEqual(
            {source: printed(source) for source in sources},
            {source: source for source in sources},
        )

    def test_a_line_ended_string_is_not_followed_by_a_second_line_terminator(self):
        """
        The span kept for a string a line ended holds that line terminator, so a printer writing
        one of its own behind the span puts a line into the file that nobody wrote.
        """
        sources = ['x = "abc\rz;', 'x = "abc\nz;', 'x = "abc\r\nz;']
        self.assertEqual(
            {source: printed(source) for source in sources},
            {source: source for source in sources},
        )

    def test_a_legal_trailing_comma_is_the_printers_to_drop_where_the_file_is_refused_elsewhere(
        self,
    ):
        """
        `x = [1, 2, ]` is a program the printer writes in its own form, and the file being refused
        somewhere else does not turn the rest of it into text to keep verbatim. What the refusal
        keeps is the item the parser could not read, and nothing around it.
        """
        source = 'x = [1, 2, ]; y = (a b);'
        self.assertEqual(printed(source), 'x = [1, 2];\ny = (a b);')
        self.assertEqual(unread_spans(JsParser(source).parse()), ['a b'])
        self.assertEqual(well_formed(source), False)


#: Files that end inside a regular expression literal, mapped to the constructs nothing closed,
#: outermost first. Node refuses each with `SyntaxError: Invalid regular expression: missing /`.
#: A literal the file ends inside is the literal it is and not text the parser refused, which is
#: what tells `x = /ab` apart from `x = /`, where the one slash spells no literal at all and stays
#: unread text.
A_FILE_THAT_ENDS_INSIDE_A_REGULAR_EXPRESSION = {
    'x = /ab': (JsScript, JsRegExpLiteral),
    'x = /ab+': (JsScript, JsRegExpLiteral),
    'x = y.replace(/[^a-z': (JsScript, JsCallExpression, JsRegExpLiteral),
}


class TestAFileThatEndsInsideARegularExpressionKeepsTheLiteralOpen(TestBase):

    def test_the_constructs_nothing_closed_are_the_ones_the_file_ends_inside(self):
        rows = A_FILE_THAT_ENDS_INSIDE_A_REGULAR_EXPRESSION
        self.assertEqual(
            {
                source: tuple(
                    type(node)
                    for node in JsParser(source).parse().walk_in_order()
                    if file_ended_inside(node)
                )
                for source in rows
            },
            dict(rows),
        )

    def test_the_literal_is_no_span_the_parser_refused(self):
        rows = A_FILE_THAT_ENDS_INSIDE_A_REGULAR_EXPRESSION
        self.assertEqual(
            {source: unread_spans(JsParser(source).parse()) for source in rows},
            {source: [] for source in rows},
        )

    def test_the_file_is_written_back_as_it_stands_and_is_no_program(self):
        rows = A_FILE_THAT_ENDS_INSIDE_A_REGULAR_EXPRESSION
        self.assertEqual(
            {source: (printed(source), well_formed(source)) for source in rows},
            {source: (source, False) for source in rows},
        )


class TestASpanTheParserCouldNotReadEndsWhereItsStatementDoes(TestBase):
    """
    A clause takes one statement, so a body no parser could read has to end where that statement
    ends and the rest of the file has to stay outside it: at the `else` of an `if`, at the `while`
    of a `do`, at the next `case` of a switch, at the statement behind a declaration. A span that
    ran on would swallow what follows it into text nothing reads again.

    Node refuses `if (x) foo bar`, `do foo bar`, and the switch, each with `SyntaxError:
    Unexpected identifier 'bar'`. The two declarations are module code, which `node --check` on a
    `.mjs` file refuses with `SyntaxError: Unexpected identifier 'B'`.

    Every shape is asked of the print as well, since one that only survives a single pass is a
    file the tool rewrites every time it reads it.
    """

    @staticmethod
    def _both_readings(source: str) -> dict[str, str]:
        return {'as written': source, 'as printed': printed(source)}

    @staticmethod
    def _head(text: str):
        return JsParser(text).parse().body[0]

    def test_an_if_keeps_its_else_behind_a_consequent_it_could_not_read(self):
        source = 'if (x) foo bar\nelse y();\nz();'

        def shape(text: str) -> tuple[type, tuple[type, str], bool]:
            statement = self._head(text)
            is_if = isinstance(statement, JsIfStatement)
            return (
                type(statement),
                a_span_the_parser_kept(statement.consequent if is_if else None),
                is_if and statement.alternate is not None,
            )

        readings = self._both_readings(source)
        self.assertEqual(
            {label: shape(text) for label, text in readings.items()},
            {label: (JsIfStatement, (JsErrorNode, 'foo bar'), True) for label in readings},
        )

    def test_a_do_while_keeps_its_test_behind_a_body_it_could_not_read(self):
        source = 'do foo bar\nwhile (x);\nz();'

        def shape(text: str) -> tuple[type, tuple[type, str]]:
            statement = self._head(text)
            is_do = isinstance(statement, JsDoWhileStatement)
            return (
                type(statement),
                a_span_the_parser_kept(statement.body if is_do else None),
            )

        readings = self._both_readings(source)
        self.assertEqual(
            {label: shape(text) for label, text in readings.items()},
            {label: (JsDoWhileStatement, (JsErrorNode, 'foo bar')) for label in readings},
        )

    def test_a_switch_keeps_its_next_case_behind_a_clause_body_it_could_not_read(self):
        source = 'switch (k) { case 1: foo bar case 2: y(); }'

        def shape(text: str) -> tuple[type, int, list[tuple[type, str]]]:
            statement = self._head(text)
            if not isinstance(statement, JsSwitchStatement):
                return (type(statement), 0, [])
            first = statement.cases[0]
            body = first.body if isinstance(first, JsSwitchCase) else [first]
            return (
                type(statement),
                len(statement.cases),
                [a_span_the_parser_kept(node) for node in body],
            )

        readings = self._both_readings(source)
        self.assertEqual(
            {label: shape(text) for label, text in readings.items()},
            {
                label: (JsSwitchStatement, 2, [(JsErrorNode, 'foo bar')])
                for label in readings
            },
        )

    def test_a_declaration_the_parser_refuses_keeps_the_statements_written_behind_it(self):
        rows = {
            'export class A B { m() {} } g = 1; h = 2;': [
                (JsErrorNode, 'export class A B { m() {} }'),
                (JsExpressionStatement, ''),
                (JsExpressionStatement, ''),
            ],
            'export default class A B {} g = 1;': [
                (JsErrorNode, 'export default class A B {}'),
                (JsExpressionStatement, ''),
            ],
        }
        self.assertEqual(
            {
                source: [
                    a_span_the_parser_kept(statement)
                    for statement in JsParser(source).parse().body
                ]
                for source in rows
            },
            rows,
        )

    def test_a_case_body_that_could_hold_the_next_case_prints_no_program(self):
        """
        The slash behind `y;` opens a regular expression literal, and `case` on the same line as
        that literal ends nothing, which is why no engine reads the file. A span cut at that word
        would put the literal in one clause and `case 2` in the next, and the printer writes a
        clause on a line of its own, where the break behind the literal ends the statement and the
        file an engine refused comes back as one it runs.
        """
        source = 'switch (x) { case 1: y; / a */ case 2: z; }'
        self.assertEqual(well_formed(printed(source)), False)


#: Spellings of a numeral the language refuses (§12.9.3): a separator not between two digits of
#: one run or behind a leading `0`, a radix prefix with no digits, an exponent with no digit behind
#: its sign, a legacy octal literal with a fraction, an exponent or an `n`, and a numeral an
#: IdentifierStart or a digit is pressed against. Node refuses `x = <spelling>;` for every one of
#: them, and `test.lib.scripts.js.test_lexer` states which token the lexer ends each at.
A_NUMERAL_THE_LANGUAGE_REFUSES = (
    '004E',
    '007e1',
    '01n',
    '00n',
    '09n',
    '08_1',
    '09_1',
    '0_1',
    '0_0',
    '0_',
    '0e',
    '0x',
    '0b',
    '0o',
    '0b2',
    '0x_1',
    '0x1_',
    '0x1g',
    '0x1n_',
    '1n1',
    '1_',
    '1__0',
    '1_e3',
    '1e',
    '1e_1',
    '1e+',
    '1e3e',
    '1.e',
    '1._5',
    '1.5_',
    '1_.5',
    '.5_',
    '3in y',
    '1.toString()',
)


class TestANumeralTheLanguageRefusesIsNoProgram(TestBase):

    def test_the_statement_holding_the_numeral_is_kept_as_text_and_is_no_program(self):
        programs = [F'x = {spelling};' for spelling in A_NUMERAL_THE_LANGUAGE_REFUSES]
        self.assertEqual(
            {
                program: (
                    well_formed(program),
                    printed(program),
                    [
                        (node.text, node.message)
                        for node in JsParser(program).parse().walk_in_order()
                        if isinstance(node, JsErrorNode)
                    ],
                )
                for program in programs
            },
            {
                program: (False, program, [(program, 'a numeral the language refuses')])
                for program in programs
            },
        )


#: Files whose parse once needed a token the source did not write. Four of the tables come from
#: `test.lib.scripts.js.deobfuscation.test_escaped_identifiers`, where the law they belong to is
#: stated: a terminal word of the grammar is matched by the characters typed, so an escaped
#: spelling of `get`, `set`, `static`, `async`, `instanceof` or `in` is a name standing where the
#: grammar wanted a word. The last four are the same shape with nothing escaped about it: two names
#: pressed together, `let` spelled with an escape where a declaration would begin, and an arrow
#: function written as the operand of `new`, which the grammar takes no arrow function for. Node
#: refuses every one of them with a `SyntaxError` and prints nothing.
A_FILE_THE_PARSER_REFUSES_THAT_AN_ENGINE_REFUSES_TOO = (
    *AN_ESCAPED_ACCESSOR_TERMINAL,
    *AN_ESCAPED_STATIC_TERMINAL,
    *AN_ESCAPED_ASYNC_TERMINAL,
    *AN_ESCAPED_KEYWORD_OPERATOR,
    "console.log('alpha' 'beta');",
    'l\\u0065t x = 1; console.log(x);',
    ' #!/usr/bin/env node\nvar x = 1;',
    '\ufeff#!/usr/bin/env node\nvar x = 1;',
    'new x => y;',
    'new (x) => y;',
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFileTheParserRefusesIsNotAnsweredWithAProgram(TestBase):
    """
    Standing where the grammar requires one token and finding another, the parser keeps the
    statement or list item it was reading as the text it is, so what comes back holds the text no
    engine agreed to read and is refused by the engine as the file was. This was an entry of
    `test.lib.scripts.js.test_unfixed_defects` while the parser wrote the token it wanted instead,
    and it stays as the regression test that entry became.
    """

    def test_a_file_the_parser_refuses_comes_back_refused(self):
        rows = A_FILE_THE_PARSER_REFUSES_THAT_AN_ENGINE_REFUSES_TOO
        refused = ('', 'SyntaxError')
        self.assertEqual(
            {source: (well_formed(source), before_and_after(source)) for source in rows},
            {source: (False, (refused, refused)) for source in rows},
        )


#: A construct nested inside itself *n* times, for every construct the parser reads by descending
#: into it. Node reads each of them a hundred deep and a thousand deep.
A_CONSTRUCT_NESTED = {
    'parentheses': lambda n: '(' * n + '1' + ')' * n + ';',
    'arrays': lambda n: '[' * n + ']' * n + ';',
    'calls': lambda n: 'f(' * n + 'x' + ')' * n + ';',
    'blocks': lambda n: '{' * n + '}' * n,
    'objects': lambda n: 'a = ' + '{b:' * n + '1' + '}' * n + ';',
    'ifs': lambda n: 'if (a) ' * n + 'x;',
    'functions': lambda n: 'function f() {' * n + '}' * n,
    'conditionals': lambda n: 'a ? ' * n + '1' + ' : 2' * n + ';',
    'array patterns': lambda n: 'var ' + '[' * n + 'a' + ']' * n + ' = 1;',
    'object patterns': lambda n: 'var ' + '{a:' * n + 'a' + '}' * n + ' = 1;',
    'parameter patterns': lambda n: 'function f(' + '[' * n + 'a' + ']' * n + ') {}',
    'prefix operators': lambda n: 'x = ' + '!' * n + 'y;',
    'new': lambda n: 'z = ' + 'new ' * n + 'y;',
    'exponentiations': lambda n: 'z = ' + 'a ** ' * n + '1;',
}

#: The same, for the two shapes the parser reads in a loop rather than by descending.
A_CHAIN_NESTED = {
    'binary operators': lambda n: 'a' + ' + a' * n + ';',
    'member accesses': lambda n: 'a' + '.b' * n + ';',
}


class TestAFileNestedTooDeepToReadIsRefusedAndNeverCrashes(TestBase):
    """
    The parser descends once per level of nesting and refuses to descend past a budget, so that a
    file nested a thousand deep is answered with the text it could not read rather than with a
    `RecursionError` from inside the tools that read and print it. A hundred levels are read; a
    thousand are refused at the budget, and the file still comes back whole: the one span the
    parser kept is text the file wrote, the print drops no character, and printing it writes it
    again. Where the budget falls is the parser's to choose and no engine answers it, which is why
    nothing here counts how much of a file was left unread. A chain the parser reads in a loop has
    no depth to refuse.
    """

    def _read(self, source: str) -> tuple[bool, bool, str, list[tuple[str, bool]]]:
        text = printed(source)
        return (
            well_formed(source),
            printed(text) == text,
            dropped_source_characters(source, text),
            [
                (node.message, node.text in source)
                for node in JsParser(source).parse().walk_in_order()
                if isinstance(node, JsErrorNode)
            ],
        )

    def test_a_hundred_levels_are_read_and_a_thousand_are_refused(self):
        self.assertEqual(
            {
                name: (self._read(shape(100)), self._read(shape(1000)))
                for name, shape in A_CONSTRUCT_NESTED.items()
            },
            {
                name: (
                    (True, True, '', []),
                    (False, True, '', [('nesting too deep', True)]),
                )
                for name in A_CONSTRUCT_NESTED
            },
        )

    def test_a_chain_a_thousand_long_is_read(self):
        self.assertEqual(
            {name: self._read(shape(1000)) for name, shape in A_CHAIN_NESTED.items()},
            {name: (True, True, '', []) for name in A_CHAIN_NESTED},
        )


#: What one edit puts into a program: a bracket, a quote, a slash, a separator, a character that
#: begins no token, a comment opener of each kind.
AN_INSERTION = (
    ')',
    '}',
    ']',
    '(',
    '{',
    '[',
    ';',
    ',',
    "'",
    '"',
    '`',
    '/',
    '*',
    ':',
    '?',
    '=>',
    '@',
    '#',
    '-->',
    '<!--',
    '/* c */',
    '// c' + chr(10),
)


def every_file_one_edit_away(source: str, rng: random.Random, count: int) -> list[str]:
    """
    *count* files one edit away from *source*: a character deleted, or one of `AN_INSERTION` put
    in, at a position *rng* picks.
    """
    mutants: list[str] = []
    for _ in range(count):
        position = rng.randrange(len(source) + 1)
        if rng.random() < 0.4 and position < len(source):
            mutants.append(source[:position] + source[position + 1:])
        else:
            mutants.append(source[:position] + rng.choice(AN_INSERTION) + source[position:])
    return mutants


class TestAFileOneEditAwayFromAProgramComesBackAsItWasWritten(TestBase):
    """
    Over every program the hand-written corpora of this module and of
    `test.lib.scripts.js.test_comment_carriers` hold, eight files one edit away from it, from a
    fixed seed. Whatever the edit made of the program, printing the print changes nothing, and
    every span the parser could not read comes back verbatim and in the order the file wrote it.

    What the file holds around such a span is the printer's to write in its own form, where a
    trailing comma or a separating semicolon is not kept: an edit that refuses one statement of a
    file leaves the rest of it a program, and `x = [1, 2, ]; y = (a b);` is such a file.
    """

    def test_every_mutant_prints_to_itself_and_keeps_every_span_it_could_not_read(self):
        rng = random.Random(20260907)
        programs = [stop.whole for stop in _STOPS.values()]
        programs.extend(every_program_holding_a_comment())
        mutants = [mutant for program in programs for mutant in every_file_one_edit_away(program, rng, 8)]
        outcome: dict[str, tuple[bool, bool]] = {}
        for mutant in mutants:
            tree = JsParser(mutant).parse()
            once = JsSynthesizer().convert(tree)
            twice = JsSynthesizer().convert(JsParser(once).parse())
            outcome[mutant] = (spans_written_in_order(once, unread_spans(tree)), twice == once)
        self.assertEqual(outcome, {mutant: (True, True) for mutant in mutants})
