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
    return [node.text for node in tree.walk_in_order() if isinstance(node, JsErrorNode)]


def spans_written_in_order(text: str, spans: list[str]) -> bool:
    cursor = 0
    for span in spans:
        found = text.find(span, cursor)
        if found < 0:
            return False
        cursor = found + len(span)
    return True


def a_span_the_parser_kept(node: object) -> tuple[type, str]:
    return type(node), node.text if isinstance(node, JsErrorNode) else ''


_HEAD = 'const registry = {};\nconst names = Object.keys(registry);\n'
"""
The two statements every source below starts with. A recovery that swallowed what stood before the
position it could not read would show up in the printed text rather than hide in a one-token file,
and the printer writes these two back character for character, which is why every expectation here
is spelled as this text followed by the tail the broken construct contributes.
"""


class Stop(NamedTuple):
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

#: A host refuses `export { a as b };` alone because no declaration binds `a`; the refusal is about
#: the name and not the spelling, since `var a; export { a as b };` is accepted.
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
        source = 'var x = (1 + 2; g(x);'
        self.assertEqual(
            (self._well_formed(source), self._printed(source)),
            (False, 'var x = (1 + 2; g(x);'),
        )


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

#: Module code is strict, so besides the reserved words it refuses to bind `await`, the words only
#: strict code reserves, `eval` and `arguments`.
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

A_POSITION_NAMING_A_BINDING_THE_FILE_CREATES = {
    'a default import'     : 'import {name} from "m";',
    'a namespace import'   : 'import * as {name} from "m";',
    'a renamed import'     : 'import {{ remote as {name} }} from "m";',
    'a plain import'       : 'import {{ {name} }} from "m";',
    'an export of a local' : 'var {name};\nexport {{ {name} }};',
}

#: In these positions the grammar takes an IdentifierName, which a reserved word is as well, rather
#: than a name the file binds.
A_POSITION_NAMING_THE_FAR_SIDE_OF_THE_BOUNDARY = {
    'an import'              : 'import {{ {name} as local }} from "m";',
    'a re-export'            : 'export {{ {name} }} from "m";',
    'a renamed re-export'    : 'export {{ {name} as local }} from "m";',
    'the name it exports as' : 'export {{ local as {name} }} from "m";',
    'a namespace re-export'  : 'export * as {name} from "m";',
    'an export of a local'   : 'var local;\nexport {{ local as {name} }};',
}


class TestAModuleTakesAWiderNameAcrossItsBoundaryThanItBinds(TestBase):

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
        self.assertEqual(
            {
                source: is_well_formed(JsParser(source).parse())
                for source in ['import { yield } from "m";', 'export { yield } from "m";']
            },
            {'import { yield } from "m";': False, 'export { yield } from "m";': True},
        )


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
        sources = ['x = "abc\rz;', 'x = "abc\nz;', 'x = "abc\r\nz;']
        self.assertEqual(
            {source: printed(source) for source in sources},
            {source: source for source in sources},
        )

    def test_a_legal_trailing_comma_is_the_printers_to_drop_where_the_file_is_refused_elsewhere(
        self,
    ):
        source = 'x = [1, 2, ]; y = (a b);'
        self.assertEqual(printed(source), 'x = [1, 2];\ny = (a b);')
        self.assertEqual(unread_spans(JsParser(source).parse()), ['a b'])
        self.assertEqual(well_formed(source), False)


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
        The `/` behind `y;` opens the regular expression literal `/ a */`, and a `case` behind it on
        the same line is a syntax error. A print that wrote `case 2` on a line of its own would end
        the statement there and turn the file into a program.
        """
        source = 'switch (x) { case 1: y; / a */ case 2: z; }'
        self.assertEqual(well_formed(printed(source)), False)


#: No digit and no IdentifierStart may stand right behind a numeral, so `3in y` and `1.toString()`
#: are refused although `3 in y` is not.
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

    def test_a_file_the_parser_refuses_comes_back_refused(self):
        rows = A_FILE_THE_PARSER_REFUSES_THAT_AN_ENGINE_REFUSES_TOO
        refused = ('', 'SyntaxError')
        self.assertEqual(
            {source: (well_formed(source), before_and_after(source)) for source in rows},
            {source: (False, (refused, refused)) for source in rows},
        )


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

A_CHAIN_NESTED = {
    'binary operators': lambda n: 'a' + ' + a' * n + ';',
    'member accesses': lambda n: 'a' + '.b' * n + ';',
}


class TestAFileNestedTooDeepToReadIsRefusedAndNeverCrashes(TestBase):

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
    mutants: list[str] = []
    for _ in range(count):
        position = rng.randrange(len(source) + 1)
        if rng.random() < 0.4 and position < len(source):
            mutants.append(source[:position] + source[position + 1:])
        else:
            mutants.append(source[:position] + rng.choice(AN_INSERTION) + source[position:])
    return mutants


class TestAFileOneEditAwayFromAProgramComesBackAsItWasWritten(TestBase):

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
