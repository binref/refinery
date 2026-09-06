from __future__ import annotations

from typing import NamedTuple

from test import TestBase

from refinery.lib.scripts import is_well_formed
from refinery.lib.scripts.js.model import JsErrorNode
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.units.sinks.ppjscript import ppjscript


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
    answered by the tree it recovers. The tree may hold a
    `refinery.lib.scripts.js.model.JsErrorNode`, which keeps the source it stands for, but it may
    not hold a shape the model calls unspellable: `refinery.lib.scripts.Synthesizer.visit` refuses
    those, and a recovery that builds one turns a file that merely fails to parse into a crash of
    the tools that print it. What is pinned here is that no such shape is reached, that the text
    comes back, and that the tree says it is not a program.
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
            'var_with_no_name': 'var ;',
            'const_with_no_name': 'const ;',
            'member_access_with_no_name': 'registry.;',
            'optional_member_access_with_no_name': 'registry?.;',
            'chained_member_access_with_no_name': 'registry.alpha.;',
            'new_meta_property_with_no_name': 'function build() {\n  new.;\n}',
            'object_getter_with_no_name': 'const o = { get () {} };',
            'object_setter_with_no_name': 'const o = { set () {} };',
            'object_async_method_with_no_name': 'const o = { async () {} };',
            'catch_parameter_with_no_name': 'try {\n  names.pop();\n} catch () {}',
            'label_with_no_statement': 'outer: ',
            'super_member_with_no_name': 'class Foo extends Object {\n  m() {\n    super.;\n  }\n}',
            'class_heritage_with_no_name': 'class Foo extends  {}',
            'export_default_with_no_value': 'export default ;',
            'computed_member_with_no_key': 'registry[];',
            'spread_with_no_argument': 'const o = { ... };',
            'for_head_with_no_binding': 'for (const ; ; ) {\n  \n}',
            'switch_case_with_no_test': 'switch (names.length) {\n  case :\n}',
            'arrow_with_no_body': 'const f = () => ;',
        }
        for name, tail in expected.items():
            with self.subTest(name):
                self.assertEqual(self._print(_STOPS[name].cut), F'{_HEAD}{tail}')

    def test_a_source_that_stops_mid_construct_is_not_a_well_formed_program(self):
        for name, stop in _STOPS.items():
            with self.subTest(name):
                self.assertEqual(is_well_formed(JsParser(stop.cut).parse()), False)

    def test_the_position_a_source_stops_at_is_kept_as_an_error_node(self):
        expected = {
            'var_with_no_name': [('', 'expected a name')],
            'const_with_no_name': [('', 'expected a name')],
            'member_access_with_no_name': [('', 'expected a property name')],
            'optional_member_access_with_no_name': [('', 'expected a property name')],
            'chained_member_access_with_no_name': [('', 'expected a property name')],
            'new_meta_property_with_no_name': [('', 'expected a property name')],
            'object_getter_with_no_name': [('', 'expected a name')],
            'object_setter_with_no_name': [('', 'expected a name')],
            'object_async_method_with_no_name': [('', 'expected a name')],
            'catch_parameter_with_no_name': [('', 'expected a name')],
            'label_with_no_statement': [('', 'unexpected token')],
            'super_member_with_no_name': [('', 'expected a property name')],
            'class_heritage_with_no_name': [('', 'unexpected token')],
            'export_default_with_no_value': [('', 'unexpected token')],
            'computed_member_with_no_key': [('', 'unexpected token')],
            'spread_with_no_argument': [('', 'unexpected token')],
            'for_head_with_no_binding': [
                ('', 'expected a name'),
                ('', 'unexpected token'),
                ('', 'unexpected token'),
                ('', 'unexpected token'),
            ],
            'switch_case_with_no_test': [('', 'unexpected token')],
            'arrow_with_no_body': [('', 'unexpected token')],
        }
        for name, errors in expected.items():
            with self.subTest(name):
                self.assertEqual(self._errors(_STOPS[name].cut), errors)

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
        }
        for name, tail in expected.items():
            with self.subTest(name):
                whole = _STOPS[name].whole
                self.assertEqual(is_well_formed(JsParser(whole).parse()), True)
                self.assertEqual(self._print(whole), F'{_HEAD}{tail}')

    def test_the_printer_reads_back_what_it_printed_for_a_source_that_stops_mid_construct(self):
        """
        The output of a recovery is itself input to the tool, and an error node prints as the text
        it kept rather than as a form any parser agreed to read, so the second pass reads something
        else than the first built. What may not happen is a refusal on the second pass: the tool
        would then fail on a file it wrote itself. Only the label keeps its spelling; the rest drift
        by the character the recovery could not attribute, and the drift is pinned rather than
        described.
        """
        expected = {
            'var_with_no_name': 'var ;;',
            'const_with_no_name': 'const ;;',
            'member_access_with_no_name': 'registry.;;',
            'optional_member_access_with_no_name': 'registry?.;;',
            'chained_member_access_with_no_name': 'registry.alpha.;;',
            'new_meta_property_with_no_name': 'function build() {\n  new.;;\n}',
            'object_getter_with_no_name': 'const o = { get() {} };',
            'object_setter_with_no_name': 'const o = { set() {} };',
            'object_async_method_with_no_name': 'const o = { async() {} };',
            'catch_parameter_with_no_name': 'try {\n  names.pop();\n} catch ()) {}',
            'label_with_no_statement': 'outer: ',
            'super_member_with_no_name':
                'class Foo extends Object {\n  m() {\n    super.;;\n  }\n}',
            'class_heritage_with_no_name': 'class Foo extends {} {}',
            'export_default_with_no_value': 'export default ;;',
            'computed_member_with_no_key': 'registry[]];',
            'spread_with_no_argument': 'const o = { ...}, ; };',
            'for_head_with_no_binding': 'for (const ;; ); }) {\n  \n}',
            'switch_case_with_no_test': 'switch (names.length) {\n  case ::\n}',
            'arrow_with_no_body': 'const f = () => ;;',
        }
        for name, tail in expected.items():
            with self.subTest(name):
                once = self._print(_STOPS[name].cut)
                self.assertEqual(self._print(once), F'{_HEAD}{tail}')

    def test_ppjscript_prints_a_source_that_stops_mid_construct(self):
        expected = {
            'var_with_no_name': 'var ;',
            'const_with_no_name': 'const ;',
            'member_access_with_no_name': 'registry.;',
            'optional_member_access_with_no_name': 'registry?.;',
            'chained_member_access_with_no_name': 'registry.alpha.;',
            'new_meta_property_with_no_name': 'function build() {\n    new.;\n}',
            'object_getter_with_no_name': 'const o = { get () {} };',
            'object_setter_with_no_name': 'const o = { set () {} };',
            'object_async_method_with_no_name': 'const o = { async () {} };',
            'catch_parameter_with_no_name': 'try {\n    names.pop();\n} catch () {}',
            'label_with_no_statement': 'outer: ',
            'super_member_with_no_name':
                'class Foo extends Object {\n    m() {\n        super.;\n    }\n}',
            'class_heritage_with_no_name': 'class Foo extends  {}',
            'export_default_with_no_value': 'export default ;',
            'computed_member_with_no_key': 'registry[];',
            'spread_with_no_argument': 'const o = { ... };',
            'for_head_with_no_binding': 'for (const ; ; ) {\n    \n}',
            'switch_case_with_no_test': 'switch (names.length) {\n    case :\n}',
            'arrow_with_no_body': 'const f = () => ;',
        }
        for name, tail in expected.items():
            with self.subTest(name):
                printed = _STOPS[name].cut.encode('utf8') | ppjscript() | str
                self.assertEqual(printed, F'{_HEAD}{tail}')


class TestParserRecoveryOverAMalformedNamePosition(TestBase):
    """
    The same law where a name position holds a token that is not a name. Nothing was cut off here,
    so the parser has text to keep, and what it kept is what comes back.
    """

    def _print(self, source: str) -> str:
        return JsSynthesizer().convert(JsParser(source).parse())

    def test_a_malformed_name_position_prints_the_text_it_read(self):
        expected = {
            'doubled_dot': 'registry..;\nalpha;',
            'dot_before_a_semicolon': 'registry.;;',
            'dot_before_a_bracket': 'registry.];',
            'dot_before_a_string': "registry.'alpha';",
            'new_dot_before_a_string': "function f() {\n  new.'target';\n}",
            'label_before_a_closing_brace': 'function f() {\n  outer: }\n}',
        }
        for name, tail in expected.items():
            with self.subTest(name):
                self.assertEqual(self._print(F'{_HEAD}{_MALFORMED[name]}'), F'{_HEAD}{tail}')

    def test_a_malformed_name_position_is_not_a_well_formed_program(self):
        for name, tail in _MALFORMED.items():
            with self.subTest(name):
                self.assertEqual(is_well_formed(JsParser(F'{_HEAD}{tail}').parse()), False)

    def test_the_token_that_was_not_a_name_is_kept_as_an_error_node(self):
        expected = {
            'doubled_dot': [('.', 'expected a property name')],
            'dot_before_a_semicolon': [(';', 'expected a property name')],
            'dot_before_a_bracket': [(']', 'expected a property name')],
            'dot_before_a_string': [("'alpha'", 'expected a property name')],
            'new_dot_before_a_string': [("'target'", 'expected a property name')],
            'label_before_a_closing_brace': [('}', 'unexpected token')],
        }
        for name, errors in expected.items():
            with self.subTest(name):
                script = JsParser(F'{_HEAD}{_MALFORMED[name]}').parse()
                self.assertEqual([
                    (node.text, node.message)
                    for node in script.walk_in_order()
                    if isinstance(node, JsErrorNode)
                ], errors)

    def test_ppjscript_prints_a_malformed_name_position(self):
        expected = {
            'doubled_dot': 'registry..;\nalpha;',
            'dot_before_a_semicolon': 'registry.;;',
            'dot_before_a_bracket': 'registry.];',
            'dot_before_a_string': "registry.'alpha';",
            'new_dot_before_a_string': "function f() {\n    new.'target';\n}",
            'label_before_a_closing_brace': 'function f() {\n    outer: }\n}',
        }
        for name, tail in expected.items():
            with self.subTest(name):
                printed = F'{_HEAD}{_MALFORMED[name]}'.encode('utf8') | ppjscript() | str
                self.assertEqual(printed, F'{_HEAD}{tail}')


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
    A file cut in the middle of a construct still has to be answered with a tree, so the parser
    writes the token it was waiting for and steps over what stood in its place. What comes back is
    then a program the file does not hold — `x = f(1, 2` prints as the call `x = f(1, 2);`, and
    `try {} catch` as a handler with a body nobody wrote — and the only thing keeping a caller from
    comparing that fabrication against the source it came from is that the parser records having
    made it.

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

    def test_a_file_that_stops_inside_a_construct_is_not_a_well_formed_program(self):
        sources = [
            source
            for group in SOURCES_THAT_STOP_INSIDE_A_CONSTRUCT.values()
            for source in group
        ]
        self.assertEqual(
            {source: self._well_formed(source) for source in sources},
            {source: False for source in sources},
        )

    def test_a_bracket_the_file_closes_with_something_else_is_not_a_well_formed_program(self):
        """
        Node refuses `var x = (1 + 2; g(x);` with `SyntaxError: Unexpected token ';'`. The file does
        not stop anywhere — it runs to its end — and what the recovery does here is drop the `;` it
        found and write the `)` it wanted, so a file written closed is what the tree reports.
        """
        self.assertEqual(self._well_formed('var x = (1 + 2; g(x);'), False)


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
