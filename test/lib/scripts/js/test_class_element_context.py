"""
A field initializer and a static block are each a function context of their own (§15.7.1), not the
body of the function around the class: `yield` is a name in both, and so is `await` in an instance
initializer, while a static block and a static initializer refuse `await` in every position. Both
refuse a reference to `arguments` through any arrow, but not through a function. A computed key and
a heritage clause keep the readings of whatever encloses the class.

V8 refuses `await` in a static initializer as an unexpected reserved word, also inside an `async`
function and with `var await = 1` in scope, where an instance initializer reads the variable.

SECURITY: every snippet here is hand-authored and benign, and Node runs it. Nothing from `samples`
may ever be fed to this.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    behavior,
    node_executable,
)
from test.lib.scripts.js.corpus import SNIPPETS
from test.lib.scripts.js.ledger import each_well_formed, folded, printed, prints
from test.lib.scripts.js.test_parameter_grammar import (
    A_FUNCTION_EXPRESSION_NAME_ITS_OWN_KIND_LEAVES_ALONE,
    A_FUNCTION_EXPRESSION_NAME_ONLY_THE_ENCLOSING_KIND_RESERVES,
    THE_SAME_BINDING_INSIDE_A_PLAIN_FUNCTION,
    every_one_of,
    refused,
    reported,
)

from refinery.lib.scripts.js.model import (
    AwaitReading,
    JsAwaitExpression,
    JsForOfStatement,
    JsIdentifier,
    JsYieldExpression,
    code_context_at,
    names_a_property,
)
from refinery.lib.scripts.js.parser import JsParser

A_CLASS_ELEMENT_NAMING_A_WORD_IT_REFUSES = [
    'class C { static { var await = 1; } }',
    'function f() { class C { static { var await = 1; } } }',
    'async function f() { class C { static { var await = 1; } } }',
    'class C { static { class D { static { var await; } } } }',
    'function* f() { class C { p = yield; } }',
    'function* f() { class C { static { yield; } } }',
    'class C { p = yield; }',
    'class C { m() { var yield; } }',
    'class C { static { var yield = 1; } }',
    'function* g() { class C { static { let yield = 1; } } }',
    'function* g() { class C { static { class yield {} } } }',
    'function* g() { class C { static { try {} catch (yield) {} } } }',
    'function* g() { class C { static { for (var yield of []) {} } } }',
    'function* g() { class C { p = (yield = 1); } }',
    'function* g() { class C { static { ({ yield } = {}); } } }',
    'async function* g() { class C { static { var yield = 1; } } }',
    'class C { static { arguments; } }',
    'class C { p = arguments; }',
    'class C { p = () => arguments; }',
]

A_CLASS_ELEMENT_WITH_A_READING_IT_DOES_NOT_HAVE = [
    'async function f() { class C { p = await x; } }',
    'async function f() { class C { p = await 1; } }',
    'function* g() { class C { p = yield 1; } }',
    'class C { static { await 1; } }',
    'function f() { class C { static { await 1; } } }',
    'async function f() { class C { static { await 1; } } }',
    'class C { static { await; } }',
    'class C { static p = await; }',
    'async function f() { class C { static p = await; } }',
    'var await = 1; class C { static p = await; }',
    'class C { static { for await (const x of []) {} } }',
    'class C { static { (await) => 1; } }',
    'var await = 1; class C { static p = (await) => 1; }',
    'class C { static { class D { [await]() {} } } }',
    'class C { static { var f = function () { await 1; } } }',
]

A_CLASS_ELEMENT_NODE_READS = [
    'async function f() { class C { p = await; } }',
    'async function h() { class C { p = (await) => 1; } }',
    'var await = 1; class C { p = await; }',
    'var await = 1; class C { static p = function () { return await; }; }',
    'var await = 1; class C { static [await] = 1; }',
    'async function f() { class C { static [await 1] = 2; } }',
    'async function f() { class C { [await 1]() {} } }',
    'async function f() { class C extends (await 1) {} }',
    'async function f() { for await (const x of []) {} }',
    'var await = 1; class C { static { function g() { return await; } } }',
    'class C { static { function f() { var await; } } }',
    'class C { static { () => await; } }',
    'class C { static { () => { var await; }; } }',
    'class C { static { let x = () => await; } }',
    'class C { static { var f = async function () { await 1; }; } }',
    'class C { static { async () => await 1; } }',
    'class C { static { async function g() { for await (const x of []) {} } } }',
    'class C { static { class D { p = await; } } }',
    'function* g() { class C { [yield] = 1; } }',
    'function* g() { class C extends (yield) {} }',
    'function* g() { class C { [yield 1]() {} } }',
    'function* g() { class C { static [yield]() {} } }',
    'for (var c = class { p = "a" in {}; }; false;) {}',
    'for (var c = class { ["a" in {}]() {} }; false;) {}',
    'for (var c = class { static ["a" in {}] = 1; }; false;) {}',
    'for (var c = class { static { "a" in {}; } }; false;) {}',
    'class C { p = function () { return arguments; }; }',
    'class C { [arguments]() {} }',
    'function f() { class C { [arguments]() {} } }',
    'class C { m() { return arguments; } }',
]

A_CLASS_ELEMENT_THAT_PRINTS = {
    'var await = 41; class C { p = await; } console.log(new C().p);':
        prints('41'),
    'var await = 2; class C { static p = function () { return await; }; } console.log(C.p());':
        prints('2'),
    'var await = 3; class C { static [await] = 4; } console.log(C[3]);':
        prints('4'),
    'class C { static { var f = () => typeof await; console.log(f()); } }':
        prints('undefined'),
    'function* g() { class C { [yield] = 1; } } console.log(g().next().value);':
        prints('undefined'),
    'for (var c = class { p = "a" in { a: 1 }; }; false;) {} console.log(new c().p);':
        prints('true'),
    'class C { m() { return arguments.length; } } console.log(new C().m(1, 2));':
        prints('2'),
    'class C { p = function () { return arguments.length; }; } console.log(new C().p(1));':
        prints('1'),
    'class C { static { async function g() { for await (const x of [7]) console.log(x); } g(); } }':
        prints('7'),
}

THE_KINDS_OF_READING = frozenset({
    'await operator',
    'for await',
    'await name',
    'yield operator',
    'yield name',
})


def _readings_taken_in(source: str) -> list[tuple[str, bool]]:
    readings: list[tuple[str, bool]] = []
    for node in JsParser(source).parse().walk():
        context = code_context_at(node)
        if isinstance(node, JsAwaitExpression):
            readings.append(('await operator', context.await_reading is AwaitReading.OPERATOR))
        elif isinstance(node, JsForOfStatement) and node.is_await:
            readings.append(('for await', context.reads_for_await))
        elif isinstance(node, JsYieldExpression):
            readings.append(('yield operator', context.yield_is_operator))
        elif isinstance(node, JsIdentifier) and not names_a_property(node):
            if node.name == 'await':
                readings.append(('await name', context.await_reading is AwaitReading.NAME))
            elif node.name == 'yield':
                readings.append(('yield name', not context.yield_is_operator))
    return readings


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhatNodeMakesOfAClassElementsOwnCode(TestBase):

    def test_node_refuses_every_element_naming_a_word_it_refuses(self):
        rows = A_CLASS_ELEMENT_NAMING_A_WORD_IT_REFUSES
        self.assertEqual(refused(rows), every_one_of(rows, True))

    def test_node_refuses_every_element_with_a_reading_it_does_not_have(self):
        rows = A_CLASS_ELEMENT_WITH_A_READING_IT_DOES_NOT_HAVE
        self.assertEqual(refused(rows), every_one_of(rows, True))

    def test_node_reads_every_element_read_as_the_enclosure_would(self):
        rows = A_CLASS_ELEMENT_NODE_READS
        self.assertEqual(refused(rows), every_one_of(rows, False))

    def test_node_prints_what_each_printing_file_is_recorded_as_printing(self):
        rows = A_CLASS_ELEMENT_THAT_PRINTS
        self.assertEqual({source: behavior(source) for source in rows}, rows)


class TestTheVerdictAnswersAsNodeDoes(TestBase):

    def test_an_element_naming_a_word_it_refuses_is_no_program(self):
        rows = A_CLASS_ELEMENT_NAMING_A_WORD_IT_REFUSES
        self.assertEqual(each_well_formed(rows), every_one_of(rows, False))

    def test_an_element_with_a_reading_it_does_not_have_is_no_program(self):
        rows = A_CLASS_ELEMENT_WITH_A_READING_IT_DOES_NOT_HAVE
        self.assertEqual(each_well_formed(rows), every_one_of(rows, False))

    def test_an_element_read_as_the_enclosure_would_is_a_program(self):
        rows = A_CLASS_ELEMENT_NODE_READS
        self.assertEqual(each_well_formed(rows), every_one_of(rows, True))

    def test_await_in_an_instance_initializer_is_the_name_it_was_written_as(self):
        source = 'async function f() { class C { p = await; } }'
        self.assertEqual(
            printed(source), 'async function f() {\n  class C {\n    p = await;\n  }\n}'
        )


class TestTheCollectorReportsWhereTheTreeSpellsTheRefusedWord(TestBase):

    def test_it_reports_on_every_element_naming_a_word_it_refuses_under_a_sloppy_seed(self):
        rows = A_CLASS_ELEMENT_NAMING_A_WORD_IT_REFUSES
        self.assertEqual(reported(rows, strict=False), every_one_of(rows, True))

    def test_it_reports_on_every_one_of_them_under_a_strict_seed(self):
        rows = A_CLASS_ELEMENT_NAMING_A_WORD_IT_REFUSES
        self.assertEqual(reported(rows, strict=True), every_one_of(rows, True))

    def test_it_reports_nothing_about_an_element_node_reads_under_either_seed(self):
        rows = A_CLASS_ELEMENT_NODE_READS
        self.assertEqual(
            {source: (sloppy, strict) for (source, sloppy), strict in zip(
                reported(rows, strict=False).items(), reported(rows, strict=True).values()
            )},
            {source: (False, False) for source in rows},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPrintingFileKeepsWhatItPrints(TestBase):

    def test_each_file_prints_the_same_through_the_printer_and_through_the_deobfuscator(self):
        rows = A_CLASS_ELEMENT_THAT_PRINTS
        self.assertEqual(
            {
                source: (behavior(printed(source)), behavior(folded(source)))
                for source in rows
            },
            {source: (printing, printing) for source, printing in rows.items()},
        )


class TestTheParserReadsEachWordAsTheModelSaysItStands(TestBase):

    @staticmethod
    def _programs() -> list[str]:
        return [
            *A_CLASS_ELEMENT_NODE_READS,
            *A_CLASS_ELEMENT_THAT_PRINTS,
            *A_FUNCTION_EXPRESSION_NAME_ITS_OWN_KIND_LEAVES_ALONE,
            *A_FUNCTION_EXPRESSION_NAME_ONLY_THE_ENCLOSING_KIND_RESERVES,
            *(
                source for source, refused in THE_SAME_BINDING_INSIDE_A_PLAIN_FUNCTION.items()
                if not refused
            ),
            *SNIPPETS.values(),
        ]

    def test_every_spelling_stands_in_the_reading_the_model_answers(self):
        readings = {source: _readings_taken_in(source) for source in self._programs()}
        self.assertEqual(
            readings,
            {source: [(kind, True) for kind, _ in taken] for source, taken in readings.items()},
        )

    def test_the_corpus_spells_every_kind_of_reading(self):
        self.assertEqual(
            {kind for taken in map(_readings_taken_in, self._programs()) for kind, _ in taken},
            THE_KINDS_OF_READING,
        )
