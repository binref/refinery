"""
What a class element's own code reads `await`, `yield` and `arguments` as, and whether the tool
reads the same texts the language does.

A field initializer and a static block are each a function context of their own (§15.7.1): neither
is the body of the function around the class, so `yield` is a name in both wherever they stand, and
so is `await` in an instance initializer, while a static block and a static initializer refuse
`await` in every position. Both refuse a reference to `arguments`, through any arrow but not through
a function. A computed key and a heritage clause are not the element's own code and keep the
readings of whatever encloses the class.

Node decides every expectation here. The question put to it is whether it reads a text at all, and
the law is that `refinery.lib.scripts.is_well_formed` answers the same: a tree the engine refuses is
no program to print, and a program the engine reads must come back one. Where a file prints
something, what it prints has to survive being printed and being deobfuscated.

The static initializer's verdict is V8's: `class C { static p = await; }` is refused with
`SyntaxError: Unexpected reserved word`, and so is the same class inside an `async` function and
with `var await = 1` in scope, where the instance initializer `p = await` reads the variable.

SECURITY: every snippet here is hand-authored and benign, and running it is what makes the engine
the oracle. Nothing from `samples` may ever be fed to this.
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

#: A class element binding or referring to a word its own context refuses, written so that the
#: word stands where a name stands. Node refuses every one of these files, and the collector
#: reports on every one of them under either seed: the tree spells the word as the name it was
#: written as, and the refusal is an early error over that name.
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

#: A class element written with an operator its own context has no reading for, or with `await`
#: where a static element refuses the word outright. Node refuses every one of these files. The
#: grammar has no tree for them, so the parser refuses them on its own and what the collector says
#: about the repair is not asked.
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

#: The same words in the positions a class element reads them as the enclosing code would, or in
#: an instance initializer, where `await` is a name whatever the function around the class is.
#: Node reads every one of these files and the collector reports nothing about them.
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

#: Files of the shapes above that print, and what Node prints for each.
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

#: The kinds of thing the parser reads a spelling of `await` or `yield` as. Each stands only where
#: the context the model answers for its node reads it that way: an `await` operator where the
#: model reads the operator, a `for await` head where the model reads the head, and a name where
#: the word is one.
THE_KINDS_OF_READING = frozenset({
    'await operator',
    'for await',
    'await name',
    'yield operator',
    'yield name',
})


def _readings_taken_in(source: str) -> list[tuple[str, bool]]:
    """
    Every spelling of `await` and `yield` in the tree of *source*, as the kind of thing the parser
    read it as and whether the context the model answers for its position reads it that way, in
    tree order.
    """
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
    """
    `refinery.lib.scripts.is_well_formed` is the tool's answer to the question Node was asked, so
    the two agree on every file of the three corpora.
    """

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
    """
    The refusal belongs to the class element and not to the mode, so the collector reports on the
    same files under either seed, which is what makes it usable as a gate on a payload whose
    destination is one of these elements.
    """

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
    """
    The parser descends `refinery.lib.scripts.js.model.CodeContext` as it builds the tree, and the
    model folds the same context back out of the finished tree, so on every program the two agree:
    every `await` operator the tree holds stands where the model reads the operator, and every
    `await` or `yield` name where the model reads a name. The corpus is every program this module
    and its neighbours know to be one, plus one program per node kind.
    """

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
