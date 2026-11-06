from __future__ import annotations

import unittest

import refinery.lib.scripts as scripts
import refinery.lib.scripts.js.deobfuscation.protospelling as protospelling

from test import TestBase, lines_executed
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints

from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.deobfuscation.protospelling import JsPrototypeSpellingNormalization
from refinery.lib.scripts.js.parser import JsParser

A_PROTOTYPE_SPELLING_AND_WHAT_NAMES_IT = {
    '({}).__proto__.z = 9;':
        'Object.prototype.z = 9;',
    'Object.getPrototypeOf({}).z = 9;':
        'Object.prototype.z = 9;',
    '({}).constructor.prototype.z = 9;':
        'Object.prototype.z = 9;',
    '[].__proto__.z = 9;':
        'Array.prototype.z = 9;',
    'Object.getPrototypeOf([]).z = 9;':
        'Array.prototype.z = 9;',
    '[].constructor.prototype.z = 9;':
        'Array.prototype.z = 9;',
}

A_SPELLING_THAT_REACHES_SOMETHING_ELSE = {
    'Object.getPrototypeOf = function () { return {q: 5}; };'
    ' console.log(Object.getPrototypeOf({}).q);':
        '5\n',
    "Object.defineProperty(Object.prototype, '__proto__', {get: function () { return {q: 5}; }});"
    ' console.log(({}).__proto__.q);':
        '5\n',
    'var Object = {prototype: {q: 1}, getPrototypeOf: function () { return {q: 5}; }};'
    ' console.log(Object.getPrototypeOf({}).q);':
        '5\n',
    'console.log(({__proto__: {q: 5}}).__proto__.q);':
        '5\n',
    "console.log(({'__proto__': {q: 5}}).__proto__.q);":
        '5\n',
    "console.log(({['__proto__']: {q: 5}}).__proto__.q);":
        '5\n',
    'var __proto__ = {q: 5}; console.log(({__proto__}).__proto__.q);':
        '5\n',
    'console.log(({...{a: 1}}).__proto__ === Object.prototype);':
        'true\n',
}


class TestAPrototypeSpellingIsWrittenAsTheNameItReaches(TestJsDeobfuscator):

    def test_each_spelling_is_written_as_the_prototype_it_names(self):
        self.assertEqual(
            {
                source: self._run_transformer(source, JsPrototypeSpellingNormalization)
                for source in A_PROTOTYPE_SPELLING_AND_WHAT_NAMES_IT
            },
            A_PROTOTYPE_SPELLING_AND_WHAT_NAMES_IT,
        )

    def test_a_receiver_the_syntax_does_not_decide_is_left_alone(self):
        source = 'var a = {};\na.__proto__.z = 9;'
        self.assertEqual(self._run_transformer(source, JsPrototypeSpellingNormalization), source)

    def test_a_name_the_file_binds_is_not_the_intrinsic(self):
        source = 'var Object = { prototype: {} };\nObject.getPrototypeOf({}).z = 9;'
        self.assertEqual(self._run_transformer(source, JsPrototypeSpellingNormalization), source)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestASpellingThatReachesSomethingElseIsNotRewritten(TestJsDeobfuscator):

    def test_a_spelling_that_reaches_something_else_still_answers_it(self):
        rows = A_SPELLING_THAT_REACHES_SOMETHING_ELSE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_reassigned_constructor_is_not_the_intrinsic(self):
        source = (
            'function C() { }'
            ' C.prototype.q = 5;'
            ' Object.prototype.constructor = C;'
            ' console.log(({}).constructor.prototype.q);'
        )
        self.assertEqual(before_and_after(source), (('5\n', None), ('5\n', None)))


#: Spellings an assignment or a `delete` reads as a reference. `Object.prototype` and
#: `Array.prototype` are neither writable nor configurable, so writing either out here makes strict
#: code throw a `TypeError` where the original went on.
A_SPELLING_STANDING_WHERE_A_REFERENCE_GOES = {
    '({}).__proto__ = {q: 1};\nconsole.log(1);':
        '1\n',
    '[].__proto__ = null;\nconsole.log("ok");':
        'ok\n',
    'console.log(delete ({}).__proto__);':
        'true\n',
}


A_RECEIVER_THE_REWRITE_MAY_NOT_DROP = {
    'var n = 0;\nfunction f() { n++; return 1; }\nvar p = [f()].__proto__;\nconsole.log(n);':
        '1\n',
    'try { var p = [...null].__proto__; console.log("none"); }'
    ' catch (e) { console.log(e.constructor.name); }':
        'TypeError\n',
}


A_MECHANISM_WRITTEN_UNDER_ANOTHER_NAME = {
    'Object.defineProperty(Array.prototype, "__proto__",'
    ' {get: function () { return {q: 5}; }});\nconsole.log([].__proto__.q);':
        '5\n',
    'Object.setPrototypeOf(Array.prototype, null);\nconsole.log([].__proto__);':
        'undefined\n',
    'function patch(A) { A.prototype.constructor = function C() {}; }\npatch(Array);'
    '\n[].constructor.prototype.q = 5;\nconsole.log([].q);':
        'undefined\n',
    'var G = Object;\nfunction patch(o) { o.getPrototypeOf = function () { return {q: 7}; }; }'
    '\npatch(G);\nconsole.log(Object.getPrototypeOf({}).q);':
        '7\n',
    '(function (Object) { Object.prototype.constructor = function C() {}; })(Object);'
    '\nconsole.log(({}).constructor.prototype === Object.prototype);':
        'false\n',
    'function C() {}\nC.prototype.q = 5;\n[Object.prototype.constructor] = [C];'
    '\nconsole.log(({}).constructor.prototype.q);':
        '5\n',
    'function C() {}\nC.prototype.q = 5;\nglobalThis.Object.prototype.constructor = C;'
    '\nconsole.log(({}).constructor.prototype.q);':
        '5\n',
    'globalThis.Object.getPrototypeOf = function () { return {q: 5}; };'
    '\nconsole.log(Object.getPrototypeOf({}).q);':
        '5\n',
}


A_NAME_A_SCOPE_CAN_ANSWER = {
    'var o = {Object: {prototype: {q: 3}}};\nwith (o) { console.log(({}).__proto__.q); }':
        'undefined\n',
    'var o = {Object: {prototype: {q: 3}, getPrototypeOf: function () { return {q: 7}; }}};'
    '\nwith (o) { console.log(Object.getPrototypeOf({}).q); }':
        '7\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestASpellingIsOnlyRewrittenWhereItIsRead(TestJsDeobfuscator):

    def test_a_spelling_standing_where_a_reference_goes_behaves_the_same_in_an_es_module(self):
        rows = A_SPELLING_STANDING_WHERE_A_REFERENCE_GOES
        self.assertEqual(
            {source: before_and_after(source, module=True) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReceiverTheRewriteDropsIsFirstAskedWhatItRuns(TestJsDeobfuscator):

    def test_a_receiver_that_runs_something_is_left_alone(self):
        rows = A_RECEIVER_THE_REWRITE_MAY_NOT_DROP
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_RECEIVER_WHOSE_ELEMENT_THROWS = {
    '[zzz].__proto__;\nconsole.log(1);\n': ('', 'ReferenceError'),
    '[q].__proto__;\nlet q = 1;\nconsole.log(1);\n': ('', 'ReferenceError'),
    '[q].__proto__.foo = function () {};\nlet q = 1;\n': ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReceiverWhoseElementThrowsIsLeftAlone(TestJsDeobfuscator):

    def test_a_receiver_whose_element_throws_is_left_alone(self):
        rows = A_RECEIVER_WHOSE_ELEMENT_THROWS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMechanismWrittenUnderAnotherNameStillRefusesTheRewrite(TestJsDeobfuscator):

    def test_a_mechanism_written_under_another_name_is_still_written(self):
        rows = A_MECHANISM_WRITTEN_UNDER_ANOTHER_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameAScopeCanAnswerIsNotTheIntrinsic(TestJsDeobfuscator):

    def test_a_name_a_scope_can_answer_is_left_alone(self):
        rows = A_NAME_A_SCOPE_CAN_ANSWER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_MECHANISM_THIS_PASS_ITSELF_MAKES_VISIBLE = {
    'function C() {}\nC.prototype.q = 5;\n'
    'function r() { return ({}).constructor.prototype.q; }\n'
    '({}).__proto__.constructor = C;\nconsole.log(r());':
        '5\n',
    'function C() {}\nC.prototype.q = 5;\n'
    'function r() { return [].constructor.prototype.q; }\n'
    '[].__proto__.constructor = C;\nconsole.log(r());':
        '5\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWriteThisPassSpellsOutIsAskedAboutByTheNextGate(TestJsDeobfuscator):

    def test_a_write_this_pass_spells_out_refuses_the_next_rewrite(self):
        rows = A_MECHANISM_THIS_PASS_ITSELF_MAKES_VISIBLE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestThePassWalksTheTreeOnce(TestBase):

    @staticmethod
    def _work(depth: int) -> int:
        ast = JsParser('f(' * depth + '[].__proto__' + ')' * depth + ';').parse()
        transformer = JsPrototypeSpellingNormalization()
        models = model_cache(transformer, ast)
        models.effects
        return lines_executed(lambda: transformer.visit(ast), scripts, protospelling)

    def test_the_work_grows_linearly_with_the_depth_of_nesting(self):
        self.assertWorkGrowsLinearly(self._work, 50)
