from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import (
    Program,
    Reading,
    a_program,
    before_and_after,
    each_program_still_prints,
    prints,
)

from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.model import JsAssignmentExpression, JsExpressionStatement, JsIdentifier
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser


class TestValuesAWriteThroughIsRecordedOnlyOnceABindingHoldsThem(TestBase):

    @staticmethod
    def _stored(value: str) -> bool:
        script = JsParser(F'var alias = Object; var self = this; var local = 1; s.v = {value};').parse()
        statement = script.body[-1]
        assert isinstance(statement, JsExpressionStatement)
        store = statement.expression
        assert isinstance(store, JsAssignmentExpression) and store.right is not None
        return ModelCache(script).intrinsic_writes.follows_only_through_bindings(store.right)

    def test_an_intrinsic_the_scan_watches_or_the_global_object(self):
        for value in (
            'Object',
            'Object.prototype',
            'Object.keys',
            'alias',
            'alias.prototype',
            'Math',
            'globalThis',
            'this',
            'self',
            'local || Object',
            '(0, Object)',
            'local ? 1 : Object',
            '(local = Object)',
        ):
            with self.subTest(value=value):
                self.assertTrue(self._stored(value))

    def test_a_value_that_is_neither(self):
        for value in (
            '1',
            '"Object"',
            'local',
            'local.prototype',
            'String.fromCharCode(1)',
            'typeof Object',
            'Object ? 1 : local',
            '(Object, local)',
        ):
            with self.subTest(value=value):
                self.assertFalse(self._stored(value))

    def test_a_property_of_the_global_object(self):
        for value in (
            'window.document',
            'globalThis.location.href',
            'this.x',
            'self.navigator',
        ):
            with self.subTest(value=value):
                self.assertFalse(self._stored(value))

    def test_a_value_the_model_was_not_built_over(self):
        cache = ModelCache(JsParser('var local = 1; s.v = local;').parse())
        self.assertTrue(cache.intrinsic_writes.follows_only_through_bindings(JsIdentifier(name='local')))


class TestBindingsWhoseValuesDenoteARootTheScanWatches(TestBase):

    @staticmethod
    def _denotes(source: str) -> bool:
        cache = ModelCache(JsParser(source).parse())
        binding = cache.model.root_scope.bindings['P']
        return cache.intrinsic_writes.denotes_a_watched_root(binding)

    def test_a_binding_holding_an_intrinsic_directly_or_through_another_name(self):
        for source in (
            'var P = Object.prototype;',
            'var P; P = Object;',
            'var Q = Math; var P = Q;',
            'var P = local || Array;',
        ):
            with self.subTest(source=source):
                self.assertTrue(self._denotes(source))

    def test_a_binding_holding_something_else(self):
        for source in (
            'var P = 1;',
            'var P = {};',
            'var P = String.fromCharCode(1);',
            'var P = window;',
        ):
            with self.subTest(source=source):
                self.assertFalse(self._denotes(source))


class TestAWriteThroughAFormThatForwardsItsValueWritesTheRoot(TestBase):
    """
    A comma, a logical or a conditional expression evaluates to one of its operands, so a property
    written on what one of them evaluates to is written on each name an operand may be.
    """

    @staticmethod
    def _written(source: str) -> frozenset[str]:
        return ModelCache(JsParser(source).parse()).intrinsic_writes.names

    def test_a_key_written_through_a_comma_a_logical_or_a_conditional_writes_each_root(self):
        for source, roots in (
            ('(0, Math).floor = f;', {'Math'}),
            ('(Math || null).floor = f;', {'Math'}),
            ('(c ? Math : JSON).floor = f;', {'Math', 'JSON'}),
            ('(0, Date).now = f;', {'Date'}),
            ('(Date || null).now = f;', {'Date'}),
            ('(c ? Date : Math).now = f;', {'Date', 'Math'}),
        ):
            with self.subTest(source=source):
                self.assertEqual(self._written(source) & roots, roots)

    def test_a_root_handed_to_a_function_writing_through_such_a_form_is_written(self):
        for source in (
            'function patch(m) { (0, m).floor = f; } patch(Math);',
            'function patch(m) { (m || 0).floor = f; } patch(Math);',
        ):
            with self.subTest(source=source):
                self.assertIn('Math', self._written(source))


class TestAFunctionStoringThroughItsParameterInAPatternWritesTheRoot(TestBase):
    """
    A pattern and the head of a `for`-`in` or `for`-`of` loop store through every member they hold,
    so a function storing a property of its parameter there writes the root a call hands it.
    """

    def test_a_root_handed_to_a_function_storing_through_a_pattern_or_a_loop_head_is_written(self):
        for source in (
            'function patch(m) { [m.floor] = [f]; } patch(Math);',
            'function patch(m) { ({ k: m.floor } = { k: f }); } patch(Math);',
            'function patch(m) { for (m.floor of [f]); } patch(Math);',
            'function patch(m) { for (m.floor in o); } patch(Math);',
        ):
            with self.subTest(source=source):
                self.assertIn('Math', ModelCache(JsParser(source).parse()).intrinsic_writes.names)


#: Programs replacing `Math.floor` through a comma, a logical or a conditional expression before
#: calling it, mapped to what Node prints for them.
A_METHOD_REPLACED_THROUGH_A_FORM_THAT_FORWARDS_ITS_VALUE = {
    inspect.cleandoc("""
        (0, Math).floor = function () { return 42; };
        console.log(Math.floor(1.5));
    """): '42\n',
    inspect.cleandoc("""
        (Math || null).floor = function () { return 42; };
        console.log(Math.floor(1.5));
    """): '42\n',
    inspect.cleandoc("""
        (process.argv.length ? Math : JSON).floor = function () { return 42; };
        console.log(Math.floor(1.5));
    """): '42\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAMethodReplacedThroughAFormThatForwardsItsValue(TestBase):

    def test_the_replaced_method_is_not_folded(self):
        rows = A_METHOD_REPLACED_THROUGH_A_FORM_THAT_FORWARDS_ITS_VALUE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestTheTestOfABranchOrALoopHandsItsValueToNothing(TestBase):
    """
    The test of an `if`, a loop or a conditional is converted to a boolean, which runs no code of
    an object, so a value read there reaches nothing that could write a property on it.
    """

    @staticmethod
    def _written(source: str) -> frozenset[str]:
        return ModelCache(JsParser(source).parse()).intrinsic_writes.names

    def test_an_intrinsic_read_as_a_test_is_not_written(self):
        for source in (
            'if (String.prototype) { f(); }',
            'var t = String.prototype ? 1 : 2;',
            'while (String.prototype && i) { i--; }',
            'for (; String.prototype; ) { break; }',
            'do {} while (String.prototype);',
            'if ((0, String.prototype)) {}',
            'var S = String; if (S[k]) {}',
        ):
            with self.subTest(source=source):
                self.assertNotIn('String', self._written(source))

    def test_an_intrinsic_a_test_reads_and_a_call_is_handed_is_written(self):
        for source in (
            'var v = String.prototype; if (v) { g(v); }',
            'if (g(String.prototype)) {}',
        ):
            with self.subTest(source=source):
                self.assertIn('String', self._written(source))


#: Programs reading `String.prototype` or a key of `String` as the test of a branch or a loop,
#: alone, beside a call it is handed to, or beside a store of it, mapped to what Node prints for
#: each run as a CommonJS file.
AN_INTRINSIC_READ_AS_A_TEST: dict[str, Program] = {
    'an if test of String.prototype': Program(
        a_program("""
            function f() { if (String.prototype) { return 'ab'.toUpperCase(); } return 'none'; }
            console.log(f());
            """),
        prints('AB'),
        Reading.COMMONJS,
    ),
    'a handed prototype still counts': Program(
        a_program("""
            function patch(p) { p.toUpperCase = function () { return 'P'; }; return true; }
            if (patch(String.prototype)) { console.log('a'.toUpperCase()); }
            """),
        prints('P'),
        Reading.COMMONJS,
    ),
    'conditional test': Program(
        a_program("""
            function f() { var t = String.prototype ? 'y' : 'n'; return t + 'q'.toUpperCase(); }
            console.log(f());
            """),
        prints('yQ'),
        Reading.COMMONJS,
    ),
    'conditional branch forwards the prototype': Program(
        a_program("""
            var p = (1 ? String.prototype : 0);
            p.toUpperCase = function () { return 'P'; };
            console.log('a'.toUpperCase());
            """),
        prints('P'),
        Reading.COMMONJS,
    ),
    'assignment in a test': Program(
        a_program("""
            var q;
            if (q = String.prototype) { q.toUpperCase = function () { return 'P'; }; }
            console.log('a'.toUpperCase());
            """),
        prints('P'),
        Reading.COMMONJS,
    ),
    'comma in a test hands nothing': Program(
        a_program("""
            function f() { if ((String.prototype, true)) { return 'c'.toUpperCase(); } }
            console.log(f());
            """),
        prints('C'),
        Reading.COMMONJS,
    ),
    'logical in a while test': Program(
        a_program("""
            function f() { var i = 0, r = ''; while (String.prototype && i < 2) { r += 'w'.toUpperCase(); i++; } return r; }
            console.log(f());
            """),
        prints('WW'),
        Reading.COMMONJS,
    ),
    'a computed key in a test': Program(
        a_program("""
            var S = String;
            function f(k) { if (S[k]) { return 'ab'.split('').join('-'); } return 'no'; }
            console.log(f('prototype'), f('fromCodePoint'));
            """),
        prints('a-b a-b'),
        Reading.COMMONJS,
    ),
    'a test then a call hands it on': Program(
        a_program("""
            function patch(p) { p.toUpperCase = function () { return 'P'; }; }
            var v = String.prototype;
            if (v) { patch(v); }
            console.log('a'.toUpperCase());
            """),
        prints('P'),
        Reading.COMMONJS,
    ),
    'test then member write through same key': Program(
        a_program("""
            var S = String;
            function f(k) {
              if (S[k]) { S[k].toUpperCase = function () { return 'P'; }; }
              return 'ab'.toUpperCase();
            }
            console.log(f('prototype'));
            """),
        prints('P'),
        Reading.COMMONJS,
    ),
    'test then assign through same key': Program(
        a_program("""
            var S = String;
            function f(k) {
              if (S[k]) { Object.assign(S[k], { toUpperCase: function () { return 'Q'; } }); }
              return 'ab'.toUpperCase();
            }
            console.log(f('prototype'));
            """),
        prints('Q'),
        Reading.COMMONJS,
    ),
    'while test and assignment': Program(
        a_program("""
            var q;
            function f() {
              var n = 0;
              while (String.prototype && (q = String.prototype) && n < 1) {
                q.toUpperCase = function () { return 'W'; };
                n++;
              }
              return 'a'.toUpperCase();
            }
            console.log(f());
            """),
        prints('W'),
        Reading.COMMONJS,
    ),
    'for test alias': Program(
        a_program("""
            function f() {
              for (var p = String.prototype; p; p = null) { p.toUpperCase = function () { return 'F'; }; }
              return 'a'.toUpperCase();
            }
            console.log(f());
            """),
        prints('F'),
        Reading.COMMONJS,
    ),
    'conditional test and branch same value': Program(
        a_program("""
            function f(k) {
              var S = String;
              var p = S[k] ? S[k] : {};
              p.toUpperCase = function () { return 'C'; };
              return 'a'.toUpperCase();
            }
            console.log(f('prototype'));
            """),
        prints('C'),
        Reading.COMMONJS,
    ),
    'test value stored by logical assignment': Program(
        a_program("""
            var keep = null;
            function f(k) {
              var S = String;
              if (keep ??= S[k]) { keep.toUpperCase = function () { return 'L'; }; }
              return 'a'.toUpperCase();
            }
            console.log(f('prototype'));
            """),
        prints('L'),
        Reading.COMMONJS,
    ),
}

#: Programs of `AN_INTRINSIC_READ_AS_A_TEST` whose method of a string folds since the test hands
#: the prototype to nothing, mapped to the text the deobfuscation writes for each.
FOLDED_PAST_A_TEST: dict[str, str] = {
    'an if test of String.prototype': inspect.cleandoc(
        """
            function f() {
              if (String.prototype) {
                return 'AB';
              }
              return 'none';
            }
            console.log(f());
        """
    ),
    'conditional test': inspect.cleandoc(
        """
            function f() {
              var t = String.prototype ? 'y' : 'n';
              return t + 'Q';
            }
            console.log(f());
        """
    ),
    'comma in a test hands nothing': inspect.cleandoc(
        """
            function f() {
              if ((String.prototype, true)) {
                return 'C';
              }
            }
            console.log(f());
        """
    ),
    'logical in a while test': inspect.cleandoc(
        """
            function f() {
              var i = 0, r = '';
              while (String.prototype && i < 2) {
                r += 'W';
                i++;
              }
              return r;
            }
            console.log(f());
        """
    ),
    'a computed key in a test': inspect.cleandoc(
        """
            var S = String;
            function f(k) {
              if (S[k]) {
                return 'a-b';
              }
              return 'no';
            }
            console.log(f('prototype'), f('fromCodePoint'));
        """
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAnIntrinsicReadAsATest(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in AN_INTRINSIC_READ_AS_A_TEST.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in AN_INTRINSIC_READ_AS_A_TEST.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestAMethodOfAStringFoldsPastATestOfItsPrototype(TestBase):

    def test_each_program_reads_as_pinned(self):
        self.assertEqual(
            {
                label: deobfuscate_source(AN_INTRINSIC_READ_AS_A_TEST[label].text, execution=ExecutionModel.commonjs)
                for label in FOLDED_PAST_A_TEST
            },
            FOLDED_PAST_A_TEST,
        )
