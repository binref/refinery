from __future__ import annotations

import inspect
import unittest

from test import TestBase, lines_executed, opportunity
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import (
    Program,
    Reading,
    a_program,
    before_and_after,
    each_program_still_prints,
    prints,
)

from refinery.lib.scripts.js.analysis import intrinsics
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.analysis.intrinsics import build_intrinsic_writes
from refinery.lib.scripts.js.analysis.model import build_semantic_model
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

    def test_a_root_handed_to_a_function_storing_through_a_pattern_or_a_loop_head_is_written(self):
        for source in (
            'function patch(m) { [m.floor] = [f]; } patch(Math);',
            'function patch(m) { ({ k: m.floor } = { k: f }); } patch(Math);',
            'function patch(m) { for (m.floor of [f]); } patch(Math);',
            'function patch(m) { for (m.floor in o); } patch(Math);',
        ):
            with self.subTest(source=source):
                self.assertIn('Math', ModelCache(JsParser(source).parse()).intrinsic_writes.names)


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

    def test_each_program_still_prints_what_the_replaced_method_returns(self):
        rows = A_METHOD_REPLACED_THROUGH_A_FORM_THAT_FORWARDS_ITS_VALUE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestTheTestOfABranchOrALoopHandsItsValueToNothing(TestBase):
    """
    A test converts its value to a boolean, which calls no method of an object, so the value it
    reads reaches no code that could write a property on it.
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

CLEANED_PAST_A_TEST: dict[str, str] = {
    'an if test of String.prototype': "console.log('AB');",
    'conditional test': "console.log('yQ');",
    'comma in a test hands nothing': "console.log('C');",
    'logical in a while test': "console.log('WW');",
    'a computed key in a test': "console.log('a-b', 'a-b');",
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

    @staticmethod
    def _deobfuscated(label: str) -> str:
        text = AN_INTRINSIC_READ_AS_A_TEST[label].text
        return deobfuscate_source(text, execution=ExecutionModel.commonjs)

    def test_each_method_folds_and_the_program_reads_as_pinned_or_clean(self):
        for label, folded in FOLDED_PAST_A_TEST.items():
            with self.subTest(label=label):
                self.assertIn(self._deobfuscated(label), (folded, CLEANED_PAST_A_TEST[label]))

    @opportunity
    def test_each_program_reads_as_the_clean_program(self):
        self.assertEqual(
            {label: self._deobfuscated(label) for label in CLEANED_PAST_A_TEST},
            CLEANED_PAST_A_TEST,
        )


class TestABuiltInReadAsAPropertyIsJudgedWhereTheAccessStands(TestBase):

    @staticmethod
    def _written(source: str) -> frozenset[str]:
        return ModelCache(JsParser(source).parse()).intrinsic_writes.names

    def test_a_built_in_read_off_the_global_object_and_called_or_read_from_is_not_written(self):
        for source in (
            'globalThis.String(1);',
            'globalThis.String.fromCharCode(65);',
            "globalThis['String'](1);",
            'var g = globalThis; g.Array.isArray(x);',
            'new globalThis.Array(3);',
        ):
            with self.subTest(source=source):
                self.assertFalse(self._written(source) & {'String', 'Array'})

    def test_a_built_in_read_as_a_property_and_handed_on_is_written(self):
        for source in (
            "var s = {}; s.x = globalThis['String']; s.x.fromCharCode = f;",
            'var s = {}; s.x = globalThis.String; s.x.fromCharCode = f;',
            'f(globalThis.String);',
            'var s = {}; s.x = o.String; s.x.fromCharCode = f;',
            'globalThis.String.prototype.x = 1;',
        ):
            with self.subTest(source=source):
                self.assertIn('String', self._written(source))

    @opportunity
    def test_a_built_in_read_as_a_property_and_stored_where_nothing_writes_it_is_not_written(self):
        for source in (
            "var s = {}; s.x = globalThis['String'];",
            'var s = {}; s.x = globalThis.String;',
            'var s = {}; s.x = o.String;',
        ):
            with self.subTest(source=source):
                self.assertNotIn('String', self._written(source))


class TestABuiltInReplacedThroughAKeyedMemberOfTheGlobalObjectIsWritten(TestBase):

    def test_a_write_through_a_keyed_member_of_the_global_object_writes_the_built_in(self):
        written = {
            source: name in ModelCache(JsParser(source).parse()).intrinsic_writes.names
            for source, name in (
                ("globalThis['Date'].now = function () { return 5e12; };", 'Date'),
                ("globalThis['Math'].floor = function () { return 42; };", 'Math'),
            )
        }
        self.assertEqual(written, {source: True for source in written})


class TestABuiltInReturnedIsJudgedWhereEachCallStands(TestBase):

    @staticmethod
    def _written(source: str) -> frozenset[str]:
        return ModelCache(JsParser(source).parse()).intrinsic_writes.names

    def test_a_built_in_returned_to_calls_that_read_from_it_is_not_written(self):
        for source in (
            "function g(k) { switch (k) { case 'a': return String; } } g('a').fromCharCode(65);",
            'function g() { return String; } g()(1);',
            'var g = () => String; g().fromCharCode(65);',
            'function g() { return globalThis.String; } new (g())(1);',
            'function g() { return String; } if (g()) { f(); }',
            'function g() { return String; } function h() { return g(); } h().fromCharCode(65);',
        ):
            with self.subTest(source=source):
                self.assertNotIn('String', self._written(source))

    def test_a_built_in_returned_to_a_call_handing_it_on_or_writing_through_it_is_written(self):
        for source in (
            'function g() { return String; } var s = g(); s.fromCharCode = f;',
            'function g() { return String; } g().prototype.x = 1;',
            'function g() { return String; } g().fromCharCode = f;',
            'function g() { return String; } (0, g()).fromCharCode = f;',
            'function g() { return String; } delete g().fromCharCode;',
            "function g() { return String; } g().__defineGetter__('x', f);",
            'function g() { return String; } h(g());',
            'function g() { return String; } function h() { return g(); } h().prototype.x = 1;',
            'var g = () => String; g().prototype.x = 1;',
        ):
            with self.subTest(source=source):
                self.assertIn('String', self._written(source))

    def test_a_built_in_returned_where_a_call_may_come_another_way_is_written(self):
        for source in (
            'function g() { return String; } h(g);',
            'var o = { g() { return String; } }; o.g().fromCharCode(65); h(o);',
            'async function g() { return String; } g().then(function (S) { S.fromCharCode = f; });',
            'function* g() { return String; } g().next().value.fromCharCode = f;',
        ):
            with self.subTest(source=source):
                self.assertIn('String', self._written(source))

    @opportunity
    def test_a_built_in_returned_where_nothing_writes_through_it_is_not_written(self):
        for source in (
            'function g() { return String; } var s = g();',
            'var o = { g() { return String; } }; o.g().fromCharCode(65);',
            'async function g() { return String; } g();',
            'function* g() { return String; } g().next();',
        ):
            with self.subTest(source=source):
                self.assertNotIn('String', self._written(source))


A_BUILT_IN_REACHED_THROUGH_A_PROPERTY_OR_A_RETURN: dict[str, Program] = {
    'read off the global object and stored': Program(
        a_program("""
            var s = {};
            s.x = globalThis['String'];
            s.x.fromCharCode = function () { return 'B'; };
            console.log(String.fromCharCode(65));
            """),
        prints('B'),
        Reading.COMMONJS,
    ),
    'returned and written through by the caller': Program(
        a_program("""
            function g(k) { switch (k) { case 'a': return String; } return undefined; }
            g('a').fromCharCode = function () { return 'B'; };
            console.log(String.fromCharCode(65));
            """),
        prints('B'),
        Reading.COMMONJS,
    ),
    'returned through a second function and written through': Program(
        a_program("""
            function g() { return String; }
            function h() { return g(); }
            h().fromCharCode = function () { return 'B'; };
            console.log(String.fromCharCode(65));
            """),
        prints('B'),
        Reading.COMMONJS,
    ),
    'returned and read from by the caller': Program(
        a_program("""
            function g(k) { switch (k) { case 'a': return String; } return undefined; }
            console.log(g('a').fromCharCode(65), String.fromCharCode(66));
            """),
        prints('A B'),
        Reading.COMMONJS,
    ),
    'read off the global object and called': Program(
        a_program("""
            console.log(globalThis.String(1) + globalThis.String.fromCharCode(65));
            """),
        prints('1A'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutABuiltInReachedThroughAPropertyOrAReturn(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in A_BUILT_IN_REACHED_THROUGH_A_PROPERTY_OR_A_RETURN.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in A_BUILT_IN_REACHED_THROUGH_A_PROPERTY_OR_A_RETURN.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestABuiltInReturnedToACallThatReadsFromItStillFolds(TestBase):

    def test_the_method_of_the_built_in_folds_beside_it(self):
        row = A_BUILT_IN_REACHED_THROUGH_A_PROPERTY_OR_A_RETURN['returned and read from by the caller']
        self.assertIn("'B'", deobfuscate_source(row.text, execution=ExecutionModel.commonjs))


#: Each call stores `5` at index 0 of `Array.prototype`, which every array inherits, so `[][0]` then
#: reads `5`.
A_PROTOTYPE_WRITTEN_BY_ITS_OWN_METHOD = (
    'globalThis.Array.prototype.push(5);',
    "globalThis['Array'].prototype.unshift(5);",
    'var g = globalThis; g.Array.prototype.splice(0, 0, 5);',
    '(globalThis.Array.prototype.push)(5);',
    'function g() { return Array; } g().prototype.push(5);',
    'function g() { return Array.prototype; } g().push(5);',
    'function id(o) { return o; } id(Array.prototype).push(5);',
)


class TestAMethodWritingItsReceiverCalledThroughAChainWritesTheBuiltIn(TestBase):

    def test_the_scan_records_the_built_in_the_chain_holds_as_written(self):
        for source in A_PROTOTYPE_WRITTEN_BY_ITS_OWN_METHOD:
            with self.subTest(source=source):
                self.assertIn('Array', ModelCache(JsParser(source).parse()).intrinsic_writes.names)

    def test_a_read_of_the_element_it_stores_is_kept_or_folded_to_it(self):
        for source in A_PROTOTYPE_WRITTEN_BY_ITS_OWN_METHOD:
            with self.subTest(source=source):
                self.assertRegex(
                    deobfuscate_source(F'{source} console.log([][0]);'),
                    r'console\.log\((\[\]\[0\]|5)\);',
                )

    @opportunity
    def test_a_read_of_the_element_it_stores_folds_to_it(self):
        for source in A_PROTOTYPE_WRITTEN_BY_ITS_OWN_METHOD:
            with self.subTest(source=source):
                deobfuscated = deobfuscate_source(F'{source} console.log([][0]);')
                self.assertIn('console.log(5);', deobfuscated)


class TestAPropertyNamedLikeAParameterIsNoReadOfIt(TestBase):

    def test_a_built_in_handed_to_a_function_reading_only_such_a_property_is_not_written(self):
        source = 'function get(data) { return data.data; } get(Math);'
        self.assertNotIn('Math', ModelCache(JsParser(source).parse()).intrinsic_writes.names)


class TestTheScanDecidesEachCalleeOnce(TestBase):

    @staticmethod
    def _work(argument: str):
        def work(count: int) -> int:
            calls = '\n'.join(F's += id({argument}) | 0;' for _ in range(count))
            source = F'function id(x) {{ return x; }}\nvar a = [1], s = 0, i = 0;\n{calls}'
            model = build_semantic_model(JsParser(source).parse())
            return lines_executed(lambda: build_intrinsic_writes(model), intrinsics)
        return work

    def test_the_work_for_a_built_in_handed_to_each_call_grows_linearly(self):
        self.assertWorkGrowsLinearly(self._work('Math'), 100)

    def test_the_work_for_a_value_read_under_a_key_not_known_handed_to_each_call_grows_linearly(self):
        self.assertWorkGrowsLinearly(self._work('a[i]'), 100)
