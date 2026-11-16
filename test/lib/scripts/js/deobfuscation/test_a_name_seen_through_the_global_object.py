"""
SECURITY: Node runs every program here. Each is written by hand; never add one taken from a sample.
"""
from __future__ import annotations

import functools
import unittest

from test import TestBase, backlog, fastest_processor_time, processor_time_ratio, todo
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import (
    Program,
    Reading,
    a_program,
    folded,
    node_prints_what_each_program_pins,
    one_expected_failure_per_program,
    printed,
    prints,
)

from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.deobfuscation.unused import JsUnusedCodeRemoval
from refinery.lib.scripts.js.model import JsFunctionDeclaration
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

A_DECLARATION_SEEN_THROUGH_THE_GLOBAL_OBJECT: dict[str, Program] = {
    'a read through globalThis': Program(
        a_program("""
            var q = 1;
            console.log(globalThis.q, q + 1);
            """),
        prints('1 2'),
        Reading.SCRIPT,
    ),
    'a read through the this of the top level': Program(
        a_program("""
            var q = 1;
            console.log(this.q, q + 1);
            """),
        prints('1 2'),
        Reading.SCRIPT,
    ),
    'a read under a computed key': Program(
        a_program("""
            var q = 1;
            console.log(globalThis['q'], q + 1);
            """),
        prints('1 2'),
        Reading.SCRIPT,
    ),
    'a read through window': Program(
        a_program("""
            globalThis.window = globalThis;
            var q = 1;
            console.log(window.q, q + 1);
            """),
        prints('1 2'),
        Reading.SCRIPT,
    ),
    'a read through window alone': Program(
        a_program("""
            globalThis.window = globalThis;
            var q = 1;
            console.log(window.q);
            """),
        prints('1'),
        Reading.SCRIPT,
    ),
    'a write through window': Program(
        a_program("""
            globalThis.window = globalThis;
            var q = 1;
            window.q = 2;
            console.log(q);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
    'a read through globalThis before a read by name': Program(
        a_program("""
            var q = 1;
            console.log(globalThis.q);
            console.log(q);
            """),
        prints('1', '1'),
        Reading.SCRIPT,
    ),
    'a read through a name holding the object before a read by name': Program(
        a_program("""
            var q = 1;
            var w = globalThis;
            console.log(w.q);
            console.log(q);
            """),
        prints('1', '1'),
        Reading.SCRIPT,
    ),
    'a read through a name holding the object': Program(
        a_program("""
            var q = 1;
            var g = globalThis;
            console.log(g.q, q + 1);
            """),
        prints('1 2'),
        Reading.SCRIPT,
    ),
    'a read through globalThis inside a function': Program(
        a_program("""
            var q = 4;
            function f() { return globalThis.q; }
            console.log(f(), q);
            """),
        prints('4 4'),
        Reading.SCRIPT,
    ),
    'a read through globalThis of an expression read once by name': Program(
        a_program("""
            var p = 2;
            var q = p * 3;
            console.log(globalThis.q, q);
            """),
        prints('6 6'),
        Reading.SCRIPT,
    ),
    'an in test': Program(
        a_program("""
            var q = 1;
            console.log('q' in globalThis, q + 1);
            """),
        prints('true 2'),
        Reading.SCRIPT,
    ),
    'an in test over a sequence': Program(
        a_program("""
            var q = 1;
            console.log('q' in (0, globalThis), q);
            """),
        prints('true 1'),
        Reading.SCRIPT,
    ),
    'a for-in finding the name': Program(
        a_program("""
            var q = 1;
            var found = false;
            for (var k in globalThis) { if (k === 'q') found = true; }
            console.log(found, q + 1);
            """),
        prints('true 2'),
        Reading.SCRIPT,
    ),
    'a for-in over a sequence': Program(
        a_program("""
            var q = 1;
            for (var k in (0, globalThis)) { if (k === 'q') console.log('saw'); }
            console.log(q);
            """),
        prints('saw', '1'),
        Reading.SCRIPT,
    ),
    'a listing finding the name': Program(
        a_program("""
            var q = 1;
            console.log(Object.keys(globalThis).indexOf('q') >= 0, q + 1);
            """),
        prints('true 2'),
        Reading.SCRIPT,
    ),
    'a listing finding a function declaration': Program(
        a_program("""
            function f() { return 1; }
            console.log(Object.keys(globalThis).indexOf('f') >= 0, f() + 1);
            """),
        prints('true 2'),
        Reading.SCRIPT,
    ),
    'a listing after the global object is stored as globalThis': Program(
        a_program("""
            globalThis.window = globalThis;
            window.globalThis = window;
            var q = 1;
            console.log(Object.keys(globalThis).indexOf('q') >= 0, q + 1);
            """),
        prints('true 2'),
        Reading.SCRIPT,
    ),
    'a function only globalThis reads': Program(
        a_program("""
            function f() { return 1; }
            console.log(typeof globalThis.f);
            """),
        prints('function'),
        Reading.SCRIPT,
    ),
    'a function only an in test sees': Program(
        a_program("""
            function f() { return 1; }
            console.log('f' in globalThis);
            """),
        prints('true'),
        Reading.SCRIPT,
    ),
    'a function only a listing sees': Program(
        a_program("""
            function f() { return 1; }
            console.log(Object.keys(globalThis).indexOf('f') >= 0);
            """),
        prints('true'),
        Reading.SCRIPT,
    ),
    'a function only a for-in sees': Program(
        a_program("""
            function f() { return 1; }
            var s = '';
            for (var k in globalThis) if (k === 'f') s = k;
            console.log(s);
            """),
        prints('f'),
        Reading.SCRIPT,
    ),
    'a function only an in test in another function sees': Program(
        a_program("""
            function f() { return 1; }
            function seen() { return 'f' in globalThis; }
            console.log(seen());
            """),
        prints('true'),
        Reading.SCRIPT,
    ),
    'a function only an in test of a parameter sees': Program(
        a_program("""
            function f() { return 1; }
            function seen(k) { return k in globalThis; }
            console.log(seen('f'));
            """),
        prints('true'),
        Reading.SCRIPT,
    ),
    'a var one function writes, an in test in another': Program(
        a_program("""
            var q;
            function f() { q = 1; return q; }
            function seen() { return 'q' in globalThis; }
            console.log(f(), seen());
            """),
        prints('1 true'),
        Reading.SCRIPT,
    ),
    'a var one function writes, a for-in in another': Program(
        a_program("""
            var q;
            function f() { q = 1; return q; }
            function seen() { for (var k in globalThis) if (k === 'q') return true; return false; }
            console.log(f(), seen());
            """),
        prints('1 true'),
        Reading.SCRIPT,
    ),
    'a var one function writes, a listing in another': Program(
        a_program("""
            var q;
            function f() { q = 1; return q; }
            function seen() { return Object.keys(globalThis).indexOf('q') >= 0; }
            console.log(f(), seen());
            """),
        prints('1 true'),
        Reading.SCRIPT,
    ),
    'a var one function writes and lists': Program(
        a_program("""
            var q;
            function f() { q = 1; return [q, Object.keys(globalThis).indexOf('q') >= 0]; }
            console.log(f());
            """),
        prints('[ 1, true ]'),
        Reading.SCRIPT,
    ),
    'a name only a function writes, an in test in another': Program(
        a_program("""
            function f() { q = 1; return q; }
            function seen() { return 'q' in globalThis; }
            console.log(f(), seen());
            """),
        prints('1 true'),
        Reading.SCRIPT,
    ),
    'a read through globalThis after it is stored as itself': Program(
        a_program("""
            globalThis.window = globalThis;
            window.globalThis = window;
            var q = 1;
            function f() { return globalThis.q; }
            console.log(f());
            """),
        prints('1'),
        Reading.SCRIPT,
    ),
    'a write through globalThis after it is stored as itself': Program(
        a_program("""
            globalThis.window = globalThis;
            window.globalThis = window;
            var q = 1;
            globalThis.q = 5;
            console.log(q);
            """),
        prints('5'),
        Reading.SCRIPT,
    ),
    'a hand-over to an unknown call after it is stored as itself': Program(
        a_program("""
            globalThis.window = globalThis;
            window.globalThis = window;
            var q = 1;
            var o = { fn: function (x) { return x.q; } };
            console.log(o.fn(globalThis));
            """),
        prints('1'),
        Reading.SCRIPT,
    ),
    'an in test of a parameter after it is stored as itself': Program(
        a_program("""
            globalThis.window = globalThis;
            window.globalThis = window;
            var q = 1;
            function f(k) { return k in globalThis; }
            console.log(f('q'), q + 1);
            """),
        prints('true 2'),
        Reading.SCRIPT,
    ),
    'a listing beside a store under a key only the run knows': Program(
        a_program("""
            var q = 1;
            var k = 'x' + Math.floor(Math.random() * 0);
            globalThis[k] = 0;
            console.log(Object.keys(globalThis).indexOf('q') >= 0, q + 1);
            """),
        prints('true 2'),
        Reading.SCRIPT,
    ),
    'an in test beside a store under a key only the run knows': Program(
        a_program("""
            var q = 1;
            var k = 'x' + Math.floor(Math.random() * 0);
            globalThis[k] = 0;
            console.log('q' in globalThis, q + 1);
            """),
        prints('true 2'),
        Reading.SCRIPT,
    ),
    'a read through globalThis beside a store under a key only the run knows': Program(
        a_program("""
            var q = 1;
            var k = 'x' + Math.floor(Math.random() * 0);
            globalThis[k] = 0;
            console.log(globalThis.q, q + 1);
            """),
        prints('1 2'),
        Reading.SCRIPT,
    ),
    'a for-in beside a store under a key only the run knows': Program(
        a_program("""
            var q = 1;
            var k = 'x' + Math.floor(Math.random() * 0);
            globalThis[k] = 0;
            var s = '';
            for (var n in globalThis) if (n === 'q') s = n;
            console.log(s, q + 1);
            """),
        prints('q 2'),
        Reading.SCRIPT,
    ),
}

A_LISTING_OF_A_BUILTIN_THE_PROGRAM_REPLACES: dict[str, Program] = {
    'a direct write': Program(
        a_program("""
            var q = 1;
            Object.getOwnPropertyNames = function (g) { g.q = 2; };
            Object.getOwnPropertyNames(globalThis);
            console.log(q + 1);
            """),
        prints('3'),
        Reading.SCRIPT,
    ),
    'a write under a computed key': Program(
        a_program("""
            var q = 1;
            Object['getOwnPropertyNames'] = function (g) { g.q = 2; };
            Object.getOwnPropertyNames(globalThis);
            console.log(q + 1);
            """),
        prints('3'),
        Reading.SCRIPT,
    ),
    'a write through a name holding the builtin': Program(
        a_program("""
            var q = 1;
            var O = Object;
            O.getOwnPropertyNames = function (g) { g.q = 2; };
            Object.getOwnPropertyNames(globalThis);
            console.log(q + 1);
            """),
        prints('3'),
        Reading.SCRIPT,
    ),
    'a write of the builtin on the global object': Program(
        a_program("""
            var q = 1;
            globalThis.Object = { getOwnPropertyNames: function (g) { g.q = 2; } };
            Object.getOwnPropertyNames(globalThis);
            console.log(q + 1);
            """),
        prints('3'),
        Reading.SCRIPT,
    ),
    'a delete': Program(
        a_program("""
            var q = 1;
            delete Object.getOwnPropertyNames;
            try { Object.getOwnPropertyNames(globalThis); } catch (e) { q = 5; }
            console.log(q + 1);
            """),
        prints('6'),
        Reading.SCRIPT,
    ),
    'a descriptor installed': Program(
        a_program("""
            var q = 1;
            Object.defineProperty(Object, 'getOwnPropertyNames', { value: function (g) { g.q = 2; } });
            Object.getOwnPropertyNames(globalThis);
            console.log(q + 1);
            """),
        prints('3'),
        Reading.SCRIPT,
    ),
    'the builtin handed to a call': Program(
        a_program("""
            var q = 1;
            function p(o) { o.getOwnPropertyNames = function (g) { g.q = 2; }; }
            p(Object);
            Object.getOwnPropertyNames(globalThis);
            console.log(q + 1);
            """),
        prints('3'),
        Reading.SCRIPT,
    ),
    'a local of the name': Program(
        a_program("""
            var q = 1;
            function f() {
              var Object = { getOwnPropertyNames: function (g) { g.q = 2; } };
              Object.getOwnPropertyNames(globalThis);
            }
            f();
            console.log(q + 1);
            """),
        prints('3'),
        Reading.SCRIPT,
    ),
    'an assign onto the builtin': Program(
        a_program("""
            var q = 1;
            Object.assign(Object, { getOwnPropertyNames: function (g) { g.q = 2; } });
            Object.getOwnPropertyNames(globalThis);
            console.log(q + 1);
            """),
        prints('3'),
        Reading.SCRIPT,
    ),
    'a write the program evaluates from text': Program(
        a_program("""
            var q = 1;
            var payload = atob('T2JqZWN0LmdldE93blByb3BlcnR5TmFtZXMgPSBmdW5jdGlvbiAoZykgeyBnLnEgPSAyOyB9Ow==');
            eval(payload);
            Object.getOwnPropertyNames(globalThis);
            console.log(q + 1);
            """),
        prints('3'),
        Reading.SCRIPT,
    ),
    'the builtin read under a computed key of the global object': Program(
        a_program("""
            var q = 1;
            var O = globalThis['Object'];
            O.getOwnPropertyNames = function (g) { g.q = 2; };
            Object.getOwnPropertyNames(globalThis);
            console.log(q + 1);
            """),
        prints('3'),
        Reading.SCRIPT,
    ),
}

A_SPELLING_OF_THE_GLOBAL_OBJECT_GIVEN_ANOTHER_OBJECT: dict[str, Program] = {
    'globalThis assigned an object, then a write through it': Program(
        a_program("""
            globalThis = { q: 99 };
            var q = 1;
            globalThis.q = 5;
            console.log(q, globalThis.q);
            """),
        prints('1 5'),
        Reading.SCRIPT,
    ),
    'globalThis assigned an object, then a read through it': Program(
        a_program("""
            globalThis = { q: 99 };
            var q = 1;
            console.log(globalThis.q + 1, q + 1);
            """),
        prints('100 2'),
        Reading.SCRIPT,
    ),
    'globalThis stored as an object on window, then a write through it': Program(
        a_program("""
            globalThis.window = globalThis;
            window.globalThis = { q: 99 };
            var q = 1;
            globalThis.q = 5;
            console.log(q, globalThis.q);
            """),
        prints('1 5'),
        Reading.SCRIPT,
    ),
    'globalThis assigned an object inside a function, then a write through it': Program(
        a_program("""
            function r() { globalThis = { q: 99 }; }
            r();
            var q = 1;
            globalThis.q = 5;
            console.log(q, globalThis.q);
            """),
        prints('1 5'),
        Reading.SCRIPT,
    ),
    'window assigned an object, then a write through it': Program(
        a_program("""
            globalThis.window = globalThis;
            window = { q: 99 };
            var q = 1;
            window.q = 5;
            console.log(q, window.q);
            """),
        prints('1 5'),
        Reading.SCRIPT,
    ),
    'globalThis assigned an object, then handed to a call that writes': Program(
        a_program("""
            globalThis = { q: 99 };
            var q = 1;
            function w(o) { o.q = 5; }
            w(globalThis);
            console.log(q);
            """),
        prints('1'),
        Reading.SCRIPT,
    ),
}

AN_ESCAPE_OF_THE_GLOBAL_OBJECT_GIVING_A_WRONG_VALUE: dict[str, Program] = {
    'a write through an object holding it': Program(
        a_program("""
            var q = 1;
            var o = { g: globalThis };
            o.g.q = 2;
            console.log(q);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
    'a write through an array holding it': Program(
        a_program("""
            var q = 1;
            var a = [globalThis];
            a[0].q = 2;
            console.log(q);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
    'a write through a function returning it': Program(
        a_program("""
            var q = 1;
            function get() { return globalThis; }
            get().q = 2;
            console.log(q);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
    'a read through a function returning it': Program(
        a_program("""
            var q = 1;
            function get() { return globalThis; }
            console.log(get().q, q + 1);
            """),
        prints('1 2'),
        Reading.SCRIPT,
    ),
    'an assign onto the this of a function': Program(
        a_program("""
            var q = 1;
            function set() { Object.assign(this, { q: 2 }); }
            set();
            console.log(q);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
}

AN_ESCAPE_OF_THE_GLOBAL_OBJECT_SEEING_A_NAME: dict[str, Program] = {
    'a spread of it': Program(
        a_program("""
            var q = 1;
            var copy = { ...globalThis };
            console.log(copy.q, q + 1);
            """),
        prints('1 2'),
        Reading.SCRIPT,
    ),
    'a listing of the this of a function': Program(
        a_program("""
            var q = 1;
            function names() { return Object.keys(this); }
            console.log(names().indexOf('q') >= 0, q + 1);
            """),
        prints('true 2'),
        Reading.SCRIPT,
    ),
    'a hasOwnProperty on it': Program(
        a_program("""
            var q = 1;
            console.log(globalThis.hasOwnProperty('q'), q + 1);
            """),
        prints('true 2'),
        Reading.SCRIPT,
    ),
    'a destructuring of it': Program(
        a_program("""
            var q = 1;
            var { q: x } = globalThis;
            console.log(x);
            """),
        prints('1'),
        Reading.SCRIPT,
    ),
}

EVERY_PROGRAM = {
    **A_DECLARATION_SEEN_THROUGH_THE_GLOBAL_OBJECT,
    **A_LISTING_OF_A_BUILTIN_THE_PROGRAM_REPLACES,
    **A_SPELLING_OF_THE_GLOBAL_OBJECT_GIVEN_ANOTHER_OBJECT,
    **AN_ESCAPE_OF_THE_GLOBAL_OBJECT_GIVING_A_WRONG_VALUE,
    **AN_ESCAPE_OF_THE_GLOBAL_OBJECT_SEEING_A_NAME,
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADeclarationSeenThroughTheGlobalObjectStillPrintsWhatItPrints(TestBase):

    def test_node_prints_what_each_program_pins(self):
        node_prints_what_each_program_pins(self, EVERY_PROGRAM)

    def test_each_program_seen_through_the_global_object_still_prints_it(self):
        for label, row in A_DECLARATION_SEEN_THROUGH_THE_GLOBAL_OBJECT.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())

    def test_each_listing_of_a_replaced_builtin_still_prints_it(self):
        for label, row in A_LISTING_OF_A_BUILTIN_THE_PROGRAM_REPLACES.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())

    def test_each_spelling_given_another_object_still_prints_it(self):
        for label, row in A_SPELLING_OF_THE_GLOBAL_OBJECT_GIVEN_ANOTHER_OBJECT.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(AN_ESCAPE_OF_THE_GLOBAL_OBJECT_GIVING_A_WRONG_VALUE, todo)
class TestAWriteThroughAnEscapedGlobalObjectReachesTheDeclaration(TestBase):
    pass


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(AN_ESCAPE_OF_THE_GLOBAL_OBJECT_SEEING_A_NAME, backlog)
class TestAReadThroughAnEscapedGlobalObjectSeesTheDeclaration(TestBase):
    pass


class TestAUseSeeingWhichNamesExistKeepsTheDeclarationAndLetsItsReadsFold(TestBase):

    def test_each_use_keeps_the_declaration_and_folds_the_read(self):
        for label, use in {
            'a listing of the own names'   : 'Object.getOwnPropertyNames(globalThis);',
            'a listing of the keys'        : 'Object.keys(globalThis);',
            'an in test'                   : "'q' in globalThis;",
            'a for-in'                     : 'for (var k in globalThis) {}',
        }.items():
            with self.subTest(label):
                self.assertEqual(
                    folded(F'var q = 1;\n{use}\nconsole.log(q + 1);\n'),
                    printed(F'var q = 1;\n{use}\nconsole.log(2);\n'),
                )

    def test_a_listing_beside_a_write_of_another_key_of_the_builtin_folds_the_read(self):
        self.assertEqual(
            folded('var q = 1;\nObject.foo = 1;\nObject.getOwnPropertyNames(globalThis);\nconsole.log(q + 1);\n'),
            printed('var q = 1;\nObject.foo = 1;\nObject.getOwnPropertyNames(globalThis);\nconsole.log(2);\n'),
        )

    def test_a_listing_keeps_a_declaration_after_it(self):
        source = "console.log(Object.getOwnPropertyNames(globalThis).indexOf('q') >= 0);\nvar q = 1;\n"
        self.assertEqual(folded(source), printed(source))

    def test_a_listing_keeps_a_function_nothing_calls(self):
        source = 'Object.getOwnPropertyNames(globalThis);\nfunction f() { return 1; }\n'
        self.assertEqual(folded(source), printed(source))

    def test_a_listing_does_not_keep_a_lexical_declaration(self):
        self.assertEqual(
            folded('let q = 1;\nObject.getOwnPropertyNames(globalThis);\nconsole.log(q + 1);\n'),
            printed('Object.getOwnPropertyNames(globalThis);\nconsole.log(2);\n'),
        )

    def test_a_listing_of_a_replaced_builtin_folds_nothing(self):
        source = a_program("""
            var q = 1;
            Object.getOwnPropertyNames = function (g) { g.q = 2; };
            Object.getOwnPropertyNames(globalThis);
            console.log(q + 1);
            """)
        self.assertEqual(folded(source), printed(source))


class TestAListingJudgedWhileTheModelIsBuiltLeavesNoAnswerOfThatJudgment(TestBase):

    def test_no_function_is_taken_for_one_only_shown_calls_reach(self):
        for label, source in {
            'a function called once': a_program("""
                function h(a) { return a + 1; }
                var x = h(1);
                Object.getOwnPropertyNames(globalThis);
                console.log(x);
                """),
            'a function returning a builtin': a_program("""
                function h() { return Math; }
                var m = h();
                Object.getOwnPropertyNames(globalThis);
                m.floor = function () { return 7; };
                console.log(Math.floor(1.5));
                """),
            'a function handed a function': a_program("""
                function apply(f, v) { return f(v); }
                console.log(apply(function (s) { return s.toUpperCase(); }, 'a'));
                Object.keys(globalThis);
                """),
        }.items():
            with self.subTest(label):
                ast = JsParser(source).parse()
                model = build_semantic_model(ast, trust_eval=False)
                function = next(node for node in ast.body if isinstance(node, JsFunctionDeclaration))
                self.assertEqual(model.reached_only_by_shown_calls(function), False)


class TestUnusedCodeRemovalTakesTimeThatGrowsWithTheProgramWhereAGuardSeesTheGlobals(TestBase):

    @staticmethod
    def _cost_ratio(small: str, large: str) -> tuple[float, str]:
        small_asts = [JsParser(small).parse() for _ in range(3)]
        large_asts = [JsParser(large).parse() for _ in range(3)]
        large_time = fastest_processor_time(functools.partial(JsUnusedCodeRemoval().visit, ast) for ast in large_asts)
        small_time = fastest_processor_time(functools.partial(JsUnusedCodeRemoval().visit, ast) for ast in small_asts)
        return processor_time_ratio(large_time, small_time), JsSynthesizer().convert(large_asts[0])

    @staticmethod
    def _guarded(names: int, sites: int) -> str:
        lines = ['var w = window || {};']
        lines.extend(F'var v{i} = {i};' for i in range(names))
        lines.append('function scan(k) {')
        lines.append('  var n = 0;')
        lines.extend(F'  for (var key in w) {{ if (key === k) n += v{i % names}; }} n += k in w;' for i in range(sites))
        lines.append('  return n;')
        lines.append('}')
        lines.append("console.log(scan('v0'));")
        return '\n'.join(lines)

    def test_names_beside_a_few_uses_seeing_them_are_kept_in_time_that_grows_with_the_program(self):
        small, large = self._guarded(1000, 16), self._guarded(8000, 16)
        ratio, output = self._cost_ratio(small, large)
        self.assertEqual(output, JsSynthesizer().convert(JsParser(large).parse()))
        self.assertLess(ratio, 2 * len(large) / len(small))

    def test_uses_seeing_a_few_names_are_kept_in_time_that_grows_with_the_program(self):
        small, large = self._guarded(16, 1000), self._guarded(16, 8000)
        ratio, output = self._cost_ratio(small, large)
        self.assertEqual(output, JsSynthesizer().convert(JsParser(large).parse()))
        self.assertLess(ratio, 2 * len(large) / len(small))
