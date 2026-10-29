"""
A store of `undefined` into a `var` that holds `undefined` already, which
`refinery.lib.scripts.js.deobfuscation.unused.JsUnusedCodeRemoval` removes where every other way a
value reaches the `var` runs after the store. Each program is written by hand, and each row says
what Node prints for it run as a CommonJS file.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    module_graph_behavior,
    node_executable,
)
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints

from refinery.lib.scripts.js.options import ExecutionModel
from refinery.units.scripting.djs import djs


def deobfuscated_by_the_unit(source: str) -> str:
    """
    The text `refinery.djs` writes for *source* under its default reading of a CommonJS file for
    Node, which trusts the code a direct `eval` runs.
    """
    return source.encode('utf8') | djs.assemble('-c', '-e', 'node') | str


#: Programs storing `undefined` into a `var`, mapped to what Node prints for each run as a CommonJS
#: file: the store before or after other values reach the `var` through a store, a closure, a call,
#: a loop, a `with` body, `eval`, a function declaration Annex B copies in, `arguments`, a parameter
#: of the same name, a `for-in` or `for-of` head, a destructuring declarator, a class field, and the
#: store spelled `void 0`.
STORES_OF_UNDEFINED: dict[str, Program] = {
    'the shape of the corpus': Program(
        a_program("""
            var lib = function () { return { k: 1 }; }(), SC;
            SC = undefined;
            (function () {
              var table = ['a', 'b'];
              SC = function (index) { return table[index]; };
            })();
            console.log(SC(0), SC(1));
            """),
        prints('a b'),
        Reading.COMMONJS,
    ),
    'store in a loop': Program(
        a_program("""
            function f(n) {
              var x, out = [];
              for (var i = 0; i < n; i++) {
                out.push(x);
                x = undefined;
                x = i;
              }
              return out;
            }
            console.log(f(3));
            """),
        prints('[ undefined, 0, 1 ]'),
        Reading.COMMONJS,
    ),
    'closure called before the store': Program(
        a_program("""
            function f() {
              var x;
              function g() { x = 5; }
              g();
              x = undefined;
              return x;
            }
            console.log(f());
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'closure called after the store': Program(
        a_program("""
            function f() {
              var x;
              x = undefined;
              function g() { x = 5; }
              g();
              return x;
            }
            console.log(f());
            """),
        prints('5'),
        Reading.COMMONJS,
    ),
    'a var at the top of the file': Program(
        a_program("""
            var SC;
            SC = undefined;
            SC = function (i) { return i + 1; };
            console.log(SC(1));
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'a let': Program(
        a_program("""
            function f() {
              let x;
              x = undefined;
              x = function () { return 1; };
              return x();
            }
            console.log(f());
            """),
        prints('1'),
        Reading.COMMONJS,
    ),
    'also a parameter': Program(
        a_program("""
            function f(x) {
              var x;
              x = undefined;
              return x;
            }
            console.log(f(7));
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'var arguments': Program(
        a_program("""
            function f() {
              var arguments;
              arguments = undefined;
              return typeof arguments;
            }
            console.log(f(1, 2));
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'store inside with': Program(
        a_program("""
            function f(o) {
              var x;
              with (o) { x = undefined; }
              return [x, o.x];
            }
            console.log(f({ x: 3 }));
            """),
        prints('[ undefined, undefined ]'),
        Reading.COMMONJS,
    ),
    'with writes before the store': Program(
        a_program("""
            function f(o) {
              var x;
              with (o) { x = 5; }
              x = undefined;
              return x;
            }
            console.log(f({}));
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'direct eval before the store': Program(
        a_program("""
            function f(s) {
              var x;
              eval(s);
              x = undefined;
              return x;
            }
            console.log(f('x = 5'));
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'annex b copy before the store': Program(
        a_program("""
            function f() {
              var x;
              { function x() {} }
              x = undefined;
              return typeof x;
            }
            console.log(f());
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'annex b copy after the store': Program(
        a_program("""
            function f() {
              var x;
              x = undefined;
              { function x() {} }
              return typeof x;
            }
            console.log(f());
            """),
        prints('function'),
        Reading.COMMONJS,
    ),
    'shadowed undefined': Program(
        a_program("""
            function f(undefined) {
              var x;
              x = undefined;
              return x;
            }
            console.log(f(4));
            """),
        prints('4'),
        Reading.COMMONJS,
    ),
    'hoisted function called before the store at file level': Program(
        a_program("""
            var x;
            g();
            x = undefined;
            function g() { x = 1; }
            console.log(x);
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'class static field writes before the store': Program(
        a_program("""
            function f() {
              var x;
              class C { static y = (x = 5); }
              x = undefined;
              return [x, C.y];
            }
            console.log(f());
            """),
        prints('[ undefined, 5 ]'),
        Reading.COMMONJS,
    ),
    'closure store in inner function': Program(
        a_program("""
            function outer() {
              var x;
              function inner() { x = undefined; }
              x = 5;
              inner();
              return x;
            }
            console.log(outer());
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'a store of void 0': Program(
        a_program("""
            function f() {
              var x;
              x = void 0;
              x = function () { return 2; };
              return x();
            }
            console.log(f());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'getter on arguments reads before': Program(
        a_program("""
            function f() {
              var x;
              var o = {};
              Object.defineProperty(o, 'p', { get: function () { x = 9; return 1; } });
              var v = o.p;
              x = undefined;
              return [v, x];
            }
            console.log(f());
            """),
        prints('[ 1, undefined ]'),
        Reading.COMMONJS,
    ),
    'a generator': Program(
        a_program("""
            function* g() {
              var x;
              x = undefined;
              x = yield 1;
              return x;
            }
            var it = g();
            it.next();
            console.log(it.next(3).value);
            """),
        prints('3'),
        Reading.COMMONJS,
    ),
    'store after a throwing try': Program(
        a_program("""
            function f() {
              var x;
              try { x = 4; throw 0; } catch (e) {}
              x = undefined;
              return x;
            }
            console.log(f());
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'store of undefined after the function': Program(
        a_program("""
            function f() {
              var x;
              x = function () { return 1; };
              x = undefined;
              return x();
            }
            console.log(f());
            """),
        ('', 'TypeError'),
        Reading.COMMONJS,
    ),
    'default param separate var env': Program(
        a_program("""
            function f(x = 7) {
              var x;
              x = undefined;
              var r = x;
              x = 1;
              return [r, x];
            }
            console.log(f());
            """),
        prints('[ undefined, 1 ]'),
        Reading.COMMONJS,
    ),
    'var arguments later write': Program(
        a_program("""
            function f() {
              var arguments;
              arguments = undefined;
              var r = typeof arguments;
              arguments = 1;
              return r + ':' + arguments;
            }
            console.log(f(1, 2));
            """),
        prints('undefined:1'),
        Reading.COMMONJS,
    ),
    'simple param later write': Program(
        a_program("""
            function f(x) {
              var x;
              x = undefined;
              var r = x;
              x = 1;
              return [r, x];
            }
            console.log(f(7));
            """),
        prints('[ undefined, 1 ]'),
        Reading.COMMONJS,
    ),
    'annex b copy before later write': Program(
        a_program("""
            function f() {
              var x;
              { function x() {} }
              x = undefined;
              var r = typeof x;
              x = 1;
              return r + x;
            }
            console.log(f());
            """),
        prints('undefined1'),
        Reading.COMMONJS,
    ),
    'commonjs module var': Program(
        a_program("""
            var module;
            module = undefined;
            var r = typeof module;
            module = 1;
            console.log(r, module);
            """),
        prints('undefined 1'),
        Reading.COMMONJS,
    ),
    'commonjs exports var': Program(
        a_program("""
            var exports;
            exports = undefined;
            var r = typeof exports;
            exports = 2;
            console.log(r, exports);
            """),
        prints('undefined 2'),
        Reading.COMMONJS,
    ),
    'commonjs arguments var': Program(
        a_program("""
            var arguments;
            arguments = undefined;
            var r = typeof arguments;
            arguments = 3;
            console.log(r, arguments);
            """),
        prints('undefined 3'),
        Reading.COMMONJS,
    ),
    'for in write before': Program(
        a_program("""
            function f(o) {
              for (var x in o) {}
              x = undefined;
              var r = x;
              x = 5;
              return [r, x];
            }
            console.log(f({ a: 1 }));
            """),
        prints('[ undefined, 5 ]'),
        Reading.COMMONJS,
    ),
    'for in corpus like': Program(
        a_program("""
            function f(o) {
              var keys = [];
              for (var k in o) { keys.push(k); }
              k = undefined;
              var probe = k;
              k = function () { return keys.length; };
              return [probe, k()];
            }
            console.log(f(JSON.parse('{"a":1,"b":2}')));
            """),
        prints('[ undefined, 2 ]'),
        Reading.COMMONJS,
    ),
    'for in key reset then reused': Program(
        a_program("""
            function last(o) {
              for (var k in o) {}
              k = undefined;
              if (Object.keys(o).length > 1) {
                return k;
              }
              k = 'single';
              return k;
            }
            console.log(last({ a: 1, b: 2 }), last({ a: 1 }));
            """),
        prints('undefined single'),
        Reading.COMMONJS,
    ),
    'for of write before': Program(
        a_program("""
            function f(o) {
              for (var x of o) {}
              x = undefined;
              var r = x;
              x = 5;
              return [r, x];
            }
            console.log(f(['q']));
            """),
        prints('[ undefined, 5 ]'),
        Reading.COMMONJS,
    ),
    'for of write before opaque': Program(
        a_program("""
            function f(o) {
              for (var x of o) {}
              x = undefined;
              var r = x;
              x = 5;
              return [r, x];
            }
            console.log(f(JSON.parse('["q"]')));
            """),
        prints('[ undefined, 5 ]'),
        Reading.COMMONJS,
    ),
    'for of write before two callers': Program(
        a_program("""
            function f(o) {
              for (var x of o) {}
              x = undefined;
              var r = x;
              x = 5;
              return [r, x];
            }
            console.log(f(new Set(['q'])), f('ab'));
            """),
        prints('[ undefined, 5 ] [ undefined, 5 ]'),
        Reading.COMMONJS,
    ),
    'for of destructuring head': Program(
        a_program("""
            function f(o) {
              for (var [x] of o) {}
              x = undefined;
              var r = x;
              x = 5;
              return [r, x];
            }
            console.log(f(new Set([['q']])), f(['ab']));
            """),
        prints('[ undefined, 5 ] [ undefined, 5 ]'),
        Reading.COMMONJS,
    ),
    'a destructuring declarator after the store': Program(
        a_program("""
            function f(o) {
              var x;
              x = undefined;
              var r = x;
              var { k: x } = o;
              return [r, x];
            }
            console.log(f({ k: 5 }));
            """),
        prints('[ undefined, 5 ]'),
        Reading.COMMONJS,
    ),
    'commonjs require var': Program(
        a_program("""
            var require;
            require = undefined;
            var r = typeof require;
            require = 4;
            console.log(r, require);
            """),
        prints('undefined 4'),
        Reading.COMMONJS,
    ),
    'default param closure': Program(
        a_program("""
            function f(x = 7, get = function () { return x; }) {
              var x;
              x = undefined;
              var r = [x, get()];
              x = 1;
              return [r, x, get()];
            }
            console.log(JSON.stringify(f()));
            """),
        prints('[[null,7],1,7]'),
        Reading.COMMONJS,
    ),
    'rest param separate env': Program(
        a_program("""
            function f(x, ...rest) {
              var x;
              x = undefined;
              var r = x;
              x = 1;
              return [r, x, rest.length];
            }
            console.log(f(7, 8));
            """),
        prints('[ undefined, 1, 1 ]'),
        Reading.COMMONJS,
    ),
    'destructured param': Program(
        a_program("""
            function f({ x }) {
              var x;
              x = undefined;
              var r = x;
              x = 1;
              return [r, x];
            }
            console.log(f({ x: 7 }));
            """),
        prints('[ undefined, 1 ]'),
        Reading.COMMONJS,
    ),
    'opaque read default param': Program(
        a_program("""
            function f(x = 7) {
              var x;
              x = undefined;
              var r = [x][Date.now() > 0 ? 0 : 0];
              x = 1;
              return r;
            }
            console.log(f());
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
}

#: Programs of `STORES_OF_UNDEFINED` whose store goes, mapped to the text the deobfuscation writes
#: for each.
REMOVED: dict[str, str] = {
    'the shape of the corpus': "console.log('a', 'b');",
    'closure called after the store': inspect.cleandoc(
        """
            function f() {
              var x;
              function g() {
                x = 5;
              }
              g();
              return x;
            }
            console.log(f());
        """
    ),
    'a var at the top of the file': 'console.log(2);',
    'annex b copy after the store': inspect.cleandoc(
        """
            function f() {
              var x;
              {
                function x() {}
              }
              return typeof x;
            }
            console.log(f());
        """
    ),
}

#: Programs storing `undefined` into a `var` that a function of another file may write before the
#: store, mapped to the files that function is called from: one CommonJS file requiring the other,
#: and one ES module importing the other, each in a cycle.
A_STORE_ANOTHER_FILE_MAY_PRECEDE = {
    a_program("""
        var x;
        exports.g = function () { x = 1; };
        require('./other.js');
        x = undefined;
        console.log(x);
        """): (
        'main.js',
        {'other.js': a_program("require('./main.js').g();")},
    ),
    a_program("""
        import { h } from './other.mjs';
        export var x;
        export function g() { x = 1; }
        h();
        x = undefined;
        console.log(x);
        """): (
        'main.mjs',
        {
            'other.mjs': a_program("""
                import { g } from './main.mjs';
                export function h() { g(); }
                """),
        },
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStoreOfUndefinedBehavesAsItDid(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in STORES_OF_UNDEFINED.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in STORES_OF_UNDEFINED.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())

    def test_a_store_before_eval_runs_still_prints_it_where_the_unit_trusts_eval(self):
        row = STORES_OF_UNDEFINED['direct eval before the store']
        self.assertEqual(behavior(deobfuscated_by_the_unit(row.text)), row.prints)

    def test_a_var_at_the_top_of_a_script_still_prints_it_where_the_host_may_write_it(self):
        row = STORES_OF_UNDEFINED['a var at the top of the file']
        self.assertEqual(Reading.SCRIPT.read(row.text), (row.prints, row.prints))

    def test_a_store_another_file_may_precede_still_prints_it(self):
        for source, (entry, others) in A_STORE_ANOTHER_FILE_MAY_PRECEDE.items():
            execution = ExecutionModel.module if entry.endswith('.mjs') else ExecutionModel.commonjs
            rewritten = deobfuscate_source(source, execution=execution)
            with self.subTest(entry=entry):
                self.assertEqual(
                    (
                        module_graph_behavior({entry: source, **others}, entry),
                        module_graph_behavior({entry: rewritten, **others}, entry),
                    ),
                    (prints('undefined'), prints('undefined')),
                )


class TestAStoreOfUndefinedGoesWhereNoOtherValueReachesTheVarBeforeIt(TestBase):

    def test_each_store_removed_reads_as_pinned(self):
        self.assertEqual(
            {
                label: deobfuscate_source(STORES_OF_UNDEFINED[label].text, execution=ExecutionModel.commonjs)
                for label in REMOVED
            },
            REMOVED,
        )

    def test_a_var_at_the_top_of_a_script_keeps_its_store(self):
        text = deobfuscate_source(STORES_OF_UNDEFINED['a var at the top of the file'].text, execution=ExecutionModel.script)
        self.assertIn('SC = undefined;', text)
