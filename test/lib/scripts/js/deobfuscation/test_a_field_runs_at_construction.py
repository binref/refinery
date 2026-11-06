"""
Every program here is written by hand, and Node runs each of them.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import Program, Reading, a_program, folded, prints

A_DECODER_CALLED_IN_A_FIELD: dict[str, Program] = {
    'a built-in replaced through a computed global name': Program(
        a_program("""
            var k = process.argv.length > 99 ? "x" : "String";
            var v = { fromCharCode: function () { return "T"; } };
            function d(n) { return String.fromCharCode(n); }
            function f() {
              class A { x = d(65); }
              globalThis[k] = v;
              return new A().x;
            }
            console.log(f());
            """),
        prints('T'),
    ),
    'a built-in replaced by an eval in an async function': Program(
        a_program("""
            var s = ["String.fromCharCode = function () { return '!'; }"][0];
            var q = (function () {
              class A { v = function (e, r) {
                var y = [];
                for (var l = 0; l < e.length; l++) { y[l] = e.charAt(l); }
                var u = String.fromCharCode(65);
                return y.join('') + u;
              }('0', 1); }
              (async function () { await eval(s); })();
              return new A().v;
            })();
            console.log(q);
            """),
        prints('0!'),
    ),
    'a static field calling the decoder before the built-in is replaced': Program(
        a_program("""
            var k = process.argv.length > 99 ? "x" : "String";
            var v = { fromCharCode: function () { return "T"; } };
            function d(n) { return String.fromCharCode(n); }
            function f() {
              class A { static x = d(65); }
              globalThis[k] = v;
              return A.x;
            }
            console.log(f());
            """),
        prints('A'),
    ),
}

A_VARIABLE_A_FIELD_READS: dict[str, Program] = {
    'a var reassigned after the class': Program(
        a_program("""
            function f() { var x = 1; class A { v = x; } x = 2; return new A().v; }
            console.log(f());
            """),
        prints('2'),
    ),
    'a let assigned after the class': Program(
        a_program("""
            function f() { let x; class A { v = x; } x = 2; return new A().v; }
            console.log(f());
            """),
        prints('2'),
    ),
    'a file-level var a field of a class its function returns reads': Program(
        a_program("""
            var x;
            function f(n) {
              x = n;
              console.log(x);
              return class { y = x; };
            }
            var C = f(1);
            f(2);
            console.log(new C().y);
            """),
        prints('1', '2', '2'),
        Reading.COMMONJS,
    ),
    'a var reassigned after a derived class': Program(
        a_program("""
            function f() {
              var x = 1;
              class B {}
              class A extends B { v = x; constructor() { super(); } }
              x = 2;
              return new A().v;
            }
            console.log(f());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'a let declared after the class and constructed after it': Program(
        a_program("""
            function f() { class A { v = y; } let y = 3; return new A().v; }
            console.log(f());
            """),
        prints('3'),
        Reading.COMMONJS,
    ),
    'a let read by a construction before its declaration runs': Program(
        a_program("""
            function f() {
              class A { v = y; }
              let r;
              try { r = new A().v; } catch (e) { r = e.name; }
              let y = 3;
              return r;
            }
            console.log(f());
            """),
        prints('ReferenceError'),
        Reading.COMMONJS,
    ),
    'a parameter reassigned after the class': Program(
        a_program("""
            function f(p) { class A { v = p; } p = 'late'; return new A().v; }
            console.log(f('early'));
            """),
        prints('late'),
        Reading.COMMONJS,
    ),
    'a var a function called after the class writes': Program(
        a_program("""
            function f() {
              var x = 1;
              function set() { x = 2; }
              class A { v = x; }
              set();
              return new A().v;
            }
            console.log(f());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'a copy of a parameter a call after the class changes': Program(
        a_program("""
            function f(a) {
              var y = a + 1;
              function bump() { a = 5; }
              class A { v = y; }
              bump();
              return new A().v;
            }
            console.log(f(1));
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'a var reassigned after a class expression': Program(
        a_program("""
            function f() { var x = 1; var C = class { v = x; }; x = 2; return new C().v; }
            console.log(f());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'an alias of Function an eval replaces after the class': Program(
        a_program("""
            function f(s) {
              var F;
              F = Function;
              class A { x = F("return 7")(); }
              eval(s);
              return new A().x;
            }
            console.log(f("F = function () { return function () { return 8; }; };"));
            """),
        prints('8'),
    ),
    'a const declared before the class': Program(
        a_program("""
            const k = 'abc';
            class A { v = k; }
            console.log(new A().v);
            """),
        prints('abc'),
        Reading.COMMONJS,
    ),
    'a flattened parameter default holding a class whose field reads an earlier parameter': Program(
        a_program("""
            function outer(n) {
              function* gen(a, b, scope = { F: {} }, args) {
                while (a + b !== 100) {
                  with (scope.RV || scope) {
                    switch (a + b) {
                      case 10:
                        F.helper = function(...rest) {
                          return gen(40, 10, { F: scope.F, L: {} }, rest)["next"]()["value"];
                        };
                        F.result = F.helper(n);
                        a = 20, b = 0;
                        break;
                      case 20:
                        return done = true, F.result;
                      case 50:
                        [L.x, L.y = class K { v = L.x; }] = args;
                        a = 60, b = 0;
                        break;
                      case 60:
                        L.x = 99;
                        return new L.y().v;
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            console.log(outer(3));
            """),
        prints('99'),
        Reading.SCRIPT,
    ),
}

A_VARIABLE_A_CONSTRUCTION_WRITES: dict[str, Program] = {
    'a var a field writes and a function reads across a construction': Program(
        a_program("""
            var x = 1;
            class C { y = (x = 2); }
            function h() { var t = x; new C(); return t; }
            console.log(h());
            """),
        prints('1'),
        Reading.COMMONJS,
    ),
    'a var a field writes through a call, read across a construction': Program(
        a_program("""
            var x = 1;
            function w() { x = 2; }
            class C { y = w(); }
            function h() { var t = x; new C(); return t; }
            console.log(h());
            """),
        prints('1'),
        Reading.COMMONJS,
    ),
    'a counter a field bumps through a call': Program(
        a_program("""
            var n = 0;
            function next() { return n++; }
            class A { id = next(); }
            var k = n;
            new A();
            console.log(k, n);
            """),
        prints('0 1'),
        Reading.COMMONJS,
    ),
    'a local a field increments on each construction': Program(
        a_program("""
            function f() { var n = 0; class A { v = ++n; } new A(); new A(); return n; }
            console.log(f());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'a file-level var written again through a field of a class declared outside': Program(
        a_program("""
            var x;
            class K { y = f(0); }
            function f(n) {
              x = n;
              if (n) new K();
              console.log(x);
            }
            f(1);
            """),
        prints('0', '0'),
        Reading.COMMONJS,
    ),
    'a file-level var written again through a field of a class declared inside': Program(
        a_program("""
            var x;
            function f(n) {
              class C { y = n ? f(0) : 0; }
              x = n;
              new C();
              console.log(x);
            }
            f(1);
            """),
        prints('0', '0'),
        Reading.COMMONJS,
    ),
    'a var a field writes through a call, read by a later call': Program(
        a_program("""
            function f() {
              var x = 1;
              function m() { x = 2; }
              function r() { return x; }
              class A { v = m(); }
              new A();
              return r();
            }
            console.log(f());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'a var a field of a class handed to a function writes': Program(
        a_program("""
            var x = 1;
            function make(K) { return new K(); }
            function h() { var t = x; make(class { y = (x = 2); }); return t; }
            console.log(h(), x);
            """),
        prints('1 2'),
        Reading.COMMONJS,
    ),
    'a var a field of a class a function returns writes, read before the construction': Program(
        a_program("""
            function f() {
              var x = 1;
              function g() { return class { v = (x = 2); }; }
              var C = g();
              var t = x;
              new C();
              return [t, x];
            }
            console.log(f().join());
            """),
        prints('1,2'),
        Reading.COMMONJS,
    ),
    'a var a field of a class a factory returns writes, read by a later function': Program(
        a_program("""
            var x = 1;
            function mk() { return class { v = (x = 2); }; }
            new (mk())();
            function r() { return x; }
            console.log(r());
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
    'a let a field of a mixin counts constructions in, read by a later function': Program(
        a_program("""
            (function () {
              let nextId = 0;
              const WithId = (Base) => class extends Base { id = nextId++; };
              class Thing extends WithId(Object) {}
              new Thing();
              new Thing();
              function count() { return nextId; }
              console.log(count());
            })();
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'a flag a function constructing an inline class sets, read by another function': Program(
        a_program("""
            function main() {
              var ready = false;
              function boot() {
                new (class { init = (ready = true); })();
              }
              function isReady() { return ready; }
              boot();
              return isReady();
            }
            console.log(main());
            """),
        prints('true'),
        Reading.COMMONJS,
    ),
    'a var a field of a class a called function constructs writes, read by an arrow': Program(
        a_program("""
            function f() {
              var x = 1;
              function g() { class A { v = (x = 2); } new A(); }
              var h = () => x;
              g();
              return h();
            }
            console.log(f());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'a var an inline construction inside a fold writes': Program(
        a_program("""
            var x = 0;
            var y = Math.floor((new (class { v = (x = 1); })(), 4.5));
            console.log(x, y);
            """),
        prints('1 4'),
        Reading.COMMONJS,
    ),
    'a field taking this in a function shaped like a global finder': Program(
        a_program("""
            function getGlobal() {
              var g;
              var h = globalThis;
              try { new (class { v = (g = this); })(); } catch (e) {}
              return g;
            }
            console.log(getGlobal() === globalThis);
            """),
        prints('false'),
        Reading.COMMONJS,
    ),
    'a global finder constructing a class whose field writes a global': Program(
        a_program("""
            var hits = 0;
            function getGlobal() {
              var h = globalThis;
              try { new (class { v = (hits = hits + 1); })(); } catch (e) {}
              return h;
            }
            var G = getGlobal();
            console.log(G === globalThis, hits);
            """),
        prints('true 1'),
        Reading.SCRIPT,
    ),
    'a global finder constructing a class whose constructor writes a global': Program(
        a_program("""
            var hits = 0;
            function getGlobal() {
              var h = globalThis;
              try { new (class { constructor() { hits = hits + 1; } })(); } catch (e) {}
              return h;
            }
            var G = getGlobal();
            console.log(G === globalThis, hits);
            """),
        prints('true 1'),
        Reading.SCRIPT,
    ),
}

WHEN_THE_PARTS_OF_A_CLASS_RUN: dict[str, Program] = {
    'a field of a derived class runs after super returns': Program(
        a_program("""
            class B { constructor() { console.log('B'); } }
            class A extends B {
              v = console.log('field');
              constructor() { console.log('before'); super(); console.log('after'); }
            }
            new A();
            """),
        prints('before', 'B', 'field', 'after'),
        Reading.COMMONJS,
    ),
    'a static block constructing runs the field during the class statement': Program(
        a_program("""
            var log = [];
            class A {
              v = log.push('field');
              static s = log.push('static');
              static { new this(); log.push('block'); }
            }
            console.log(log.join());
            """),
        prints('static,field,block'),
        Reading.COMMONJS,
    ),
    'a static field reads the value the variable holds at the class': Program(
        a_program("""
            function f() { var x = 1; class A { static v = x; } x = 2; return A.v; }
            console.log(f());
            """),
        prints('1'),
        Reading.COMMONJS,
    ),
    'a computed key of a field is evaluated once, at the class': Program(
        a_program("""
            var k = 'a';
            class A { [k] = 1; }
            k = 'b';
            console.log(Object.keys(new A()).join());
            """),
        prints('a'),
        Reading.COMMONJS,
    ),
    'a static block constructing writes a var during the class statement': Program(
        a_program("""
            function h() {
              var x = 1;
              var t = x;
              class C { y = (x = 2); static { new this(); } }
              return [t, x].join();
            }
            console.log(h());
            """),
        prints('1,2'),
        Reading.COMMONJS,
    ),
    'a var an eval in a field declares stays in the field': Program(
        a_program("""
            function f() { class A { v = eval('var y = 1; y'); } new A(); return typeof y; }
            console.log(f());
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutADecoderCalledInAField(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in A_DECODER_CALLED_IN_A_FIELD.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in A_DECODER_CALLED_IN_A_FIELD.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFieldReadsAVariableWhenAnInstanceIsConstructed(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in A_VARIABLE_A_FIELD_READS.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in A_VARIABLE_A_FIELD_READS.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAConstructionWritesWhatTheCodeAroundItReads(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in A_VARIABLE_A_CONSTRUCTION_WRITES.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in A_VARIABLE_A_CONSTRUCTION_WRITES.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestEachPartOfAClassRunsWhenTheLanguageSays(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in WHEN_THE_PARTS_OF_A_CLASS_RUN.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in WHEN_THE_PARTS_OF_A_CLASS_RUN.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestWhatAFieldReadsIsStillFolded(TestBase):

    A_FIELD_DECODING_ITS_VALUE_AND_ITS_KEY = a_program("""
        var t = ['hello', 'world', 'key'];
        var d = function (i) { return t[i]; };
        class A { greeting = d(0); [d(2)] = d(1); }
        console.log(new A().greeting);
        """)

    def test_a_decoder_call_in_the_initializer_and_the_computed_key_of_a_field_is_decoded(self):
        self.assertIn(folded(self.A_FIELD_DECODING_ITS_VALUE_AND_ITS_KEY), (
            inspect.cleandoc("""
                class A {
                  greeting = 'hello';
                  ['key'] = 'world';
                }
                console.log(new A().greeting);
                """),
            inspect.cleandoc("""
                class A {
                  greeting = 'hello';
                  key = 'world';
                }
                console.log(new A().greeting);
                """),
        ))

    @opportunity
    def test_a_computed_key_decoded_to_a_name_is_written_as_the_name(self):
        self.assertEqual(folded(self.A_FIELD_DECODING_ITS_VALUE_AND_ITS_KEY), inspect.cleandoc("""
            class A {
              greeting = 'hello';
              key = 'world';
            }
            console.log(new A().greeting);
            """))

    def test_a_constant_is_written_into_the_initializer_of_a_field(self):
        source = a_program("""
            const k = 'abc';
            class A { v = k; w = k + 'd'; }
            console.log(new A().v);
            """)
        self.assertEqual(folded(source), inspect.cleandoc("""
            class A {
              v = 'abc';
              w = 'abcd';
            }
            console.log(new A().v);
            """))
