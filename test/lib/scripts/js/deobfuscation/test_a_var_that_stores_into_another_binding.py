"""
SECURITY: every program in this module is written by hand and benign; never add one taken from a
sample.
"""
from __future__ import annotations

import unittest

from test import TestBase, todo
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import (
    a_program,
    prints,
    what_each_deobfuscated_script_pins,
    what_each_deobfuscated_script_prints,
    what_each_script_pins,
    what_each_script_prints,
)

A_VAR_THAT_STORES_INTO_A_CATCH_PARAMETER = {
    'the only value of the var': (
        a_program("""
            function f() {
              var b;
              try { throw 0; } catch (b) { var b = 'c'; }
              console.log(b);
            }
            f();
        """),
        prints('undefined'),
    ),
    'the parameter read after the initializer': (
        a_program("""
            function f() {
              var b = 'a';
              try { throw 'e'; } catch (b) { var b = 'c'; console.log(b); }
              console.log(b);
            }
            f();
        """),
        prints('c', 'a'),
    ),
    'the var returned after a first value': (
        a_program("""
            function f() {
              var b = 'a';
              try { throw 0; } catch (b) { var b = 'c'; }
              return b;
            }
            console.log(f());
        """),
        prints('a'),
    ),
    'the var never read outside the handler': (
        a_program("""
            function f() {
              try { throw 0; } catch (b) { var b = 'c'; console.log(b); }
            }
            f();
        """),
        prints('c'),
    ),
    'a for-in head of the name': (
        a_program("""
            function f(o) {
              var b = 'a';
              try { throw 0; } catch (b) { for (var b in o) {} console.log(b); }
              return b;
            }
            console.log(f({ k: 1 }));
        """),
        prints('k', 'a'),
    ),
    'a for-in head with the legacy initializer': (
        a_program("""
            function f(o) {
              var b = 'a';
              try { throw 0; } catch (b) { for (var b = 'c' in o) {} console.log(b); }
              return b;
            }
            console.log(f({}), f({ k: 1 }));
        """),
        prints('c', 'k', 'a a'),
    ),
    'a for-of head of the name': (
        a_program("""
            function f() {
              var b = 'a';
              try { throw 0; } catch (b) { for (var b of ['x', 'y']) {} console.log(b); }
              return b;
            }
            console.log(f());
        """),
        prints('y', 'a'),
    ),
    'the whole body of a loop': (
        a_program("""
            function f() {
              var b = 'a';
              try { throw 0; } catch (b) { for (var i = 0; i < 1; i++) var b = 'c'; console.log(b); }
              return b;
            }
            console.log(f());
        """),
        prints('c', 'a'),
    ),
    'a for head of the name': (
        a_program("""
            function f() {
              var b = 'a';
              try { throw 0; } catch (b) { for (var b = 'c'; false;) {} console.log(b); }
              return b;
            }
            console.log(f());
        """),
        prints('c', 'a'),
    ),
    'a for head declaring another name beside it': (
        a_program("""
            function f() {
              var b = 'a';
              try { throw 0; } catch (b) { for (var b = 'c', i = 0; i < 1; i++) {} console.log(b, i); }
              return b;
            }
            console.log(f());
        """),
        prints('c 1', 'a'),
    ),
    'a labeled for head of the name': (
        a_program("""
            function f() {
              var b = 'a';
              try { throw 0; } catch (b) { out: for (var b = 'c'; ; ) { break out; } console.log(b); }
              return b;
            }
            console.log(f());
        """),
        prints('c', 'a'),
    ),
    'an array destructuring declarator': (
        a_program("""
            function f() {
              var b = 'a';
              try { throw 0; } catch (b) { var [b] = ['c']; console.log(b); }
              return b;
            }
            console.log(f());
        """),
        prints('c', 'a'),
    ),
    'an array destructuring declarator whose default reads the name': (
        a_program("""
            function f() {
              var b = 'a', d;
              try { throw 0; } catch (b) { var [b, d = b] = ['c']; console.log(b, d); }
              return [b, d].join();
            }
            console.log(f());
        """),
        prints('c c', 'a,c'),
    ),
    'a declarator list with the middle one stored into the parameter': (
        a_program("""
            function f() {
              try { throw 0; } catch (b) { var a = 1, b = 'c', d = a; console.log(a, b, d); }
              return [a, b, d];
            }
            console.log(f().join());
        """),
        prints('1 c 1', '1,,1'),
    ),
    'at the top of the script': (
        a_program("""
            try { throw 0; } catch (b) { var b = 'c'; }
            console.log(b);
        """),
        prints('undefined'),
    ),
    'nested in a block in the handler': (
        a_program("""
            function f() {
              var b = 'a';
              try { throw 0; } catch (b) { { var b = 'c'; } }
              return b;
            }
            console.log(f());
        """),
        prints('a'),
    ),
    'the var read before and after the handler': (
        a_program("""
            function f() {
              var b = 'a';
              console.log(b);
              try { throw 0; } catch (b) { var b = 'c'; }
              console.log(b);
            }
            f();
        """),
        prints('a', 'a'),
    ),
    'the value read in the handler and the var stored after it': (
        a_program("""
            function h(v) { console.log(v); }
            function f() {
              try { throw 0; } catch (b) { var b = 'c'; h(b); }
              b = 2;
              return b;
            }
            console.log(f());
        """),
        prints('c', '2'),
    ),
    'the var returned after a first number': (
        a_program("""
            function f() {
              var b = 1;
              try { throw 0; } catch (b) { var b = 2; }
              return b;
            }
            console.log(f());
        """),
        prints('1'),
    ),
    'a function called through the parameter': (
        a_program("""
            function f() {
              try { throw 0; } catch (b) { var b = function () { return 'k'; }; console.log(b()); }
              return typeof b;
            }
            console.log(f());
        """),
        prints('k', 'undefined'),
    ),
    'the string a branch tests': (
        a_program("""
            var b;
            try { throw 0; } catch (b) { var b = 'c'; }
            if (b) console.log('yes');
            console.log('end');
        """),
        prints('end'),
    ),
    'the last statement of the script': (
        a_program("""
            try { throw 0; } catch (b) { var b = 'c'; }
            if (typeof b) console.log(b);
        """),
        prints('undefined'),
    ),
}

A_VAR_THAT_STORES_INTO_THE_OBJECT_OF_A_WITH = {
    'the only value of the var': (
        a_program("""
            function f(o) {
              with (o) { var b = 'c'; }
              console.log(b);
            }
            f({}); f({ b: 0 });
        """),
        prints('c', 'undefined'),
    ),
    'the object read after': (
        a_program("""
            function f(o) {
              with (o) { var b = 'c'; }
              return o.b;
            }
            console.log(f({}), f({ b: 0 }));
        """),
        prints('undefined c'),
    ),
    'a for-in head of the name': (
        a_program("""
            function f(o, p) {
              var b = 'a';
              with (o) { for (var b in p) {} }
              return b;
            }
            console.log(f({}, { k: 1 }), f({ b: 0 }, { k: 1 }));
        """),
        prints('k a'),
    ),
    'a for-of head of the name': (
        a_program("""
            function f(o) {
              var b = 'a';
              with (o) { for (var b of ['x', 'y']) {} }
              return [b, o.b].join();
            }
            console.log(f({}), f({ b: 0 }));
        """),
        prints('y, a,y'),
    ),
    'an object destructuring declarator whose default reads the name': (
        a_program("""
            function f(o) {
              with (o) { var { b, c = b } = { b: 'c' }; }
              return [typeof b, o.b, c].join();
            }
            console.log(f({}), f({ b: 0 }));
        """),
        prints('string,,c undefined,c,c'),
    ),
    'the var read before and after the body': (
        a_program("""
            function f(o) {
              var b = 'a';
              console.log(b);
              with (o) { var b = 'c'; }
              console.log(b);
            }
            f({}); f({ b: 0 });
        """),
        prints('a', 'c', 'a', 'a'),
    ),
    'a function stored into the var or the object': (
        a_program("""
            function f(o) {
              with (o) { var b = function () { return 'k'; }; }
              return typeof b;
            }
            console.log(f({}), f({ b: 0 }));
        """),
        prints('function undefined'),
    ),
    'the name a function takes from the declarator': (
        a_program("""
            function f(o) {
              try { throw 0; } catch (b) { var b = function () {}; var n = b.name; }
              with (o) { var c = () => 0; }
              return [n, typeof c === 'function' ? c.name : o.c.name].join();
            }
            console.log(f({}), f({ c: 0 }));
        """),
        prints('b,c b,c'),
    ),
    'an object whose has trap counts the lookups of the name': (
        a_program("""
            var seen = 0;
            var o = new Proxy({}, { has(t, k) { if (k === 'b') seen++; return false; } });
            function f() { with (o) { var b = 'c'; } return b; }
            console.log(f(), seen);
        """),
        prints('c 1'),
    ),
}

A_VAR_THAT_STORES_CODE_INTO_ANOTHER_BINDING = {
    'a catch parameter holds the code eval runs': (
        a_program("""
            var code;
            try { throw 0; } catch (code) { var code = 'console.log(1)'; }
            eval(code);
            console.log(typeof code);
        """),
        prints('undefined'),
    ),
    'the object of a with holds the code eval runs': (
        a_program("""
            function f(o) {
              with (o) { var code = 'console.log(1)'; }
              eval(code);
            }
            f({ code: 0 });
        """),
        prints(),
    ),
}

A_VALUE_A_PASS_READS_STORED_INTO_ANOTHER_BINDING = {
    'a namespace object stored into the parameter': (
        a_program("""
            function f() {
              var N = {};
              try { throw {}; } catch (N) { var N = { a: 1, b: 2 }; }
              N.c = 3;
              return JSON.stringify(N);
            }
            console.log(f());
        """),
        prints('{"c":3}'),
    ),
    'an array of strings stored into the parameter': (
        a_program("""
            function f() {
              var A = ['x', 'y'];
              try { throw 0; } catch (A) { var A = ['p', 'q']; console.log(A[1]); }
              return A[0] + A[1];
            }
            console.log(f());
        """),
        prints('q', 'xy'),
    ),
    'a decoder function stored into the parameter': (
        a_program("""
            function f() {
              var D = function (i) { return ['a', 'b'][i]; };
              try { throw 0; } catch (D) { var D = function (i) { return ['x', 'y'][i]; }; console.log(D(0)); }
              return D(1);
            }
            console.log(f());
        """),
        prints('x', 'b'),
    ),
    'a wrapper function stored into the parameter': (
        a_program("""
            function g(a, b) { return a + b; }
            function f() {
              var w = function (a, b) { return g(a, b); };
              try { throw 0; } catch (w) { var w = function (a, b) { return a * b; }; console.log(w(2, 3)); }
              return w(2, 3);
            }
            console.log(f());
        """),
        prints('6', '5'),
    ),
    'the global object stored into the parameter': (
        a_program("""
            var q = 1;
            function f() {
              var G = { q: 2 };
              try { throw 0; } catch (G) { var G = globalThis; console.log(G.q); }
              return G.q;
            }
            console.log(f());
        """),
        prints('1', '2'),
    ),
    'a dead store after the handler': (
        a_program("""
            function f() {
              var b = 'a';
              try { throw 0; } catch (b) { var b = 'c'; console.log(b); }
              b = 'd';
              return b;
            }
            console.log(f());
        """),
        prints('c', 'd'),
    ),
    'a with in a catch': (
        a_program("""
            function f(o) {
              var b = 'a';
              try { throw 'e'; } catch (b) { with (o) { var b = 'c'; } console.log(b); }
              return b;
            }
            console.log(f({}), f({ b: 0 }));
        """),
        prints('c', 'e', 'a a'),
    ),
    'a catch in a with': (
        a_program("""
            function f(o) {
              var b = 'a';
              with (o) { try { throw 'e'; } catch (b) { var b = 'c'; console.log(b); } }
              return [b, o.b].join();
            }
            console.log(f({}), f({ b: 0 }));
        """),
        prints('c', 'c', 'a, a,0'),
    ),
    'an object without the name': (
        a_program("""
            function f() {
              var b = 'a';
              with ({}) { var b = 'c'; }
              return b;
            }
            console.log(f());
        """),
        prints('c'),
    ),
    'a parameter of a nested catch of another name': (
        a_program("""
            function f() {
              var b = 'a';
              try { throw 0; } catch (b) { try { throw 1; } catch (e) { var b = 'c'; } console.log(b); }
              return b;
            }
            console.log(f());
        """),
        prints('c', 'a'),
    ),
    'a closure reading the var': (
        a_program("""
            function f() {
              var b = 'a';
              var r = function () { return b; };
              try { throw 0; } catch (b) { var b = 'c'; }
              return r();
            }
            console.log(f());
        """),
        prints('a'),
    ),
    'a closure in the handler reading the parameter': (
        a_program("""
            function f() {
              var r;
              try { throw 'e'; } catch (b) { var b = 'c'; r = function () { return b; }; }
              return [r(), typeof b].join();
            }
            console.log(f());
        """),
        prints('c,undefined'),
    ),
    'a string the inliner evaluates': (
        a_program("""
            function f() {
              var s = 'console.log(2)';
              try { throw 0; } catch (s) { var s = 'console.log(1)'; }
              eval(s);
            }
            f();
        """),
        prints('2'),
    ),
    'a loop counter stored into the parameter': (
        a_program("""
            function f() {
              var i = 5;
              try { throw 0; } catch (i) { for (var i = 0; i < 2; i++) {} console.log(i); }
              return i;
            }
            console.log(f());
        """),
        prints('2', '5'),
    ),
    'a counter updated after the handler': (
        a_program("""
            function f() {
              var n = 1;
              try { throw 0; } catch (n) { var n = 10; }
              n++;
              return n;
            }
            console.log(f());
        """),
        prints('2'),
    ),
    'a var never read anywhere but stored through the object': (
        a_program("""
            function f(o) {
              with (o) { var k = 'v'; }
              return JSON.stringify(o);
            }
            console.log(f({}), f({ k: 0 }));
        """),
        prints('{} {"k":"v"}'),
    ),
    'a global stored into the parameter at the top of the script': (
        a_program("""
            var x = 'a';
            try { throw 0; } catch (x) { var x = 'c'; }
            function r() { return x; }
            console.log(r());
        """),
        prints('a'),
    ),
    'an unread var whose store a handler reads': (
        a_program("""
            function f() {
              try { throw 0; } catch (k) { var k = [1, 2, 3]; console.log(k.length); }
            }
            f();
        """),
        prints('3'),
    ),
    'a constructor temporary stored into the parameter': (
        a_program("""
            function f() {
              try { throw 0; } catch (t) { var t = new Function('return 7'); console.log(t()); }
            }
            f();
        """),
        prints('7'),
    ),
    'an object a namespace pass may flatten': (
        a_program("""
            function f() {
              try { throw 0; } catch (N) { var N = {}; N.a = 1; console.log(N.a); }
            }
            f();
        """),
        prints('1'),
    ),
    'a sequence of order and counter declarators': (
        a_program("""
            function f() {
              try { throw 0; } catch (o) {
                var o = '1|0'.split('|'), c = 0;
                while (true) {
                  switch (o[c++]) {
                    case '0': console.log('zero'); continue;
                    case '1': console.log('one'); continue;
                  }
                  break;
                }
                console.log(o.length);
              }
            }
            f();
        """),
        prints('one', 'zero', '2'),
    ),
    'a dispatcher table stored into the parameter': (
        a_program("""
            function f() {
              try { throw 0; } catch (T) {
                var T = { a: function () { return 'x'; } };
                console.log(T.a(), typeof T);
              }
            }
            f();
        """),
        prints('x object'),
    ),
    'a table of functions held by the parameter': (
        a_program("""
            function f() {
              try { throw 0; } catch (T) {
                var T = [function (a) { return a + 1; }, function (a) { return a * 2; }];
                console.log(T[1](5));
              }
              return typeof T;
            }
            console.log(f());
        """),
        prints('10', 'undefined'),
    ),
    'a module map held by the parameter': (
        a_program("""
            function f() {
              try { throw 0; } catch (M) {
                var M = { a: function () { return 'A'; }, b: function () { return 'B'; } };
                console.log(M.a() + M.b());
              }
              return typeof M;
            }
            console.log(f());
        """),
        prints('AB', 'undefined'),
    ),
}

ANOTHER_BINDING_A_VAR_DOES_NOT_STORE_INTO = {
    'an assignment in the handler': (
        a_program("""
            function f() {
              var b = 'a';
              try { throw 0; } catch (b) { b = 'c'; }
              return b;
            }
            console.log(f());
        """),
        prints('a'),
    ),
    'a var of another name in the handler': (
        a_program("""
            function f() {
              try { throw 0; } catch (e) { var b = 'c'; }
              return b;
            }
            console.log(f());
        """),
        prints('c'),
    ),
}

A_FREE_NAME_A_WITH_BODY_IN_A_CALLED_FUNCTION_STORES = {
    'a called function': (
        a_program("""
            function w(o) { with (o) { g = 5; } }
            function f() {
              var b = typeof g;
              w({});
              return b;
            }
            console.log(f());
        """),
        prints('undefined'),
    ),
    'a callback': (
        a_program("""
            function f(k) {
              var b = typeof g;
              k();
              return b;
            }
            console.log(f(function () { with ({}) { g = 5; } }));
        """),
        prints('undefined'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsWhatEachProgramPins(TestBase):

    def test_a_var_that_stores_into_a_catch_parameter(self):
        rows = A_VAR_THAT_STORES_INTO_A_CATCH_PARAMETER
        self.assertEqual(what_each_script_prints(rows), what_each_script_pins(rows))

    def test_a_var_that_stores_into_the_object_of_a_with(self):
        rows = A_VAR_THAT_STORES_INTO_THE_OBJECT_OF_A_WITH
        self.assertEqual(what_each_script_prints(rows), what_each_script_pins(rows))

    def test_a_var_that_stores_code_into_another_binding(self):
        rows = A_VAR_THAT_STORES_CODE_INTO_ANOTHER_BINDING
        self.assertEqual(what_each_script_prints(rows), what_each_script_pins(rows))

    def test_a_value_a_pass_reads_stored_into_another_binding(self):
        rows = A_VALUE_A_PASS_READS_STORED_INTO_ANOTHER_BINDING
        self.assertEqual(what_each_script_prints(rows), what_each_script_pins(rows))

    def test_another_binding_a_var_does_not_store_into(self):
        rows = ANOTHER_BINDING_A_VAR_DOES_NOT_STORE_INTO
        self.assertEqual(what_each_script_prints(rows), what_each_script_pins(rows))

    def test_a_free_name_a_with_body_in_a_called_function_stores(self):
        rows = A_FREE_NAME_A_WITH_BODY_IN_A_CALLED_FUNCTION_STORES
        self.assertEqual(what_each_script_prints(rows), what_each_script_pins(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheDeobfuscationPrintsWhatTheProgramDoes(TestBase):

    def test_a_var_that_stores_into_a_catch_parameter(self):
        rows = A_VAR_THAT_STORES_INTO_A_CATCH_PARAMETER
        self.assertEqual(what_each_deobfuscated_script_prints(rows), what_each_deobfuscated_script_pins(rows))

    def test_a_var_that_stores_into_the_object_of_a_with(self):
        rows = A_VAR_THAT_STORES_INTO_THE_OBJECT_OF_A_WITH
        self.assertEqual(what_each_deobfuscated_script_prints(rows), what_each_deobfuscated_script_pins(rows))

    def test_a_var_that_stores_code_into_another_binding(self):
        rows = A_VAR_THAT_STORES_CODE_INTO_ANOTHER_BINDING
        self.assertEqual(what_each_deobfuscated_script_prints(rows), what_each_deobfuscated_script_pins(rows))

    def test_a_value_a_pass_reads_stored_into_another_binding(self):
        rows = A_VALUE_A_PASS_READS_STORED_INTO_ANOTHER_BINDING
        self.assertEqual(what_each_deobfuscated_script_prints(rows), what_each_deobfuscated_script_pins(rows))

    def test_another_binding_a_var_does_not_store_into(self):
        rows = ANOTHER_BINDING_A_VAR_DOES_NOT_STORE_INTO
        self.assertEqual(what_each_deobfuscated_script_prints(rows), what_each_deobfuscated_script_pins(rows))

    @todo
    def test_a_free_name_a_with_body_in_a_called_function_stores(self):
        rows = A_FREE_NAME_A_WITH_BODY_IN_A_CALLED_FUNCTION_STORES
        self.assertEqual(what_each_deobfuscated_script_prints(rows), what_each_deobfuscated_script_pins(rows))
