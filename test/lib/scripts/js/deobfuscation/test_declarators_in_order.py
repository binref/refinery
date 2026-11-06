"""
SECURITY: the programs here run in Node, and every one is written by hand in this file. No sample
and no stored obfuscator fixture may ever be added here.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints

from refinery.lib.scripts.js.options import ExecutionModel

DECLARATORS: dict[str, Program] = {
    'later declarator reads earlier': Program(
        a_program("""
            function f() { var s = 'a|b|c', t = s.split('|'), u = t[1]; return u; }
            console.log(f());
            """),
        prints('b'),
        Reading.COMMONJS,
    ),
    'middle declarator rewrites the first': Program(
        a_program("""
            function f() { var s = 'x', t = (s = 'y'), u = s + t; return u; }
            console.log(f());
            """),
        prints('yy'),
        Reading.COMMONJS,
    ),
    'middle declarator throws in try': Program(
        a_program("""
            function f() { var a = 1; try { var a = 2, b = null.x, c = a; } catch (e) { return a + ':' + c; } }
            console.log(f());
            """),
        prints('2:undefined'),
        Reading.COMMONJS,
    ),
    'loop reads a later declarator of the last iteration': Program(
        a_program("""
            function f() {
              var r = [];
              for (var i = 0; i < 2; i++) { var a = i ? b : 'first', b = 'second'; r.push(a); }
              return r.join();
            }
            console.log(f());
            """),
        prints('first,second'),
        Reading.COMMONJS,
    ),
    'let reads a later let': Program(
        a_program("""
            function f() { try { let a = b, b = 1; return a; } catch (e) { return e.name; } }
            console.log(f());
            """),
        prints('ReferenceError'),
        Reading.COMMONJS,
    ),
    'let reads an earlier let': Program(
        a_program("""
            function f() { let a = 'p', b = a + 'q'; return b; }
            console.log(f());
            """),
        prints('pq'),
        Reading.COMMONJS,
    ),
    'a closure called in a declarator writes an earlier one': Program(
        a_program("""
            function f() { var g = function () { s = 'z'; }, s = 'x', t = (g(), s); return t; }
            console.log(f());
            """),
        prints('z'),
        Reading.COMMONJS,
    ),
    'a declarator reads a later var before it is stored': Program(
        a_program("""
            function f() { var a = b, b = 'v'; return typeof a; }
            console.log(f());
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'first store dead behind the second declarator': Program(
        a_program("""
            function f() { var a = 1, b = (a = 2, a); return b; }
            console.log(f());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'declarators at the top of a file': Program(
        a_program("""
            var s = 'a', t = s + 'b';
            console.log(t);
            """),
        prints('ab'),
        Reading.COMMONJS,
    ),
    'declarators under a case': Program(
        a_program("""
            switch (1) { case 1: var s = 'm', t = s + 'n'; console.log(t); }
            """),
        prints('mn'),
        Reading.COMMONJS,
    ),
    'a getter run by a declarator writes an earlier one': Program(
        a_program("""
            function f() {
              var o = { get k() { s = 'g'; return 1; } };
              var s = 'x', n = o.k, t = s;
              return t + n;
            }
            console.log(f());
            """),
        prints('g1'),
        Reading.COMMONJS,
    ),
    'a declarator throws, the handler reads the one before': Program(
        a_program("""
            function f() {
              var t = 'none';
              try { var s = 'set', u = JSON.parse('{'), w = 1; } catch (e) { t = s; }
              return t;
            }
            console.log(f());
            """),
        prints('set'),
        Reading.COMMONJS,
    ),
    'const chain': Program(
        a_program("""
            function f() { const a = 'k', b = a.toUpperCase(), c = b + b; return c; }
            console.log(f());
            """),
        prints('KK'),
        Reading.COMMONJS,
    ),
    'for head declarators': Program(
        a_program("""
            function f() { var r = ''; for (var i = 0, s = 'x' + i; i < 2; i++) r += s; return r; }
            console.log(f());
            """),
        prints('x0x0'),
        Reading.COMMONJS,
    ),
    'generator yields between declarators': Program(
        a_program("""
            function* g() { var a = 'a', b = yield a, c = a + b; return c; }
            var it = g(); it.next(); console.log(it.next('b').value);
            """),
        prints('ab'),
        Reading.COMMONJS,
    ),
    'a var repeated in one declaration': Program(
        a_program("""
            function f() { var a = 'one', a = a + 'two'; return a; }
            console.log(f());
            """),
        prints('onetwo'),
        Reading.COMMONJS,
    ),
    'effect order across declarators': Program(
        a_program("""
            function f() {
              var log = [];
              var a = (log.push('a'), 1), b = (log.push('b'), 2), c = a + b;
              return log.join('') + c;
            }
            console.log(f());
            """),
        prints('ab3'),
        Reading.COMMONJS,
    ),
    'iife in middle rewrites earlier': Program(
        a_program("""
            var s = 'x', t = (function () { s = 'y'; return s; })(), u = s;
            console.log(s, t, u);
            """),
        prints('y y y'),
        Reading.COMMONJS,
    ),
    'getter in last declarator rewrites earlier': Program(
        a_program("""
            function f() {
              var o = { get k() { a = 2; return 0; } };
              var a = 1, b = o.k + a;
              return b;
            }
            console.log(f());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'valueof in last declarator': Program(
        a_program("""
            function f() {
              var a = 1, b = '' + { valueOf: function () { a = 3; return 0; } } + a;
              return b;
            }
            console.log(f());
            """),
        prints('03'),
        Reading.COMMONJS,
    ),
    'let closure reads later let': Program(
        a_program("""
            function f() {
              try {
                let g = function () { return b; }, a = g(), b = 1;
                return a;
              } catch (e) {
                return e.name;
              }
            }
            console.log(f());
            """),
        prints('ReferenceError'),
        Reading.COMMONJS,
    ),
    'dead first store read by closure in middle': Program(
        a_program("""
            function f() {
              var a = 'first', b = read(), a = 'second';
              function read() { return a; }
              return b + a;
            }
            console.log(f());
            """),
        prints('firstsecond'),
        Reading.COMMONJS,
    ),
    'increment between': Program(
        a_program("""
            function f() {
              var a = 1, b = (a++, a), c = a;
              return [a, b, c].join();
            }
            console.log(f());
            """),
        prints('2,2,2'),
        Reading.COMMONJS,
    ),
    'tostring conversion in middle writes earlier': Program(
        a_program("""
            function f() {
              var s = 'x', o = { toString: function () { s = 'z'; return 'k'; } }, key = String(o), t = s;
              return key + t;
            }
            console.log(f());
            """),
        prints('kz'),
        Reading.COMMONJS,
    ),
    'declarators in a loop closures': Program(
        a_program("""
            function f() {
              var fs = [];
              for (var i = 0; i < 3; i++) {
                var a = i, g = function () { return a; };
                fs.push(g);
              }
              return fs.map(function (h) { return h(); }).join();
            }
            console.log(f());
            """),
        prints('2,2,2'),
        Reading.COMMONJS,
    ),
    'declarator reads earlier then store dead': Program(
        a_program("""
            function f(p) {
              var a = p, b = a + 1, a = 7;
              return [a, b].join();
            }
            console.log(f(1));
            """),
        prints('7,2'),
        Reading.COMMONJS,
    ),
    'throwing middle declarator finally': Program(
        a_program("""
            function f() {
              var log = '';
              try {
                var a = 'A', b = null.q, c = 'C';
              } catch (e) {
                log += typeof a + typeof c;
              } finally {
                log += a;
              }
              return log;
            }
            console.log(f());
            """),
        prints('stringundefinedA'),
        Reading.COMMONJS,
    ),
    'unused declarator with effect': Program(
        a_program("""
            function f() {
              var n = 0;
              var a = n++, b = n++, c = n;
              return c;
            }
            console.log(f());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'global alias store across declarators': Program(
        a_program("""
            var g = 'one', h = (globalThis.g = 'two', g);
            console.log(g, h);
            """),
        prints('one one'),
        Reading.COMMONJS,
    ),
    'arguments mapped separate statements': Program(
        a_program("""
            function f(a) {
              var x = arguments[0];
              a = 5;
              var y = arguments[0];
              return [x, y, a].join();
            }
            console.log(f(1));
            """),
        prints('1,5,5'),
        Reading.COMMONJS,
    ),
    'label switch declarations': Program(
        a_program("""
            function f(k) {
              switch (k) {
                case 1:
                  var a = 'p', b = a + 'q';
                case 2:
                  var c = typeof a + b;
                  return c;
              }
            }
            console.log(f(1), f(2));
            """),
        prints('stringpq undefinedundefined'),
        Reading.COMMONJS,
    ),
    'single use init moved past effect': Program(
        a_program("""
            function f() {
              var out = [];
              function note(v) { out.push(v); return v; }
              var a = note('1'), b = note('2'), c = a;
              return out.join('') + c;
            }
            console.log(f());
            """),
        prints('121'),
        Reading.COMMONJS,
    ),
    'call between declarators writes global': Program(
        a_program("""
            var shared = 'before';
            function bump() { shared = 'after'; return 0; }
            function f() {
              var a = shared, b = bump(), c = a + shared;
              return c;
            }
            console.log(f());
            """),
        prints('beforeafter'),
        Reading.COMMONJS,
    ),
    'delete between declarators property read': Program(
        a_program("""
            function f() {
              var o = { k: 'v' }, r = o.k, d = delete o.k, q = o.k;
              return [r, q].join();
            }
            console.log(f());
            """),
        prints('v,'),
        Reading.COMMONJS,
    ),
    'property write between declarators': Program(
        a_program("""
            function f() {
              var o = { k: 'v' }, r = o.k, w = (o.k = 'w'), q = o.k;
              return [r, q].join();
            }
            console.log(f());
            """),
        prints('v,w'),
        Reading.COMMONJS,
    ),
    'array push between declarators': Program(
        a_program("""
            function f() {
              var a = [1], n = a.length, p = a.push(2), m = a.length;
              return [n, m].join();
            }
            console.log(f());
            """),
        prints('1,2'),
        Reading.COMMONJS,
    ),
    'catch reads earlier rewritten by throwing': Program(
        a_program("""
            function thrower() { throw new Error('x'); }
            function f() {
              try {
                var a = 1, b = (a = 2, thrower()), c = 3;
              } catch (e) {
                return [a, typeof c].join();
              }
            }
            console.log(f());
            """),
        prints('2,undefined'),
        Reading.COMMONJS,
    ),
    'dead store redeclared': Program(
        a_program("""
            function f(p) {
              var a = p * 2, b = a, a = 2;
              return b + a;
            }
            console.log(f(5));
            """),
        prints('12'),
        Reading.COMMONJS,
    ),
    'closure sees later redeclaration': Program(
        a_program("""
            function f() {
              var a = 1, g = function () { return a; }, a = 2;
              return g();
            }
            console.log(f());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'tamper in later declarator': Program(
        a_program("""
            function f() {
              var s = 'ab'.toUpperCase(), t = (String.prototype.toUpperCase = function () { return 'X'; }, 0), u = 'cd'.toUpperCase();
              return s + u;
            }
            console.log(f());
            """),
        prints('ABX'),
        Reading.COMMONJS,
    ),
    'tamper by call in earlier declarator': Program(
        a_program("""
            function patch() { String.prototype.toUpperCase = function () { return 'Y'; }; return 1; }
            function f() {
              var p = patch(), u = 'cd'.toUpperCase();
              return u + p;
            }
            console.log(f());
            """),
        prints('Y1'),
        Reading.COMMONJS,
    ),
    'tamper getter in last declarator': Program(
        a_program("""
            function f(o) {
              var s = 'ab'.toUpperCase(), u = o.k + 'cd'.toUpperCase();
              return s + u;
            }
            console.log(f({ get k() { String.prototype.toUpperCase = function () { return 'Z'; }; return ''; } }));
            """),
        prints('ABZ'),
        Reading.COMMONJS,
    ),
    'tamper in earlier declarator fold later': Program(
        a_program("""
            var S = String;
            function f(k) {
              var p = S[k], q = (p.toUpperCase = function () { return 'Q'; }), u = 'cd'.toUpperCase();
              return u;
            }
            console.log(f('prototype'));
            """),
        prints('Q'),
        Reading.COMMONJS,
    ),
}

FOLDED: dict[str, str] = {
    'declarators at the top of a file': "console.log('ab');",
    'declarators under a case': inspect.cleandoc(
        """
            switch (1) {
              case 1:
                console.log('mn');
            }
        """
    ),
}

UNWRAPPED: dict[str, str] = {
    'declarators under a case': "console.log('mn');",
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeclaratorsInOrderBehaveAsTheyDid(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in DECLARATORS.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in DECLARATORS.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestALaterDeclaratorReadsAnEarlierOne(TestBase):

    def test_the_declarators_at_the_top_of_a_file_and_under_a_case_fold(self):
        for label, folded in FOLDED.items():
            with self.subTest(label=label):
                self.assertIn(
                    deobfuscate_source(DECLARATORS[label].text, execution=ExecutionModel.commonjs),
                    (folded, UNWRAPPED.get(label, folded)),
                )

    @opportunity
    def test_a_switch_on_a_constant_around_the_folded_declarators_goes(self):
        self.assertEqual(
            {
                label: deobfuscate_source(DECLARATORS[label].text, execution=ExecutionModel.commonjs)
                for label in UNWRAPPED
            },
            UNWRAPPED,
        )
