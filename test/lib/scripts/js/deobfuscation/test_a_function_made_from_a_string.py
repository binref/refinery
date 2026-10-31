"""
Functions a program makes from strings and calls through an array: a flag computed by a function
from the default of its parameter, a function that runs the text it is handed as a direct `eval`,
the functions that text declares and answers, and functions left forwarding their calls to the
element of an array that holds one of those. Each program is written by hand, and each row says
what Node prints for it run as a CommonJS file.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
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


#: Calls of functions whose parameters have defaults, with what Node prints for each.
DEFAULTED_PARAMETERS: dict[str, Program] = {
    'a flag given by its default': Program(
        a_program("""
            function f(flag = true) { return flag; }
            var g = f();
            console.log(g, f(false), f(null));
            """),
        prints('true false null'),
        Reading.COMMONJS,
    ),
    'a default reading the parameter before it': Program(
        a_program("""
            function f(a, b = a + 1) { return b; }
            console.log(f(1), f(1, 7));
            """),
        prints('2 7'),
        Reading.COMMONJS,
    ),
    'a default reading the parameter after it': Program(
        a_program("""
            function h(a = b, b = 1) { return a; }
            try { console.log(h()); } catch (e) { console.log(e.name); }
            """),
        prints('ReferenceError'),
        Reading.COMMONJS,
    ),
    'a default reading a name the body declares again': Program(
        a_program("""
            var x = 5;
            function k(a = x) { var x = 2; return a + x; }
            console.log(k());
            """),
        prints('7'),
        Reading.COMMONJS,
    ),
    'a default holding a function over the parameters': Program(
        a_program("""
            function m(a = () => b, b = 3) { var b = 4; return a(); }
            console.log(m());
            """),
        prints('3'),
        Reading.COMMONJS,
    ),
    'a default with an effect': Program(
        a_program("""
            var n = 0;
            function s(a = n++) { return a; }
            s();
            s(5);
            console.log(n);
            """),
        prints('1'),
        Reading.COMMONJS,
    ),
    'an arguments object beside a default': Program(
        a_program("""
            function u(a = 1) { a = 2; return arguments[0]; }
            console.log(u(5), u());
            """),
        prints('5 undefined'),
        Reading.COMMONJS,
    ),
    'a default reading this': Program(
        a_program("""
            function t(a = this) { return typeof a; }
            console.log(t());
            """),
        prints('object'),
        Reading.COMMONJS,
    ),
}

#: Calls of a function that answers the direct `eval` of its parameter, with what Node prints for
#: each: texts that declare a function and answer it, or answer a value, and texts that read what
#: the function's own scope holds, write the name of the function they declare, or declare more.
CALLS_RUNNING_THEIR_ARGUMENT: dict[str, Program] = {
    'a call after eval was replaced under a key the run computes': Program(
        a_program("""
            function w(code) { return eval(code); }
            var k = 'ev' + 'al';
            globalThis[k] = function () { return 'replaced'; };
            console.log(w('1 + 1'));
            """),
        prints('replaced'),
        Reading.COMMONJS,
    ),
    'a text whose function reads a name of the function running it by a direct eval': Program(
        a_program("""
            function W(code) { return eval(code); }
            var code = 'outer';
            var X = W("function E() { return eval('code'); } E;");
            console.log(X());
            """),
        prints("function E() { return eval('code'); } E;"),
        Reading.COMMONJS,
    ),
    'a text whose function reads the type of such a name by a direct eval': Program(
        a_program("""
            function W(code) { return eval(code); }
            var X = W("function E() { return eval('typeof code'); } E;");
            console.log(X());
            """),
        prints('string'),
        Reading.COMMONJS,
    ),
    'a text whose function runs its argument by a direct eval': Program(
        a_program("""
            function W(code) { return eval(code); }
            var code = 'outer';
            var X = W("function E(s) { return eval(s); } E;");
            console.log(X('code'));
            """),
        prints('function E(s) { return eval(s); } E;'),
        Reading.COMMONJS,
    ),
    'a function the text declares and answers': Program(
        a_program("""
            var A = [W("function E() { var [a, b] = arguments; return a + b.length; } E;")];
            console.log(A[0](1, [2, 3]));
            function W(code) { return eval(code); }
            """),
        prints('3'),
        Reading.COMMONJS,
    ),
    'a strict text': Program(
        a_program("""
            var S = W('"use strict"; function E() { return typeof this; } E;');
            console.log(S());
            function W(code) { return eval(code); }
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'a sloppy text reading this': Program(
        a_program("""
            var S = W('function E() { return typeof this; } E;');
            console.log(S());
            function W(code) { return eval(code); }
            """),
        prints('object'),
        Reading.COMMONJS,
    ),
    'a sloppy text run by a strict function': Program(
        a_program("""
            function W(code) { 'use strict'; return eval(code); }
            var S = W('function E() { return typeof this; } E;');
            console.log(S());
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'a value the text computes': Program(
        a_program("""
            console.log(W('6 * 7'));
            function W(code) { return eval(code); }
            """),
        prints('42'),
        Reading.COMMONJS,
    ),
    'a text reading the parameter of the function running it': Program(
        a_program("""
            var code = 'outer';
            var A = W("function E() { return code; } E;");
            console.log(A());
            function W(code) { return eval(code); }
            """),
        prints('function E() { return code; } E;'),
        Reading.COMMONJS,
    ),
    'a text whose function writes its own name': Program(
        a_program("""
            var A = W("function E() { E = 5; return typeof E; } E;");
            console.log(A(), A());
            function W(code) { return eval(code); }
            """),
        prints('number number'),
        Reading.COMMONJS,
    ),
    'a text whose function writes its own name through eval': Program(
        a_program("""
            var A = W("function E() { eval('E = 5'); return typeof E; } E;");
            console.log(A());
            function W(code) { return eval(code); }
            """),
        prints('number'),
        Reading.COMMONJS,
    ),
    'a name the call site binds otherwise': Program(
        a_program("""
            var v = ['outer'][0 * Date.now()];
            function g() { var v = ['inner'][0 * Date.now()]; return [W("function E() { return v; } E;"), v]; }
            var [e, w] = g();
            console.log(e(), w, v);
            function W(code) { return eval(code); }
            """),
        prints('outer inner outer'),
        Reading.COMMONJS,
    ),
    'a text declaring a var': Program(
        a_program("""
            console.log(W("var q = 1; q + 1"));
            function W(code) { return eval(code); }
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'two calls with one text': Program(
        a_program("""
            var a = W("function E() {} E;"), b = W("function E() {} E;");
            console.log(a === b, typeof a);
            function W(code) { return eval(code); }
            """),
        prints('false function'),
        Reading.COMMONJS,
    ),
    'a call passing another argument': Program(
        a_program("""
            var n = 0;
            console.log(W("1 + 1", n++), n);
            function W(code) { return eval(code); }
            """),
        prints('2 1'),
        Reading.COMMONJS,
    ),
    'a function replaced before the call': Program(
        a_program("""
            function W(code) { return eval(code); }
            W = function () { return 'replaced'; };
            console.log(W("1 + 1"));
            """),
        prints('replaced'),
        Reading.COMMONJS,
    ),
}

#: Functions forwarding their calls to an element of an array, which forwards them to a function it
#: declares, with what Node prints for each.
FORWARDERS_THROUGH_AN_ARRAY: dict[str, Program] = {
    'a forwarder whose apply the program replaced through getPrototypeOf': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function R(a) { return a * 2; } return R.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            Object.getPrototypeOf(g).apply = function () { return 'replaced'; };
            console.log(g(4));
            """),
        prints('replaced'),
        Reading.COMMONJS,
    ),
    'a forwarder whose apply the program replaced through __proto__': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function R(a) { return a * 2; } return R.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            g.__proto__.apply = function () { return 'replaced'; };
            console.log(g(4));
            """),
        prints('replaced'),
        Reading.COMMONJS,
    ),
    'a forwarder whose apply the program replaced through a prototype it hands on': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function R(a) { return a * 2; } return R.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            function tamper(p) { p.apply = function () { return 'replaced'; }; }
            tamper(Object.getPrototypeOf(g));
            console.log(g(4));
            """),
        prints('replaced'),
        Reading.COMMONJS,
    ),
    'a forwarder of the arguments': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function f(a, b) { return a + b; } return f.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            console.log(g(1, 2), g('a', 'b'));
            """),
        prints('3 ab'),
        Reading.COMMONJS,
    ),
    'a forwarder of the receiver': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function f() { return this.k; } return f.apply(this, args); }];
            var o = { k: 'own', m: function () { return T[0].apply(this, [T, arguments]); } };
            console.log(o.m());
            """),
        prints('own'),
        Reading.COMMONJS,
    ),
    'a strict function reading this, forwarded from sloppy code': Program(
        a_program("""
            var T = [function () { 'use strict'; var [t, args] = arguments; function f() { return typeof this; } return f.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            console.log(g());
            """),
        prints('object'),
        Reading.COMMONJS,
    ),
    'two forwarders of one element': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function f(a) { return a * 2; } return f.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            function h() { return T[0].apply(this, [T, arguments]); }
            console.log(g(2), h(3));
            """),
        prints('4 6'),
        Reading.COMMONJS,
    ),
    'an array the program writes': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function f() { return 1; } return f.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            T[0] = function () { return 2; };
            console.log(g());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'a forwarder called before the array holds the element': Program(
        a_program("""
            try { console.log(g()); } catch (e) { console.log(e.name); }
            var T = [function () { var [t, args] = arguments; function f() { return 1; } return f.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            console.log(g());
            """),
        prints('TypeError', '1'),
        Reading.COMMONJS,
    ),
    'a name the forwarder sees bound otherwise': Program(
        a_program("""
            var v = ['outer'][0 * Date.now()];
            var T = [function () { var [t, args] = arguments; function f() { return v; } return f.apply(this, args); }];
            function outer() { var v = ['inner'][0 * Date.now()]; function g() { return T[0].apply(this, [T, arguments]); } return g() + v; }
            console.log(outer());
            """),
        prints('outerinner'),
        Reading.COMMONJS,
    ),
    'a forwarder whose length is read': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function f(a, b) { return a + b; } return f.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            console.log(g.length, g(1, 2));
            """),
        prints('0 3'),
        Reading.COMMONJS,
    ),
    'a forwarder constructed with new': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function f(a) { this.a = a; return 1; } return f.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            console.log(new g(4).a);
            """),
        prints('4'),
        Reading.COMMONJS,
    ),
    'a forwarded function reading new.target': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function f() { return typeof new.target; } return f.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            console.log(new g() instanceof g, g());
            """),
        prints('true undefined'),
        Reading.COMMONJS,
    ),
    'a forwarded function writing a parameter its arguments object reads': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function f(a) { a = 2; return arguments[0]; } return f.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            console.log(g(1));
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'a forwarder in strict code to a sloppy function reading this': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function f() { return typeof this; } return f.apply(this, args); }];
            function g() { 'use strict'; return T[0].apply(this, [T, arguments]); }
            console.log(g());
            """),
        prints('object'),
        Reading.COMMONJS,
    ),
    'a strict function writing a parameter its arguments object reads, forwarded from sloppy code': Program(
        a_program("""
            var T = [function () { 'use strict'; var [t, args] = arguments; function f(a) { a = 2; return arguments[0]; } return f.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            console.log(g(1));
            """),
        prints('1'),
        Reading.COMMONJS,
    ),
    'a getter forwarding to a function with a parameter': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function f(a) { return typeof a; } return f.apply(this, args); }];
            var o = { get k() { return T[0].apply(this, [T, arguments]); } };
            console.log(o.k);
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'an element reading the array it is handed': Program(
        a_program("""
            var T = [function () { var [t, args] = arguments; function f() { return t.length; } return f.apply(this, args); }];
            function g() { return T[0].apply(this, [T, arguments]); }
            console.log(g());
            """),
        prints('1'),
        Reading.COMMONJS,
    ),
}

#: The three together: a flag computed from a default, the function running text that declares the
#: functions of an array, and forwarders to its elements, one of which a function calls and throws
#: the result of away. Node prints `5` for it.
ALL_THREE = a_program("""
    function integrity(flag = true) { return flag; }
    var ok = integrity();
    var T = [W("function E0() { var [t, args] = arguments; function add(a, b) { return a + b; } return add.apply(this, args); } E0;"), W('"use strict"; function E1() { var [t, args] = arguments; function check() { return void 0; } return check.apply(this, args); } E1;')];
    function sum() { return T[0].apply(this, [T, arguments]); }
    class C { m() { (function () { return T[1].apply(this, [T, arguments]); })(); return sum(2, 3); } }
    console.log(new C().m());
    function W(code) { if (ok) { return eval(code); } }
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionMadeFromAStringStillPrintsWhatItPrints(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for rows in (DEFAULTED_PARAMETERS, CALLS_RUNNING_THEIR_ARGUMENT, FORWARDERS_THROUGH_AN_ARRAY):
            for label, row in rows.items():
                with self.subTest(label=label):
                    self.assertEqual(row.behaves(), row.prints)
        self.assertEqual(behavior(ALL_THREE), prints('5'))

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for rows in (DEFAULTED_PARAMETERS, CALLS_RUNNING_THEIR_ARGUMENT, FORWARDERS_THROUGH_AN_ARRAY):
            for label, row in rows.items():
                for reading in (Reading.COMMONJS, Reading.MODULE):
                    program = row._replace(reading=reading)
                    with self.subTest(label=label, reading=reading.name):
                        self.assertEqual(program.read(), program.required())

    def test_each_program_still_prints_it_where_the_unit_trusts_eval(self):
        for rows in (DEFAULTED_PARAMETERS, CALLS_RUNNING_THEIR_ARGUMENT, FORWARDERS_THROUGH_AN_ARRAY):
            for label, row in rows.items():
                with self.subTest(label=label):
                    self.assertEqual(behavior(deobfuscated_by_the_unit(row.text)), row.prints)

    def test_all_three_together_still_print_it_where_the_unit_trusts_eval(self):
        self.assertEqual(behavior(deobfuscated_by_the_unit(ALL_THREE)), prints('5'))


class TestAFunctionMadeFromAStringIsWrittenOut(TestBase):

    def test_a_flag_given_by_its_default_is_computed(self):
        self.assertEqual(
            deobfuscate_source(
                DEFAULTED_PARAMETERS['a flag given by its default'].text,
                execution=ExecutionModel.commonjs,
            ),
            'console.log(true, false, null);',
        )

    def test_each_text_declaring_and_answering_a_function_becomes_that_function(self):
        self.assertEqual(
            deobfuscated_by_the_unit(
                CALLS_RUNNING_THEIR_ARGUMENT['a function the text declares and answers'].text,
            ),
            a_program("""
                var A = [function E() {
                  var [a, b] = arguments;
                  return a + b.length;
                }];
                console.log(A[0](1, [2, 3]));
                """).rstrip(),
        )

    def test_a_strict_text_becomes_a_strict_function(self):
        self.assertEqual(
            deobfuscated_by_the_unit(CALLS_RUNNING_THEIR_ARGUMENT['a strict text'].text),
            a_program("""
                var S = function E() {
                  "use strict";
                  return typeof this;
                };
                console.log(S());
                """).rstrip(),
        )

    def test_a_text_the_scope_of_its_function_decides_stays_a_string(self):
        for label in (
            'a sloppy text run by a strict function',
            'a text reading the parameter of the function running it',
            'a text whose function writes its own name',
            'a name the call site binds otherwise',
            'a text declaring a var',
            'a call passing another argument',
            'a function replaced before the call',
        ):
            with self.subTest(label=label):
                self.assertIn('eval(', deobfuscated_by_the_unit(CALLS_RUNNING_THEIR_ARGUMENT[label].text))

    def test_a_forwarder_of_the_arguments_takes_the_function_back(self):
        self.assertEqual(
            deobfuscate_source(
                FORWARDERS_THROUGH_AN_ARRAY['a forwarder of the arguments'].text,
                execution=ExecutionModel.commonjs,
            ),
            "console.log(3, 'ab');",
        )

    def test_a_forwarder_of_the_receiver_takes_the_function_back(self):
        self.assertEqual(
            deobfuscate_source(
                FORWARDERS_THROUGH_AN_ARRAY['a forwarder of the receiver'].text,
                execution=ExecutionModel.commonjs,
            ),
            a_program("""
                var o = { k: 'own', m: function() {
                  return this.k;
                } };
                console.log(o.m());
                """).rstrip(),
        )

    def test_a_forwarder_the_function_cannot_replace_stays(self):
        for label in (
            'a strict function reading this, forwarded from sloppy code',
            'two forwarders of one element',
            'an array the program writes',
            'a forwarder called before the array holds the element',
            'a name the forwarder sees bound otherwise',
            'a forwarded function reading new.target',
            'a forwarder in strict code to a sloppy function reading this',
            'a getter forwarding to a function with a parameter',
            'an element reading the array it is handed',
        ):
            with self.subTest(label=label):
                text = deobfuscate_source(
                    FORWARDERS_THROUGH_AN_ARRAY[label].text,
                    execution=ExecutionModel.commonjs,
                )
                self.assertIn('.apply(this, [T, arguments])', text)

    def test_all_three_together_leave_the_program(self):
        self.assertEqual(
            deobfuscated_by_the_unit(ALL_THREE),
            a_program("""
                class C {
                  m() {
                    return 5;
                  }
                }
                console.log(new C().m());
                """).rstrip(),
        )
