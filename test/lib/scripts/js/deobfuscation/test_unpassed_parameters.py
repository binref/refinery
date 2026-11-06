"""
Parameters no call passes, which an obfuscation that moves the declarations of a function into its
parameter list leaves at the end of the list: a function stored under `if (!p)`, a `var` whose value
is made of literals as a default, and any other `var` as a plain parameter.

SECURITY: every program run through Node here is hand-authored and benign. The file read from the
sample store is deobfuscated and compared as text, and never run.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import behavior, deobfuscate_source, node_executable
from test.lib.scripts.js.deobfuscation.test_a_table_read_through_an_accessor import deobfuscated_by_the_unit
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import (
    JsAssignmentPattern,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
)
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser


def deobfuscated(source: str) -> str:
    return deobfuscate_source(source, execution=ExecutionModel.commonjs, environment=HostEnvironment.node)


A_PROGRAM_CALLING_OR_READING_A_PROPERTY_OF_FUNCTION = (
    'new Function("return this")(); function f(a, p) {} f.call(null, 1);',
    'Function.prototype.toString.call(g); function f(a, p) {} f.call(null, 1);',
)


class TestTheModelAnswersWhetherACallPassesAParameter(TestBase):

    @staticmethod
    def _never_passed(source: str, trusting: bool = False) -> dict[str, bool]:
        model = build_semantic_model(JsParser(source).parse(), trust_eval=trusting)
        function = next(node for node in model.root.walk() if isinstance(node, JsFunctionDeclaration))
        answers = {}
        for parameter in function.params:
            if isinstance(parameter, JsAssignmentPattern):
                parameter = parameter.left
            assert isinstance(parameter, JsIdentifier)
            binding = model.binding_of(parameter)
            assert binding is not None
            answers[parameter.name] = model.parameter_never_passed(binding)
        return answers

    def test_a_parameter_after_the_arguments_of_every_call_is_never_passed(self):
        self.assertEqual(self._never_passed('function f(a, p) {} f(1); f(2);'), {'a': False, 'p': True})

    def test_a_parameter_with_a_default_is_never_passed_alike(self):
        self.assertEqual(self._never_passed('function f(a, p = 1) {} f(1);'), {'a': False, 'p': True})

    def test_a_call_passing_the_parameter_passes_it(self):
        self.assertEqual(self._never_passed('function f(a, p) {} f(1); f(1, 2);'), {'a': False, 'p': False})

    def test_a_spread_at_or_before_the_position_may_pass_it(self):
        for source in ('function f(a, p) {} f(...xs);', 'function f(a, p) {} f(1, ...xs);'):
            with self.subTest(source=source):
                self.assertEqual(self._never_passed(source), {'a': False, 'p': False})

    def test_a_function_handed_on_has_calls_the_text_does_not_show(self):
        self.assertEqual(self._never_passed('function f(a, p) {} f(1); g(f);'), {'a': False, 'p': False})

    def test_a_function_nothing_calls_passes_nothing_the_answer_could_rest_on(self):
        self.assertEqual(self._never_passed('function f(a, p) {}'), {'a': False, 'p': False})

    def test_a_call_through_call_or_apply_passes_what_follows_the_receiver(self):
        for source in (
            'function f(a, p) {} f.call(null, 1);',
            'function f(a, p) {} f.apply(null, [1]);',
            'function f(a, p) {} f.call(null, 1); f.apply(null);',
        ):
            with self.subTest(source=source):
                self.assertEqual(self._never_passed(source), {'a': False, 'p': True})

    def test_apply_of_a_list_not_written_out_or_a_spread_receiver_may_pass_any_parameter(self):
        for source in (
            'function f(a, p) {} f.apply(null, xs);',
            'function f(a, p) {} f.apply(null, [1, , 2]);',
            'function f(a, p) {} f.call(...xs);',
        ):
            with self.subTest(source=source):
                self.assertEqual(self._never_passed(source), {'a': False, 'p': False})

    def test_a_call_the_program_may_have_replaced_shows_no_call(self):
        for source in (
            'Object.getPrototypeOf(function () {}).call = g; function f(a, p) {} f.call(null, 1);',
            'Function.prototype.call = g; function f(a, p) {} f.call(null, 1);',
            'var F = Function; F.prototype.apply = g; function f(a, p) {} f.apply(null, [1]);',
        ):
            for trusting in (False, True):
                with self.subTest(source=source, trusting=trusting):
                    self.assertEqual(self._never_passed(source, trusting), {'a': False, 'p': False})

    def test_calling_or_reading_a_property_of_function_shows_the_call_to_the_trusting_model(self):
        for source in A_PROGRAM_CALLING_OR_READING_A_PROPERTY_OF_FUNCTION:
            with self.subTest(source=source):
                self.assertEqual(self._never_passed(source, True), {'a': False, 'p': True})

    @opportunity
    def test_calling_or_reading_a_property_of_function_shows_the_call_to_the_suspecting_model(self):
        for source in A_PROGRAM_CALLING_OR_READING_A_PROPERTY_OF_FUNCTION:
            with self.subTest(source=source):
                self.assertEqual(self._never_passed(source, False), {'a': False, 'p': True})


class TestTheModelAnswersWhetherACallThroughATablePassesAParameter(TestBase):

    @staticmethod
    def _never_passed(source: str) -> bool:
        model = build_semantic_model(JsParser(source).parse())
        entry = next(
            node for node in model.root.walk()
            if isinstance(node, JsFunctionExpression) and node.params
        )
        parameter = entry.params[0]
        assert isinstance(parameter, JsIdentifier)
        binding = model.binding_of(parameter)
        assert binding is not None
        return model.parameter_never_passed(binding)

    def test_an_entry_no_call_through_its_table_passes_an_argument_to_is_never_passed(self):
        for source in (
            'var t; t = {f: function (p) {}}; function d(k) { return t[k](); } d("f");',
            'var t = {f: function (p) {}}; function d(k) { return t[k].apply(this); } d("f");',
            'var t = {f: function (p) {}}; t.f(); t["f"].call(null);',
            'var t = {f: function (p) {}, g: () => this}; t.f(); if (t) t.g();',
            'function d(k, t) { t = {f: function (p) {}}; return t[k](); } d("f", 1);',
        ):
            with self.subTest(source=source):
                self.assertTrue(self._never_passed(source))

    def test_an_entry_a_call_through_its_table_may_pass_an_argument_to_is_passed(self):
        for source in (
            'var t = {f: function (p) {}}; function d(k, v) { return t[k](v); } d("f");',
            'var t = {f: function (p) {}}; function d(k, v) { return t[k].apply(null, v); } d("f", [1]);',
            'var t = {f: function (p) {}}; function d(k, v) { return t[k].call(null, v); } d("f");',
            'var t = {f: function (p) {}}; t.f(); new t.f(1);',
        ):
            with self.subTest(source=source):
                self.assertFalse(self._never_passed(source))

    def test_an_entry_called_under_a_key_only_the_run_knows_is_never_passed_only_where_such_a_key_is_taken_for_its_own(self):
        source = 'var t = {f: function (p) {}}; function d(k) { return t[k](); } d(input());'
        model = build_semantic_model(JsParser(source).parse())
        entry = next(node for node in model.root.walk() if isinstance(node, JsFunctionExpression))
        parameter = entry.params[0]
        assert isinstance(parameter, JsIdentifier)
        binding = model.binding_of(parameter)
        assert binding is not None
        self.assertEqual(
            (model.parameter_never_passed(binding), model.parameter_never_passed(binding, own_keys=True)),
            (False, True),
        )

    def test_an_entry_of_a_table_that_may_be_handed_on_has_calls_the_text_does_not_show(self):
        for source in (
            'var t = {f: function (p) {}}; t.f(); g(t);',
            'var t = {f: function (p) {}}; t.f(); var h = t.f; g(h);',
            'var t = {f: function (p) {}}; t.f(); g(t.valueOf());',
            'var t = {f: function (p) {}, g: function () { return this; }}; t.f(); h(t.g());',
            'var t = {f: function (p) {}, g() { return super.valueOf(); }}; t.f(); h(t.g());',
            'var t = {f: function (p) {}, get g() { return this; }}; t.f(); h(t.g);',
            'var t = {f: function (p) {}, ...o}; t.f();',
            'var t = {f: function (p) {}, g: h}; t.f();',
        ):
            with self.subTest(source=source):
                self.assertFalse(self._never_passed(source))

    @opportunity
    def test_an_entry_of_a_table_no_code_can_hand_on_with_an_argument_is_never_passed(self):
        for source in (
            'var t = {f: function (p) {}}; t.f(); var h = t.f;',
            'var t = {f: function (p) {}}; t.f(); t.f.x = 1;',
            'var t = {f: function (p) {}}; t.f(); t.valueOf();',
            'var t = {f: function (p) {}, g: function () { return this; }}; t.f();',
            'var t = {f: function (p) {}, g() { return super.valueOf(); }}; t.f();',
            'var t = {f: function (p) {}, get g() { return 1; }}; t.f();',
            'g({f: function (p) {}}.f());',
            'var t = {f: function (p) {}}; function d(k, v) { return t[k].apply(null, v); } d("f", []);',
        ):
            with self.subTest(source=source):
                self.assertTrue(self._never_passed(source))


UNPASSED: dict[str, Program] = {
    'a moved function declaration': Program(
        a_program("""
            function parse(source, decode) {
              if (!decode) {
                decode = function (n) {
                  return 'abcdef'.slice(n, n + 2);
                };
              }
              console.log(decode(1), decode(source));
            }
            parse(2);
            parse(3);
            """),
        prints('bc cd', 'bc de'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the parameter read before the store': Program(
        a_program("""
            function f(a, p) {
              console.log(typeof p);
              if (!p) {
                p = function () { return a; };
              }
              return p();
            }
            console.log(f(1), f(2));
            """),
        prints('undefined', 'undefined', '1 2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a closure reading the parameter called before the store': Program(
        a_program("""
            function f(a, p) {
              g();
              if (!p) {
                p = function () { return a; };
              }
              function g() { console.log(typeof p); }
              return p();
            }
            console.log(f(1));
            """),
        prints('undefined', '1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call passing the parameter': Program(
        a_program("""
            function f(a, p) {
              if (!p) {
                p = function () { return 'own'; };
              }
              return p();
            }
            console.log(f(1), f(1, function () { return 'passed'; }));
            """),
        prints('own passed'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the function called through call and apply': Program(
        a_program("""
            function f(a, p) {
              if (!p) {
                p = function () { return 'own'; };
              }
              return p();
            }
            console.log(f.call(null, 1, function () { return 'call'; }), f.apply(null, [1]));
            """),
        prints('call own'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the length of the function read': Program(
        a_program("""
            function f(a, p) {
              if (!p) {
                p = function () { return a; };
              }
              return p();
            }
            console.log(f.length, f(1));
            """),
        prints('2 1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a default made of literals beside a sloppy read of arguments': Program(
        a_program("""
            function f(a, p = 1) {
              a = 2;
              return [arguments[0], p].join();
            }
            console.log(f(5));
            """),
        prints('5,1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'defaults made of literals': Program(
        a_program("""
            function f(a, limit = [1, 2], flag = !0) {
              limit.push(a);
              return limit.join() + flag;
            }
            console.log(f(3), f(4));
            """),
        prints('1,2,3true 1,2,4true'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a plain parameter assigned later': Program(
        a_program("""
            function f(a, x) {
              console.log(typeof x);
              x = a * 2;
              return x;
            }
            console.log(f(2), f(3));
            """),
        prints('undefined', 'undefined', '4 6'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a default reading the parameter': Program(
        a_program("""
            function f(a = () => typeof p, p) {
              if (!p) {
                p = function () { return 'p'; };
              }
              return a() + p();
            }
            console.log(f());
            """),
        prints('functionp'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'eval reading the parameter': Program(
        a_program("""
            function f(a, p) {
              if (!p) {
                p = function () { return 'p'; };
              }
              return eval('p()') + a;
            }
            console.log(f(1));
            """),
        prints('p1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a generator with a moved function': Program(
        a_program("""
            function* gen(a, p) {
              if (!p) {
                p = function () { return a * 10; };
              }
              yield p();
              yield p() + 1;
            }
            console.log([...gen(2)].join());
            """),
        prints('20,21'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the function handed on as a callback': Program(
        a_program("""
            function f(a, p) {
              if (!p) {
                p = function () { return 'own'; };
              }
              return a + p();
            }
            console.log(['x', 'y'].map(f).join());
            """),
        ('', 'TypeError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a recursion passing fewer arguments': Program(
        a_program("""
            function f(n, p) {
              if (!p) {
                p = function (k) { return k * 2; };
              }
              return n <= 0 ? 0 : p(n) + f(n - 1);
            }
            console.log(f(3));
            """),
        prints('12'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a store of undefined where a var stood': Program(
        a_program("""
            var SC;
            console.log(typeof SC);
            SC = undefined;
            SC = function (i) { return 'ab'[i]; };
            console.log(SC(0), SC(1));
            """),
        prints('undefined', 'a b'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a store of undefined inside a loop': Program(
        a_program("""
            function f() {
              var x;
              var out = [];
              for (var i = 0; i < 2; i++) {
                out.push(typeof x);
                x = undefined;
                out.push(typeof x);
                x = i;
              }
              return out.join();
            }
            console.log(f());
            """),
        prints('undefined,undefined,number,undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a store of undefined after a closure wrote the var': Program(
        a_program("""
            function f() {
              var x;
              function set() { x = 5; }
              set();
              x = undefined;
              return typeof x;
            }
            console.log(f());
            """),
        prints('undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a store of a shadowed undefined': Program(
        a_program("""
            function f() {
              var undefined = 7;
              var x;
              x = undefined;
              return x;
            }
            console.log(f());
            """),
        prints('7'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a store of undefined into a var declared with a value': Program(
        a_program("""
            function f() {
              var x = 3;
              x = undefined;
              return typeof x;
            }
            console.log(f());
            """),
        prints('undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a moved function in strict mode': Program(
        a_program("""
            function f(a, p) {
              'use strict';
              if (!p) {
                p = function () { return typeof this; };
              }
              return p() + a;
            }
            console.log(f(1));
            """),
        prints('undefined1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a constructor with a moved function': Program(
        a_program("""
            class C {
              constructor(a, p) {
                if (!p) {
                  p = function () { return a + 1; };
                }
                this.v = p();
              }
            }
            console.log(new C(1).v);
            """),
        prints('2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the count of the arguments read': Program(
        a_program("""
            function f(a, p) {
              if (!p) {
                p = function () { return 'p'; };
              }
              return arguments.length + p();
            }
            console.log(f(1));
            """),
        prints('1p'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the parameter written through arguments': Program(
        a_program("""
            function f(a, p) {
              arguments[1] = function () { return 'via arguments'; };
              if (!p) {
                p = function () { return 'own'; };
              }
              return p();
            }
            console.log(f(1));
            """),
        prints('own'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a check standing before the store': Program(
        a_program("""
            function f(a, p) {
              if (Math.random() > 2) {
                while (true) {}
              }
              if (!p) {
                p = function (x) { return x + a; };
              }
              return p(1);
            }
            console.log(f(1), f(2));
            """),
        prints('2 3'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a moved generator function': Program(
        a_program("""
            function f(a, p) {
              if (!p) {
                p = function* () { yield a; };
              }
              return [...p()].join();
            }
            console.log(f(3));
            """),
        prints('3'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'two moved functions reading each other': Program(
        a_program("""
            function f(src, a, b) {
              if (!b) {
                b = function (s) { return s.toUpperCase(); };
              }
              if (!a) {
                a = function (start, length) { return b(src.slice(start, start + length)); };
              }
              return a(1, 2);
            }
            console.log(f('abcd'), f('wxyz'));
            """),
        prints('BC XY'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a moved function after a passed parameter with a default': Program(
        a_program("""
            function f(a = 1, p) {
              if (!p) {
                p = function () { return a; };
              }
              return p();
            }
            console.log(f(), f(5));
            """),
        prints('1 5'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a closure in an earlier default reading the name': Program(
        a_program("""
            var p = 'outer';
            function f(a = () => typeof p, p) {
              if (!p) {
                p = function () { return 'inner'; };
              }
              return a() + p();
            }
            console.log(f());
            """),
        prints('functioninner'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'moved vars as plain parameters after a moved function': Program(
        a_program("""
            var table = ['alpha', 'beta', 'gamma'];
            function pick(index, label, limit, word) {
              if (!label) {
                label = function (text) { return '<' + text + '>'; };
              }
              limit = 2;
              if (index > limit) {
                return label('none');
              }
              word = table[index];
              return label(word);
            }
            console.log(pick(0), pick(1), pick(5));
            """),
        prints('<alpha> <beta> <none>'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a moved var with a default made of literals after a moved function': Program(
        a_program("""
            function f(a, p, limit = 2) {
              if (!p) {
                p = function (x) { return x * limit; };
              }
              limit += a;
              return p(a);
            }
            console.log(f(1), f(2));
            """),
        prints('3 8'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a moved var before the moved function': Program(
        a_program("""
            function f(a, x, p) {
              if (!p) {
                p = function () { return typeof x; };
              }
              x = a;
              return p();
            }
            console.log(f(1), f('s'));
            """),
        prints('number string'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'defaults and plain parameters with no stored function': Program(
        a_program("""
            function M(states, scope = { P: {} }, runtime, arg) {
              scope.P.v = states[0];
              return [scope.P.v, typeof runtime, typeof arg].join();
            }
            console.log(M([1]), M([2]));
            """),
        prints('1,undefined,undefined 2,undefined,undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a moved var read before it is written, after a moved function': Program(
        a_program("""
            function f(a, p, x) {
              if (!p) {
                p = function () { return typeof x; };
              }
              var before = p();
              x = a;
              return before + p();
            }
            console.log(f(1));
            """),
        prints('undefinednumber'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the stored parameter named like a block function of the body': Program(
        a_program("""
            function f(a, p) {
              if (!p) {
                p = function () { return 'stored'; };
              }
              {
                function p() { return 'block'; }
              }
              return p();
            }
            console.log(f(1), f(2));
            """),
        prints('stored stored'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a plain parameter named like a block function of the body': Program(
        a_program("""
            function f(a, q, p) {
              if (!p) {
                p = function () { return 'stored'; };
              }
              {
                function q() { return 'block'; }
              }
              return typeof q + p();
            }
            console.log(f(1), f(2));
            """),
        prints('undefinedstored undefinedstored'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a defaulted parameter named like a function of the body': Program(
        a_program("""
            function f(a, limit = 2, p) {
              if (!p) {
                p = function () { return typeof limit; };
              }
              function limit() {}
              return p();
            }
            console.log(f(1), f(2));
            """),
        prints('function function'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a generator whose default throws': Program(
        a_program("""
            function* g(a, x = 'k' in 'text', p) {
              if (!p) {
                p = function () { return 1; };
              }
              yield p() + x;
            }
            var it;
            try { it = g(1); console.log('created'); } catch (e) { console.log('call threw'); }
            try { if (it) it.next(); console.log('ran'); } catch (e) { console.log('next threw'); }
            """),
        prints('call threw', 'ran'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the stored parameter named like a block function in a branch': Program(
        a_program("""
            function f(a, p) {
              if (!p) {
                p = function () { return 'stored'; };
              }
              if (a > 0) {
                function p() { return 'block'; }
              }
              return p();
            }
            console.log(f(process.argv.length), f(-process.argv.length));
            """),
        prints('stored stored'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a plain parameter named like a function in a case clause': Program(
        a_program("""
            function f(a, q, p) {
              if (!p) {
                p = function () { return 'stored'; };
              }
              switch (a) {
                case 1:
                  function q() { return 'case'; }
              }
              return typeof q + p();
            }
            console.log(f(1), f(2));
            """),
        prints('undefinedstored undefinedstored'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a class constructed again through the constructor of an instance': Program(
        a_program("""
            class Vec {
              constructor(x, scale, norm) {
                if (!norm) { norm = function (v) { return v * (scale || 1); }; }
                this.x = norm(x);
              }
              scaled(s) { return new this.constructor(this.x, s); }
            }
            var v = new Vec(3);
            console.log(v.x, v.scaled(2).x);
            """),
        prints('3 6'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a subclass constructed again through new.target': Program(
        a_program("""
            class Base {
              constructor() {
                if (!Base.copied) { Base.copied = true; this.copy = new new.target(5, 2); }
              }
            }
            class D extends Base {
              constructor(x, y, f) {
                super();
                if (!f) { f = function () { return x * (y || 1); }; }
                this.v = f();
              }
            }
            var d = new D(3);
            console.log(d.v, d.copy.v);
            """),
        prints('3 10'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a subclass of a built-in constructed again by a method of the built-in': Program(
        a_program("""
            var seen = [];
            class R extends RegExp {
              constructor(source, flags, note) {
                if (!note) { note = function (f) { return f === undefined ? 'none' : f; }; }
                super(source, flags);
                seen.push(note(flags));
              }
            }
            'a,b'.split(new R(','));
            console.log(seen.join(' '));
            """),
        prints('none y'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a defaulted parameter named like a block function of the body': Program(
        a_program("""
            function f(a, lim = 2, p) {
              if (!p) {
                p = function () { return 'stored'; };
              }
              {
                function lim() {}
              }
              return typeof lim + p();
            }
            console.log(f(1), f(2));
            """),
        prints('numberstored numberstored'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
}

RESTORED: dict[str, str] = {
    'a moved function declaration': inspect.cleandoc(
        """
            function parse(source) {
              function decode(n) {
                return 'abcdef'.slice(n, n + 2);
              }
              console.log('bc', decode(source));
            }
            parse(2);
            parse(3);
        """
    ),
    'a generator with a moved function': inspect.cleandoc(
        """
            function* gen(a) {
              function p() {
                return a * 10;
              }
              yield p();
              yield p() + 1;
            }
            console.log([...gen(2)].join());
        """
    ),
    'two moved functions reading each other': inspect.cleandoc(
        """
            function f(src) {
              function b(s) {
                return s.toUpperCase();
              }
              function a(start, length) {
                return b(src.slice(start, start + length));
              }
              return a(1, 2);
            }
            console.log(f('abcd'), f('wxyz'));
        """
    ),
    'a moved function after a passed parameter with a default': inspect.cleandoc(
        """
            function f(a = 1) {
              function p() {
                return a;
              }
              return p();
            }
            console.log(f(), f(5));
        """
    ),
    'a moved var with a default made of literals after a moved function': inspect.cleandoc(
        """
            function f(a) {
              var limit = 2;
              function p(x) {
                return x * limit;
              }
              limit += a;
              return p(a);
            }
            console.log(f(1), f(2));
        """
    ),
    'a moved var read before it is written, after a moved function': inspect.cleandoc(
        """
            function f(a) {
              var x;
              function p() {
                return typeof x;
              }
              var before = p();
              x = a;
              return before + p();
            }
            console.log(f(1));
        """
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionWithParametersNoCallPassesBehavesAsItDid(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in UNPASSED.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in UNPASSED.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestAParameterNoCallPassesIsADeclarationAgain(TestBase):

    def test_each_function_restored_reads_as_pinned(self):
        self.assertEqual(
            {label: deobfuscated(UNPASSED[label].text) for label in RESTORED},
            RESTORED,
        )

    def test_a_check_standing_before_the_store_is_no_read_of_the_parameter(self):
        text = deobfuscated(UNPASSED['a check standing before the store'].text)
        self.assertIn('function f(a) {', text)
        self.assertIn('function p(x) {', text)


class TestAFunctionAHostCallsKeepsItsParameters(TestBase):

    def test_the_parameters_of_a_function_of_a_library_stay(self):
        source = inspect.cleandoc("""
            function fetchData(url, callback) {
              if (!callback) { callback = function (d) { console.log('default', d); }; }
              callback(url.length);
            }
            function init() { fetchData('abc'); }
        """)
        text = deobfuscate_source(source, execution=ExecutionModel.script, environment=HostEnvironment.node)
        self.assertIn('function fetchData(url, callback) {', text)

    def test_the_parameters_of_an_entrypoint_stay(self):
        for source, kept in {
            inspect.cleandoc("""
                function handler(evt, opt = 1, cb) {
                  if (!cb) { cb = function (e) { return 'default:' + e; }; }
                  return cb(evt) + opt;
                }
                handler(1);
            """): 'function handler(evt, opt = 1, cb) {',
            inspect.cleandoc("""
                function handler({x}, cb) {
                  if (!cb) { cb = function (e) { return 'default:' + e; }; }
                  return cb(x);
                }
                handler({x: 1});
            """): 'function handler({ x }, cb) {',
            inspect.cleandoc("""
                function handler(evt, cb) {
                  if (!cb) { cb = function (e) { return 'default:' + e; }; }
                  return cb(evt);
                }
                handler(1);
            """): 'function handler(evt, cb) {',
        }.items():
            with self.subTest(source=source):
                text = deobfuscate_source(
                    source,
                    execution=ExecutionModel.script,
                    environment=HostEnvironment.node,
                    entrypoints=('handler',),
                )
                self.assertIn(kept, text)


ENTRY = inspect.cleandoc("""
    run: function (p) {
      if (!p) {
        p = function () {
          return 'own';
        };
      }
      return p();
    },
""")

PASSED = inspect.cleandoc("""
    function passed() {
      return 'passed';
    }
""")


def holding_the_entry(text: str) -> str:
    lines = []
    for line in a_program(text).splitlines():
        indent = line[:len(line) - len(line.lstrip())]
        if line.strip() == 'ENTRY':
            lines.extend(indent + part for part in ENTRY.splitlines())
        elif line.strip() == 'PASSED':
            lines.extend(indent + part for part in PASSED.splitlines())
        else:
            lines.append(line)
    return a_program('\n'.join(lines))


THROUGH_A_TABLE: dict[str, Program] = {
    'a table an inherited method hands back under a key the program computes': Program(
        a_program("""
            var T = { e: function () { return String; } };
            function d(k) { return T[k](); }
            d(['value', 'Of'].join('')).e().fromCharCode = function () { return 'B'; };
            console.log(String.fromCharCode(65));
            """),
        prints('B'),
        Reading.COMMONJS,
    ),
    'an entry selected by a key only the run knows': Program(
        holding_the_entry("""
            var table;
            table = {
              ENTRY
              size: function () {
                return 3;
              },
            };
            function dispatch(name) {
              return table[name]();
            }
            console.log(dispatch('run'), dispatch('size'));
            """),
        prints('own 3'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an entry selected through apply and call': Program(
        holding_the_entry("""
            var table;
            table = {
              ENTRY
            };
            function viaApply(name) {
              return table[name].apply(this);
            }
            function viaCall(name) {
              return table[name].call(null);
            }
            console.log(viaApply('run'), viaCall('run'));
            """),
        prints('own own'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an entry handed an argument': Program(
        holding_the_entry("""
            PASSED
            var table;
            table = {
              ENTRY
            };
            function dispatch(name, value) {
              return table[name](value);
            }
            console.log(dispatch('run'), dispatch('run', passed));
            """),
        prints('own passed'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an entry handed an argument through apply and call': Program(
        holding_the_entry("""
            PASSED
            var table;
            table = {
              ENTRY
            };
            function viaList(name, list) {
              return table[name].apply(null, list);
            }
            function viaArray(name, value) {
              return table[name].apply(null, [value]);
            }
            function viaCall(name, value) {
              return table[name].call(null, value);
            }
            console.log(viaList('run', []), viaList('run', [passed]), viaArray('run', passed), viaCall('run', passed));
            """),
        prints('own passed passed passed'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a table a parameter holds': Program(
        holding_the_entry("""
            function dispatch(name, table) {
              table = {
                ENTRY
              };
              return table[name]();
            }
            console.log(dispatch('run'), dispatch('run', 1));
            """),
        prints('own own'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a table an entry reading its this hands back': Program(
        holding_the_entry("""
            PASSED
            var table;
            table = {
              self: function () {
                return this;
              },
              ENTRY
            };
            function dispatch(name) {
              return table[name]();
            }
            console.log(dispatch('run'), dispatch('self').run(passed));
            """),
        prints('own passed'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a table the valueOf it inherits hands back': Program(
        holding_the_entry("""
            PASSED
            var table;
            table = {
              ENTRY
            };
            console.log(table['run'](), table.valueOf().run(passed));
            """),
        prints('own passed'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a table a method hands back': Program(
        holding_the_entry("""
            PASSED
            var table;
            table = {
              self() {
                return super.valueOf();
              },
              ENTRY
            };
            function dispatch(name) {
              return table[name]();
            }
            console.log(dispatch('run'), dispatch('self').run(passed));
            """),
        prints('own passed'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a table an accessor hands on': Program(
        holding_the_entry("""
            PASSED
            var leaked;
            var table;
            table = {
              get self() {
                leaked = super.valueOf();
                return function () {
                  return 'got';
                };
              },
              ENTRY
            };
            function dispatch(name) {
              return table[name]();
            }
            console.log(dispatch('run'), dispatch('self'), leaked.run(passed));
            """),
        prints('own got passed'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a table its prototype hands back': Program(
        holding_the_entry("""
            PASSED
            var table;
            table = {
              __proto__: {
                self: function () {
                  return this;
                },
              },
              ENTRY
            };
            function dispatch(name) {
              return table[name]();
            }
            console.log(dispatch('run'), dispatch('self').run(passed));
            """),
        prints('own passed'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a table read through a mapped arguments': Program(
        holding_the_entry("""
            PASSED
            function dispatch(name, table) {
              table = {
                ENTRY
              };
              return table[name]() + ' ' + arguments[1].run(passed);
            }
            console.log(dispatch('run', 0));
            """),
        prints('own passed'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a table whose entry a replaced call runs': Program(
        holding_the_entry("""
            PASSED
            var functions = Object.getPrototypeOf(function () {});
            var call = functions.call;
            functions.call = function () {
              return this(passed);
            };
            var table;
            table = {
              ENTRY
            };
            function dispatch(name) {
              return table[name].call(null);
            }
            var result = dispatch('run');
            functions.call = call;
            console.log(result);
            """),
        prints('passed'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a table whose entry a call replaced through the name Function runs': Program(
        holding_the_entry("""
            PASSED
            var call = Function.prototype.call;
            Function.prototype.call = function () {
              return this(passed);
            };
            var table;
            table = {
              ENTRY
            };
            function dispatch(name) {
              return table[name].call(null);
            }
            var result = dispatch('run');
            Function.prototype.call = call;
            console.log(result);
            """),
        prints('passed'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a function called only through call and apply': Program(
        a_program("""
            function f(a, p) {
              if (!p) {
                p = function () {
                  return a;
                };
              }
              return p();
            }
            console.log(f.call(null, 1), f.apply(null, [2]), f.apply(null));
            """),
        prints('1 2 undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a function run where it is written through call': Program(
        a_program("""
            console.log(function (a, p) {
              if (!p) {
                p = function () {
                  return a * 2;
                };
              }
              return p();
            }.call(null, 4));
            """),
        prints('8'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionCalledThroughATableOrCallBehavesAsItDid(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in THROUGH_A_TABLE.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in THROUGH_A_TABLE.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())

    def test_each_program_still_prints_it_after_the_unit_trusting_what_eval_runs(self):
        for label, row in THROUGH_A_TABLE.items():
            with self.subTest(label=label):
                self.assertEqual(behavior(deobfuscated_by_the_unit(row.text)), row.prints)


class TestAFunctionEveryCallOfWhichATableOrCallShowsDeclaresWhatWasMoved(TestBase):

    def test_an_entry_no_call_through_its_table_hands_an_argument_loses_its_parameter_and_store(self):
        for label in (
            'an entry selected by a key only the run knows',
            'an entry selected through apply and call',
            'a table a parameter holds',
        ):
            with self.subTest(label=label):
                text = deobfuscated(THROUGH_A_TABLE[label].text)
                self.assertIn('run: function() {', text)
                self.assertNotIn('if (!p)', text)

    def test_a_function_called_through_call_and_apply_alone_declares_its_function(self):
        for label, head in (
            ('a function called only through call and apply', 'function f(a) {'),
            ('a function run where it is written through call', 'function(a) {'),
        ):
            with self.subTest(label=label):
                text = deobfuscated(THROUGH_A_TABLE[label].text)
                self.assertIn(head, text)
                self.assertIn('function p() {', text)


#: The deobfuscation of the file this module reads from the sample store, which the obfuscation
#: wrote for one program with its declarations moved into parameter lists, dead code, an integrity
#: lock, a debugger lock and an end date lock.
MOVED_DECLARATIONS_AND_LOCKS_DEOBFUSCATED = inspect.cleandoc(
    """
    function* countdown(n) {
      while (n > 0) {
        yield n--;
      }
    }
    var counter = 0;
    for (const value of countdown(3)) {
      counter += value;
    }
    console.log('<alpha>', '<beta>', '<none>');
    console.log(60, counter);
    """
)

MOVED_DECLARATIONS_AND_LOCKS_DEOBFUSCATED_WITH_THE_COUNTER_DECLARED_APART = inspect.cleandoc(
    """
    function* countdown(n) {
      while (n > 0) {
        yield n--;
      }
    }
    var counter;
    counter = 0;
    for (const value of countdown(3)) {
      counter += value;
    }
    console.log('<alpha>', '<beta>', '<none>');
    console.log(60, counter);
    """
)

MOVED_DECLARATIONS_AND_LOCKS_SHA256 = 'b33e21334d1dd86e5fd8786d0c7fd4385fe5f288ea7d135f201af6ed43ac404f'


class TestTheFileTheObfuscationWrote(TestBase):

    def _deobfuscated(self) -> str:
        source = self.download_sample(MOVED_DECLARATIONS_AND_LOCKS_SHA256).decode('utf-8')
        return deobfuscate_source(source, execution=ExecutionModel.commonjs)

    def test_the_file_with_moved_declarations_and_locks_reads_as_pinned(self):
        self.assertIn(
            self._deobfuscated(),
            (
                MOVED_DECLARATIONS_AND_LOCKS_DEOBFUSCATED,
                MOVED_DECLARATIONS_AND_LOCKS_DEOBFUSCATED_WITH_THE_COUNTER_DECLARED_APART,
            ),
        )

    @opportunity
    def test_the_file_with_moved_declarations_and_locks_declares_its_counter_with_its_value(self):
        self.assertEqual(self._deobfuscated(), MOVED_DECLARATIONS_AND_LOCKS_DEOBFUSCATED)
