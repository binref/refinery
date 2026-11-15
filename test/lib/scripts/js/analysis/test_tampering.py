"""
Whether the builtins a fold or an interpreted call trusts still behave as the language defines them
at one point of the program, the anchor.

SECURITY: every program here is written by hand in this file and is benign. No sample may ever be
fed to these tests.
"""
from __future__ import annotations

import inspect
import time

from refinery.lib.scripts import Node, _remove_from_parent
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.analysis.effects import AnchoredTrust
from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.analysis.model import Role, enclosing_function, reference_role
from refinery.lib.scripts.js.analysis.tampering import denotes_function_intrinsic
from refinery.lib.scripts.js.deobfuscation.interpreter import InterpreterError, JsInterpreter
from refinery.lib.scripts.js.model import (
    JsCallExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNumericLiteral,
    JsUnaryExpression,
    strip_parens,
)
from refinery.lib.scripts.js.options import DeobfuscationOptions, ExecutionModel
from refinery.lib.scripts.js.parser import JsParser
from test import TestBase, a_property_of_the_pin_itself

_FROM_CHAR_CODE = 'fromCharCode'

_DECODER_STEP = 'charAt'


def _call_with_property(ast: Node, property_name: str) -> JsCallExpression:
    for node in ast.walk():
        if (
            isinstance(node, JsCallExpression)
            and isinstance(node.callee, JsMemberExpression)
            and isinstance(node.callee.property, JsIdentifier)
            and node.callee.property.name == property_name
        ):
            return node
    raise AssertionError(F'no call to a .{property_name} method')


def _call_of_name(ast: Node, callee_name: str) -> JsCallExpression:
    for node in ast.walk():
        if (
            isinstance(node, JsCallExpression)
            and isinstance(node.callee, JsIdentifier)
            and node.callee.name == callee_name
        ):
            return node
    raise AssertionError(F'no call to {callee_name}')


def _decoder_iife_call(ast: Node, property_name: str) -> JsCallExpression:
    for node in ast.walk():
        if not (
            isinstance(node, JsCallExpression)
            and isinstance(node.callee, JsMemberExpression)
            and isinstance(node.callee.property, JsIdentifier)
            and node.callee.property.name == property_name
        ):
            continue
        decoder = enclosing_function(node)
        if decoder is None:
            continue
        for call in ast.walk():
            if isinstance(call, JsCallExpression) and strip_parens(call.callee) is decoder:
                return call
    raise AssertionError(F'no decoder IIFE calling a .{property_name} method')


_A_SITE_BEFORE_THE_ANCHOR = {
    'an opaque write through a spelled global base': inspect.cleandoc("""
        var k, v;
        globalThis[k] = v;
        String.fromCharCode(65);
    """),
    'an opaque compound write': inspect.cleandoc("""
        var k, v;
        globalThis[k] += 1;
        String.fromCharCode(65);
    """),
    'an opaque update write': inspect.cleandoc("""
        var k;
        globalThis[k]++;
        String.fromCharCode(65);
    """),
    'an opaque delete': inspect.cleandoc("""
        var k;
        delete globalThis[k];
        String.fromCharCode(65);
    """),
    'a write in a function invoked both before and after': inspect.cleandoc("""
        function g() { return String.fromCharCode(65); }
        g();
        var k, v;
        globalThis[k] = v;
        g();
    """),
    'a construction-valued name passed as a callback': inspect.cleandoc("""
        var t = Function("this.String = 9;");
        [0].forEach(t);
        String.fromCharCode(65);
    """),
    'an eval-alias call before the anchor': inspect.cleandoc("""
        var e = eval;
        e("String = 9");
        String.fromCharCode(65);
    """),
    'a string timer before the anchor': inspect.cleandoc("""
        setTimeout("String = 9", 0);
        String.fromCharCode(65);
    """),
    'a static import anywhere': inspect.cleandoc("""
        import x from "y";
        String.fromCharCode(65);
    """),
    'a with statement anywhere': inspect.cleandoc("""
        var o, x;
        with (o) { x = 1; }
        String.fromCharCode(65);
    """),
    'a file required before the anchor': inspect.cleandoc("""
        require("./setup.js");
        String.fromCharCode(65);
    """),
    'vm required before the anchor': inspect.cleandoc("""
        require("vm");
        String.fromCharCode(65);
    """),
    'a span of source the model never read': inspect.cleandoc("""
        var k = "abc
        ;String.fromCharCode(65);
    """),
    'a loop the anchor re-executes in': inspect.cleandoc("""
        var c, k, v;
        while (c) { String.fromCharCode(65); globalThis[k] = v; }
    """),
    'an alias invoked twice across the site': inspect.cleandoc("""
        var k, v;
        function g() { String.fromCharCode(65); globalThis[k] = v; }
        var q = g;
        q();
        q();
    """),
    'an unbound immediate construction': inspect.cleandoc("""
        Function("this.String = 9")();
        String.fromCharCode(65);
    """),
    'a construction held in a container': inspect.cleandoc("""
        var fns = [Function("String = 9")];
        fns[0]();
        String.fromCharCode(65);
    """),
    'a construction held as an object member': inspect.cleandoc("""
        var o = { m: Function("String = 9") };
        o.m();
        String.fromCharCode(65);
    """),
    'a construction returned by a factory': inspect.cleandoc("""
        function mk() { return { f: Function("String = 9") }; }
        mk().f();
        String.fromCharCode(65);
    """),
    'a construction handed to sort': inspect.cleandoc("""
        var g = Function;
        ["String = 9", "p"].sort(g);
        String.fromCharCode(65);
    """),
    'a construction handed to forEach': inspect.cleandoc("""
        [0].forEach(Function("this.String = 9"));
        String.fromCharCode(65);
    """),
    'a potential arguments.callee read': inspect.cleandoc("""
        var k, v;
        (function () {
          String.fromCharCode(65);
          globalThis[k] = v;
          arguments.callee();
        })();
    """),
    'a computed arguments.callee read': inspect.cleandoc("""
        var k, v;
        (function () {
          String.fromCharCode(65);
          globalThis[k] = v;
          arguments['callee']();
        })();
    """),
    'a runtime-keyed re-entry read off the arguments object': inspect.cleandoc("""
        var k, v, i;
        (function () {
          String.fromCharCode(65);
          globalThis[k] = v;
          i = 'callee';
          arguments[i]();
        })();
    """),
    'a potential .caller read': inspect.cleandoc("""
        var k, v;
        (function () {
          String.fromCharCode(65);
          globalThis[k] = v;
          arguments.callee.call(null);
        })();
    """),
    'a caller read under a key a table holds': inspect.cleandoc("""
        var k, v;
        var table = ["caller"];
        function h() { h[table[0]](); }
        function g() {
          String.fromCharCode(65);
          globalThis[k] = v;
          h();
        }
        g();
    """),
    'a construction of the activation through new.target': inspect.cleandoc("""
        var k, v;
        var again = true;
        function F() {
          String.fromCharCode(65);
          globalThis[k] = v;
          if (again) { again = false; new new.target(); }
        }
        new F();
    """),
    'a parameter-base write through a handed-over global': inspect.cleandoc("""
        var k, v;
        function t(x) { x[k] = v; }
        t(globalThis);
        String.fromCharCode(65);
    """),
    'the global object handed to Reflect.set': inspect.cleandoc("""
        Reflect.set(globalThis, "String", 9);
        String.fromCharCode(65);
    """),
    'an eval re-invoking the enclosing activation': inspect.cleandoc("""
        function g() { String.fromCharCode(65); globalThis.eval("String = 9; g()"); }
        g();
    """),
    'a stored-code eval re-invoking the activation': inspect.cleandoc("""
        var c = "String = 9; g()";
        function g() { String.fromCharCode(65); (0, eval)(c); }
        g();
    """),
    'a timer re-invoking the enclosing activation': inspect.cleandoc("""
        function g() { String.fromCharCode(65); setTimeout("String = 9; g()", 0); }
        g();
    """),
    'a script-scope named activation under a surface': inspect.cleandoc("""
        var k, v;
        var e = eval;
        function g() { String.fromCharCode(65); globalThis[k] = v; }
        g();
    """),
    'a constructed function invoked before the anchor': inspect.cleandoc("""
        var f = new Function("this.String = 9");
        f();
        String.fromCharCode(65);
    """),
    'a destructured eval invoked': inspect.cleandoc("""
        const {eval} = globalThis;
        eval("String = 9");
        String.fromCharCode(65);
    """),
    'a destructured eval under a runtime key invoked': inspect.cleandoc("""
        var k;
        const {[k]: e} = globalThis;
        e("String = 9");
        String.fromCharCode(65);
    """),
}
"""
The enumeration's every arm as a defeat: a computed-key store through a base that may be the
global object (each store form), a read of the object in an argument position (the hand-over and
`Reflect.set` spellings), a code-execution surface, a construction followed to every position
that obtains its value, and the multiplicity family — re-entry spellings, aliases, loops, and a
named activation reflective text could re-invoke.
"""

_A_SITE_THE_ANCHOR_ESCAPED = {
    'a write in a function invoked only later': inspect.cleandoc("""
        var k, v;
        String.fromCharCode(65);
        function h() { globalThis[k] = v; }
        h();
    """),
    'a computed-literal alias write': inspect.cleandoc("""
        var g = globalThis;
        g["String"] = 9;
        String.fromCharCode(65);
    """),
    'a construction invoked only after the anchor': inspect.cleandoc("""
        String.fromCharCode(65);
        var g = Function;
        var s = g("return 1");
        s();
    """),
    'a destructured intrinsic never invoked': inspect.cleandoc("""
        String.fromCharCode(65);
        const {eval} = globalThis;
    """),
    'a fold inside a loop in a clean program': inspect.cleandoc("""
        var s = 0;
        for (var i = 0; i < 3; i++) { s = String.fromCharCode(65); }
    """),
    'a twice-called function in a clean program': inspect.cleandoc("""
        function g() { return String.fromCharCode(65); }
        g();
        g();
    """),
    'a benign construction': inspect.cleandoc("""
        var d = new Date();
        d.getTime();
        String.fromCharCode(65);
    """),
    'a file required only after the anchor': inspect.cleandoc("""
        String.fromCharCode(65);
        require("./setup.js");
    """),
    'a builtin module that runs no code required before the anchor': inspect.cleandoc("""
        require("fs");
        String.fromCharCode(65);
    """),
    'a script-scope named activation with the surface removed': inspect.cleandoc("""
        var k, v;
        function g() { String.fromCharCode(65); globalThis[k] = v; }
        g();
    """),
    'a computed dispatch on a list base': inspect.cleandoc("""
        var k, v, i;
        var names = ["callee", "caller"];
        function g(name) { globalThis[name] = v; }
        String.fromCharCode(65);
        i = 0;
        g(names[i]);
    """),
    'a key a table holds that names no way back into the activation': inspect.cleandoc("""
        var k, v;
        var table = ["other"];
        function h() { h[table[0]](); }
        function g() {
          String.fromCharCode(65);
          globalThis[k] = v;
          h();
        }
        g();
    """),
    'the arguments.callee of another function': inspect.cleandoc("""
        var k, v;
        function h() { return arguments.callee; }
        function g() {
          String.fromCharCode(65);
          globalThis[k] = v;
          h();
        }
        g();
    """),
    'a runtime-keyed read off a strict arguments object': inspect.cleandoc("""
        var k, v, i, out;
        (function () {
          'use strict';
          String.fromCharCode(65);
          globalThis[k] = v;
          i = 'callee';
          out = arguments[i];
        })();
    """),
}
"""
Each refuse row's twin. The computed-literal alias write clears by design — a written *name* is
the per-name arm's question, not the oracle's — and the `new` predicate clears a construction
that is not `Function`, which is what keeps `new Date()` from refusing every anchor in a real
program.
"""


class TestBuiltinsIntactAt(TestBase):

    def _verdict(self, source: str) -> bool:
        ast = JsParser(source).parse()
        return ModelCache(ast).builtins_intact_at(_call_with_property(ast, _FROM_CHAR_CODE))

    def test_every_site_before_the_anchor_refuses(self):
        for label, source in _A_SITE_BEFORE_THE_ANCHOR.items():
            with self.subTest(label):
                self.assertFalse(self._verdict(source))

    def test_every_site_the_anchor_escapes_clears(self):
        for label, source in _A_SITE_THE_ANCHOR_ESCAPED.items():
            with self.subTest(label):
                self.assertTrue(self._verdict(source))

    def test_an_anchor_its_statement_runs_on_some_runs_clears_under_a_write_after_it(self):
        for label, expression in (
            ('in an arm', 'c ? String.fromCharCode(65) : 0'),
            ('below and', 'c && String.fromCharCode(65)'),
        ):
            source = inspect.cleandoc(F"""
                var k, v;
                function f(c) {{
                  var r = {expression};
                  globalThis[k] = v;
                  return r;
                }}
                f();
            """)
            with self.subTest(label):
                self.assertTrue(self._verdict(source))

    def test_an_anchor_its_statement_runs_on_some_runs_refuses_under_a_write_before_it(self):
        source = inspect.cleandoc("""
            var k, v;
            function f(c) {
              globalThis[k] = v;
              var r = c && String.fromCharCode(65);
              return r;
            }
            f();
        """)
        self.assertFalse(self._verdict(source))

    def test_an_entrypoint_matched_activation_refuses_under_the_option(self):
        """
        A host may call an entry point again after the write in it has run, so the write may run
        before the anchor. A top-level function of a CommonJS file is no property of the global
        object, and no host reaches it by its name.
        """
        source = inspect.cleandoc("""
            var k, v;
            function g() {
              var r = String.fromCharCode(65);
              globalThis[k] = v;
              return r;
            }
            g();
        """)
        ast = JsParser(source).parse()
        anchor = _call_with_property(ast, _FROM_CHAR_CODE)
        self.assertTrue(ModelCache(ast).builtins_intact_at(anchor))
        options = DeobfuscationOptions(entrypoints=('g',))
        self.assertFalse(ModelCache(ast, options).builtins_intact_at(anchor))
        options = DeobfuscationOptions(entrypoints=('g',), execution=ExecutionModel.commonjs)
        self.assertTrue(ModelCache(ast, options).builtins_intact_at(anchor))


class TestTheTrustQuestionsAtAnAnchor(TestBase):

    _CLEAN = inspect.cleandoc("""
        var s = String.fromCharCode(65);
        var t = ["x"].concat("a|b".split("|"));
    """)
    _SURFACE_AFTER = inspect.cleandoc("""
        var s = String.fromCharCode(65);
        var t = ["x"].concat("a|b".split("|"));
        var k;
        eval(k);
    """)
    _SURFACE_BEFORE = inspect.cleandoc("""
        var k;
        eval(k);
        var s = String.fromCharCode(65);
        var t = ["x"].concat("a|b".split("|"));
    """)

    def test_a_question_the_whole_program_answers_asks_no_oracle(self):
        ast = JsParser(self._CLEAN).parse()
        cache = ModelCache(ast)

        def oracle() -> bool:
            raise AssertionError('the oracle was asked')

        trust = AnchoredTrust(cache.effects, oracle, lambda: False)
        self.assertTrue(trust.intrinsic_name('String'))
        self.assertTrue(trust.prototype(str))
        self.assertTrue(trust.chain(list))
        self.assertEqual(trust.global_typeof('String'), 'function')

    def test_a_surface_after_the_anchor_is_cleared_at_the_anchor_only(self):
        ast = JsParser(self._SURFACE_AFTER).parse()
        cache = ModelCache(ast)
        anchor = _call_with_property(ast, _FROM_CHAR_CODE)
        self.assertFalse(cache.effects.trusted_intrinsic_name('String'))
        self.assertTrue(cache.trust_at(anchor).intrinsic_name('String'))
        self.assertTrue(cache.trust_at(anchor).prototype(str))
        self.assertFalse(cache.effects.program_trust().intrinsic_name('String'))

    def test_a_surface_before_the_anchor_is_not_cleared(self):
        ast = JsParser(self._SURFACE_BEFORE).parse()
        cache = ModelCache(ast)
        anchor = _call_with_property(ast, _FROM_CHAR_CODE)
        self.assertFalse(cache.trust_at(anchor).intrinsic_name('String'))
        self.assertFalse(cache.trust_at(anchor).prototype(str))

    def test_a_call_nested_in_an_argument_is_cleared_through_the_view(self):
        for label, source, foldable in (
            ('a surface after the call', self._SURFACE_AFTER, True),
            ('a surface before the call', self._SURFACE_BEFORE, False),
        ):
            with self.subTest(label):
                ast = JsParser(source).parse()
                cache = ModelCache(ast)
                concat = _call_with_property(ast, 'concat')
                self.assertFalse(cache.effects.call_is_foldable(concat))
                self.assertEqual(cache.effects.call_is_foldable(concat, trust=cache.trust_at(concat)), foldable)

    def test_a_typeof_of_a_name_the_host_lacks_folds_only_before_every_load(self):
        source = inspect.cleandoc("""
            var a = typeof window;
            require("./setup.js");
            var b = typeof window;
        """)
        ast = JsParser(source).parse()
        cache = ModelCache(ast, DeobfuscationOptions(environment=HostEnvironment.node))
        first, second = (
            node.operand for node in ast.walk_in_order()
            if isinstance(node, JsUnaryExpression) and node.operator == 'typeof'
        )
        self.assertEqual(cache.trust_at(first).global_typeof('window'), 'undefined')
        self.assertIsNone(cache.trust_at(second).global_typeof('window'))
        self.assertIsNone(cache.effects.program_trust().global_typeof('window'))


class TestSingularValueAt(TestBase):
    """
    Each program keeps its variable inside an anonymous immediately-invoked function: the `eval`
    could call a named top-level function again, which alone refuses the value.
    """

    @staticmethod
    def _value_at(source: str):
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        read = next(
            n for n in ast.walk()
            if isinstance(n, JsIdentifier) and n.name == 'x' and cache.model.is_reference(n)
        )
        return cache.tampering.singular_value_at(cache.model.resolve(read), read)

    def test_an_eval_after_the_read_repairs_the_volatility(self):
        value = self._value_at(
            inspect.cleandoc("""
                var out;
                var q = (function () {
                  var x = 1;
                  out = x;
                  eval(payload);
                })();
            """)
        )
        self.assertIsInstance(value, JsNumericLiteral)
        self.assertEqual(value.value, 1)

    @staticmethod
    def _value_at_the_last_read(source: str):
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        reads = [
            node for node in ast.walk_in_order()
            if isinstance(node, JsIdentifier)
            and node.name == 'x'
            and cache.model.is_reference(node)
            and reference_role(node) is Role.READ
        ]
        return cache.tampering.singular_value_at(cache.model.resolve(reads[-1]), reads[-1])

    def test_an_eval_after_a_read_below_and_repairs_the_volatility(self):
        value = self._value_at_the_last_read(
            inspect.cleandoc("""
                var out, c;
                var q = (function () {
                  var x = 1;
                  out = c && x;
                  eval(payload);
                })();
            """)
        )
        self.assertIsInstance(value, JsNumericLiteral)
        self.assertEqual(value.value, 1)

    def test_a_store_below_and_establishes_no_value(self):
        self.assertIsNone(self._value_at_the_last_read(
            inspect.cleandoc("""
                var out, c;
                var q = (function () {
                  var x;
                  c && (x = 1);
                  out = x;
                  eval(payload);
                })();
            """)
        ))

    def test_an_eval_before_the_read_refuses(self):
        self.assertIsNone(self._value_at(
            inspect.cleandoc("""
                var out;
                var q = (function () {
                  var x = 1;
                  eval(payload);
                  out = x;
                })();
            """)
        ))

    def test_a_never_invoked_sibling_eval_is_no_hazard(self):
        value = self._value_at(
            inspect.cleandoc("""
                var out;
                var q = (function () {
                  var x = 1;
                  out = x;
                  var g = function () { eval(payload); };
                })();
            """)
        )
        self.assertIsInstance(value, JsNumericLiteral)
        self.assertEqual(value.value, 1)

    def test_a_read_on_a_cycle_refuses_the_repair(self):
        self.assertIsNone(self._value_at(
            inspect.cleandoc("""
                var out = [];
                var q = (function () {
                  var x = 1;
                  for (var i = 0; i < 2; i++) {
                    out.push(x);
                    eval(payload);
                  }
                })();
            """)
        ))

    def test_a_do_while_read_before_a_post_loop_eval_stays_refused(self):
        self.assertIsNone(self._value_at(
            inspect.cleandoc("""
                var out = [];
                var q = (function () {
                  var x = 1;
                  var i = 0;
                  do { out.push(x); i++; } while (i < 2);
                  eval(payload);
                })();
            """)
        ))

    def test_a_two_channel_binding_gets_no_repair(self):
        self.assertIsNone(self._value_at(
            inspect.cleandoc("""
                var out;
                var q = (function () {
                  var x = 1;
                  x = 2;
                  out = x;
                  eval(payload);
                })();
            """)
        ))

    def test_a_parameter_gets_no_repair(self):
        self.assertIsNone(self._value_at(
            inspect.cleandoc("""
                var out;
                var q = (function (x) {
                  out = x;
                  eval(payload);
                })(7);
            """)
        ))

    def test_a_script_scope_binding_fails_closed(self):
        source = inspect.cleandoc("""
            var out;
            var x = 1;
            out = x;
            eval(payload);
        """)
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        read = next(
            n for n in ast.walk()
            if isinstance(n, JsIdentifier) and n.name == 'x' and cache.model.is_reference(n)
        )
        binding = cache.model.resolve(read)
        self.assertEqual(cache.model.singular_value(binding).value, 1)
        self.assertIsNone(cache.tampering.singular_value_at(binding, read))

    def test_a_read_before_its_declarator_refuses(self):
        self.assertIsNone(self._value_at(
            inspect.cleandoc("""
                var out;
                var q = (function () {
                  out = x;
                  var x = 1;
                  eval(payload);
                })();
            """)
        ))

    @a_property_of_the_pin_itself
    def test_a_splice_during_a_pinned_window_does_not_leak_past_the_pass(self):
        source = inspect.cleandoc("""
            var out;
            var q = (function () {
              var x = 1;
              eval(payload);
              out = x;
            })();
        """)
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        read = next(
            n for n in ast.walk()
            if isinstance(n, JsIdentifier) and n.name == 'x' and cache.model.is_reference(n)
        )
        binding = cache.model.resolve(read)
        self.assertIsNone(cache.tampering.singular_value_at(binding, read))
        with cache.pinned():
            _remove_from_parent(next(
                n for n in ast.walk()
                if isinstance(n, JsCallExpression)
                and isinstance(n.callee, JsIdentifier) and n.callee.name == 'eval'
            ).parent)
            self.assertIsNone(cache.tampering.singular_value_at(binding, read))
        self.assertEqual(cache.tampering.singular_value_at(binding, read).value, 1)


class TestThePositionedAliasHop(TestBase):

    @staticmethod
    def _verdict(source: str, *, positioned: bool = False, callee: str = 'xTe', **kwargs) -> bool | None:
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        node = _call_of_name(ast, callee).callee
        if positioned:
            kwargs['positioned_value'] = cache.tampering.singular_value_at
        return denotes_function_intrinsic(
            node, cache.model, cache.effects, cache.dominance, **kwargs)

    _EVAL_AFTER = inspect.cleandoc("""
        var q = (function () {
          function jCb(l) { return l; }
          var xTe = jCb.constructor;
          var Urn = xTe('', 'return 1;');
          (async function () { await eval(payload); })();
        })();
    """)

    def test_a_volatile_alias_denotes_the_intrinsic_where_ordering_repairs_it(self):
        self.assertFalse(self._verdict(self._EVAL_AFTER))
        self.assertTrue(self._verdict(
            self._EVAL_AFTER, positioned=True))

    def test_a_computed_constructor_key_repairs_the_same_way(self):
        source = self._EVAL_AFTER.replace('jCb.constructor', "jCb['constructor']")
        self.assertFalse(self._verdict(source))
        self.assertTrue(self._verdict(source, positioned=True))

    def test_an_eval_before_the_alias_read_still_declines(self):
        source = inspect.cleandoc("""
            var q = (function () {
              function jCb(l) { return l; }
              (async function () { await eval(payload); })();
              var xTe = jCb.constructor;
              var Urn = xTe('', 'return 1;');
            })();
        """)
        self.assertFalse(self._verdict(source, positioned=True))

    def test_a_written_constructor_key_refuses_every_navigation(self):
        source = F'Function.constructor = g;\n{self._EVAL_AFTER}'
        self.assertFalse(self._verdict(source, positioned=True))

    def test_an_alias_read_before_its_declarator_still_declines(self):
        source = inspect.cleandoc("""
            var q = (function () {
              function jCb(l) { return l; }
              var Urn = xTe('', 'return 1;');
              var xTe = jCb.constructor;
              (async function () { await eval(payload); })();
            })();
        """)
        self.assertFalse(self._verdict(source, positioned=True))

    def test_a_named_function_call_is_not_an_intrinsic_spelling(self):
        source = self._EVAL_AFTER.replace(
            "var Urn = xTe('', 'return 1;');", "var Urn = jCb('return 1;');")
        self.assertFalse(self._verdict(source, positioned=True, callee='jCb'))

    def test_the_spliced_name_gates_stay_in_front_of_the_repair(self):
        with self.subTest('the identifier the arm resolves'):
            self.assertFalse(self._verdict(
                self._EVAL_AFTER, positioned=True, spliced_names=('xTe',)))
        with self.subTest('the member hop base'):
            self.assertFalse(self._verdict(
                self._EVAL_AFTER, positioned=True, spliced_names=('jCb',)))

    def test_a_channel_read_on_a_cycle_refuses_at_the_inner_hop(self):
        source = inspect.cleandoc("""
            var q = (function () {
              function jCb(l) { return l; }
              var xTe;
              for (var i = 0; i < 2; i++) { xTe = jCb.constructor; }
              var Urn = xTe('', 'return 1;');
              (async function () { await eval(payload); })();
            })();
        """)
        self.assertFalse(self._verdict(source, positioned=True))


class TestAnAnchoredInterpreterTrustsWhatTheOracleCleared(TestBase):

    def _execute(self, source: str, anchor_of, expression_of) -> object:
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        interpreter = JsInterpreter(
            effects=cache.effects,
            model=cache.model,
            anchor=anchor_of(ast),
            tampering=cache.tampering,
        )
        return interpreter.eval_expression(expression_of(ast))

    @staticmethod
    def _unanchored_refuses(source: str, expression_of) -> bool:
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        try:
            JsInterpreter(effects=cache.effects, model=cache.model).eval_expression(
                expression_of(ast))
        except InterpreterError:
            return True
        return False

    def test_a_method_call_folds_under_a_write_the_anchor_precedes(self):
        source = inspect.cleandoc("""
            var k, v;
            function f() {
              var r = String.fromCharCode(65);
              globalThis[k] = v;
              return r;
            }
            f();
        """)
        expression = lambda ast: _call_with_property(ast, _FROM_CHAR_CODE)
        self.assertTrue(self._unanchored_refuses(source, expression))
        self.assertEqual(self._execute(source, expression, expression), 'A')

    def test_a_method_call_still_refuses_under_a_write_that_precedes_the_anchor(self):
        source = inspect.cleandoc("""
            var k, v;
            function f() {
              globalThis[k] = v;
              return String.fromCharCode(65);
            }
            f();
        """)
        expression = lambda ast: _call_with_property(ast, _FROM_CHAR_CODE)
        with self.assertRaises(InterpreterError):
            self._execute(source, expression, expression)

    def test_a_for_in_walk_reads_a_clean_chain_at_the_anchor(self):
        source = inspect.cleandoc("""
            var e = eval;
            function f(o) {
              var s = "";
              for (var key in o) { s += key; }
              return s;
            }
            f({a: 1, b: 2});
        """)
        self.assertTrue(self._unanchored_refuses(source, lambda ast: _call_of_name(ast, 'f')))
        self.assertEqual(
            self._execute(
                source,
                lambda ast: _call_of_name(ast, 'f'),
                lambda ast: _call_of_name(ast, 'f')),
            'ab',
        )

    def test_a_for_of_walk_reads_a_clean_chain_at_the_anchor(self):
        source = inspect.cleandoc("""
            var e = eval;
            function f(a) {
              var s = "";
              for (var item of a) { s += item; }
              return s;
            }
            f(["a", "b"]);
        """)
        self.assertTrue(self._unanchored_refuses(source, lambda ast: _call_of_name(ast, 'f')))
        self.assertEqual(
            self._execute(
                source,
                lambda ast: _call_of_name(ast, 'f'),
                lambda ast: _call_of_name(ast, 'f')),
            'ab',
        )

    def test_an_absent_property_read_answers_undefined_at_the_anchor(self):
        source = inspect.cleandoc("""
            var e = eval;
            function f(o) {
              return o.zz;
            }
            f({a: 1});
        """)
        self.assertTrue(self._unanchored_refuses(source, lambda ast: _call_of_name(ast, 'f')))
        self.assertIsNone(
            self._execute(
                source,
                lambda ast: _call_of_name(ast, 'f'),
                lambda ast: _call_of_name(ast, 'f')),
        )

    def test_an_attributed_prototype_write_still_refuses_at_the_anchor(self):
        source = inspect.cleandoc("""
            Object.prototype.z = 9;
            function f(o) {
              var s = "";
              for (var key in o) { s += key; }
              return s;
            }
            f({a: 1});
        """)
        with self.assertRaises(InterpreterError):
            self._execute(
                source,
                lambda ast: _call_of_name(ast, 'f'),
                lambda ast: _call_of_name(ast, 'f'))

    def test_the_child_interpreter_forwards_the_anchor(self):
        source = inspect.cleandoc("""
            var k, v;
            function g() { return String.fromCharCode(65); }
            function f() { return g(); }
            var r = f();
            globalThis[k] = v;
        """)
        self.assertEqual(
            self._execute(
                source,
                lambda ast: _call_of_name(ast, 'f'),
                lambda ast: _call_of_name(ast, 'f')),
            'A',
        )

    _DECODER_IIFE = inspect.cleandoc("""
        var q = (function () {
          function jCb(l) { return l; }
          var xTe = jCb.constructor;
          var Urn = xTe('', 'return 1;');
          var _a = function (e, r) {
            var y = [];
            for (var l = 0; l < e.length; l++) { y[l] = e.charAt(l); }
            var u = String.fromCharCode(127);
            return y.join('').split('%').join(u);
          }('0', 1);
          (async function () { await eval(_a[0]); })();
          return _a;
        })();
    """)

    def test_a_decoder_folds_with_a_later_eval_sibling(self):
        expression = lambda ast: _decoder_iife_call(ast, _DECODER_STEP)
        self.assertTrue(self._unanchored_refuses(self._DECODER_IIFE, expression))
        self.assertEqual(self._execute(self._DECODER_IIFE, expression, expression), '0')

    def test_a_decoder_stays_standing_when_the_eval_sibling_runs_first(self):
        source = self._DECODER_IIFE.replace(
            '  var xTe = jCb.constructor;\n'
            "  var Urn = xTe('', 'return 1;');\n"
            '  var _a = function',
            '  var xTe = jCb.constructor;\n'
            "  var Urn = xTe('', 'return 1;');\n"
            '  (async function () { await eval(out); })();\n'
            '  var _a = function'
        ).replace('  (async function () { await eval(_a[0]); })();\n', '')
        expression = lambda ast: _decoder_iife_call(ast, _DECODER_STEP)
        self.assertTrue(self._unanchored_refuses(source, expression))
        with self.assertRaises(InterpreterError):
            self._execute(source, expression, expression)

    def test_a_decoder_its_statement_runs_on_some_runs_folds_with_a_later_eval_sibling(self):
        for label, opening, closing in (
            ('in an arm', '  var _a = c ? function (e, r) {\n', "  }('0', 1) : 0;\n"),
            ('below and', '  var _a = c && function (e, r) {\n', "  }('0', 1);\n"),
        ):
            source = self._DECODER_IIFE.replace(
                '  var _a = function (e, r) {\n', opening).replace("  }('0', 1);\n", closing)
            expression = lambda ast: _decoder_iife_call(ast, _DECODER_STEP)
            with self.subTest(label):
                self.assertEqual(self._execute(source, expression, expression), '0')

    def test_a_decoder_without_the_eval_sibling_folds(self):
        source = self._DECODER_IIFE.replace(
            '  (async function () { await eval(_a[0]); })();\n', '')
        expression = lambda ast: _decoder_iife_call(ast, _DECODER_STEP)
        self.assertEqual(self._execute(source, expression, expression), '0')


class TestManyAnchorsShareOneEnumeration(TestBase):

    def test_every_anchor_answers_within_the_bound(self):
        body = ['function f() {']
        for index in range(1000):
            body.append(F'  var r{index} = String.fromCharCode(65);')
        for index in range(8):
            body.append(F'  globalThis[k{index}] = v{index};')
        body.append('  return r0;')
        body.append('}')
        declarations = ', '.join(F'k{index}, v{index}' for index in range(8))
        source = F'var {declarations};\n' + '\n'.join(body) + '\nvar r = f();'
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        anchors = [
            node for node in ast.walk()
            if isinstance(node, JsCallExpression)
            and isinstance(node.callee, JsMemberExpression)
            and isinstance(node.callee.property, JsIdentifier)
            and node.callee.property.name == _FROM_CHAR_CODE
        ]
        self.assertEqual(len(anchors), 1000)
        started = time.perf_counter()
        verdicts = [cache.builtins_intact_at(anchor) for anchor in anchors]
        elapsed = time.perf_counter() - started
        self.assertTrue(all(verdicts))
        self.assertLess(elapsed, 30.0)


class TestAnAnchorRunsAtMostOnce(TestBase):

    def test_a_call_in_a_static_field_runs_once_with_its_class(self):
        ast = JsParser('function d(i) { return i; } class A { static v = d(0); }').parse()
        self.assertTrue(ModelCache(ast).tampering.at_most_once(_call_of_name(ast, 'd')))

    def test_a_call_in_a_field_of_a_class_constructed_twice_runs_twice(self):
        ast = JsParser('function d(i) { return i; } class A { v = d(0); } new A(); new A();').parse()
        self.assertFalse(ModelCache(ast).tampering.at_most_once(_call_of_name(ast, 'd')))
