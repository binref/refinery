from __future__ import annotations

import inspect
import time
import unittest

from test import TestBase, backlog, opportunity, todo
from test.lib.scripts.js.analysis.differential import (
    deobfuscate_source,
    host_behavior,
    node_executable,
)
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import (
    before_and_after,
    before_and_after_in_a_host,
    each_program_still_prints,
    wontfix,
)

from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.deobfuscation.dispatcher import (
    _UNREADABLE,
    JsDispatcherUnwrapper,
    _string_argument,
)
from refinery.lib.scripts.js.model import (
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
)
from refinery.lib.scripts.js.options import DeobfuscationOptions, ExecutionModel
from refinery.lib.scripts.js.parser import JsParser

A_LENGTH_HELPER = [
    'function setLen(fn, length = 1) {',
    '  Object["defineProperty"](fn, "length", { "value": length, "configurable": false });',
    '  return fn;',
    '}',
]


def a_router(
    dict_lines: list[str],
    *,
    router: str = 'd',
    payload: str = 'p',
    cache: str = 'c',
    lengths: str = '{}',
) -> list[str]:
    return [
        F'var {cache} = Object["create"](null);',
        F'var {payload};',
        F'function {router}(name, flagArg, returnTypeArg, fnLengths = {lengths}) {{',
        '  var output;',
        '  var fns = {',
        *dict_lines,
        '  };',
        F'  if (flagArg === "clearF") {{ {payload} = []; }}',
        '  if (flagArg === "createF") {',
        '    function createFunction() {',
        F'      var fn = function (...args) {{ {payload} = args; return fns[name].apply(this); }};',
        '      var fnLength = fnLengths[name];',
        '      if (fnLength) { setLen(fn, fnLength); }',
        '      return fn;',
        '    }',
        F'    output = {cache}[name] || ({cache}[name] = createFunction());',
        '  } else {',
        '    output = fns[name]();',
        '  }',
        '  if (returnTypeArg === "wrapF") { return { "wk": output }; }',
        '  else { return output; }',
        '}',
    ]


def a_dispatcher(
    dict_lines: list[str],
    tail_lines: list[str],
    *,
    prefix_lines: list[str] | None = None,
    lengths: str = '{}',
) -> str:
    """
    A program declaring the length helper and the router `d` with its payload `p` and its cache `c`,
    between *prefix_lines* and *tail_lines*.
    """
    return '\n'.join((
        *(prefix_lines or ()),
        *A_LENGTH_HELPER,
        *a_router(dict_lines, lengths=lengths),
        *tail_lines,
    ))


def functions_declared_after_the_unwrap(source: str, options: DeobfuscationOptions | None = None) -> list[str]:
    ast = JsParser(source).parse()
    transformer = JsDispatcherUnwrapper()
    transformer.options = options
    transformer.models = ModelCache(ast, options)
    transformer.visit(ast)
    return [
        node.id.name
        for node in ast.walk()
        if isinstance(node, JsFunctionDeclaration) and node.id is not None
    ]


def unwrapped(source: str, options: DeobfuscationOptions | None = None) -> bool:
    return 'd' not in functions_declared_after_the_unwrap(source, options)


ADD = '"k1": function () { var [a, b] = p; return a + b; }'
SEVEN = '"k2": function () { return 7; }'
BOTH = [F'{ADD},', SEVEN]


class TestDispatcherUnwrapping(TestJsDeobfuscator):

    def test_single_function_direct_call(self):
        source = a_dispatcher(
            dict_lines=['"abc": function() { var [x] = p; return x + 1; }'],
            tail_lines=['console.log((p = [5], d("abc")));'],
        )
        self.assertEqual('console.log(6);', self._deobfuscate(source))

    def test_multi_function_dispatcher(self):
        source = a_dispatcher(
            dict_lines=[
                '"f1": function() { var [a, b] = p; return a + b; },',
                '"f2": function() { var [a, b] = p; return a * b; }',
            ],
            tail_lines=[
                'var x = (p = [2, 3], d("f1"));',
                'var y = (p = [x, 4], d("f2"));',
                'console.log(y);',
            ],
        )
        self.assertEqual('console.log(20);', self._deobfuscate(source))

    def test_wrapped_reference(self):
        source = a_dispatcher(
            dict_lines=['"id": function() { var [x] = p; return x; }'],
            tail_lines=[
                'var fn = new d("id", "createF", "wrapF")["wk"];',
                'console.log(fn(42));',
            ],
        )
        self.assertEqual('console.log(42);', self._deobfuscate(source))

    def test_boilerplate_removal(self):
        source = a_dispatcher(
            dict_lines=['"k": function() { return 42; }'],
            tail_lines=['console.log(d("k"));'],
        )
        self.assertEqual('console.log(42);', self._deobfuscate(source))

    def test_a_dispatch_through_a_key_another_pass_folds_is_unwrapped(self):
        source = a_dispatcher(
            dict_lines=['"f1": function() { var [a, b, c] = p; return a + b + c; }'],
            tail_lines=[
                'var k = "f" + 1;',
                'console.log((p = ["a", "b", "c"], d(k)));',
            ],
        )
        self.assertEqual("console.log('abc');", self._deobfuscate(source))

    def test_unwrapping_invalidates_shared_model_cache(self):
        source = a_dispatcher(dict_lines=['"k": function() { return 42; }'], tail_lines=['console.log(d("k"));'])
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        transformer = JsDispatcherUnwrapper()
        transformer.models = cache
        transformer.visit(ast)
        remaining = sorted(
            node.id.name
            for node in ast.walk()
            if isinstance(node, JsFunctionDeclaration) and node.id is not None
        )
        self.assertEqual(['k'], remaining)
        self.assertIsNone(cache.model.lookup('setLen', cache.model.root_scope))
        self.assertIsNone(cache.model.lookup('d', cache.model.root_scope))


ORDINARY_CODE_SHAPED_LIKE_THE_ROUTER = {
    inspect.cleandoc("""
        var history;
        function run(cmd, mode, note) {
          var actions = {
            greet: function () { return "hello"; },
            count: function () { return 3; }
          };
          if (mode === "fresh") { history = []; }
          history.push(cmd);
          return actions[cmd]() + "/" + history.length;
        }
        console.log(run("greet", "fresh"), run("count", "more"));
    """): 'hello/1 3/2\n',
    inspect.cleandoc("""
        var seen;
        function route(path, mode, opts) {
          var table = {
            "home": function () { return "H"; },
            "about": function () { return "A"; }
          };
          if (mode === "reset") { seen = []; }
          console.log("route " + path);
          return table[path]();
        }
        console.log(route("home", "reset") + route("about"));
    """): 'route home\nroute about\nHA\n',
    inspect.cleandoc("""
        var memo = {};
        var log;
        function compute(key, mode, unused) {
          var impl = {
            sq: function () { return 49; },
            cube: function () { return 343; }
          };
          if (mode === "clear") { log = []; }
          if (mode === "cached") {
            return memo[key] || (memo[key] = impl[key]());
          }
          return impl[key]();
        }
        console.log(compute("sq", "cached"), compute("cube", "clear"));
    """): '49 343\n',
    inspect.cleandoc("""
        function run(cmd, mode, opt) {
          var buf;
          var actions = {
            a: function () { return 1; },
            b: function () { return 2; }
          };
          if (mode === "reset") { buf = []; }
          console.log("run " + cmd);
          return actions[cmd]();
        }
        console.log(run("a", "reset") + run("b"));
    """): 'run a\nrun b\n3\n',
}

THE_ROUTER_WITH_ITS_INNER_NAMES_REUSED = {
    inspect.cleandoc("""
        function setLen(fn, length = 1) {
          Object["defineProperty"](fn, "length", { "value": length, "configurable": false });
          return fn;
        }
        var c = Object["create"](null);
        var p;
        function d(name, flagArg, returnTypeArg, fnLengths = {}) {
          var output;
          var fns = {
            "k1": function () { var [a, b] = p; return a + b; },
            "k2": function () { return 7; }
          };
          if (flagArg === "clearF") { p = []; }
          if (flagArg === "createF") {
            function createFunction() {
              var flagArg = function (...flagArg) { p = flagArg; return fns[name].apply(this); };
              var returnTypeArg = fnLengths[name];
              if (returnTypeArg) { setLen(flagArg, returnTypeArg); }
              return flagArg;
            }
            output = c[name] || (c[name] = createFunction());
          } else {
            output = fns[name]();
          }
          if (returnTypeArg === "wrapF") { return { "wk": output }; }
          else { return output; }
        }
        console.log((p = [1, 2], d("k1")), d("k1", "createF")(3, 4));
    """): '3 7\n',
}


A_ROUTER_DECLARED_AGAIN = {
    a_dispatcher(
        BOTH,
        [
            'function d() { return "again"; }',
            'console.log((p = [1, 2], d("k1")));',
        ],
    ): 'again\n',
}


class TestOnlyTheRouterIsUnwrapped(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_ordinary_code_shaped_like_the_router_still_prints(self):
        rows = ORDINARY_CODE_SHAPED_LIKE_THE_ROUTER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_router_declared_again_still_prints(self):
        rows = A_ROUTER_DECLARED_AGAIN
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_the_router_with_its_inner_names_reused_still_prints(self):
        rows = THE_ROUTER_WITH_ITS_INNER_NAMES_REUSED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_router_with_its_inner_names_reused_is_unwrapped(self):
        rows = THE_ROUTER_WITH_ITS_INNER_NAMES_REUSED
        self.assertEqual({source: unwrapped(source) for source in rows}, {source: True for source in rows})


KEYS_THAT_ARE_NOT_FREE_NAMES = {
    a_dispatcher(
        ['"3abc": function () { var [a] = p; return a * 2; }'],
        ['console.log((p = [4], d("3abc")));'],
    ): '8\n',
    a_dispatcher(
        ['"delete": function () { var [a] = p; return a * 3; }'],
        ['console.log((p = [4], d("delete")));'],
    ): '12\n',
    a_dispatcher(
        ['"eval": function () { var [a] = p; return a * 5; }'],
        ['console.log((p = [4], d("eval")));'],
    ): '20\n',
    a_dispatcher(
        ['"helper": function () { var [a] = p; return "D" + a; }'],
        ['console.log((p = [1], d("helper")), helper());'],
        prefix_lines=['function helper() { return "H"; }'],
    ): 'D1 H\n',
    a_dispatcher(
        [ADD],
        [
            'function g() { var k1 = 5; return (p = [k1, 1], d("k1")); }',
            'console.log(g());',
        ],
    ): '6\n',
    a_dispatcher(
        ['"a": function () { var [x] = p; return "A" + x; }'],
        [
            'var _a = "u";',
            'function h(a) { return a + _a; }',
            'console.log((p = [h(1)], d("a")));',
        ],
    ): 'A1u\n',
    a_dispatcher([ADD], ['console.log("k1", (p = [1, 2], d("k1")));']): 'k1 3\n',
    a_dispatcher(
        BOTH,
        [
            'var o = { k1: "prop" };',
            'console.log(o.k1, (p = [1, 2], d("k1")));',
        ],
    ): 'prop 3\n',
    a_dispatcher(
        [ADD],
        [
            'function g() { function k1() { return "inner"; } return k1() + (p = [1, 2], d("k1")); }',
            'console.log(g());',
        ],
    ): 'inner3\n',
    a_dispatcher(
        ['"a": function () { return "A"; },', '"_a": function () { return "B"; }'],
        [
            'var a = 1;',
            'console.log(d("a", "clearF"), d("_a", "clearF"), a);',
        ],
    ): 'A B 1\n',
    a_dispatcher(
        ['"3x": function () { return "A"; },', '"_3x": function () { return "B"; }'],
        ['console.log(d("3x", "clearF"), d("_3x", "clearF"));'],
    ): 'A B\n',
    '\n'.join((
        'function outer(k1) {',
        a_dispatcher([ADD], ['return [(p = [1, 2], d("k1")), typeof k1];']),
        '}',
        'console.log(outer(5));',
    )): '[ 3, \'number\' ]\n',
    a_dispatcher([ADD], ['var k1 = 5;', 'console.log((p = [1, 2], d("k1")));']): '3\n',
    a_dispatcher([ADD], ['console.log(typeof k1, (p = [1, 2], d("k1")));']): 'undefined 3\n',
    '\n'.join((
        'var k1 = "G";',
        'function outer() {',
        a_dispatcher([ADD], ['return k1 + (p = [1, 2], d("k1"));']),
        '}',
        'console.log(outer());',
    )): 'G3\n',
}

KEYS_THAT_ARE_NOT_FREE_NAMES_IN_A_SCRIPT = {
    a_dispatcher([ADD], ['console.log(typeof k1, (p = [1, 2], d("k1")));']): ('undefined 3\n', None),
    a_dispatcher(
        [ADD],
        [
            'function g() { var k1 = 5; return (p = [k1, 1], d("k1")); }',
            'console.log(g());',
        ],
    ): ('6\n', None),
    a_dispatcher([ADD], ['var k1 = 5;', 'console.log((p = [1, 2], d("k1")));']): ('3\n', None),
    a_dispatcher(
        [ADD],
        [
            'console.log((p = [1, 2], d("k1")));',
            'function later() { return k1; }',
            'console.log(typeof later());',
        ],
    ): ('3\n', 'ReferenceError'),
}


class TestARecoveredFunctionNeitherCapturesNorIsCaptured(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_keys_that_are_not_free_names_still_print(self):
        rows = KEYS_THAT_ARE_NOT_FREE_NAMES
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_keys_that_are_not_free_names_in_a_script_still_print(self):
        rows = KEYS_THAT_ARE_NOT_FREE_NAMES_IN_A_SCRIPT
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            {source: (behavior, behavior) for source, behavior in rows.items()},
        )

    def test_a_key_a_pattern_names_under_every_suffix_names_no_function_the_pattern_names(self):
        source = a_dispatcher(['"main": function () { return 1; }'], ['console.log(d("main"));'])
        options = DeobfuscationOptions(entrypoints=('m*',))
        names = functions_declared_after_the_unwrap(source, options)
        self.assertEqual([name for name in names if options.names_entrypoint(name)], [])

    @opportunity
    def test_a_key_a_pattern_names_under_every_suffix_is_recovered_under_another_name(self):
        source = a_dispatcher(['"main": function () { return 1; }'], ['console.log(d("main"));'])
        options = DeobfuscationOptions(entrypoints=('m*',))
        names = functions_declared_after_the_unwrap(source, options)
        recovered = [name for name in names if name not in ('d', 'createFunction', 'setLen')]
        self.assertNotIn('d', names)
        self.assertEqual(len(recovered), 1)
        self.assertEqual([name for name in names if options.names_entrypoint(name)], [])

    @wontfix('the obfuscation makes up its keys at random, so no program reads one off the global object')
    def test_a_key_read_off_the_global_object_in_a_script(self):
        rows = {
            a_dispatcher([ADD], ['console.log(typeof globalThis["k1"], (p = [1, 2], d("k1")));']): ('undefined 3\n', None),
            a_dispatcher([ADD], ['console.log(typeof globalThis[`k1`], (p = [1, 2], d("k1")));']): ('undefined 3\n', None),
            a_dispatcher([ADD], ['console.log(typeof globalThis["k" + 1], (p = [1, 2], d("k1")));']): ('undefined 3\n', None),
        }
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            {source: (behavior, behavior) for source, behavior in rows.items()},
        )


DISPATCHES_INSIDE_THE_TABLE = {
    a_dispatcher(
        [
            '"k1": function () { var [a] = p; return "one" + (p = [a + 1], d("k3")); },',
            '"k3": function () { var [b] = p; return "three" + b; }',
        ],
        ['console.log((p = [1], d("k1")));'],
    ): 'onethree2\n',
    a_dispatcher(
        [
            '"k1": function () { var [a] = p; return (p = [(p = [a], d("k3"))], d("k3")); },',
            '"k3": function () { var [b] = p; return "<" + b + ">"; }',
        ],
        ['console.log((p = ["x"], d("k1")));'],
    ): '<<x>>\n',
    a_dispatcher(
        [
            '"k1": function () { var [a] = p; return [d("k2", "clearF"), d("k2", "clearF", "wrapF")["wk"], '
            'new d("k2", "clearF", "wrapF")["wk"], d("k3", "createF")(a), d("k3", "createF", "wrapF")["wk"](a), '
            'new d("k3", "createF", "wrapF")["wk"](a)].join(); },',
            F'{SEVEN},',
            '"k3": function () { var [b] = p; return b * 2; }',
        ],
        ['console.log((p = [5], d("k1")));'],
    ): '7,7,7,10,10,10\n',
    a_dispatcher(
        BOTH,
        [
            'function outer() {',
            '  var c2 = Object["create"](null);',
            '  var q;',
            '  function e(name, flagArg, returnTypeArg, fnLengths = {}) {',
            '    var output;',
            '    var fns = { "k1": function () { var [a] = q; return "inner" + a; } };',
            '    if (flagArg === "clearG") { q = []; }',
            '    output = fns[name]();',
            '    return output;',
            '  }',
            '  return (q = [1], e("k1")) + (p = [1, 2], d("k1"));',
            '}',
            'console.log(outer());',
        ],
    ): 'inner13\n',
}

EVERY_FORM_OF_A_DISPATCH = {
    a_dispatcher(BOTH, ['console.log((p = [1, 2], d("k1")));']): '3\n',
    a_dispatcher(BOTH, ['console.log((p = [1, 2], d("k1", "zz", "wrapF")["wk"]));']): '3\n',
    a_dispatcher(BOTH, ['console.log((p = [1, 2], new d("k1", "zz", "wrapF")["wk"]));']): '3\n',
    a_dispatcher(BOTH, ['console.log(d("k2", "clearF"));']): '7\n',
    a_dispatcher(BOTH, ['console.log(d("k2", "clearF", "wrapF")["wk"]);']): '7\n',
    a_dispatcher(BOTH, ['console.log(new d("k2", "clearF", "wrapF")["wk"]);']): '7\n',
    a_dispatcher(BOTH, ['var f = d("k1", "createF");', 'console.log(f(3, 4));']): '7\n',
    a_dispatcher(BOTH, ['var f = d("k1", "createF", "wrapF")["wk"];', 'console.log(f(3, 4));']): '7\n',
    a_dispatcher(BOTH, ['var f = new d("k1", "createF", "wrapF")["wk"];', 'console.log(f(3, 4));']): '7\n',
    a_dispatcher(BOTH, ['console.log(d("k1", "createF") === new d("k1", "createF", "wrapF")["wk"]);']): 'true\n',
    a_dispatcher(BOTH, ['console.log(d("k1", "createF").call({}, 3, 4));']): '7\n',
    a_dispatcher(BOTH, ['console.log([1, 2].map(d("k2", "createF")).join());']): '7,7\n',
    a_dispatcher(
        BOTH,
        [
            'var f = d("k2", "createF");',
            'f.tag = 1;',
            'console.log(d("k2", "createF").tag);',
        ],
    ): '1\n',
    a_dispatcher(
        ['"k4": function () { var [v] = p; return { v: v }; }'],
        [
            'var C = d("k4", "createF");',
            'console.log(new C(9).v);',
        ],
    ): '9\n',
}

DISPATCHES_WHOSE_RESULT_IS_CALLED = {
    a_dispatcher(
        [
            '"k2": function () { return function () {'
            ' return this && typeof this.wk === "function" ? "wrapper" : "plain"; }; }',
        ],
        ['console.log(d("k2", "clearF", "wrapF")["wk"](1));'],
    ): 'wrapper\n',
    a_dispatcher(
        [
            '"k2": function () { return function () {'
            ' return this && typeof this.wk === "function" ? "wrapper" : "plain"; }; }',
        ],
        ['console.log(new d("k2", "clearF", "wrapF")["wk"](1));'],
    ): 'wrapper\n',
    a_dispatcher(
        [
            '"k2": function () { return function () {'
            ' return this && typeof this.wk === "function" ? "wrapper" : "plain"; }; }',
        ],
        ['console.log(d("k2", "clearF", "wrapF")["wk"]`x`);'],
    ): 'wrapper\n',
    a_dispatcher(
        [
            '"k2": function () { return function () {'
            ' return this && typeof this.wk === "function" ? "wrapper" : "plain"; }; }',
        ],
        ['console.log(d("k2", "clearF", "wrapF")["wk"]?.(1));'],
    ): 'wrapper\n',
    a_dispatcher(
        [
            '"k1": function () { var [a] = p; return function () {'
            ' return this && typeof this.wk === "function" ? "wrapper" : "plain" + a; }; }',
        ],
        ['console.log((p = [1], d("k1", "zz", "wrapF")["wk"])(1));'],
    ): 'plain1\n',
    a_dispatcher(
        [
            '"k2": function () { return function () {'
            ' return this && typeof this.wk === "function" ? "wrapper" : "plain"; }; }',
        ],
        ['console.log(d("k2", "clearF")(1));'],
    ): 'plain\n',
    a_dispatcher(
        ['"k2": function () { return function () { return typeof this.wk; }; }'],
        [
            'try { console.log(d("k2", "clearF", "wrapF")["wk"]()); } catch (e) { console.log(e.constructor.name); }',
        ],
    ): 'function\n',
    a_dispatcher(
        [
            '"k3": function () { return function () { '
            'return typeof this === "object" && this !== null && "wk" in this ? "wrapper" : "plain"; }; }',
        ],
        ['console.log((d("k3", "clearF", "wrapF")["wk"])(1));'],
    ): 'wrapper\n',
    a_dispatcher(
        ['"k4": function () { return function () { console.log(typeof this); }; }'],
        [
            'd("k4", "clearF", "wrapF")["wk"]();',
        ],
    ): 'object\n',
    a_dispatcher(
        [
            '"k3": function () { return function () { '
            'return typeof this === "object" && this !== null && "wk" in this ? "wrapper" : "plain"; }; }',
        ],
        ['console.log(d("k3", "clearF", "wrapF").wk(1));'],
    ): 'wrapper\n',
    a_dispatcher(
        ['"k5": function () { return function () { this.made = typeof this; }; }'],
        [
            'console.log(new (d("k5", "clearF", "wrapF")["wk"])().made);',
        ],
    ): 'object\n',
    a_dispatcher(
        ['"k1": function () { var [a] = p; return function () { this.v = a; }; }'],
        [
            'console.log(new ((p = [7], d("k1")))().v);',
        ],
    ): '7\n',
    a_dispatcher(
        ['"k1": function () { return function () { this.v = 8; }; }'],
        [
            'console.log(new (d("k1", "clearF"))().v);',
        ],
    ): '8\n',
    a_dispatcher(
        ['"k1": function () { return function () { this.v = 9; }; }'],
        [
            'console.log(new (d("k1", "clearF", "wrapF")["wk"])().v);',
        ],
    ): '9\n',
    a_dispatcher(
        ['"k1": function () { return function () { this.v = 10; }; }'],
        [
            'console.log(new (new d("k1", "clearF", "wrapF")["wk"])().v);',
        ],
    ): '10\n',
}


class TestEveryDispatchIsRewrittenToWhatItDenotes(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_dispatches_inside_the_table_still_print(self):
        rows = DISPATCHES_INSIDE_THE_TABLE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_every_form_of_a_dispatch_still_prints(self):
        rows = EVERY_FORM_OF_A_DISPATCH
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_dispatches_whose_result_is_called_still_print(self):
        rows = DISPATCHES_WHOSE_RESULT_IS_CALLED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_every_form_of_a_dispatch_is_unwrapped(self):
        rows = {
            **DISPATCHES_INSIDE_THE_TABLE,
            **EVERY_FORM_OF_A_DISPATCH,
            **DISPATCHES_WHOSE_RESULT_IS_CALLED,
            **KEYS_THAT_ARE_NOT_FREE_NAMES,
        }
        self.assertEqual({source: unwrapped(source) for source in rows}, {source: True for source in rows})


A_DISPATCH_STANDING_AS_A_STATEMENT = {
    a_dispatcher(
        ['"k1": function () { var [a, b] = p; console.log(a + b); }'],
        ['p = [1, 2], d("k1");'],
    ): '3\n',
    a_dispatcher(
        ['"k1": function () { var [a, b] = p; console.log(a + b); }'],
        ['(p = [3, 4], d("k1"));'],
    ): '7\n',
    a_dispatcher(
        ['"k1": function () { var [a, b] = p; console.log(a + b); }'],
        ['function run(c) { if (c) p = [5, 6], d("k1"); }', 'run(1);', 'run(0);'],
    ): '11\n',
    a_dispatcher(
        ['"k1": function () { var [a, b] = p; console.log(a + b); }'],
        ['p = [1, 1], d("k1"), console.log("after");'],
    ): '2\nafter\n',
}


class TestADispatchStandingAsAStatementIsRewritten(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_program_still_prints(self):
        rows = A_DISPATCH_STANDING_AS_A_STATEMENT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_router_is_gone_after_the_deobfuscation(self):
        rows = A_DISPATCH_STANDING_AS_A_STATEMENT
        self.assertEqual(
            {source: 'function d(' in deobfuscate_source(source, execution=ExecutionModel.module) for source in rows},
            {source: False for source in rows},
        )


A_DISPATCH_THROUGH_A_COMPUTED_KEY = {
    a_dispatcher(
        dict_lines=['"f1": function() { var [a, b, c] = p; return a + b + c; }'],
        tail_lines=[
            'var k = "f" + 1;',
            'console.log((p = ["a", "b", "c"], d(k)));',
        ],
    ): 'abc\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADispatcherIsKeptWhileACallToItSurvives(TestBase):

    def test_a_dispatch_through_a_computed_key_still_prints(self):
        rows = A_DISPATCH_THROUGH_A_COMPUTED_KEY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_DISPATCH_WHOSE_PAYLOAD_HOLDS_A_HOLE = {
    "Array.prototype[1] = 'X';\n" + a_dispatcher(
        dict_lines=['"f1": function() { var [a, b, c] = p; return a + b + c; }'],
        tail_lines=['console.log((p = ["first", , "third"], d("f1")));'],
    ): 'firstXthird\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADispatcherPayloadHoleIsTheChainsToAnswer(TestBase):

    def test_a_payload_position_no_element_was_written_in_finds_what_the_chain_holds(self):
        rows = A_DISPATCH_WHOSE_PAYLOAD_HOLDS_A_HOLE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_DISPATCH_WRITTEN_INTO_ANOTHER_DISPATCHS_PAYLOAD = {
    a_dispatcher(
        dict_lines=[
            '"f1": function() { var [a] = p; return "A" + a; },',
            '"f2": function() { var [b] = p; return "B" + b; }',
        ],
        tail_lines=['console.log((p = [(p = ["x"], d("f1"))], d("f2")));'],
    ): 'BAx\n',
    a_dispatcher(
        dict_lines=[
            '"f1": function() { var [a] = p; return "A" + a; },',
            '"f2": function() { var [b] = p; return "B" + b; }',
        ],
        tail_lines=[
            'var k = "f" + 1;',
            'console.log((p = [(p = ["x"], d(k))], d("f2")));',
        ],
    ): 'BAx\n',
}


A_DISPATCH_SPELLED_AROUND_THE_CALL = {
    a_dispatcher(
        dict_lines=['"f1": function() { return 5; }'],
        tail_lines=['console.log(d("f1", "x", "wrapF")["wk"]);'],
    ): '5\n',
    "Array.prototype[1] = 'X';\n" + a_dispatcher(
        dict_lines=['"f1": function() { var [a, b, c] = p; return a + b + c; }'],
        tail_lines=['console.log((p = ["first", , "third"], d("f1", "x", "wrapF")["wk"]));'],
    ): 'firstXthird\n',
    a_dispatcher(
        dict_lines=['"f1": function() { var [a, b, c] = p; return a + b + c; }'],
        tail_lines=['console.log((p = ["a", "b", "c"], (d("f1"))));'],
    ): 'abc\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestEveryDispatchThroughADispatcherIsAccountedFor(TestBase):

    def test_a_dispatch_written_into_another_dispatchs_payload_is_accounted_for(self):
        rows = A_DISPATCH_WRITTEN_INTO_ANOTHER_DISPATCHS_PAYLOAD
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_dispatch_spelled_around_the_call_is_not_read_as_a_bare_one(self):
        rows = A_DISPATCH_SPELLED_AROUND_THE_CALL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_DISPATCH_WHOSE_FLAGS_SAY_SOMETHING_ELSE = {
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=['console.log((p = ["x"], d("f1", "clearF")));'],
    ): 'Aundefined\n',
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=['console.log(typeof (p = ["x"], d("f1", "createF")));'],
    ): 'function\n',
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=['console.log((p = ["x"], d("f1")["wk"]));'],
    ): 'undefined\n',
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=['console.log((p = ["x"], d("f1", "y", "wrapF")).wk);'],
    ): 'Ax\n',
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=['console.log(typeof (p = ["x"], new d("f1")));'],
    ): 'object\n',
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=[
            'p = ["x"];',
            'console.log(typeof new d("f1", "zz", "wrapF")["wk"]);',
        ],
    ): 'string\n',
    a_dispatcher(BOTH, ['console.log(typeof d("k2", "clearF", "wrapF"));']): 'object\n',
    a_dispatcher(BOTH, ['console.log(d("k2", "clearF")["wk"]);']): 'undefined\n',
    a_dispatcher(BOTH, ['console.log(typeof new d("k2", "clearF"));']): 'object\n',
    a_dispatcher(
        BOTH,
        [
            'var o = d("k2", "clearF", "wrapF");',
            'd("k2", "clearF", "wrapF")["wk"] = 5;',
            'console.log(typeof k2, o.wk);',
        ],
    ): 'undefined 7\n',
    a_dispatcher(
        BOTH,
        [
            'var n = new d("k1", "createF", "wrapF")["wk"]++;',
            'console.log(typeof n);',
        ],
    ): 'number\n',
    a_dispatcher(BOTH, ['console.log(delete d("k1", "createF", "wrapF")["wk"]);']): 'true\n',
    a_dispatcher(
        BOTH,
        [
            'for (d("k1", "createF", "wrapF")["wk"] in { a: 1 }) ;',
            'console.log((p = [1, 2], d("k1")));',
        ],
    ): '3\n',
    a_dispatcher(
        BOTH,
        [
            'try { d("k1", "createF") = 5; } catch (e) { console.log(e.constructor.name); }',
            'console.log((p = [1, 2], d("k1")));',
        ],
    ): 'ReferenceError\n3\n',
    a_dispatcher(
        BOTH,
        [
            'try { for (d("k1", "createF") in { a: 1 }) ; } catch (e) { console.log(e.constructor.name); }',
            'console.log((p = [1, 2], d("k1")));',
        ],
    ): 'ReferenceError\n3\n',
}


A_BARE_DISPATCH_OVER_A_PAYLOAD_SOMETHING_ELSE_FILLED = {
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=['p = ["x"];', 'console.log(d("f1"));'],
    ): 'Ax\n',
}


A_DISPATCH_ARGUMENT_THE_REWRITE_WOULD_DROP = {
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=[
            'var n = 0;',
            'function s() { n++; return "z"; }',
            'console.log((p = ["x"], d("f1", s())));',
            'console.log(n);',
        ],
    ): 'Ax\n1\n',
    a_dispatcher(
        dict_lines=[
            '"f1": function() { var [a] = p; return "A" + a; },',
            '"f2": function() { var [b] = p; return "B" + b; }',
        ],
        tail_lines=['console.log((p = ["a"], d("f1", (p = ["b"], d("f2")))));'],
    ): 'Ab\n',
    a_dispatcher(BOTH, ['var n = 0;', 'console.log(d("k2", "clearF", "zz", n++), n);']): '7 1\n',
    a_dispatcher(BOTH, ['console.log(d("k1", "createF", "zz", { "k1": 5 }).length);']): '5\n',
    a_dispatcher(
        BOTH,
        [
            'try { console.log(typeof d("k1", "createF", "zz", null)); } catch (e) { console.log(e.constructor.name); }',
        ],
    ): 'TypeError\n',
}


A_WRAPPED_REFERENCE_THAT_IS_CALLED = {
    a_dispatcher(
        dict_lines=['"id": function() { var [x] = p; return x; }'],
        tail_lines=[
            'var fn = new d("id", "createF", "wrapF")["wk"];',
            'console.log(fn(42));',
        ],
    ): '42\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWrappedReferenceIsCallableAfterUnwrapping(TestBase):

    def test_a_called_wrapped_reference_still_prints(self):
        rows = A_WRAPPED_REFERENCE_THAT_IS_CALLED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADispatchIsReadPastItsKey(TestBase):

    def test_a_dispatch_whose_flags_say_something_else_is_left_alone(self):
        rows = A_DISPATCH_WHOSE_FLAGS_SAY_SOMETHING_ELSE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_bare_dispatch_does_not_claim_the_payload_is_empty(self):
        rows = A_BARE_DISPATCH_OVER_A_PAYLOAD_SOMETHING_ELSE_FILLED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_dispatch_argument_the_rewrite_would_drop_is_first_asked_what_it_runs(self):
        rows = A_DISPATCH_ARGUMENT_THE_REWRITE_WOULD_DROP
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: An entry runs inside the router's scope, where the `createF` branch declares `createFunction` in
#: a block: in sloppy code that name hides the global of the same name and is `undefined` until the
#: branch runs.
ENTRIES_THAT_SEE_THE_ROUTER = {
    a_dispatcher(
        ['"k6": function () { return this && this.k6 ? "fns" : "other"; }'],
        [
            'console.log(d("k6", "clearF"));',
        ],
    ): 'fns\n',
    a_dispatcher(
        ['"k6": function () { var f = () => this && this.k6 ? "fns" : "other"; return f(); }'],
        [
            'console.log(d("k6", "clearF"));',
        ],
    ): 'fns\n',
    a_dispatcher(
        ['"k7": function () { var [a] = p; return arguments.length; }'],
        [
            'console.log((p = [1], d("k7")));',
        ],
    ): '0\n',
    a_dispatcher(
        ['"k8": function () { return { t: typeof new.target }; }'],
        [
            'var C = d("k8", "createF");',
            'console.log(new C().t);',
        ],
    ): 'undefined\n',
    a_dispatcher(['"k9": function () { return typeof name; }'], ['console.log(d("k9", "clearF"));']): 'string\n',
    a_dispatcher(['"k9": function () { return typeof fns; }'], ['console.log(d("k9", "clearF"));']): 'object\n',
    a_dispatcher(
        ['"k9": function () { var [a] = p; return eval("typeof name + a"); }'],
        [
            'console.log((p = [1], d("k9")));',
        ],
    ): 'string1\n',
    a_dispatcher(
        ['"k1": function () { var [x] = p; var f = () => arguments.length; return f(); }'],
        [
            'console.log((p = [5], d("k1")));',
        ],
    ): '0\n',
    a_dispatcher(
        ['"k1": function () { var [x] = p; var f = () => typeof new.target; return { t: f() }; }'],
        [
            'var C = d("k1", "createF");',
            'console.log(new C(1).t);',
        ],
    ): 'undefined\n',
    a_dispatcher(
        ['"k9": function () { return typeof createFunction; }'],
        [
            'console.log(d("k9", "clearF"));',
        ],
        prefix_lines=['var createFunction = function () { return "G"; };'],
    ): 'undefined\n',
    a_dispatcher(
        ['"k9": function () { return createFunction(); }'],
        [
            'try { console.log(d("k9", "clearF")); } catch (e) { console.log(e.constructor.name); }',
        ],
        prefix_lines=['var createFunction = function () { return "G"; };'],
    ): 'TypeError\n',
    a_dispatcher(
        ['"k9": function () { return typeof fn; }'],
        [
            'console.log(d("k9", "clearF"));',
        ],
        prefix_lines=['var fn = 1;'],
    ): 'number\n',
}

#: The entry takes `n` from the payload, not from its argument, so `fact(n - 1)` reads 5 again and
#: the recursion never ends.
A_NAMED_ENTRY = {
    a_dispatcher(
        ['"ke": function fact() { var [n] = p; return n < 2 ? 1 : n * fact(n - 1); }'],
        [
            'console.log((p = [5], d("ke")));',
        ],
    ): ('', 'RangeError'),
}

ENTRIES_OF_EVERY_KIND = {
    a_dispatcher(['"k1": function* () { yield 1; yield 2; }'], ['console.log([...d("k1", "clearF")].join());']): '1,2\n',
    a_dispatcher(['"k1": function* () { return 5; }'], ['console.log(typeof d("k1", "clearF").next);']): 'function\n',
    a_dispatcher(['"k1": async function* () { yield 3; }'], ['d("k1", "clearF").next().then(r => console.log(r.value));']): '3\n',
    a_dispatcher(['"k1": async function () { return 4; }'], ['d("k1", "clearF").then(v => console.log(v));']): '4\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnEntryMovesOutOnlyIfItCannotTell(TestBase):

    def test_entries_that_see_the_router_still_print(self):
        rows = ENTRIES_THAT_SEE_THE_ROUTER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_named_entry_still_throws(self):
        rows = A_NAMED_ENTRY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (behavior, behavior) for source, behavior in rows.items()},
        )

    def test_entries_of_every_kind_still_print(self):
        rows = ENTRIES_OF_EVERY_KIND
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_entries_of_every_kind_are_unwrapped(self):
        rows = ENTRIES_OF_EVERY_KIND
        self.assertEqual({source: unwrapped(source) for source in rows}, {source: True for source in rows})

    @wontfix('the obfuscation never dispatches an async function or a generator')
    def test_a_value_form_of_an_entry_of_another_kind_is_constructed(self):
        rows = {
            a_dispatcher(
                ['"k1": async function () { return 1; }'],
                [
                    'var C = d("k1", "createF");',
                    'try { console.log(typeof new C().then); } catch (e) { console.log(e.constructor.name); }',
                ],
            ): 'function\n',
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


UNPACKINGS_A_PARAMETER_LIST_SPELLS = {
    a_dispatcher(
        ['"k1": function () { var [a, ...rest] = p; return a + rest.length; },', SEVEN],
        [
            'console.log((p = [1, 2, 3], d("k1")), d("k2", "clearF"));',
        ],
    ): '3 7\n',
    a_dispatcher(
        ['"k1": function () { var [{ x, y }] = p; return x + y; },', SEVEN],
        [
            'console.log((p = [{ x: 1, y: 2 }], d("k1")), d("k2", "clearF"));',
        ],
    ): '3 7\n',
    a_dispatcher(
        ['"k1": function () { var [[x, y]] = p; return x * y; },', SEVEN],
        [
            'console.log((p = [[3, 4]], d("k1")), d("k2", "clearF"));',
        ],
    ): '12 7\n',
    a_dispatcher(
        ['"k1": function () { var [[, y]] = p; return y; },', SEVEN],
        [
            'console.log((p = [[3, 4]], d("k1")), d("k2", "clearF"));',
        ],
    ): '4 7\n',
}

UNPACKINGS_READ_AS_PARAMETERS = {
    **UNPACKINGS_A_PARAMETER_LIST_SPELLS,
    a_dispatcher(
        ['"k1": function () { var [{ [key()]: v }] = p; function key() { return "inner"; } return v; }'],
        [
            'console.log((p = [{ inner: "I", outer: "O" }], d("k1")));',
        ],
        prefix_lines=['function key() { return "outer"; }'],
    ): 'I\n',
    a_dispatcher(
        [
            '"k1": function () { var [{ [key()]: v }] = p; function key() { count++; return "inner"; } return v + count; }',
        ],
        [
            'console.log((p = [{ inner: "I", outer: "O" }], d("k1")));',
        ],
        prefix_lines=['var count = 0;', 'function key() { return "outer"; }'],
    ): 'I1\n',
    a_dispatcher(
        ['"k1": function () { var [{ a = 1 }] = p; return a; }'],
        [
            'console.log((p = [{}], d("k1")));',
        ],
    ): '1\n',
    a_dispatcher(
        ['"kc": function () { var [a, b, e] = p; return [a, b, e].join(); }'],
        [
            'console.log((p = [1, , 3], d("kc")));',
        ],
    ): '1,,3\n',
    a_dispatcher(
        ['"kc": function () { var [a, b, e] = p; return [a, b, e].join(); }'],
        [
            'function g() { return (p = [...arguments], d("kc")); }',
            'console.log(g(1, 2, 3));',
        ],
    ): '1,2,3\n',
    a_dispatcher(['"kd": function () { var [a = 5] = p; return a; }'], ['console.log((p = [], d("kd")));']): '5\n',
    a_dispatcher(
        ['"kd": function () { var [...a] = p; return a.length; }'],
        [
            'console.log((p = [1, 2], d("kd")));',
        ],
    ): '2\n',
    a_dispatcher(['"kh": function () { var [a, , e] = p; return a + e; }'], ['console.log((p = [1, 2, 3], d("kh")));']): '4\n',
    a_dispatcher(
        ['"k1": function () { var [x] = p; function x() { return 1; } return typeof x; }'],
        [
            'console.log((p = [5], d("k1")));',
        ],
    ): 'number\n',
    a_dispatcher(
        ['"k1": function () { var [x] = p; { function x() { return 1; } } return typeof x; }'],
        [
            'console.log((p = [5], d("k1")));',
        ],
    ): 'function\n',
    a_dispatcher(
        [
            '"k1": function () { var [a] = p; function g() { function a() {} return typeof a; } return g() + a; }',
        ],
        ['console.log((p = [1], d("k1")));'],
    ): 'function1\n',
    a_dispatcher(
        [
            '"k1": function () { var [cb] = p; function cb() { return "inner"; } return typeof cb === "function" ? cb() : cb; }',
        ],
        ['console.log([1].map(d("k1", "createF")).join());'],
    ): '1\n',
    a_dispatcher(
        ['"k1": function* () { var [a] = p; yield a; },', '"k2": function () { return 0; }'],
        [
            'var g = (p = ["first"], d("k1"));',
            '(p = ["second"], d("k2"));',
            'console.log(g.next().value);',
        ],
    ): 'second\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnUnpackingBecomesAParameterListOnlyWhereItMeansTheSame(TestBase):

    def test_unpackings_read_as_parameters_still_print(self):
        rows = UNPACKINGS_READ_AS_PARAMETERS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_unpackings_a_parameter_list_spells_are_unwrapped(self):
        rows = UNPACKINGS_A_PARAMETER_LIST_SPELLS
        self.assertEqual({source: unwrapped(source) for source in rows}, {source: True for source in rows})


THE_PAYLOAD_AND_THE_CACHE_READ_ELSEWHERE = {
    a_dispatcher(
        [
            '"ka": function () { if (globalThis.flag) { (p = ["inner"], d("kb")); } var [v] = p; return v; },',
            '"kb": function () { var [w] = p; return w; }',
        ],
        ['globalThis.flag = true;', 'console.log((p = ["outer"], d("ka")));'],
    ): 'inner\n',
    a_dispatcher(
        ['"ka": function () { var [v] = p; return v + p.length; }'],
        [
            'console.log((p = ["x", "y"], d("ka")));',
        ],
    ): 'x2\n',
    a_dispatcher(BOTH, ['console.log((p = [1, 2], d("k1")), p.length);']): '3 2\n',
    a_dispatcher(BOTH, ['console.log((p = [1, 2], d("k1")), typeof c);']): '3 object\n',
    a_dispatcher(
        [
            '"ka": function () { var x = (p = ["inner"], d("kb")), [v] = p; return v + x; },',
            '"kb": function () { var [w] = p; return w; }',
        ],
        ['console.log((p = ["outer"], d("ka")));'],
    ): 'innerinner\n',
    a_dispatcher(BOTH, ['var f = d("k1", "createF");', 'console.log(c["k1"] === f);']): 'true\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestThePayloadAndTheCacheAreReadOnlyWhereTheUnwrapRemovesThem(TestBase):

    def test_the_payload_and_the_cache_read_elsewhere_still_print(self):
        rows = THE_PAYLOAD_AND_THE_CACHE_READ_ELSEWHERE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @wontfix('no obfuscated program replaces the array iterator or apply, and a polyfill writes both')
    def test_a_built_in_the_router_uses_replaced(self):
        rows = {
            a_dispatcher(
                BOTH,
                [
                    'Array.prototype[Symbol.iterator] = function* () { yield 40; yield 2; };',
                    'console.log((p = [1, 2], d("k1")));',
                ],
            ): '42\n',
            a_dispatcher(
                BOTH,
                [
                    'var f = d("k1", "createF");',
                    'Function.prototype.apply = function () { return "patched"; };',
                    'console.log(f(1, 2));',
                ],
            ): 'patched\n',
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_LENGTH_HELPER_SOMETHING_ELSE_READS = {
    '\n'.join((
        *A_LENGTH_HELPER,
        *a_router(BOTH),
        *a_router(['"k6": function () { return typeof this; }'], router='e', payload='q', cache='c2'),
        'console.log((p = [1, 2], d("k1")), e("k6", "clearF"), [1].map(e("k6", "createF"))[0]);',
    )): '3 object object\n',
    a_dispatcher(BOTH, ['console.log((p = [1, 2], d("k1")), typeof setLen);']): '3 function\n',
}

A_CACHE_INITIALIZER_THAT_RUNS_PROGRAM_CODE = {
    a_dispatcher(
        BOTH,
        ['console.log((p = [1, 2], d("k1")));'],
        prefix_lines=['Object.create = function () { console.log("create"); return {}; };'],
    ): 'create\n3\n',
    '\n'.join((
        'function f(Object) {',
        a_dispatcher(BOTH, ['return (p = [1, 2], d("k1"));']),
        '}',
        'console.log(f({ create: function () { console.log("create"); return {}; } }));',
    )): 'create\n3\n',
}

A_MODULE_EXPORTING_THE_PAYLOAD_AND_THE_CACHE = {
    '\n'.join((
        *A_LENGTH_HELPER,
        *(F'export {line}' for line in a_router(BOTH)[:2]),
        *a_router(BOTH)[2:],
        'console.log((p = [1, 2], d("k1")), d("k2", "clearF"));',
    )): '3 7\n',
}


class TestTheUnwrapRemovesOnlyWhatOnlyTheRouterUsed(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_length_helper_something_else_reads_still_prints(self):
        rows = A_LENGTH_HELPER_SOMETHING_ELSE_READS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_cache_initializer_that_runs_program_code_still_prints(self):
        rows = A_CACHE_INITIALIZER_THAT_RUNS_PROGRAM_CODE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_module_exporting_the_payload_and_the_cache_still_prints(self):
        rows = A_MODULE_EXPORTING_THE_PAYLOAD_AND_THE_CACHE
        self.assertEqual(
            {source: before_and_after(source, module=True) for source in rows},
            each_program_still_prints(rows),
        )

    @wontfix('the obfuscation declares the cache, the payload and the length helper itself, beside the router')
    def test_template_parts_beside_the_router_written_otherwise(self):
        router = a_router(['"k1": function () { var [a] = p; return a + v; }'])
        rows = {
            '\n'.join((
                *A_LENGTH_HELPER,
                'var c = { "k1": function () { return "cached"; } };',
                *a_router(BOTH)[1:],
                'console.log(d("k1", "createF")(1, 2));',
            )): 'cached\n',
            '\n'.join((
                *A_LENGTH_HELPER,
                *router[:2],
                'function outer(v) {',
                *router[2:],
                '  return d("k1", "createF");',
                '}',
                'console.log(outer(1)(10), outer(2)(10));',
            )): '11 11\n',
            '\n'.join((
                'function setLen(fn, length) { console.log("helper"); return fn; }',
                *a_router(BOTH, lengths='{ "k1": 2 }'),
                'console.log(d("k1", "createF")(1, 2));',
            )): 'helper\n3\n',
            a_dispatcher(BOTH, ['try { d("k2", "clearF"); } catch (e) { console.log(e.constructor.name); }']).replace(
                'var p;',
                'const p = [];',
            ): 'TypeError\n',
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_an_empty_function_a_host_calls_stays(self):
        source = '\n'.join((
            'function OnHostEvent() {}',
            a_dispatcher(BOTH, ['console.log((p = [1, 2], d("k1")));']),
        ))
        calls = ('OnHostEvent',)
        self.assertEqual(
            host_behavior(deobfuscate_source(source, entrypoints=calls), calls=calls),
            host_behavior(source, calls=calls),
        )


OTHER_WAYS_TO_THE_ROUTER = {
    a_dispatcher(
        BOTH,
        [
            'with ({ d: function () { return "shadow"; } }) { console.log((p = [1, 2], d("k1"))); }',
        ],
    ): 'shadow\n',
    a_dispatcher(
        BOTH,
        [
            'function g() { return eval(\'d("k2", "clearF")\'); }',
            'console.log(g(), (p = [1, 2], d("k1")));',
        ],
    ): '7 3\n',
    a_dispatcher(
        BOTH,
        [
            'function g() { return eval(Math.random() < 2 ? \'d("k2", "clearF")\' : ""); }',
            'console.log(g(), (p = [1, 2], d("k1")));',
        ],
    ): '7 3\n',
    a_dispatcher(BOTH, ['var h = d;', 'console.log(h("k2", "clearF"), (p = [1, 2], d("k1")));']): '7 3\n',
    a_dispatcher(
        BOTH,
        [
            'try { d("zz", "clearF"); } catch (e) { console.log(e.constructor.name); }',
            'console.log((p = [1, 2], d("k1")));',
        ],
    ): 'TypeError\n3\n',
    a_dispatcher(BOTH, ['console.log(d?.("k2", "clearF"));']): '7\n',
    a_dispatcher(
        BOTH,
        [
            'class K { m() { return (p = [1, 2], d("k1")); } }',
            'console.log(new K().m());',
        ],
    ): '3\n',
    a_dispatcher(
        BOTH,
        [
            'console.log((p = [1, 2], d("k1")), d("k2", "clearF"));',
        ],
        prefix_lines=['"use strict";'],
    ): '3 7\n',
    a_dispatcher(
        BOTH,
        [
            'console.log((p = [1, 2], d("k1")));',
            'd = function () { return "X"; };',
            'console.log((p = [1, 2], d("k1")));',
        ],
    ): '3\nX\n',
    a_dispatcher(
        BOTH,
        [
            'var g;',
            'with ({ d: function () { return "shadow"; } }) { g = function () { return (p = [1, 2], d("k1")); }; }',
            'console.log(g());',
        ],
    ): 'shadow\n',
}

OTHER_WAYS_TO_THE_ROUTER_IN_A_SCRIPT = {
    a_dispatcher(
        BOTH,
        [
            'console.log((0, eval)(Math.random() < 2 ? \'d("k2", "clearF")\' : ""), (p = [1, 2], d("k1")));',
        ],
    ): ('7 3\n', None),
}

A_PAYLOAD_WRITTEN_INSIDE_A_WITH_BODY = {
    a_dispatcher(
        BOTH,
        [
            'var g;',
            'with ({ p: [] }) { g = function () { return (p = [1, 2], d("k1")); }; }',
            'console.log(g());',
        ],
    ): ('', 'TypeError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheRouterIsReachedOnlyThroughWhatThePassReads(TestBase):

    def test_other_ways_to_the_router_still_print(self):
        rows = OTHER_WAYS_TO_THE_ROUTER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_other_ways_to_the_router_in_a_script_still_print(self):
        rows = OTHER_WAYS_TO_THE_ROUTER_IN_A_SCRIPT
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            {source: (behavior, behavior) for source, behavior in rows.items()},
        )

    def test_a_payload_written_inside_a_with_body_still_throws(self):
        rows = A_PAYLOAD_WRITTEN_INSIDE_A_WITH_BODY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (behavior, behavior) for source, behavior in rows.items()},
        )


DEFAULTED = '"k1": function () { var [a, b = 1] = p; return a + b; }'

WHAT_A_VALUE_FORM_IS_ASKED = {
    a_dispatcher(BOTH, ['console.log(d("k1", "createF").length);'], lengths='{ "k1": 2 }'): '2\n',
    a_dispatcher(BOTH, ['console.log(String(d("k1", "createF")).length > 0);']): 'true\n',
    a_dispatcher(BOTH, ['console.log(d("k1", "createF").length);']): '0\n',
    a_dispatcher(BOTH, ['console.log(d("k1", "createF").bind(null, 1).length);']): '0\n',
    a_dispatcher(
        [DEFAULTED],
        ['var f = d("k1", "createF");', 'console.log(f.length, f(2));'],
        lengths='{ "k1": 1 }',
    ): '1 3\n',
    a_dispatcher([DEFAULTED], ['var f = d("k1", "createF");', 'console.log(f.length, f(2));']): '0 3\n',
}

WHAT_ONLY_THE_STAND_IN_ANSWERS = {
    a_dispatcher(BOTH, ['console.log(d("k1", "createF").name);']): 'fn\n',
    a_dispatcher(BOTH, ['console.log(new d("k1", "createF", "wrapF")["wk"].name);']): 'fn\n',
    a_dispatcher(
        BOTH,
        ['console.log(Object.getOwnPropertyDescriptor(d("k1", "createF"), "length").configurable);'],
        lengths='{ "k1": 2 }',
    ): 'false\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAValueFormIsTheFunctionItStandsFor(TestBase):

    def test_what_a_value_form_is_asked_still_prints(self):
        rows = WHAT_A_VALUE_FORM_IS_ASKED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @backlog
    def test_what_only_the_stand_in_answers_still_prints(self):
        rows = WHAT_ONLY_THE_STAND_IN_ANSWERS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestUnwrappingTakesTimeThatGrowsWithTheProgram(TestBase):

    @staticmethod
    def _fastest_of_three(count: int) -> float:
        lines = list(A_LENGTH_HELPER)
        for index in range(count):
            lines.append(F'function outer{index}(v) {{')
            lines.extend(a_router(
                [F'"j{index}": function () {{ var [x] = q{index}; return x * 2; }}'],
                router=F'e{index}',
                payload=F'q{index}',
                cache=F'c{index}',
            ))
            lines.append(F'  return (q{index} = [v], e{index}("j{index}"));')
            lines.append('}')
        calls = ' + '.join(F'outer{index}({index})' for index in range(count))
        lines.append(F'console.log({calls});')
        source = '\n'.join(lines)
        times: list[float] = []
        for _ in range(3):
            ast = JsParser(source).parse()
            transformer = JsDispatcherUnwrapper()
            transformer.models = ModelCache(ast)
            start = time.perf_counter()
            transformer.visit(ast)
            times.append(time.perf_counter() - start)
        return min(times)

    @todo
    def test_functions_each_holding_a_router_are_unwrapped_in_time_that_grows_with_the_program(self):
        small_time = self._fastest_of_three(5)
        large_time = self._fastest_of_three(40)
        # The large program is eight times the small one, and the bound allows twice that ratio.
        self.assertLess(large_time / small_time, 16)


class TestStringArgumentReadsAPresentArgumentThatDenotesNothingAsUnreadable(TestBase):

    @staticmethod
    def _call(source: str) -> JsCallExpression:
        statement = JsParser(source + ';').parse().body[0]
        assert isinstance(statement, JsExpressionStatement)
        call = statement.expression
        assert isinstance(call, JsCallExpression)
        return call

    def test_a_present_argument_that_denotes_nothing_is_unreadable_not_absent(self):
        call = self._call(F'f("K", "{chr(92)}xZZ", g())')
        self.assertEqual(
            [_string_argument(call, index) for index in range(4)],
            ['K', _UNREADABLE, _UNREADABLE, None],
        )
