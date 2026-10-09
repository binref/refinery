from __future__ import annotations

import inspect
import time
import unittest

from test import TestBase
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
from refinery.lib.scripts.js.parser import JsParser

#: The length helper the obfuscation declares beside its router when it records the length of each
#: function: it gives the stand-in the router hands out the length of the function it stands for.
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
    """
    The lines of the router the obfuscation writes, with the payload and the cache it declares in
    front of it. *dict_lines* spell the entries of its table; *lengths* is the default of its fourth
    parameter, which holds the length the stand-in for each key is given.
    """
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
    A program holding one router `d` with its payload `p`, its cache `c` and the length helper,
    preceded by *prefix_lines* and followed by *tail_lines*, the code dispatching through it. The
    router empties the payload for the flag `clearF`, hands out the stand-in of an entry for the
    flag `createF`, and wraps its result under the key `wk` for the flag `wrapF`.

    It is written here, where the laws about unwrapping it are stated, and read from wherever else a
    program built around one is needed.
    """
    return '\n'.join((
        *(prefix_lines or ()),
        *A_LENGTH_HELPER,
        *a_router(dict_lines, lengths=lengths),
        *tail_lines,
    ))


def unwrapped(source: str) -> bool:
    """
    Whether the dispatcher pass alone, run on *source*, leaves no function named `d`.
    """
    ast = JsParser(source).parse()
    transformer = JsDispatcherUnwrapper()
    transformer.models = ModelCache(ast)
    transformer.visit(ast)
    return not any(
        isinstance(node, JsFunctionDeclaration) and node.id is not None and node.id.name == 'd'
        for node in ast.walk()
    )


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

    def test_unwrapping_invalidates_shared_model_cache(self):
        """
        Unwrapping removes the router and the length helper only the router called, so a later
        transform sharing the analysis cache must not observe a model that still declares either.
        """
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


#: Functions written like the router that are not it, mapped to what Node prints for each: a command
#: runner, a router that logs, a memoizer, and a router resetting a list of its own. Each keeps a
#: table of functions selected by name and resets a list for one flag, and each does more than the
#: router does or less.
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

#: The router as a renaming obfuscation leaves it, mapped to what Node prints for it: the stand-in,
#: its rest parameter and the recorded length all carry names the router's parameters carry too, so
#: each name is a different binding in each place it is written.
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


#: The router followed by another declaration of its name, mapped to what Node prints for it: the
#: later declaration is the function the name holds when the program runs.
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
    """
    The pass reads a function as the router only where it is the template the obfuscation writes,
    statement by statement, with each name the binding the template means. Ordinary code built from
    the same parts is left alone, and the router is read whatever names it is written with.
    """

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


#: Programs in which the key of an entry is a name that is not free where the recovered function is
#: declared or called, mapped to what Node prints for each: a key that is no name, a reserved word,
#: `eval`, a global function, a local where it is called, a name the underscore form of which is
#: taken too, a key spelled as a string or read as a property, a name a nested function declares,
#: a key a variable takes beside the key its underscore form spells, two keys spelling one name, a
#: parameter of the enclosing function, a variable nothing reads, a free global read elsewhere, and
#: a global the enclosing function reads.
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

#: The same, run as classic scripts, where a top-level declaration is a property of the global
#: object, mapped to what Node prints for each: a free global read elsewhere, a local where the
#: entry is called, a variable nothing reads, and a global a function declared later reads.
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
    """
    A recovered function is declared where the router was and named after its key where that is a
    name nothing else means there. Declaring it must change what no other name refers to, and every
    dispatch rewritten to call it must reach it rather than a nearer binding of the same name.
    """

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


#: Dispatches written inside the table, mapped to what Node prints for each: an entry dispatching to
#: another, a dispatch inside a payload inside an entry, an entry dispatching through every form,
#: and a router of another shape with the same keys inside a function.
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

#: Each form a dispatch is written in, mapped to what Node prints for it: a call with arguments, a
#: call without, and a reference to the function, each plain, wrapped, and constructed and wrapped;
#: then a reference compared with itself, called with a receiver, handed to `map`, given a
#: property, and constructed.
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

#: Dispatches whose result is called or constructed where it stands, mapped to what Node prints for
#: each. The result of a wrapped call is read off the wrapper, so calling it as a method gives it
#: the wrapper as its receiver: through brackets, a dot, parentheses, at the start of a statement,
#: as a tag, optionally, and after `new`. Constructing it, or calling it through a pair or a plain
#: call, gives it none.
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
    """
    The flags behind the key decide what a dispatch denotes: the function itself, a call of it with
    the payload emptied, or a call of it with what the payload holds, wrapped or not. Each form is
    rewritten to that, wherever it stands, the table included, and the router is gone afterwards.
    A wrapper whose result is called as its method stays around the call, since it is that call's
    receiver.
    """

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


#: A program that dispatches through a callee name built by an expression rather than written as a
#: string literal, mapped to what Node prints for it. The dispatcher is reached the ordinary way and
#: answers the ordinary way; only the spelling of the name keeps the unwrapper from reading it.
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
    """
    Unwrapping a dispatcher recovers the functions its table holds, replaces each dispatch through
    it with what that dispatch denotes, and removes the declaration. A dispatch whose key is not
    written as a string literal is one the pass cannot read, and the whole unwrap is refused where
    one is present rather than the removal alone: the dispatch left standing would call a router
    whose payload no recovered function reads.
    """

    def test_a_dispatch_through_a_computed_key_keeps_the_dispatcher(self):
        rows = A_DISPATCH_THROUGH_A_COMPUTED_KEY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: A program that installs a value at the index a dispatcher's payload was written with no element
#: in, and dispatches through it, mapped to what Node prints for it. The dispatcher reaches its
#: callee's arguments by reading them off the payload, so a position the payload does not hold is
#: read from the prototype chain like any other.
A_DISPATCH_WHOSE_PAYLOAD_HOLDS_A_HOLE = {
    "Array.prototype[1] = 'X';\n" + a_dispatcher(
        dict_lines=['"f1": function() { var [a, b, c] = p; return a + b + c; }'],
        tail_lines=['console.log((p = ["first", , "third"], d("f1")));'],
    ): 'firstXthird\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADispatcherPayloadHoleIsTheChainsToAnswer(TestBase):
    """
    Unwrapping a dispatcher into direct calls has to spell out each argument the payload carried,
    and a position the payload was written with no element in is not one it carries: what reaches
    the callee there is whatever the prototype chain answers for that index. Spelling it `undefined`
    is right only while that chain is the one the language describes, so the rewrite asks the effect
    model whether it still is, and refuses the dispatch where it is not.

    This is the law `test.lib.scripts.js.deobfuscation.test_inherited_reads` states of a read, at a
    site that decides it in the syntax rather than in the interpreter. The same program with the
    prototype left alone is `test_dispatcher_sparse_payload_preserves_arity` and prints
    `firstundefinedthird`, which is what the refusal here must not cost.

    Retired from `test.lib.scripts.js.test_release_blockers` and kept as the regression it retired
    into.
    """

    def test_a_payload_position_no_element_was_written_in_finds_what_the_chain_holds(self):
        rows = A_DISPATCH_WHOSE_PAYLOAD_HOLDS_A_HOLE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs whose dispatch is written inside another dispatch's payload, mapped to what Node prints
#: for each. The direct-call rewrite carries the payload elements into the call it builds, so a
#: dispatch standing in one is not taken away with the dispatch it is an argument of: the first row
#: is one this pass can read and has to rewrite as well, and the second is one it cannot, which
#: leaves a call the declaration is still needed for.
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


#: Dispatches written in forms this pass reads only in part, mapped to what Node prints for each.
#: The first two unwrap the return value on the wrap key, which is the callee's result rather than
#: the callee, and the third writes the ordinary payload pair with a grouping around the call.
#: Reading any of them as a bare zero-argument dispatch calls the callee with no arguments at all.
#: The second stands where the payload pair is refused, which is what leaves the unwrap to be read
#: by whoever else claims the call inside it.
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
    """
    Removing the declaration is right exactly while no reference to it survives, so the plan has to
    account for each reference one by one. A dispatch nested in a payload is the shape that shows
    it: what the rewrite of the outer dispatch does with that payload is carry it over, so the
    inner dispatch is still there afterwards and is either rewritten too or is a reason to refuse.
    """

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


#: Dispatches whose flag arguments say the expression means something other than the reading its
#: shape suggests, mapped to what Node prints for each. The key selects the table entry and the two
#: flags behind it select the branch: emptying the payload, handing back the entry instead of what
#: calling it returned, and wrapping that result in an object under the wrap key. A `new` dispatch
#: hands back the object the dispatcher returned only where it returned one, which is the wrapper
#: branch alone. The last nine are each one flag away from a form this pass reads, or write to one
#: of its forms: the access on the wrap key, or a value form, a call that throws as a target.
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


#: A bare dispatch over a payload something else filled, mapped to what Node prints for it. Reading
#: one as a call with no arguments is a claim about the payload rather than about the site: the
#: callee takes its arguments out of the array, and a dispatch that does not empty it first reaches
#: whatever the last one left there.
A_BARE_DISPATCH_OVER_A_PAYLOAD_SOMETHING_ELSE_FILLED = {
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=['p = ["x"];', 'console.log(d("f1"));'],
    ): 'Ax\n',
}


#: Dispatches carrying an argument the replacement keeps no room for, mapped to what Node prints for
#: each. The dispatcher takes its arguments out of the payload, so everything the site writes after
#: the key is read by the dispatcher alone and is gone from the call this pass builds — which makes
#: what evaluating it did the site's to account for. The second writes a whole dispatch there, which
#: no payload carries over. The last two hand a value form a fourth argument, which runs nothing
#: but which the router reads as its table of lengths.
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


#: A wrapped reference taken through the create/wrap flags and then called, mapped to what Node
#: prints for it. Calling the reference fills the payload from its own arguments, so `fn(42)`
#: reaches the entry with `42` as its first payload element; the unwrapper reads that entry's
#: payload destructuring as its parameters, so the direct call it builds carries `42` the same way.
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
    """
    The wrapped-reference form names a table entry rather than calling it, and the entry is called
    later through the reference. Unwrapping it to the extracted function must keep that call
    behaving as it did: the payload the entry destructured becomes the function's parameters, so a
    later `fn(42)` reaches the same value it reached through the payload.
    """

    def test_a_called_wrapped_reference_still_prints(self):
        rows = A_WRAPPED_REFERENCE_THAT_IS_CALLED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADispatchIsReadPastItsKey(TestBase):
    """
    The key names the table entry and settles nothing else. Which branch of the dispatcher runs, and
    therefore what the expression standing at the site denotes, is decided by the two flags behind
    the key and by whether the site spelled `new` — and the payload the callee reads its arguments
    from is filled by the dispatch before it, not by the one being read. A reading that takes the
    key alone answers a value the original never computed, and a dispatch written to is no value.
    """

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


#: Table entries that would tell they were moved out of the router, mapped to what Node prints for
#: each. Inside the table an entry is called as a method of the table, by the router, inside the
#: router's scope: it reads the table as `this`, also from an arrow, the router's `arguments`, no
#: `new.target`, the router's parameters and table through a direct `eval` or by name, its own name,
#: and the names the router declares in place of the globals of the same names.
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

#: A named entry that calls itself by its name, mapped to what Node prints for it: the router calls
#: the entry with an empty payload, so the recursion never ends.
A_NAMED_ENTRY = {
    a_dispatcher(
        ['"ke": function fact() { var [n] = p; return n < 2 ? 1 : n * fact(n - 1); }'],
        [
            'console.log((p = [5], d("ke")));',
        ],
    ): ('', 'RangeError'),
}

#: Entries that unpack nothing and whose call answers a wrapper around what the body does, mapped
#: to what Node prints for each: a generator, a generator that never yields, an `async` generator,
#: and an `async` function.
ENTRIES_OF_EVERY_KIND = {
    a_dispatcher(['"k1": function* () { yield 1; yield 2; }'], ['console.log([...d("k1", "clearF")].join());']): '1,2\n',
    a_dispatcher(['"k1": function* () { return 5; }'], ['console.log(typeof d("k1", "clearF").next);']): 'function\n',
    a_dispatcher(['"k1": async function* () { yield 3; }'], ['d("k1", "clearF").next().then(r => console.log(r.value));']): '3\n',
    a_dispatcher(['"k1": async function () { return 4; }'], ['d("k1", "clearF").then(v => console.log(v));']): '4\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnEntryMovesOutOnlyIfItCannotTell(TestBase):
    """
    A recovered function keeps the body and the kind of its entry but is called by its own name,
    outside the router, with its unpacking as parameters. An entry that can tell any of that apart
    stays in the router, and the router with it.
    """

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


#: Entries whose unpacking a parameter list spells, mapped to what Node prints for each: a rest
#: element, an object pattern, an array pattern, and an array pattern that skips an element.
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

#: Entries whose unpacking is read as their parameter list, mapped to what Node prints for each:
#: those above, a computed key, a computed key that runs code, a nested default, a hole in the
#: payload, a spread payload, a default, a rest element alone, a hole in the unpacking, which no
#: parameter list can skip, a parameter a function declaration of the body overwrites, in a block,
#: in a nested function, and through a value form, and a generator whose payload another dispatch
#: fills before its first step.
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
    """
    The first statement of an entry unpacks the payload, and the recovered function takes its
    pattern as its parameter list. A parameter list is bound at the call, before the function
    declarations of the body, and evaluates its defaults and computed keys in a scope of its own;
    the unpacking runs where it stands. Where that difference shows, the entry stays.
    """

    def test_unpackings_read_as_parameters_still_print(self):
        rows = UNPACKINGS_READ_AS_PARAMETERS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_unpackings_a_parameter_list_spells_are_unwrapped(self):
        rows = UNPACKINGS_A_PARAMETER_LIST_SPELLS
        self.assertEqual({source: unwrapped(source) for source in rows}, {source: True for source in rows})


#: The payload and the cache read where the unwrap does not remove them, mapped to what Node prints
#: for each: code before the unpacking that dispatches, a read of the payload after it, a read of
#: the payload and of the cache outside the router, an unpacking that is not the first declarator,
#: and the cache compared with what the router handed out.
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
    """
    The unwrap takes away every read of the payload and the cache it knows of: the unpackings, the
    assignments in front of the dispatches and the router's own. A read anywhere else would read
    what the router no longer writes, so it keeps the router.
    """

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


#: Programs reading the length helper or sharing it between two routers, mapped to what Node prints
#: for each: the second router's entry reads `this`, so that router stays and calls the helper.
A_LENGTH_HELPER_SOMETHING_ELSE_READS = {
    '\n'.join((
        *A_LENGTH_HELPER,
        *a_router(BOTH),
        *a_router(['"k6": function () { return typeof this; }'], router='e', payload='q', cache='c2'),
        'console.log((p = [1, 2], d("k1")), e("k6", "clearF"), [1].map(e("k6", "createF"))[0]);',
    )): '3 object object\n',
    a_dispatcher(BOTH, ['console.log((p = [1, 2], d("k1")), typeof setLen);']): '3 function\n',
}

#: Programs in which the initializer of the cache runs code of the program, mapped to what Node
#: prints for each: `Object.create` replaced, and `Object` a parameter of the function holding the
#: router.
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

#: A module exporting the payload and the cache, mapped to what Node prints for it.
A_MODULE_EXPORTING_THE_PAYLOAD_AND_THE_CACHE = {
    '\n'.join((
        *A_LENGTH_HELPER,
        *(F'export {line}' for line in a_router(BOTH)[:2]),
        *a_router(BOTH)[2:],
        'console.log((p = [1, 2], d("k1")), d("k2", "clearF"));',
    )): '3 7\n',
}


class TestTheUnwrapRemovesOnlyWhatOnlyTheRouterUsed(TestBase):
    """
    The router goes with the payload, the cache and the length helper, each only where nothing else
    references it and no importer reads it, and the cache only where its initializer runs nothing.
    No other function beside the router is removed, however empty: a host may call it by name.
    """

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


#: Other ways a program reaches the router, mapped to what Node prints for each: from a `with` body,
#: through a direct `eval` of a string written out and of one only known when it runs, through
#: another name, with a key the table lacks, through an optional call, from a class method, in a
#: strict script, after assigning the router, and from a function inside a `with` body.
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

#: The router reached in a classic script through an indirect `eval` of a string only known when it
#: runs, mapped to what Node prints for it: code run that way sees every global of the script.
OTHER_WAYS_TO_THE_ROUTER_IN_A_SCRIPT = {
    a_dispatcher(
        BOTH,
        [
            'console.log((0, eval)(Math.random() < 2 ? \'d("k2", "clearF")\' : ""), (p = [1, 2], d("k1")));',
        ],
    ): ('7 3\n', None),
}

#: Writing the payload from a function inside a `with` body whose object holds a payload of its own,
#: mapped to what Node prints for it: the entry unpacks what the program never filled.
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
    """
    The router goes only once every reference to it is a dispatch the pass has rewritten, with none
    resolved at run time and no direct `eval` positioned to reach it or to declare a name a
    rewritten dispatch would find first.
    """

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


#: Reads of what the router hands out where the program uses a function as a value, mapped to what
#: Node prints for each: the stand-in's text, and its length where the obfuscation records lengths.
WHAT_A_VALUE_FORM_IS_ASKED = {
    a_dispatcher(BOTH, ['console.log(d("k1", "createF").length);'], lengths='{ "k1": 2 }'): '2\n',
    a_dispatcher(BOTH, ['console.log(String(d("k1", "createF")).length > 0);']): 'true\n',
}

#: The same, where the stand-in and the recovered function answer differently, mapped to what Node
#: prints for each: its name, its length without recorded lengths, the length of it bound, and its
#: name through `new`.
WHAT_ONLY_THE_STAND_IN_ANSWERS = {
    a_dispatcher(BOTH, ['console.log(d("k1", "createF").name);']): 'fn\n',
    a_dispatcher(BOTH, ['console.log(d("k1", "createF").length);']): '0\n',
    a_dispatcher(BOTH, ['console.log(d("k1", "createF").bind(null, 1).length);']): '0\n',
    a_dispatcher(BOTH, ['console.log(new d("k1", "createF", "wrapF")["wk"].name);']): 'fn\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAValueFormIsTheFunctionItStandsFor(TestBase):
    """
    Where the program uses one of its functions as a value, the router hands out a stand-in that
    forwards to the entry, and the unwrap puts the recovered function there instead. The two answer
    a call alike, and differ in their name and, without recorded lengths, in their length.
    """

    def test_what_a_value_form_is_asked_still_prints(self):
        rows = WHAT_A_VALUE_FORM_IS_ASKED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.expectedFailure
    def test_what_only_the_stand_in_answers_still_prints(self):
        rows = WHAT_ONLY_THE_STAND_IN_ANSWERS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestUnwrappingTakesTimeThatGrowsWithTheProgram(TestBase):
    """
    Each program below holds the same function the given number of times, each function holding a
    router of its own, so an unwrap whose time grows with the program takes about eight times as
    long for eight times the functions.
    """

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
        # The fastest of three runs is compared, so a pause of the machine during one run cannot
        # decide the test.
        times: list[float] = []
        for _ in range(3):
            ast = JsParser(source).parse()
            transformer = JsDispatcherUnwrapper()
            transformer.models = ModelCache(ast)
            start = time.perf_counter()
            transformer.visit(ast)
            times.append(time.perf_counter() - start)
        return min(times)

    @unittest.expectedFailure
    def test_functions_each_holding_a_router_are_unwrapped_in_time_that_grows_with_the_program(self):
        small_time = self._fastest_of_three(5)
        large_time = self._fastest_of_three(40)
        # Each unwrap builds the model of the whole program once, so the time grows with the square
        # of the program: about 64 times as long. The bound is twice the size ratio, 16.
        self.assertLess(large_time / small_time, 16)


class TestStringArgumentReadsAPresentArgumentThatDenotesNothingAsUnreadable(TestBase):
    """
    `_string_argument` keeps three answers apart: the fixed string an argument denotes, `None` where
    the call has no argument at that index, and `_UNREADABLE` where it has one this pass cannot read
    as a fixed string. A string written with a `\\x` escape naming no character is present but
    denotes nothing, so it is unreadable and not absent — answering `None` for it would let the pass
    read a flag it cannot see as a flag that is not there and take the safety gate off the
    unwrapping. The backslash is spelled with `chr(92)` so nothing between the source and the parser
    reads it as an escape of its own.
    """

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
