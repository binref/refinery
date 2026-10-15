"""
Programs storing a value in a part of a statement that runs on some runs of the statement only:
below `&&`, in an arm of `?:`, behind a logical assignment, in an optional call, or in the default
of a destructuring pattern. On a run that completes the statement without the store, a function
called after it reads the variable unset, a test after it is decided the other way, and an `in`
finds no key.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import (
    a_program,
    before_and_after,
    each_program_still_prints,
)

#: Programs storing into a variable declared without a value in a part of a statement that runs on
#: some runs only, and reading the variable in a function called after that statement, mapped to
#: what Node prints for them.
A_VALUE_STORED_ON_SOME_RUNS_READ_BY_A_FUNCTION = {
    a_program("""
        var c;
        Math.random() > 2 && (c = 5);
        function f(x) { return x + c; }
        console.log(f(Math.random() > 2 ? 1 : 2));
        """): 'NaN\n',
    a_program("""
        let o;
        "undefined" != typeof window && (o = !0);
        function n(e) { return e + (o ? " (browser)" : " (node)"); }
        console.log(n(Math.random() > 2 ? 1 : 2));
        """): '2 (node)\n',
    a_program("""
        var c;
        Math.random() > 2 && (c = 5);
        function f(n) { return n <= 0 ? c : f(n - 1); }
        console.log(f(2));
        """): 'undefined\n',
    a_program("""
        var c;
        Math.random() > 2 ? (c = 5) : 0;
        function f(n) { return n <= 0 ? c : f(n - 1); }
        console.log(f(2));
        """): 'undefined\n',
    a_program("""
        var c, y = 1;
        y ||= (c = 5);
        function f(n) { return n <= 0 ? c : f(n - 1); }
        console.log(f(2));
        """): 'undefined\n',
    a_program("""
        function D(s) { var out = ""; for (var i = 0; i < s.length; i++) { out += s[i].toUpperCase(); } return out; }
        function S(a, b) { return D(cfg.slice(a, a + b)); }
        var cfg, flag = Math.random() > 2;
        flag && (cfg = "hello world");
        var r; try { r = S(0, 5); } catch (e) { r = e.constructor.name; }
        console.log(r);
        """): 'TypeError\n',
    a_program("""
        function f(n) { return n <= 0 ? base : f(n - 1) + 1; }
        var base, flag = Math.random() > 2;
        flag && (base = 10);
        console.log(f(3));
        """): 'NaN\n',
    a_program("""
        function f(n) { return n <= 0 ? c : f(n - 1); }
        var c;
        Math.random() > 2 && (c = 5);
        console.log(f(2));
        """): 'undefined\n',
    a_program("""
        var c;
        Math.random() > 2 && (c = 5);
        var f = function (n) { return n <= 0 ? c : f(n - 1); };
        console.log(f(2));
        """): 'undefined\n',
}

#: Programs storing into a variable or a property in a part of a statement that runs on some runs
#: only, and testing after the statement whether the store ran, mapped to what Node prints for them.
A_VALUE_STORED_ON_SOME_RUNS_DECIDING_A_TEST = {
    a_program("""
        var c;
        Math.random() > 2 && (c = {});
        if (c) { console.log("yes"); } else { console.log("no"); }
        """): 'no\n',
    a_program("""
        var c;
        Math.random() > 2 && (c = {});
        function f() { return c ? "set" : "unset"; }
        console.log(f());
        """): 'unset\n',
    a_program("""
        var o = {};
        Math.random() > 2 && (o.k = 1);
        console.log("k" in o);
        """): 'false\n',
    a_program("""
        var o = {}, y = 1;
        y ||= (o.k = 1);
        console.log("k" in o);
        """): 'false\n',
    a_program("""
        var o = {};
        Math.random() > 2 ? (o.k = 1) : 0;
        console.log("k" in o);
        """): 'false\n',
    a_program("""
        var o = {}, p = null;
        p?.f(o.k = 1);
        console.log("k" in o);
        """): 'false\n',
    a_program("""
        var c, y = 1;
        y ||= (c = {});
        if (c) { console.log("yes"); } else { console.log("no"); }
        """): 'no\n',
}

#: Programs storing into a variable through a destructuring default, or storing into another one in
#: the default, at any depth of the pattern, mapped to what Node prints for them: the default runs
#: only where the value it stands for is missing.
A_VALUE_STORED_IN_A_DEFAULT = {
    a_program("""
        var cfg = JSON.parse('{"level": 3}'), level;
        ({ level: level = 1 } = cfg);
        function report() { return "level " + level; }
        console.log(report());
        """): 'level 3\n',
    a_program("""
        var b;
        ({ a: b = 5 } = { a: 1 });
        function f() { return b; }
        console.log(f(), b);
        """): '1 1\n',
    a_program("""
        var x, b;
        ({ a: b = (x = 5) } = { a: 1 });
        function f() { return x; }
        console.log(f(), b);
        """): 'undefined 1\n',
    a_program("""
        var x, b;
        ({ a: [b = (x = 5)] } = { a: [1] });
        function f() { return x; }
        console.log(f(), b);
        """): 'undefined 1\n',
    a_program("""
        var x, b;
        for ([b = (x = 5)] of [[1]]) ;
        function f() { return x; }
        console.log(f(), b);
        """): 'undefined 1\n',
    a_program("""
        function f(o) { var x = 1, b; ({ a: b = (x = 2) } = o); return x; }
        console.log(f({ a: 3 }));
        """): '1\n',
    a_program("""
        function f(xs) { var x = 1, b; for ([b = (x = 2)] of xs) { console.log(x); x = 9; } return x; }
        console.log(f([[3], [3]]));
        """): '1\n9\n9\n',
    a_program("""
        var o = {}, b;
        ({ a: b = (o.k = 1) } = { a: 2 });
        console.log("k" in o);
        """): 'false\n',
    a_program("""
        var c, b;
        ({ a: b = (c = {}) } = { a: 2 });
        if (c) { console.log("yes"); } else { console.log("no"); }
        """): 'no\n',
    a_program("""
        function f(o) { var b, x = 0; ({ a: b = (x = 2) } = o); return x; }
        console.log(f({ a: 1 }), f({}));
        """): '0 2\n',
    a_program("""
        function f(xs) { var b, x = 0; for ([b = (x = 2)] of xs) {} return x; }
        console.log(f([[1]]), f([[]]));
        """): '0 2\n',
    a_program("""
        function f(o) { var b, x = 0; ({ a: [b = (x = 2)] } = o); return x; }
        console.log(f({ a: [1] }), f({ a: [] }));
        """): '0 2\n',
    a_program("""
        function f(o) { var b; ({ a: b = 2 } = o); function g() { return b; } return g(); }
        console.log(f({ a: 1 }), f({}));
        """): '1 2\n',
    a_program("""
        function g(o) {
          var b, c;
          ({ a: [b = (c = 5)] } = o);
          function f() { return c; }
          return f();
        }
        console.log(g({ a: [1] }), g({ a: [] }));
        """): 'undefined 5\n',
    a_program("""
        function g(o) {
          var b, x = 1;
          ({ a: [b = (x = 2)] } = o);
          return x;
        }
        console.log(g({ a: [7] }), g({ a: [] }));
        """): '1 2\n',
    a_program("""
        function g(o) {
          var b, c;
          ({ a: { b = (c = 5) } } = o);
          function f() { return c; }
          return f();
        }
        console.log(g({ a: { b: 1 } }), g({ a: {} }));
        """): 'undefined 5\n',
    a_program("""
        function g(o) {
          var b, c;
          ({ a: [b = (c = 5)] } = o);
          if (c) { return "taken"; }
          return "skipped";
        }
        console.log(g({ a: [1] }), g({ a: [] }));
        """): 'skipped taken\n',
}

#: Programs whose `for-in` or `for-of` target is a pattern with a default that stores, read in the
#: body and after it, mapped to what Node prints for them.
A_VALUE_STORED_IN_A_DEFAULT_OF_A_LOOP_TARGET = {
    a_program("""
        function g(xs) {
          var b, c;
          for ({ a: [b = (c = 5)] } of xs) {
            return c;
          }
          return 0;
        }
        console.log(g([{ a: [1] }]), g([{ a: [] }]));
        """): 'undefined 5\n',
    a_program("""
        function g(xs) {
          var b, c;
          function f() { return c; }
          for ({ a: [b = (c = 5)] } of xs) {
            return f();
          }
          return 0;
        }
        console.log(g([{ a: [1] }]), g([{ a: [] }]));
        """): 'undefined 5\n',
    a_program("""
        function g(xs) {
          var b, c = 1;
          for ({ a: [b = (c = 2)] } of xs) {
            return c;
          }
          return 0;
        }
        console.log(g([{ a: [7] }]), g([{ a: [] }]));
        """): '1 2\n',
    a_program("""
        function g(xs) {
          var b, c;
          for ({ a: [b = (c = 5)] } of xs) {
            if (c) { return "taken"; }
            return "skipped";
          }
          return 0;
        }
        console.log(g([{ a: [1] }]), g([{ a: [] }]));
        """): 'skipped taken\n',
    a_program("""
        var x, b;
        function f() { return x; }
        for ([b = (x = 5)] of [[1]]) { console.log(f(), b); }
        """): 'undefined 1\n',
    a_program("""
        var c, b;
        for ([b = (c = {})] of [[1]]) { if (c) { console.log("yes"); } else { console.log("no"); } }
        """): 'no\n',
    a_program("""
        var b;
        for ([b = 5] of [[1]]) { console.log(b); }
        """): '1\n',
    a_program("""
        var b;
        for ({ a: b = 5 } of [{ a: 1 }]) { console.log(b); }
        """): '1\n',
    a_program("""
        var x, b;
        function f() { return x; }
        for ({ a: b = (x = 5) } of [{ a: 1 }]) { console.log(f(), b); }
        """): 'undefined 1\n',
    a_program("""
        function f(xs) { var x = 1, b; for ([b = (x = 2)] of xs) { console.log(x); x = 9; } return 0; }
        console.log(f([[3], [3]]));
        """): '1\n9\n0\n',
    a_program("""
        function g() { var b; for ([b = 5] in { ab: 1 }) { return b; } }
        console.log(g());
        """): 'a\n',
    a_program("""
        function g(xs) { var x, b; function f() { return x; } for ([b = (x = 5)] of xs) { return f(); } }
        console.log(g([[1]]));
        """): 'undefined\n',
    a_program("""
        var X;
        try {
          for ([X = (globalThis.Y = 1)] of [[0]]) { var Z = Y; }
          console.log("done");
        } catch (e) { console.log(e.name); }
        """): 'ReferenceError\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAValueStoredOnSomeRuns(TestBase):

    def test_a_function_reading_the_value_still_prints_the_same(self):
        rows = A_VALUE_STORED_ON_SOME_RUNS_READ_BY_A_FUNCTION
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_test_of_the_value_still_prints_the_same(self):
        rows = A_VALUE_STORED_ON_SOME_RUNS_DECIDING_A_TEST
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_value_stored_in_a_default_still_prints_the_same(self):
        rows = A_VALUE_STORED_IN_A_DEFAULT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_value_stored_in_a_default_of_a_loop_target_still_prints_the_same(self):
        rows = A_VALUE_STORED_IN_A_DEFAULT_OF_A_LOOP_TARGET
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
