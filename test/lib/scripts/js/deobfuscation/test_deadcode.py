from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.deobfuscation.deadcode import JsDeadCodeElimination
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser


class TestDeadCodeElimination(TestJsDeobfuscator):

    def test_if_true_keeps_consequent(self):
        self.assertEqual('x();', self._deadcode('if (true) { x(); } else { y(); }'))

    def test_if_false_keeps_alternate(self):
        self.assertEqual('y();', self._deadcode('if (false) { x(); } else { y(); }'))

    def test_if_false_no_else_removed(self):
        self.assertEqual('', self._deadcode('if (false) { x(); }'))

    def test_if_true_splices_block(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = 1;
                var b = 2;
                var c = 3;
                var d = 4;
                """
            ),
            self._deadcode('var a = 1; if (true) { var b = 2; var c = 3; } var d = 4;'),
        )


class TestDeadCodeLiteralConditions(TestJsDeobfuscator):

    def test_if_zero_eliminates_consequent(self):
        self.assertEqual('live();', self._deadcode('if (0) { dead(); } else { live(); }'))

    def test_if_empty_string_eliminates_consequent(self):
        self.assertEqual('live();', self._deadcode('if ("") { dead(); } else { live(); }'))

    def test_if_null_eliminates_consequent(self):
        self.assertEqual('live();', self._deadcode('if (null) { dead(); } else { live(); }'))

    def test_if_nonzero_keeps_consequent(self):
        self.assertEqual('live();', self._deadcode('if (1) { live(); } else { dead(); }'))

    def test_if_nonempty_string_keeps_consequent(self):
        self.assertEqual('live();', self._deadcode("if ('x') { live(); } else { dead(); }"))

    def test_if_zero_no_else_removed(self):
        self.assertEqual('', self._deadcode('if (0) { dead(); }'))

    def test_if_undefined_eliminates_consequent(self):
        self.assertEqual(
            'live();',
            self._deadcode('if (undefined) { dead(); } else { live(); }'),
        )


class TestEffectfulConstantCondition(TestJsDeobfuscator):

    def test_effectful_array_test_kept_when_branches_empty(self):
        self.assertEqual(
            '[v6(), false];',
            self._deadcode('if ([v6(), false]) {} else {}'),
        )

    def test_effectful_array_test_kept_before_consequent(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                [v6()];
                keep();
                """
            ),
            self._deadcode('if ([v6()]) { keep(); }'),
        )

    def test_pure_array_test_dropped(self):
        self.assertEqual('a();', self._deadcode('if ([1, 2]) { a(); } else { b(); }'))

    def test_pure_call_array_test_dropped(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function p() {
                  return 1;
                }
                a();
                """
            ),
            self._deadcode('function p() { return 1; } if ([p(), false]) { a(); } else { b(); }'),
        )


class TestRegressions(TestJsDeobfuscator):

    def test_dead_code_spliced_parent_pointers(self):
        ast = JsParser('if (true) { var a = 1; var b = 2; }').parse()
        t = JsDeadCodeElimination()
        t.visit(ast)
        self.assertTrue(t.changed)
        for stmt in ast.body:
            self.assertIs(stmt.parent, ast)


class TestRegressionBugs(TestJsDeobfuscator):

    def test_deadcode_block_scoped_declarations_not_leaked(self):
        result = self._deadcode(
            'if (true) { let x = 1; f(x); } let x = 2;'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                {
                  let x = 1;
                  f(x);
                }
                let x = 2;
                """
            ),
            result,
        )


class TestAConditionalWriteInAKeptTestKeepsALaterBranch(TestJsDeobfuscator):
    """
    A pruned branch whose test may have an effect leaves the test behind as a statement, where the
    `if` stood. When that statement assigns a name under a branch that may not run, a later test
    reading the name has no known value, and its branch stays.
    """

    def test_an_assignment_in_a_nested_block(self):
        source = inspect.cleandoc(
            """
            function main(c) {
              var o;
              if (c) {
                if ([o = {}, f()]) { A(); }
              }
              if (o) { X(); } else { Y(); }
            }
            SINK(main);
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function main(c) {
                  var o;
                  if (c) {
                    [o = {}, f()];
                    A();
                  }
                  if (o) {
                    X();
                  } else {
                    Y();
                  }
                }
                SINK(main);
                """
            ),
            self._deadcode(source),
        )

    def test_an_assignment_in_a_loop_body(self):
        source = inspect.cleandoc(
            """
            function main(n) {
              var o;
              while (n--) {
                if ([o = {}]) { A(); }
              }
              if (o) { X(); } else { Y(); }
            }
            SINK(main);
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function main(n) {
                  var o;
                  while (n--) {
                    [o = {}];
                    A();
                  }
                  if (o) {
                    X();
                  } else {
                    Y();
                  }
                }
                SINK(main);
                """
            ),
            self._deadcode(source),
        )

    def test_an_assignment_at_script_scope(self):
        source = inspect.cleandoc(
            """
            var o;
            if (c) {
              if ({ k: o = {} }) { A(); }
            }
            if (o) { X(); } else { Y(); }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var o;
                if (c) {
                  ({ k: o = {} });
                  A();
                }
                if (o) {
                  X();
                } else {
                  Y();
                }
                """
            ),
            self._deadcode(source),
        )


class TestALocalContainerBindingIsTruthyWhereEstablished(TestJsDeobfuscator):
    """
    A guard testing a local the model can resolve to a single allocation answers from that
    allocation — every object is truthy, an empty array included — but only where the read is
    ordered after the value's establishment: a never-reassigned `var` still reads `undefined`
    before its initializer runs, and the branch the undefined read would take is not the branch
    the allocation takes.
    """

    @staticmethod
    def _deadcode(source: str, *, trust_eval: bool = False) -> str:
        from refinery.lib.scripts.js.options import DeobfuscationOptions
        ast = JsParser(source).parse()
        for _ in range(10):
            transform = JsDeadCodeElimination()
            transform.options = DeobfuscationOptions(trust_eval=trust_eval)
            transform.visit(ast)
            if not transform.changed:
                break
        from refinery.lib.scripts.js.synth import JsSynthesizer
        return JsSynthesizer().convert(ast)

    def test_a_guard_on_an_established_array_folds(self):
        self.assertEqual(
            "function f() {\n  var a = ['x'];\n  SINK('kept');\n}",
            self._deadcode(
                'function f() { var a = [\'x\']; if (!a) { return; } SINK(\'kept\'); }'),
        )

    def test_an_empty_array_is_truthy(self):
        self.assertEqual(
            'function f() {\n  var a = [];\n  y();\n}',
            self._deadcode('function f() { var a = []; if (!a) { x(); } else { y(); } }'),
        )

    def test_a_read_before_the_initializer_runs_is_kept(self):
        source = inspect.cleandoc(
            """
            function f() {
              if (!a) {
                return;
              }
              var a = ['x'];
              SINK('kept');
            }
            """
        )
        self.assertEqual(source, self._deadcode(source))

    def test_a_reassigned_binding_is_kept(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a = ['x'];
              a = [];
              if (!a) {
                return;
              }
              SINK('kept');
            }
            """
        )
        self.assertEqual(source, self._deadcode(source))

    def test_a_cross_function_guard_on_an_established_array_folds(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = ['x'];
                SINK(function() {
                  SINK('kept');
                });
                """
            ),
            self._deadcode(
                inspect.cleandoc(
                    """
                    var a = ['x'];
                    SINK(function() {
                      if (!a) {
                        return;
                      }
                      SINK('kept');
                    });
                    """
                )
            ),
        )

    def test_a_cross_function_guard_under_an_eval_folds_only_with_trust(self):
        """
        The value the guard tests can be rebound by the payload the `eval` runs, so the suspecting
        model keeps the branch and the trusting model folds it.
        """
        script = inspect.cleandoc(
            """
            function f() {
              var a = ['x'];
              SINK(function() {
                if (!a) {
                  return;
                }
                SINK('kept');
              });
              eval(input);
            }
            """
        )
        self.assertEqual(script, self._deadcode(script))
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  var a = ['x'];
                  SINK(function() {
                    SINK('kept');
                  });
                  eval(input);
                }
                """
            ),
            self._deadcode(script, trust_eval=True),
        )

    def test_a_script_scope_guard_under_an_opaque_global_write_is_kept(self):
        """
        The top-level `var a` is a property of the global object, and `globalThis[k] = 0` may store
        under the key `a`, so the guard cannot fold under either model — an opaque global write is
        never trust-excused.
        """
        source = inspect.cleandoc(
            """
            var a = ['x'];
            globalThis[k] = 0;
            if (!a) {
              X();
            } else {
              Y();
            }
            """
        )
        self.assertEqual(source, self._deadcode(source))
        self.assertEqual(source, self._deadcode(source, trust_eval=True))

    def test_a_script_scope_guard_under_an_indirect_eval_is_kept(self):
        """
        `window.eval` is indirect eval, a reflective surface kept under both models; it runs in the
        global scope and can rebind the global `a`, so the guard cannot fold.
        """
        source = inspect.cleandoc(
            """
            var a = ['x'];
            window.eval(payload);
            if (!a) {
              X();
            } else {
              Y();
            }
            """
        )
        self.assertEqual(source, self._deadcode(source))
        self.assertEqual(source, self._deadcode(source, trust_eval=True))

    def test_a_computed_eval_key_destructuring_can_rebind_a_global_guard(self):
        """
        `{['eval']: e}` binds the `eval` intrinsic out of the global object as surely as `{eval: e}`
        does, so `e(payload)` is indirect eval running in the global scope that can rebind the
        global `a`; the guard cannot fold under either model.
        """
        source = inspect.cleandoc(
            """
            var a = ['x'];
            const { ['eval']: e } = globalThis;
            e(payload);
            if (!a) {
              X();
            } else {
              Y();
            }
            """
        )
        self.assertEqual(source, self._deadcode(source))
        self.assertEqual(source, self._deadcode(source, trust_eval=True))

    def test_a_computed_variable_key_destructuring_can_rebind_a_global_guard(self):
        """
        `{[k]: e} = globalThis` is the destructuring counterpart of the member read `globalThis[k]`:
        the runtime resolves the key, which may be `eval`, so `e(payload)` may be indirect eval
        rebinding the global `a`. The guard cannot fold under either model, matching how the member
        read is kept.
        """
        source = inspect.cleandoc(
            """
            var a = ['x'];
            const { [k]: e } = globalThis;
            e(payload);
            if (!a) {
              X();
            } else {
              Y();
            }
            """
        )
        self.assertEqual(source, self._deadcode(source))
        self.assertEqual(source, self._deadcode(source, trust_eval=True))

    def test_an_alias_read_under_a_dynamic_key_can_rebind_a_global_guard(self):
        """
        `var g = globalThis; g[k]` reads an unknown global through an alias just as `globalThis[k]`
        reads it on the spelled global object: the runtime key may resolve to `eval`, so
        `g[k](payload)` may be indirect eval rebinding the global `a`. The guard cannot fold under
        either model, matching how the read on the spelled global object is kept.
        """
        source = inspect.cleandoc(
            """
            var g = globalThis;
            var a = ['x'];
            g[k](payload);
            if (!a) {
              X();
            } else {
              Y();
            }
            """
        )
        self.assertEqual(source, self._deadcode(source))
        self.assertEqual(source, self._deadcode(source, trust_eval=True))

    def test_an_alias_read_under_a_dynamic_key_keeps_the_guard_through_the_pipeline(self):
        """
        Through the whole pipeline a multi-use alias of the global object read under a runtime key
        keeps the guard. The second read of `g` holds the alias in place so the inliner does not
        rewrite it back to `globalThis`, and `g[k](payload)` still reads as an indirect eval that may
        rebind the global `a`.
        """
        source = inspect.cleandoc(
            """
            var g = globalThis;
            g.use;
            var a = ['x'];
            g[k](payload);
            if (!a) {
              X();
            } else {
              Y();
            }
            """
        )
        self.assertEqual(source, deobfuscate_source(source))


def deobfuscated(source: str) -> str:
    return deobfuscate_source(source, execution=ExecutionModel.commonjs, environment=HostEnvironment.node)


#: Programs holding statements control never reaches, mapped to what Node prints for each run as a
#: CommonJS file: code behind a `return`, `throw`, `break`, `continue`, `yield` or `await`, in the
#: cases of a `switch`, around a `try` and its `finally`, behind loops, inside a `with`, a labeled
#: block and a class static block, and in lists where the same run also prunes an `if`. Several of
#: them declare a name behind the jump that code which runs still reads.
NEVER_RUNS: dict[str, Program] = {
    'a call behind a return': Program(
        a_program("""
            function f(n) { console.log('in', n); return n + 1; console.log('never'); }
            console.log(f(1));
            """),
        prints('in 1', '2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a let behind a return that a closure reads': Program(
        a_program("""
            function f() { const g = () => typeof x; return g; let x = 1; }
            try { console.log(f()()); } catch (e) { console.log(e.name); }
            """),
        prints('ReferenceError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a var behind a return that a closure reads': Program(
        a_program("""
            var y = 'outer';
            function f() { const g = () => y; return g; var y = 1; }
            console.log(f()());
            """),
        prints('undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a function declared behind a return': Program(
        a_program("""
            function f() { return g(); function g() { return 'g'; } }
            console.log(f());
            """),
        prints('g'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a function declared in a block behind a return, read before': Program(
        a_program("""
            function f() { const read = () => typeof h; return read; { function h() {} } }
            console.log(f()());
            """),
        prints('undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a var in a nested block behind a throw': Program(
        a_program("""
            var z = 'outer';
            function f(n) { const g = () => z; if (n) { return g; } throw g; { var z = 2; } }
            console.log(f(1)());
            try { f(0); } catch (e) { console.log(e()); }
            """),
        prints('undefined', 'undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'statements behind a break in a loop and in a switch': Program(
        a_program("""
            for (let i = 0; i < 3; i++) { if (i === 1) { console.log('skip'); continue; console.log('never'); } console.log(i); }
            switch (2) { case 2: { console.log('two'); break; console.log('never'); } }
            outer: { console.log('in'); break outer; console.log('never'); }
            """),
        prints('0', 'skip', '2', 'two', 'in'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a class declared behind a return that a closure reads': Program(
        a_program("""
            function f() { const g = () => typeof C; return g; class C {} }
            try { console.log(f()()); } catch (e) { console.log(e.name); }
            """),
        prints('ReferenceError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a labeled function behind a return in sloppy code': Program(
        a_program("""
            function f() { return typeof k; L: function k() {} }
            console.log(f());
            """),
        prints('function'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a statement behind a return at the top of a CommonJS file': Program(
        a_program("""
            console.log('top');
            return;
            console.log('never');
            """),
        prints('top'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a var storing nothing behind a return': Program(
        a_program("""
            var w = 'outer';
            function f() { const g = () => w; return g; var w; }
            console.log(f()());
            """),
        prints('undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call behind an if and else that both return': Program(
        a_program("""
            function f(c) { if (c) { return 1; } else { return 2; } console.log('never'); }
            console.log(f(true), f(false));
            """),
        prints('1 2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call behind a return in a switch case': Program(
        a_program("""
            function f(c) {
              switch (c) {
                case 1: console.log('one'); return 1; console.log('never');
                case 2: console.log('two');
              }
              return 0;
            }
            console.log(f(1), f(2), f(3));
            """),
        prints('one', 'two', '1 0 0'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a var behind a return in a switch case that a closure reads': Program(
        a_program("""
            var v = 'outer';
            function f(c) {
              const g = () => v;
              switch (c) { case 1: return g; var v = 1; }
              return g;
            }
            console.log(f(1)(), f(2)());
            """),
        prints('undefined undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call behind a yield': Program(
        a_program("""
            function* g() { yield 1; console.log('after yield'); return 2; console.log('never'); }
            console.log([...g()]);
            """),
        prints('after yield', '[ 1 ]'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call behind an await': Program(
        a_program("""
            async function f() { await null; console.log('after await'); return 1; console.log('never'); }
            f().then(v => console.log('done', v));
            """),
        prints('after await', 'done 1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a finally behind a return, and a call behind the try': Program(
        a_program("""
            function f() {
              try { return 1; } finally { console.log('finally'); }
              console.log('never');
            }
            console.log(f());
            """),
        prints('finally', '1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a finally whose return overrides the one of the try': Program(
        a_program("""
            function f() {
              try { return 1; console.log('never 1'); } finally { console.log('finally'); return 2; console.log('never 2'); }
              console.log('never 3');
            }
            console.log(f());
            """),
        prints('finally', '2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call behind a try whose block throws into a catch': Program(
        a_program("""
            function f() {
              try { throw new Error('x'); console.log('never'); } catch (e) { console.log('caught', e.message); }
              console.log('after try');
              return 0;
            }
            console.log(f());
            """),
        prints('caught x', 'after try', '0'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call behind an inner loop that always continues the outer one, which may run no iteration': Program(
        a_program("""
            function f(n) {
              var out = [];
              outer: for (var i = 0; i < 2; i++) {
                for (var j = 0; j < n; j++) { out.push(i + ':' + j); continue outer; out.push('never'); }
                out.push('inner ran no iteration ' + i);
              }
              return out;
            }
            console.log(f(0), f(1));
            """),
        prints("[ 'inner ran no iteration 0', 'inner ran no iteration 1' ] [ '0:0', '1:0' ]"),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call behind a do-while left by a break': Program(
        a_program("""
            function f() { do { console.log('body'); break; console.log('never'); } while (true); console.log('after'); }
            f();
            """),
        prints('body', 'after'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call behind a loop without a test that is left only by a return': Program(
        a_program("""
            function f(n) { var i = 0; while (true) { if (i++ > n) { return i; } } console.log('never'); }
            console.log(f(2));
            """),
        prints('4'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'cases behind a returning case, with a default between them': Program(
        a_program("""
            function f(x) {
              var out = [];
              switch (x) {
                case 1: out.push('one'); return out; out.push('never');
                default: out.push('default');
                case 2: out.push('two'); break; out.push('never');
                case 3: out.push('three');
              }
              return out;
            }
            console.log(f(1), f(2), f(3), f(4));
            """),
        prints("[ 'one' ] [ 'two' ] [ 'three' ] [ 'default', 'two' ]"),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call behind a return inside a with': Program(
        a_program("""
            function f(o) { with (o) { console.log(a); return a; } console.log('never'); }
            console.log(f({ a: 7 }));
            """),
        prints('7', '7'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call behind a for-in left by a break': Program(
        a_program("""
            function f(o) { for (var k in o) { console.log(k); break; console.log('never'); } console.log('after'); }
            f({ a: 1, b: 2 }); f({});
            """),
        prints('a', 'after', 'after'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call behind a labeled block left by a break': Program(
        a_program("""
            function f(c) { L: { if (c) break L; console.log('in block'); } console.log('after block'); }
            f(true); f(false);
            """),
        prints('after block', 'in block', 'after block'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call behind an if whose constant test the same run decides, inside a block that never runs': Program(
        a_program("""
            function f() {
              if (true) { console.log('kept'); return 1; console.log('never 1'); }
              { if (false) { console.log('never 2'); } else { var v = 3; } console.log('never 3'); }
              return v;
            }
            console.log(f());
            """),
        prints('kept', '1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a var behind a return inside an if the same run lifts, read by a closure': Program(
        a_program("""
            function f() {
              var g = function () { return typeof w; };
              if (1) { return g(); var w = 1; }
              return 'never';
            }
            console.log(f());
            """),
        prints('undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'code behind an if the same run lifts whose block ends in a return, and a function declared behind': Program(
        a_program("""
            function f() {
              if (true) { console.log('lifted'); return h(); }
              console.log('runs on entry tree only in the graph');
              function h() { return 'hoisted'; }
            }
            console.log(f());
            """),
        prints('lifted', 'hoisted'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a class static block whose code stands behind a throw caught by its own try': Program(
        a_program("""
            class A {
              static { try { throw 1; console.log('never'); } catch (e) { console.log('static caught', e); } console.log('static after'); }
            }
            console.log(typeof A);
            """),
        prints('static caught 1', 'static after', 'function'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a getter run by a read inside a try whose catch must stay': Program(
        a_program("""
            var o = { get p() { throw new Error('getter'); } };
            function f() { try { o.p; console.log('never reached at run time'); } catch (e) { console.log('caught', e.message); } }
            f();
            """),
        prints('caught getter'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an empty try whose catch never runs and whose finally does': Program(
        a_program("""
            function f() { try { } catch (e) { console.log('never'); } finally { console.log('finally'); } return 1; }
            console.log(f());
            """),
        prints('finally', '1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a switch every case of which returns, a default among them, and code behind it': Program(
        a_program("""
            function f(x) { switch (x) { case 1: return 'a'; default: return 'd'; case 2: return 'b'; } console.log('never'); }
            console.log(f(1), f(2), f(3));
            """),
        prints('a b d'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a statement behind a return at the top of a CommonJS file, declaring a var a function reads': Program(
        a_program("""
            function f() { return typeof q; }
            console.log(f());
            return;
            var q = 1;
            console.log('never');
            """),
        prints('undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a var in a labeled block behind a return that a closure reads': Program(
        a_program("""
            var x = 'outer';
            function f() { const g = () => x; return g; L: { var x = 1; } }
            console.log(f()());
            """),
        prints('undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a function in a nested block behind a break, read through Annex B before': Program(
        a_program("""
            function f() {
              const r = [];
              for (let i = 0; i < 2; i++) { r.push(typeof h); if (i >= 0) { break; { function h() {} } } }
              return r.join() + ' ' + typeof h;
            }
            console.log(f());
            """),
        prints('undefined undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a var behind a continue in a for-in head': Program(
        a_program("""
            var k = 'outer';
            function f() { const g = () => k; for (const z of [1]) { continue; for (var k in { a: 1 }) {} } return g(); }
            console.log(f());
            """),
        prints('undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a class behind a throw inside a try, read by the catch': Program(
        a_program("""
            function f() { try { const g = () => typeof C; throw g; class C {} } catch (e) { try { return e(); } catch (x) { return x.name; } } }
            console.log(f());
            """),
        prints('ReferenceError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'statements behind a break of a labeled block in a switch case block': Program(
        a_program("""
            function f(n) { switch (n) { case 1: { L: { console.log('in'); break L; console.log('never'); } console.log('out'); break; console.log('never'); } } return n; }
            console.log(f(1));
            """),
        prints('in', 'out', '1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
}

#: The text the deobfuscation writes for each program of `NEVER_RUNS`. What never runs is gone, but
#: a declaration scoped to its list stays, and a `var` stays for the names a removed statement
#: declares.
NEVER_RUNS_DEOBFUSCATED: dict[str, str] = {
    'a call behind a return': inspect.cleandoc(
        """
            function f(n) {
              console.log('in', n);
              return n + 1;
            }
            console.log(f(1));
        """
    ),
    'a let behind a return that a closure reads': inspect.cleandoc(
        """
            function f() {
              const g = () => typeof x;
              return g;
              let x = 1;
            }
            try {
              console.log(f()());
            } catch (e) {
              console.log(e.name);
            }
        """
    ),
    'a var behind a return that a closure reads': inspect.cleandoc(
        """
            function f() {
              const g = () => y;
              return g;
              var y;
            }
            console.log(f()());
        """
    ),
    'a function declared behind a return': inspect.cleandoc(
        """
            console.log('g');
        """
    ),
    'a function declared in a block behind a return, read before': inspect.cleandoc(
        """
            function f() {
              const read = () => typeof h;
              return read;
              var h;
            }
            console.log(f()());
        """
    ),
    'a var in a nested block behind a throw': inspect.cleandoc(
        """
            function f(n) {
              const g = () => z;
              if (n) {
                return g;
              }
              throw g;
              var z;
            }
            console.log(f(1)());
            try {
              f(0);
            } catch (e) {
              console.log(e());
            }
        """
    ),
    'statements behind a break in a loop and in a switch': inspect.cleandoc(
        """
            for (let i = 0; i < 3; i++) {
              if (i === 1) {
                console.log('skip');
                continue;
              }
              console.log(i);
            }
            switch (2) {
              case 2:
                {
                  console.log('two');
                  break;
                }
            }
            outer: {
              console.log('in');
              break outer;
            }
        """
    ),
    'a class declared behind a return that a closure reads': inspect.cleandoc(
        """
            function f() {
              const g = () => typeof C;
              return g;
              class C {}
            }
            try {
              console.log(f()());
            } catch (e) {
              console.log(e.name);
            }
        """
    ),
    'a labeled function behind a return in sloppy code': inspect.cleandoc(
        """
            console.log('function');
        """
    ),
    'a statement behind a return at the top of a CommonJS file': inspect.cleandoc(
        """
            console.log('top');
            return;
        """
    ),
    'a var storing nothing behind a return': inspect.cleandoc(
        """
            function f() {
              const g = () => w;
              return g;
              var w;
            }
            console.log(f()());
        """
    ),
    'a call behind an if and else that both return': inspect.cleandoc(
        """
            console.log(1, 2);
        """
    ),
    'a call behind a return in a switch case': inspect.cleandoc(
        """
            function f(c) {
              switch (c) {
                case 1:
                  console.log('one');
                  return 1;
                case 2:
                  console.log('two');
              }
              return 0;
            }
            console.log(f(1), f(2), f(3));
        """
    ),
    'a var behind a return in a switch case that a closure reads': inspect.cleandoc(
        """
            function f(c) {
              const g = () => v;
              switch (c) {
                case 1:
                  return g;
                  var v;
              }
              return g;
            }
            console.log(f(1)(), f(2)());
        """
    ),
    'a call behind a yield': inspect.cleandoc(
        """
            function* g() {
              yield 1;
              console.log('after yield');
              return 2;
            }
            console.log([...g()]);
        """
    ),
    'a call behind an await': inspect.cleandoc(
        """
            async function f() {
              await null;
              console.log('after await');
              return 1;
            }
            f().then(v => console.log('done', v));
        """
    ),
    'a finally behind a return, and a call behind the try': inspect.cleandoc(
        """
            function f() {
              try {
                return 1;
              } finally {
                console.log('finally');
              }
              console.log('never');
            }
            console.log(f());
        """
    ),
    'a finally whose return overrides the one of the try': inspect.cleandoc(
        """
            function f() {
              try {
                return 1;
              } finally {
                console.log('finally');
                return 2;
              }
            }
            console.log(f());
        """
    ),
    'a call behind a try whose block throws into a catch': inspect.cleandoc(
        """
            function f() {
              try {
                throw new Error('x');
              } catch (e) {
                console.log('caught', e.message);
              }
              console.log('after try');
              return 0;
            }
            console.log(f());
        """
    ),
    'a call behind an inner loop that always continues the outer one, which may run no iteration': inspect.cleandoc(
        """
            function f(n) {
              var out = [];
              outer: for (var i = 0; i < 2; i++) {
                for (var j = 0; j < n; j++) {
                  out.push(i + ':' + j);
                  continue outer;
                }
                out.push('inner ran no iteration ' + i);
              }
              return out;
            }
            console.log(f(0), f(1));
        """
    ),
    'a call behind a do-while left by a break': inspect.cleandoc(
        """
            do {
              console.log('body');
              break;
            } while (true);
            console.log('after');
        """
    ),
    'a call behind a loop without a test that is left only by a return': inspect.cleandoc(
        """
            function f(n) {
              var i = 0;
              while (true) {
                if (i++ > n) {
                  return i;
                }
              }
              console.log('never');
            }
            console.log(f(2));
        """
    ),
    'cases behind a returning case, with a default between them': inspect.cleandoc(
        """
            console.log(['one'], ['two'], ['three'], ['default', 'two']);
        """
    ),
    'a call behind a return inside a with': inspect.cleandoc(
        """
            function f(o) {
              with (o) {
                console.log(a);
                return a;
              }
            }
            console.log(f({ a: 7 }));
        """
    ),
    'a call behind a for-in left by a break': inspect.cleandoc(
        """
            function f(o) {
              for (var k in o) {
                console.log(k);
                break;
              }
              console.log('after');
            }
            f({ a: 1, b: 2 });
            f({});
        """
    ),
    'a call behind a labeled block left by a break': inspect.cleandoc(
        """
            function f(c) {
              L: {
                if (c) {
                  break L;
                }
                console.log('in block');
              }
              console.log('after block');
            }
            f(true);
            f(false);
        """
    ),
    'a call behind an if whose constant test the same run decides, inside a block that never runs': inspect.cleandoc(
        """
            function f() {
              console.log('kept');
              return 1;
            }
            console.log(f());
        """
    ),
    'a var behind a return inside an if the same run lifts, read by a closure': inspect.cleandoc(
        """
            function f() {
              var g = function() {
                return typeof w;
              };
              return g();
              var w;
            }
            console.log(f());
        """
    ),
    'code behind an if the same run lifts whose block ends in a return, and a function declared behind': inspect.cleandoc(
        """
            function f() {
              console.log('lifted');
              return 'hoisted';
            }
            console.log(f());
        """
    ),
    'a class static block whose code stands behind a throw caught by its own try': inspect.cleandoc(
        """
            class A {
              static {
                try {
                  throw 1;
                  console.log('never');
                } catch (e) {
                  console.log('static caught', e);
                }
                console.log('static after');
              }
            }
            console.log(typeof A);
        """
    ),
    'a getter run by a read inside a try whose catch must stay': inspect.cleandoc(
        """
            var o = { get p() {
              throw new Error('getter');
            } };
            try {
              o.p;
              console.log('never reached at run time');
            } catch (e) {
              console.log('caught', e.message);
            }
        """
    ),
    'an empty try whose catch never runs and whose finally does': inspect.cleandoc(
        """
            function f() {
              try {} catch (e) {} finally {
                console.log('finally');
              }
              return 1;
            }
            console.log(f());
        """
    ),
    'a switch every case of which returns, a default among them, and code behind it': inspect.cleandoc(
        """
            console.log('a', 'b', 'd');
        """
    ),
    'a statement behind a return at the top of a CommonJS file, declaring a var a function reads': inspect.cleandoc(
        """
            function f() {
              return typeof q;
            }
            console.log(f());
            return;
            var q;
        """
    ),
    'a var in a labeled block behind a return that a closure reads': inspect.cleandoc(
        """
            function f() {
              const g = () => x;
              return g;
              var x;
            }
            console.log(f()());
        """
    ),
    'a function in a nested block behind a break, read through Annex B before': inspect.cleandoc(
        """
            console.log('undefined undefined');
        """
    ),
    'a var behind a continue in a for-in head': inspect.cleandoc(
        """
            function f() {
              const g = () => k;
              for (const z of [1]) {
                continue;
                var k;
              }
              return g();
            }
            console.log(f());
        """
    ),
    'a class behind a throw inside a try, read by the catch': inspect.cleandoc(
        """
            function f() {
              try {
                const g = () => typeof C;
                throw g;
                class C {}
              } catch (e) {
                try {
                  return e();
                } catch (x) {
                  return x.name;
                }
              }
            }
            console.log(f());
        """
    ),
    'statements behind a break of a labeled block in a switch case block': inspect.cleandoc(
        """
            function f(n) {
              switch (n) {
                case 1:
                  {
                    L: {
                      console.log('in');
                      break L;
                    }
                    console.log('out');
                    break;
                  }
              }
              return n;
            }
            console.log(f(1));
        """
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStatementThatNeverRunsGoesWithoutAChangeInBehavior(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in NEVER_RUNS.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in NEVER_RUNS.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestAStatementThatNeverRunsGoes(TestBase):

    def test_each_program_reads_as_pinned(self):
        self.assertEqual(
            {label: deobfuscated(row.text) for label, row in NEVER_RUNS.items()},
            NEVER_RUNS_DEOBFUSCATED,
        )
