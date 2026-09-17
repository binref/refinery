from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.deadcode import JsDeadCodeElimination
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
