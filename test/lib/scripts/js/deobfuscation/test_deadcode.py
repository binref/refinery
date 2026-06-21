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
