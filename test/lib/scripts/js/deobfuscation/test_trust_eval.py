"""
SECURITY: every program in this module is written by hand and benign; never add one taken from a
sample.
"""
from __future__ import annotations

from inspect import cleandoc

from test import TestBase, opportunity
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import on_separate_lines

from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.options import DeobfuscationOptions
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


#: Code run from a string above this read could replace `String.prototype.charAt`, so only the
#: trusting model folds it.
_JUNK = "console.log('abc'.charAt(1));"

_JUNK_FOLDED = "console.log('b');"


def _printed(source: str) -> str:
    return JsSynthesizer().convert(JsParser(source).parse())


def _deobfuscated(source: str, *, trust_eval: bool = False) -> str:
    ast = JsParser(source).parse()
    deobfuscate(ast, trust_eval=trust_eval)
    return JsSynthesizer().convert(ast)


class TestJsTrustedEvalExcusesTheSurfacesThatRunUnreadableCode(TestJsDeobfuscator):

    _RUNS_UNREADABLE_CODE = (
        'eval(input);',
        'var g = Function(payload);\nSINK(g);',
        'setTimeout(code, 10);',
    )

    def test_the_read_below_one_is_left_standing_by_default(self):
        for opener in self._RUNS_UNREADABLE_CODE:
            with self.subTest(opener):
                self.assertEqual(
                    _deobfuscated(on_separate_lines(opener, _JUNK)),
                    on_separate_lines(_printed(opener), _JUNK),
                )

    def test_the_read_below_one_is_folded_under_the_option(self):
        for opener in self._RUNS_UNREADABLE_CODE:
            with self.subTest(opener):
                self.assertEqual(
                    _deobfuscated(on_separate_lines(opener, _JUNK), trust_eval=True),
                    on_separate_lines(_printed(opener), _JUNK_FOLDED),
                )


class TestJsTrustedEvalDoesNotExcuseAMutationTheScriptWritesDown(TestJsDeobfuscator):

    _MUTATES_IN_PLAIN_SIGHT = (
        'String.prototype.charAt = q;',
        cleandoc("""
            with (String.prototype) {
              charAt = q;
            }
        """),
        cleandoc("""
            function f(a b) {
              return 1;
            }
        """),
    )

    def test_the_read_below_one_is_left_standing_by_default(self):
        for mutation in self._MUTATES_IN_PLAIN_SIGHT:
            with self.subTest(mutation):
                self.assertEqual(
                    _deobfuscated(on_separate_lines(mutation, _JUNK)),
                    on_separate_lines(_printed(mutation), _JUNK),
                )

    def test_the_read_below_one_is_left_standing_under_the_option_too(self):
        for mutation in self._MUTATES_IN_PLAIN_SIGHT:
            with self.subTest(mutation):
                self.assertEqual(
                    _deobfuscated(on_separate_lines(mutation, _JUNK), trust_eval=True),
                    on_separate_lines(_printed(mutation), _JUNK),
                )

    @opportunity
    def test_the_read_below_a_with_body_writing_another_name_is_folded_under_either_model(self):
        writes_another_name = cleandoc("""
            with (o) {
              x = 2;
            }
        """)
        for trust_eval in (False, True):
            with self.subTest(trust_eval=trust_eval):
                self.assertEqual(
                    _deobfuscated(on_separate_lines(writes_another_name, _JUNK), trust_eval=trust_eval),
                    on_separate_lines(_printed(writes_another_name), _JUNK_FOLDED),
                )

    def test_a_read_a_runtime_key_store_may_replace_is_left_standing_under_the_option(self):
        script = cleandoc("""
            var s = 'ab';
            globalThis[k] = 0;
            console.log(s.length);
        """)
        self.assertEqual(_deobfuscated(script, trust_eval=True), script)


class TestJsTrustedEvalDoesNotExcuseAnIndirectEval(TestJsDeobfuscator):

    _INDIRECT_EVAL = (
        'var e = eval;\ne(input);',
        'window.eval(input);',
    )

    def test_the_read_below_one_is_left_standing_under_the_option(self):
        for opener in self._INDIRECT_EVAL:
            with self.subTest(opener):
                self.assertEqual(
                    _deobfuscated(on_separate_lines(opener, _JUNK), trust_eval=True),
                    on_separate_lines(_printed(opener), _JUNK),
                )

    def test_a_computed_eval_destructuring_key_is_not_trusted(self):
        script = F"const {{Function, ['eval']: e}} = globalThis;\ne(input);\n{_JUNK}"
        self.assertEqual(
            _deobfuscated(script, trust_eval=True),
            F'const {{ Function, eval: e }} = globalThis;\ne(input);\n{_JUNK}',
        )

    def test_a_computed_variable_destructuring_key_is_not_trusted(self):
        script = F'const {{Function, [k]: e}} = globalThis;\ne(input);\n{_JUNK}'
        self.assertEqual(
            _deobfuscated(script, trust_eval=True),
            F'const {{ Function, [k]: e }} = globalThis;\ne(input);\n{_JUNK}',
        )


class TestJsTrustedEvalChangesNothingAboutAScriptThatRunsNoUnreadableCode(TestJsDeobfuscator):

    _CLOSED_WORLD_SCRIPTS = (
        "var a = 1 + 1;\nconsole.log(a);",
        "function f() {\n  return 'x';\n}\nconsole.log(f());",
        "console.log('abc'.charAt(1));",
    )

    def test_both_models_produce_the_same_output(self):
        for script in self._CLOSED_WORLD_SCRIPTS:
            with self.subTest(script):
                self.assertEqual(
                    _deobfuscated(script),
                    _deobfuscated(script, trust_eval=True),
                )


class TestJsTrustedEvalReachesATransformThatBuildsItsOwnCache(TestBase):

    _SCRIPT = F'eval(input);\n{_JUNK}'

    def _run_alone(self, trust_eval: bool) -> str:
        ast = JsParser(self._SCRIPT).parse()
        for _ in range(10):
            transform = JsSimplifications()
            transform.options = DeobfuscationOptions(trust_eval=trust_eval)
            transform.visit(ast)
            if not transform.changed:
                break
        return JsSynthesizer().convert(ast)

    def test_the_pass_leaves_the_read_standing_without_the_option(self):
        self.assertEqual(self._run_alone(False), self._SCRIPT)

    def test_the_pass_folds_the_read_under_the_option(self):
        self.assertEqual(self._run_alone(True), F'eval(input);\n{_JUNK_FOLDED}')
