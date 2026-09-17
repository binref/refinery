"""
The strict switch of `refinery.units.scripting.js` — `-s`/`--strict` — selects between the two
models `refinery.lib.scripts.js.options.DeobfuscationOptions.trust_eval` names. The suspecting
model, which the library default and every differential entry in this tree runs, is the only sound
one: code supplied as data may read or write anything the scope it runs in can reach. The trusting
model, which the unit runs by default, assumes such code inert and folds more.

The junk every row below measures is one read that only the trusting model answers: a method call
on a literal receiver, which the suspecting model refuses wherever a reflective surface stands above
it, because the payload could have installed a getter on the prototype the read resolves through.
SECURITY: every program here is hand-authored in this file and benign.
"""
from __future__ import annotations

from inspect import cleandoc

from test import TestBase
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.options import DeobfuscationOptions
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


#: A read that only a clean world answers, spelled once per row's script below it.
_JUNK = "console.log('abc'.charAt(1));"

#: The discarded read the trusting model folds the junk to.
_JUNK_FOLDED = "console.log('b');"


def _printed(source: str) -> str:
    """
    The text the synthesizer writes for *source* with no pass run over it, so that a row's
    expectation spells its opener as the tool prints it rather than as the file spelled it.
    """
    return JsSynthesizer().convert(JsParser(source).parse())


def _deobfuscated(source: str, *, trust_eval: bool = False) -> str:
    """
    The text `deobfuscate` writes for *source* under the model *trust_eval* selects; the library
    default is the suspecting one, which is the only sound answer.
    """
    ast = JsParser(source).parse()
    deobfuscate(ast, trust_eval=trust_eval)
    return JsSynthesizer().convert(ast)


class TestJsTrustedEvalExcusesTheSurfacesThatRunUnreadableCode(TestJsDeobfuscator):
    """
    Under `trust_eval` a surface that runs code this analysis cannot read is assumed to leave the
    world as it found it, so the read written below it is answered. Each row is one such surface,
    and each is asserted twice: left standing without the option, which is the only sound answer
    and the library default, and folded with it.
    """

    _RUNS_UNREADABLE_CODE = (
        'eval(input);',
        'var g = Function(payload);\nSINK(g);',
        'setTimeout(code, 10);',
    )

    def test_the_read_below_one_is_left_standing_by_default(self):
        for opener in self._RUNS_UNREADABLE_CODE:
            with self.subTest(opener):
                self.assertEqual(
                    _deobfuscated(F'{opener}\n{_JUNK}'),
                    F'{_printed(opener)}\n{_JUNK}',
                )

    def test_the_read_below_one_is_folded_under_the_option(self):
        for opener in self._RUNS_UNREADABLE_CODE:
            with self.subTest(opener):
                self.assertEqual(
                    _deobfuscated(F'{opener}\n{_JUNK}', trust_eval=True),
                    F'{_printed(opener)}\n{_JUNK_FOLDED}',
                )


class TestJsTrustedEvalDoesNotExcuseAMutationTheScriptWritesDown(TestJsDeobfuscator):
    """
    The option is an assumption about code that cannot be read, not a licence to disbelieve a
    statement the walk can see. A mutation written out in the script — a patched prototype, a
    `with`-body write, an unread span of source — opens the world under both models, and so does a
    store under a runtime key, which may replace the name a read below it observes.
    """

    _MUTATES_IN_PLAIN_SIGHT = (
        'String.prototype.charAt = q;',
        'with (o) {\n  x = 2;\n}',
        'function f(a b) {\n  return 1;\n}',
    )

    def test_the_read_below_one_is_left_standing_by_default(self):
        for mutation in self._MUTATES_IN_PLAIN_SIGHT:
            with self.subTest(mutation):
                self.assertEqual(
                    _deobfuscated(F'{mutation}\n{_JUNK}'),
                    F'{_printed(mutation)}\n{_JUNK}',
                )

    def test_the_read_below_one_is_left_standing_under_the_option_too(self):
        for mutation in self._MUTATES_IN_PLAIN_SIGHT:
            with self.subTest(mutation):
                self.assertEqual(
                    _deobfuscated(F'{mutation}\n{_JUNK}', trust_eval=True),
                    F'{_printed(mutation)}\n{_JUNK}',
                )

    def test_a_read_a_runtime_key_store_may_replace_is_left_standing_under_the_option(self):
        script = cleandoc("""
            var s = 'ab';
            globalThis[k] = 0;
            console.log(s.length);
        """)
        self.assertEqual(_deobfuscated(script, trust_eval=True), script)


class TestJsTrustedEvalDoesNotExcuseAnIndirectEval(TestJsDeobfuscator):
    """
    A spelling of `eval` that is not the callee of a direct call runs its text in the global scope,
    and the trusting model keeps the surface: the assumption covers code the model cannot position
    in its own scope, not a hand-over of the intrinsic the script performs in plain sight.
    """

    _INDIRECT_EVAL = (
        'var e = eval;\ne(input);',
        'window.eval(input);',
    )

    def test_the_read_below_one_is_left_standing_under_the_option(self):
        for opener in self._INDIRECT_EVAL:
            with self.subTest(opener):
                self.assertEqual(
                    _deobfuscated(F'{opener}\n{_JUNK}', trust_eval=True),
                    F'{_printed(opener)}\n{_JUNK}',
                )

    def test_a_computed_eval_destructuring_key_is_not_trusted(self):
        """
        `{['eval']: e}` hands out the `eval` intrinsic through a string-literal key as surely as
        `{eval: e}` does, so the surface is kept even beside a trusted `Function` extraction and the
        read below the indirect call stands rather than folding to `_JUNK_FOLDED`.
        """
        script = F"const {{Function, ['eval']: e}} = globalThis;\ne(input);\n{_JUNK}"
        self.assertEqual(
            _deobfuscated(script, trust_eval=True),
            F'const {{ Function, eval: e }} = globalThis;\ne(input);\n{_JUNK}',
        )

    def test_a_computed_variable_destructuring_key_is_not_trusted(self):
        """
        `{[k]: e}` reads a global under a key only the runtime resolves, which may be `eval`, so it is
        the destructuring counterpart of the member read `globalThis[k]` and the surface is kept even
        beside a trusted `Function` extraction; the read below the indirect call stands rather than
        folding to `_JUNK_FOLDED`.
        """
        script = F'const {{Function, [k]: e}} = globalThis;\ne(input);\n{_JUNK}'
        self.assertEqual(
            _deobfuscated(script, trust_eval=True),
            F'const {{ Function, [k]: e }} = globalThis;\ne(input);\n{_JUNK}',
        )


class TestJsTrustedEvalChangesNothingAboutAScriptThatRunsNoUnreadableCode(TestJsDeobfuscator):
    """
    A script with nothing to excuse comes out of both models byte for byte the same, so that the
    option is measured as the one thing it is rather than as a second deobfuscation mode.
    """

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
    """
    The option travels on the transformer, so a pass run without the pipeline's shared cache builds
    one that carries it. A cache that defaulted the option instead would answer under a
    configuration the transformer beside it does not hold, which is one run reading two settings.
    """

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
