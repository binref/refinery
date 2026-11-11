from __future__ import annotations

import inspect
import unittest

from refinery.lib.scripts.js.deobfuscation.evaluator import JsFunctionEvaluator
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.units.scripting.djs import djs
from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, host_behavior, node_executable
from test.lib.scripts.js.ledger import STRING_TIMERS


def deobfuscated(source: str, *, strict: bool, commonjs: bool = False) -> str:
    return source.encode('utf8') | djs(strict=strict, commonjs=commonjs) | str


BOTH_MODELS = (False, True)

A_TOP_LEVEL_LET_READ_BY_CODE_RUN_FROM_A_STRING = {
    'a Function body': inspect.cleandoc(
        """
        let k = 5;
        Function("console.log(k)")();
        """
    ),
    'an indirect eval': inspect.cleandoc(
        """
        let k = 5;
        (0, eval)("console.log(k)");
        """
    ),
    'a string timer': inspect.cleandoc(
        """
        const k = function () { console.log(7); };
        setTimeout("k()", 0);
        """
    ),
}

A_LET_DECLARED_BY_A_STRING_TIMER = {
    'read by a later timer of the file': inspect.cleandoc(
        """
        setTimeout("let k = 1;", 0);
        setTimeout("console.log(k)", 10);
        """
    ),
    'read by a later timer the file cannot read': inspect.cleandoc(
        """
        setTimeout("let k = 1;", 0);
        setTimeout(process.argv.length > 99 ? "" : "console.log(k)", 10);
        """
    ),
    'a const called by a later timer': inspect.cleandoc(
        """
        setTimeout("const run = function () { console.log(3); };", 0);
        setTimeout(process.argv.length > 99 ? "" : "run()", 10);
        """
    ),
    'a class a later timer tests': inspect.cleandoc(
        """
        setTimeout("class C {}", 0);
        setTimeout(process.argv.length > 99 ? "" : "console.log(typeof C)", 10);
        """
    ),
}

A_LET_A_STRING_TIMER_DECLARES_BESIDE_ONE_OF_THE_FILE = inspect.cleandoc(
    """
    let k = 1;
    setTimeout("let k = 2; console.log(k)", 0);
    """
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestCodeRunFromAStringFindsATopLevelLet(TestBase):

    def test_each_program_prints_what_it_printed(self):
        for label, source in A_TOP_LEVEL_LET_READ_BY_CODE_RUN_FROM_A_STRING.items():
            for strict in BOTH_MODELS:
                with self.subTest(label=label, strict=strict):
                    output = deobfuscated(source, strict=strict)
                    self.assertEqual(
                        host_behavior(source, prelude=STRING_TIMERS),
                        host_behavior(output, prelude=STRING_TIMERS),
                        output,
                    )

    def test_each_string_is_read_as_code(self):
        for label, source in A_TOP_LEVEL_LET_READ_BY_CODE_RUN_FROM_A_STRING.items():
            for strict in BOTH_MODELS:
                with self.subTest(label=label, strict=strict):
                    output = deobfuscated(source, strict=strict)
                    self.assertNotIn('Function(', output)
                    self.assertNotIn('eval', output)
                    self.assertNotIn('setTimeout("', output)

    def test_the_binding_keeps_its_temporal_dead_zone(self):
        source = inspect.cleandoc(
            """
            Function("console.log(k)")();
            let k = 5;
            """
        )
        self.assertEqual(host_behavior(source), ('', 'ReferenceError'))
        for strict in BOTH_MODELS:
            with self.subTest(strict=strict):
                output = deobfuscated(source, strict=strict)
                self.assertEqual(host_behavior(source), host_behavior(output), output)

    def test_no_top_level_let_of_a_commonjs_file_is_found(self):
        for label, source in A_TOP_LEVEL_LET_READ_BY_CODE_RUN_FROM_A_STRING.items():
            if label == 'a string timer':
                continue
            self.assertEqual(behavior(source), ('', 'ReferenceError'))
            for strict in BOTH_MODELS:
                with self.subTest(label=label, strict=strict):
                    output = deobfuscated(source, strict=strict, commonjs=True)
                    self.assertEqual(behavior(source), behavior(output), output)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestALetInABlockIsNoNameGlobalCodeFinds(TestBase):

    def test_code_run_from_a_string_does_not_find_it(self):
        source = inspect.cleandoc(
            """
            {
              let k = 1;
              Function("console.log(typeof k)")();
            }
            """
        )
        for strict in BOTH_MODELS:
            with self.subTest(strict=strict):
                output = deobfuscated(source, strict=strict)
                self.assertEqual(host_behavior(source), host_behavior(output), output)

    def test_code_run_from_a_string_writes_what_its_scope_finds(self):
        rows = {
            'a Function body writes a global': (
                '{ let k = 1; Function("k = 2")(); console.log(k, typeof globalThis.k); }',
                BOTH_MODELS,
            ),
            'a direct eval writes the let': (
                '{ let k = 1; eval("k = 2"); console.log(k, typeof globalThis.k); }',
                BOTH_MODELS,
            ),
            'an unread direct eval': (
                '{ let k = 1; eval(process.argv.length > 99 ? "" : "k = 2"); console.log(k); }',
                (True,),
            ),
            'an unread Function body': (
                '{ let k = 1; Function(process.argv.length > 99 ? "" : "k = 2")(); console.log(k); }',
                BOTH_MODELS,
            ),
        }
        for label, (source, models) in rows.items():
            for strict in models:
                with self.subTest(label=label, strict=strict):
                    output = deobfuscated(source, strict=strict)
                    self.assertEqual(host_behavior(source), host_behavior(output), output)

    def test_a_dead_let_in_a_block_is_removed_beside_code_the_file_cannot_read(self):
        source = inspect.cleandoc(
            """
            {
              let dead = 1;
              console.log(2);
            }
            setTimeout(process.argv.length > 99 ? "" : "console.log(3)", 0);
            """
        )
        output = deobfuscated(source, strict=True)
        self.assertNotIn('dead', output)
        self.assertEqual(host_behavior(source), host_behavior(output), output)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestCodeRunFromAStringCallsAFunctionDeclaredInABlockThroughItsCopy(TestBase):

    _SOURCE = inspect.cleandoc(
        """
        {
          function f() {
            return 'x';
          }
          console.log(f());
        }
        Function(process.argv.length > 99 ? '' : 'console.log(f())')();
        """
    )

    def test_the_function_evaluator_keeps_the_function(self):
        ast = JsParser(self._SOURCE).parse()
        JsFunctionEvaluator().visit(ast)
        output = JsSynthesizer().convert(ast)
        self.assertEqual(host_behavior(self._SOURCE), ('x\nx\n', None))
        self.assertEqual(host_behavior(self._SOURCE), host_behavior(output), output)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestALetDeclaredByAStringTimerJoinsTheGlobalScope(TestBase):

    def test_each_program_prints_what_it_printed(self):
        for label, source in A_LET_DECLARED_BY_A_STRING_TIMER.items():
            for strict in BOTH_MODELS:
                with self.subTest(label=label, strict=strict):
                    output = deobfuscated(source, strict=strict)
                    self.assertEqual(
                        host_behavior(source, prelude=STRING_TIMERS),
                        host_behavior(output, prelude=STRING_TIMERS),
                        output,
                    )

    def test_one_the_file_already_declares_still_throws_when_the_timer_runs(self):
        source = A_LET_A_STRING_TIMER_DECLARES_BESIDE_ONE_OF_THE_FILE
        output = deobfuscated(source, strict=True)
        self.assertEqual(host_behavior(source, prelude=STRING_TIMERS), ('', 'SyntaxError'))
        self.assertEqual(
            host_behavior(source, prelude=STRING_TIMERS),
            host_behavior(output, prelude=STRING_TIMERS),
            output,
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStoreIntoTheGlobalObjectUnderAKeyOnlyTheRuntimeKnows(TestBase):

    _KEY = 'process.argv.length > 99 ? "x" : "k"'

    def test_it_replaces_a_top_level_var(self):
        source = F'var k = 1;\nglobalThis[{self._KEY}] = 2;\nconsole.log(k);'
        self.assertEqual(host_behavior(source), ('2\n', None))
        for strict in BOTH_MODELS:
            with self.subTest(strict=strict):
                output = deobfuscated(source, strict=strict)
                self.assertEqual(host_behavior(source), host_behavior(output), output)

    def test_it_leaves_a_top_level_let_alone(self):
        source = F'let k = 1;\nglobalThis[{self._KEY}] = 2;\nconsole.log(k);'
        self.assertEqual(host_behavior(source), ('1\n', None))
        for strict in BOTH_MODELS:
            with self.subTest(strict=strict):
                output = deobfuscated(source, strict=strict)
                self.assertIn('console.log(1);', output)
                self.assertEqual(host_behavior(source), host_behavior(output), output)
