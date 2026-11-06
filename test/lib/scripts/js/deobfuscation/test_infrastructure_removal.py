"""
SECURITY: every program here is hand-written and benign, and written out in this file so that what
the engine runs is what is read here. No sample and no stored fixture may ever be handed to the
engine.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import (
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints

from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import JsCallExpression, JsIdentifier
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser


def _a_string_array(tail: str) -> str:
    machinery = inspect.cleandoc("""
        function A() { var s = ['hello', 'world']; A = function () { return s; }; return A(); }
        function ACC(i, k) { i = i - 0; var a = A(); var r = a[i]; return r; }
        (function (getArray, target) {
          var arr = getArray();
          while (true) {
            var sum = 1;
            if (sum === target) break; else arr['push'](arr['shift']());
          }
        })(A, 1);
    """)
    return F'{machinery}\n{tail}\n'


def _a_scramble(tail: str) -> str:
    """
    `pb` and `decrypt` are stubs that let the program run. The one call the deobfuscation resolves
    discards its value, so what the stubs return never meets what it substitutes.
    """
    machinery = inspect.cleandoc("""
        function pb() { return 'K'; }
        function decrypt() { return 'X'; }
        class Scramble {
          constructor(pw, salt) {
            this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
            this.rounds = 3;
          }
          decode(input) { return decrypt(input, this.masterKey, this.rounds); }
        }
        var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
        var salt = 'fec5863b88643968ecff0c2c8afecbaf';
        var instance = new Scramble(key, salt);
        function decode(x) { return instance.decode(x); }
        decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
    """)
    return F'{machinery}\n{tail}\n'


A_CALL_LEFT_NAMING_A_DECODER_THAT_WAS_REMOVED = {
    _a_string_array(
        'var n = Number(process.argv.length) - 1;\nconsole.log(ACC(0), ACC(n));'
    ): 'hello world\n',
    _a_scramble('console.log(decode(process.argv[1]));'): 'X\n',
}


A_CALL_A_DYNAMIC_SCOPE_RESOLVES_STILL_NAMES_THE_DECODER = {
    _a_string_array('with (Math) { console.log(ACC(0), ACC(round(0.2))); }'): 'hello hello\n',
}


A_DECODER_REMOVED_WITH_NOTHING_LEFT_CALLING_IT = {
    _a_string_array('console.log(ACC(0));'): 'hello\n',
    _a_scramble("console.log('done');"): 'done\n',
}


def _deobfuscated(source: str) -> str:
    return deobfuscate_source(source, execution=ExecutionModel.module)


def _names_called_without_a_declaration(source: str) -> set[str]:
    ast = JsParser(source).parse()
    model = build_semantic_model(ast)
    return {
        node.callee.name
        for node in ast.walk()
        if isinstance(node, JsCallExpression)
        and isinstance(node.callee, JsIdentifier)
        and model.resolve(node.callee) is None
    }


def _names_called(source: str) -> set[str]:
    return {
        node.callee.name
        for node in JsParser(source).parse().walk()
        if isinstance(node, JsCallExpression)
        and isinstance(node.callee, JsIdentifier)
    }


def _names_declared_at_the_top_level(source: str) -> set[str]:
    ast = JsParser(source).parse()
    return set(build_semantic_model(ast).root_scope.bindings)


class TestADecoderIsKeptWhileACallToItSurvives(TestBase):

    def test_the_deobfuscation_declares_every_name_it_calls(self):
        rows = A_CALL_LEFT_NAMING_A_DECODER_THAT_WAS_REMOVED
        self.assertEqual(
            {source: _names_called_without_a_declaration(_deobfuscated(source)) for source in rows},
            {source: _names_called_without_a_declaration(source) for source in rows},
        )

    def test_a_name_only_a_dynamic_scope_reaches_keeps_the_decoder_while_it_is_called(self):
        source, = A_CALL_A_DYNAMIC_SCOPE_RESOLVES_STILL_NAMES_THE_DECODER
        deobfuscated = _deobfuscated(source)
        still_called = _names_called(deobfuscated) & _names_declared_at_the_top_level(source)
        self.assertLessEqual(still_called, _names_declared_at_the_top_level(deobfuscated))

    @opportunity
    def test_a_decoder_whose_calls_in_a_dynamic_scope_are_answered_leaves_no_declaration_behind(self):
        source, = A_CALL_A_DYNAMIC_SCOPE_RESOLVES_STILL_NAMES_THE_DECODER
        self.assertEqual(_names_declared_at_the_top_level(_deobfuscated(source)), set())

    def test_a_decoder_nothing_calls_leaves_no_declaration_behind(self):
        rows = A_DECODER_REMOVED_WITH_NOTHING_LEFT_CALLING_IT
        self.assertEqual(
            [_names_declared_at_the_top_level(_deobfuscated(source)) for source in rows],
            [set(), set()],
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheProgramPrintsWhatItPrintedBeforeTheDecoderWasRemoved(TestBase):

    def test_a_program_with_a_call_the_pass_cannot_answer(self):
        rows = A_CALL_LEFT_NAMING_A_DECODER_THAT_WAS_REMOVED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_program_naming_the_decoder_from_a_dynamic_scope(self):
        rows = A_CALL_A_DYNAMIC_SCOPE_RESOLVES_STILL_NAMES_THE_DECODER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_program_whose_calls_the_pass_answers_all_of(self):
        rows = A_DECODER_REMOVED_WITH_NOTHING_LEFT_CALLING_IT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
