"""
A pass may delete the machinery it has finished reading only once nothing names it any more.

`refinery.lib.scripts.js.deobfuscation.stringarray` and
`refinery.lib.scripts.js.deobfuscation.scramble` each recognize a decoder, answer the calls to it
they can, and then delete the decoder together with everything it was built from. A call they could
not answer — an index that is not a constant, an argument the program reads at run time — is left
standing, and deleting the decoder under it hands back a file that names a function it no longer
declares. Nothing about the file says so: it is of ordinary length, nothing is half-rewritten, and
the call reads like any other. Running it is what says otherwise, and running it is what an analyst
holding a sample must not do.

`refinery.lib.scripts.js.deobfuscation.helpers.nothing_still_names` is where the rule lives. It
reads the model's reference facts rather than the call shapes a pass happens to match, so a name
handed to something else, and an alias taken through a form the pass does not recognize, count as
references too.

SECURITY: every program here is hand-authored and benign, and it is written in this file so that
what the engine is handed is what is read here. No sample and no stored fixture may be fed to this.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints

from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import JsCallExpression, JsIdentifier
from refinery.lib.scripts.js.parser import JsParser


def _a_string_array(tail: str) -> str:
    """
    A program of the shape `refinery.lib.scripts.js.deobfuscation.stringarray` recognizes — a holder
    that replaces itself on its first call, an accessor that reads it by index, and a rotation loop
    — followed by *tail*. The loop's sum matches its target at once, so no rotation takes place and
    the strings stand in the order they are written.
    """
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
    A program of the shape `refinery.lib.scripts.js.deobfuscation.scramble` recognizes, followed by
    *tail*. `pb` and `decrypt` are stubs so that the program runs at all; the call the pass resolves
    has its value discarded, so what the stubs compute is never compared against what the pass
    substitutes.
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


#: Programs in which one call names a decoder the pass cannot answer, because its argument is not a
#: constant, mapped to what Node prints for each.
A_CALL_LEFT_NAMING_A_DECODER_THAT_WAS_REMOVED = {
    _a_string_array(
        'var n = Number(process.argv.length) - 1;\nconsole.log(ACC(0), ACC(n));'
    ): 'hello world\n',
    _a_scramble('console.log(decode(process.argv[1]));'): 'X\n',
}


#: A program naming the decoder from inside a `with` body, where the name may denote a property of
#: the object instead and so resolves to no binding statically, mapped to what Node prints for it.
#: `Math` carries no `ACC`, so the call reaches the declaration and prints what the array holds.
A_CALL_A_DYNAMIC_SCOPE_RESOLVES_STILL_NAMES_THE_DECODER = {
    _a_string_array('with (Math) { console.log(ACC(0), ACC(round(0.2))); }'): 'hello hello\n',
}


#: The same two shapes with nothing left over for the pass to be unable to answer, which is what
#: makes the entry above about the removal and not about the pass.
A_DECODER_REMOVED_WITH_NOTHING_LEFT_CALLING_IT = {
    _a_string_array('console.log(ACC(0));'): 'hello\n',
    _a_scramble("console.log('done');"): 'done\n',
}


def _deobfuscated(source: str) -> str:
    """
    What *source* comes back as, read under the module execution model the oracle runs each program
    with, which is the model `test.lib.scripts.js.ledger.before_and_after` asks for as well.
    """
    return deobfuscate_source(source, module=True)


def _names_called_without_a_declaration(source: str) -> set[str]:
    """
    Every name a call in *source* names that *source* declares nowhere. A deobfuscation may not add
    to this set: a name that resolved to a declaration before and resolves to nothing after is a
    function the output has stopped having.
    """
    ast = JsParser(source).parse()
    model = build_semantic_model(ast)
    return {
        node.callee.name
        for node in ast.walk()
        if isinstance(node, JsCallExpression)
        and isinstance(node.callee, JsIdentifier)
        and model.resolve(node.callee) is None
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

    def test_a_name_only_a_dynamic_scope_reaches_keeps_the_decoder(self):
        """
        `refinery.lib.scripts.js.analysis.model.SemanticModel.resolve` answers nothing for a name in
        a `with` body, so the reference the removal has to see is the one
        `refinery.lib.scripts.js.analysis.model.SemanticModel.dynamic_references` holds. The output
        declares the names the input declared.
        """
        source, = A_CALL_A_DYNAMIC_SCOPE_RESOLVES_STILL_NAMES_THE_DECODER
        self.assertEqual(
            _names_declared_at_the_top_level(source),
            _names_declared_at_the_top_level(_deobfuscated(source)),
        )

    def test_a_decoder_nothing_calls_leaves_no_declaration_behind(self):
        rows = A_DECODER_REMOVED_WITH_NOTHING_LEFT_CALLING_IT
        self.assertEqual(
            [_names_declared_at_the_top_level(_deobfuscated(source)) for source in rows],
            [set(), set()],
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheProgramPrintsWhatItPrintedBeforeTheDecoderWasRemoved(TestBase):

    def test_a_program_with_a_call_the_pass_cannot_answer(self):
        """
        Node prints `hello world` for the string-array program of
        `A_CALL_LEFT_NAMING_A_DECODER_THAT_WAS_REMOVED` and `X` for the scramble one.
        """
        rows = A_CALL_LEFT_NAMING_A_DECODER_THAT_WAS_REMOVED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_program_naming_the_decoder_from_a_dynamic_scope(self):
        """
        Node prints `hello hello`: `Math` carries no `ACC`, so both calls in the `with` body reach
        the declaration, and `round(0.2)` is the `Math` property the body does supply.
        """
        rows = A_CALL_A_DYNAMIC_SCOPE_RESOLVES_STILL_NAMES_THE_DECODER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_program_whose_calls_the_pass_answers_all_of(self):
        """
        Node prints `hello` and `done` for the two programs of
        `A_DECODER_REMOVED_WITH_NOTHING_LEFT_CALLING_IT`, and each deobfuscation prints the same
        while removing the decoder. Without this the entry above would pass for a pass that resolved
        nothing at all.
        """
        rows = A_DECODER_REMOVED_WITH_NOTHING_LEFT_CALLING_IT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
