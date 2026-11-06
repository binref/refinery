"""
SECURITY: every program here is hand-authored in this file and benign. No sample and no stored
obfuscator fixture may be fed to this.
"""
from __future__ import annotations

import unittest

from test import TestBase, backlog, opportunity
from test.lib.scripts.js.analysis.differential import host_behavior, node_executable
from test.lib.scripts.js.ledger import (
    a_program,
    before_and_after_in_a_host,
    deobfuscated_host_behavior,
    folded,
    prints,
)

_A_WRITE_NO_LONGER_BLOCKS_A_METHOD_CALL = {
    'a string method on a literal receiver': (
        a_program("""
            var k = process.env.KEY;
            globalThis[k] = 0;
            console.log('abc'.charAt(1));
            """),
        a_program("""
            var k = process.env.KEY;
            globalThis[k] = 0;
            console.log('b');
            """).rstrip(chr(10)),
    ),
}
"""
Each program stores a property on the global object under a key the analysis cannot read, and each
must still fold across it: a write cannot run code or read a value, so the call sitting behind it
folds as it would without the write. The write and its key are what stay — the recall cost of a
sound design, pinned here so it is a cost and not a regression.
"""

#: A top-level `const` is no property of the global object, so a store under a runtime key cannot
#: replace the decoder.
_A_DECODER_A_CONST_HOLDS_CALLED_ACROSS_THE_WRITE = a_program("""
    var k = process.env.KEY;
    globalThis[k] = 0;
    const d = function (s) {
      return s.charAt(1);
    };
    console.log(d('abc'));
    """)

_THE_DECODER_CALL_FOLDED = a_program("""
    var k = process.env.KEY;
    globalThis[k] = 0;
    const d = function(s) {
      return s.charAt(1);
    };
    console.log('b');
    """).rstrip(chr(10))

_THE_DECODER_CALL_FOLDED_AND_THE_DECODER_REMOVED = a_program("""
    var k = process.env.KEY;
    globalThis[k] = 0;
    console.log('b');
    """).rstrip(chr(10))

_A_GLOBAL_WRITTEN_UNDER_A_RUNTIME_KEY = {
    'the written name is the intrinsic a call spells': a_program("""
        var k = process.env.KEY || 'Math';
        globalThis[k] = { floor: function () { return 999; } };
        console.log(Math.floor(1.7));
        """),
    'the written name is a top-level var': a_program("""
        var q = 1;
        var k = process.env.KEY || 'q';
        globalThis[k] = 2;
        console.log(q);
        """),
    'the written name is reached through a name holding the object': a_program("""
        var g = globalThis;
        var k = process.env.KEY || 'String';
        g[k] = {};
        console.log(String.fromCharCode(65));
        """),
    'the written name is reached through that name in parentheses': a_program("""
        var g = globalThis;
        var k = process.env.KEY || 'String';
        (g)[k] = {};
        console.log(String.fromCharCode(65));
        """),
    'the written name holds a construction': a_program("""
        var h = Function('return 1;');
        var k = process.env.KEY || 'h';
        globalThis[k] = Function('return 2;');
        console.log(h());
        """),
}
"""
Each program resolves its key at runtime to a name the deobfuscator cannot see, so what the host
does is what decides: the write replaces that name, and the text the fold keeps must run the
replacement exactly as the original does. A read-naming surface answered none of these — a write
that names nothing withdraws nothing — and an unfettered exemption would have folded across the
replacement: these rows are what keeps the write fact routed.
"""

_A_DECODER_A_FUNCTION_DECLARATION_BINDS_REPLACED_BY_THE_WRITE = a_program("""
    var k = process.env.KEY || 'd';
    globalThis[k] = 0;
    function d(s) {
      return s.charAt(1);
    }
    console.log(d('abc'));
    """)


class TestAWriteThatNamesNothingStillFolds(TestBase):

    def test_each_program_folds_to_the_pinned_text(self):
        for label, (source, expected) in _A_WRITE_NO_LONGER_BLOCKS_A_METHOD_CALL.items():
            with self.subTest(label):
                self.assertEqual(folded(source), expected)

    def test_a_decoder_a_const_holds_folds_across_the_write(self):
        self.assertIn(folded(_A_DECODER_A_CONST_HOLDS_CALLED_ACROSS_THE_WRITE), (
            _THE_DECODER_CALL_FOLDED,
            _THE_DECODER_CALL_FOLDED_AND_THE_DECODER_REMOVED,
        ))

    @opportunity
    def test_a_decoder_a_const_holds_is_removed_once_its_call_folds_across_the_write(self):
        self.assertEqual(
            folded(_A_DECODER_A_CONST_HOLDS_CALLED_ACROSS_THE_WRITE),
            _THE_DECODER_CALL_FOLDED_AND_THE_DECODER_REMOVED,
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAGlobalWrittenUnderARuntimeKeyStillBinds(TestBase):

    def test_every_program_behaves_the_way_the_host_does(self):
        for label, source in _A_GLOBAL_WRITTEN_UNDER_A_RUNTIME_KEY.items():
            with self.subTest(label):
                before, after = before_and_after_in_a_host(source)
                self.assertEqual(after, before)

    def test_a_host_throws_where_a_write_replaced_a_decoder_a_function_declaration_binds(self):
        source = _A_DECODER_A_FUNCTION_DECLARATION_BINDS_REPLACED_BY_THE_WRITE
        self.assertEqual(host_behavior(source), ('', 'TypeError'))

    @backlog
    def test_a_decoder_a_function_declaration_binds_is_not_folded_across_a_write_replacing_it(self):
        source = _A_DECODER_A_FUNCTION_DECLARATION_BINDS_REPLACED_BY_THE_WRITE
        self.assertEqual(deobfuscated_host_behavior(source), ('', 'TypeError'))

_A_READ_THE_WRITE_HAS_NOT_REACHED = {
    'a read before the write': (
        a_program("""
            var s = 'abcdef';
            var k = process.env.KEY || 's';
            var t = s.charAt(2);
            globalThis[k] = 0;
            console.log(t);
            """),
        "var k = process.env.KEY || 's';\n"
        "var t = 'c';\n"
        "globalThis[k] = 0;\n"
        "console.log(t);",
    ),
    'a read inside the write key': (
        a_program("""
            var s = 'abcdef';
            globalThis[s.charAt(0)] = 0;
            console.log(1);
            """),
        "console.log(1);",
    ),
    'a read behind a key that folds': (
        a_program("""
            var k = ['s'].join('');
            var q = 'abcdef';
            globalThis[k] = 0;
            var t = q.charAt(2);
            console.log(t);
            """),
        "console.log('c');",
    ),
}
"""
A read the write may replace, standing where the write has not run yet. The first reads before the
store; the second reads inside the store's own key, which the assignment evaluates before it stores
(§13.15.5); the third reads after the store, but behind a key that folds to a literal first — which
takes the write out of the runtime-key class entirely, so nothing volatile remains for the read to
be killed by. Each folds to the text pinned beside it.

The first row's `console.log(t)` is the located kill's own half: the key resolves at runtime to any
name, `t` among them, so the read after the store is not folded and a host whose `KEY` is `'t'` is
handed a program that still prints the written value. The second and third lose the store outright —
a literal key nothing reads names no binding the sweep must keep.
"""

_A_READ_BEFORE_THE_WRITE = a_program("""
    var s = 'abcdef';
    var k = process.env.KEY || 's';
    var t = s.charAt(2);
    globalThis[k] = 0;
    console.log(t);
    """)

_A_READ_THE_WRITE_HAS_REACHED = a_program("""
    var s = 'abcdef';
    var k = process.env.KEY || 's';
    globalThis[k] = 0;
    var t = s.charAt(2);
    console.log(t);
    """)


class TestAReadTheWriteHasNotReachedYetFolds(TestBase):

    def test_each_program_folds_to_the_pinned_text(self):
        for label, (source, expected) in _A_READ_THE_WRITE_HAS_NOT_REACHED.items():
            with self.subTest(label):
                self.assertEqual(folded(source), expected)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReadTheWriteHasReachedStaysStanding(TestBase):

    def test_each_program_still_prints_and_throws_what_the_host_does(self):
        self.assertEqual(
            before_and_after_in_a_host(_A_READ_BEFORE_THE_WRITE),
            (prints('c'), prints('c')),
        )
        self.assertEqual(
            before_and_after_in_a_host(_A_READ_THE_WRITE_HAS_REACHED),
            (('', 'TypeError'), ('', 'TypeError')),
        )


_A_CONSTRUCTION_INVOKED_UNDER_A_RUNTIME_KEY_WRITE = {
    'the write follows the invocation': (
        a_program("""
            var k, v;
            var f = Function("return 42;");
            var r = f();
            globalThis[k] = v;
            """),
        "var k, v;\n"
        "var r = 42;\n"
        "globalThis[k] = v;",
    ),
    'the write precedes the invocation': (
        a_program("""
            var k, v;
            globalThis[k] = v;
            var f = Function("return 42;");
            var r = f();
            """),
        "var k, v;\n"
        "globalThis[k] = v;\n"
        "var f = Function(\"return 42;\");\n"
        "var r = f();",
    ),
}
"""
A script-scope name holding a construction is a property of the global object under the script
execution model, so a store under a runtime key may rebind it — the question the construction
resolver used to refuse on the presence of the write alone. The tampering oracle answers it with
the point supplied: a write guaranteed to follow the invocation does not reach the value the call
runs, so the construction resolves and its body folds; a write that may precede it keeps the call
standing exactly as before.
"""


class TestAConstructionUnderARuntimeKeyWrite(TestBase):

    def test_each_program_folds_to_the_pinned_text(self):
        for label, (source, expected) in _A_CONSTRUCTION_INVOKED_UNDER_A_RUNTIME_KEY_WRITE.items():
            with self.subTest(label):
                self.assertEqual(folded(source), expected)
