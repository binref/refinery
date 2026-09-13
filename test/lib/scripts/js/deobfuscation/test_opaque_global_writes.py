"""
A computed global write stores a property and names nothing.

`globalThis[expr] = v` was once counted as a reflective surface — the same alarm as `eval` — and
that one flag withdrew every trust question program-wide, refusing to execute the very decoder
whose folding would have removed the computed key: a deadlock. The surface and the write are now
separate questions (`refinery.lib.scripts.js.analysis.model.SemanticModel.has_opaque_global_write`):
naming a global at runtime still blocks everything it blocked, while storing a property under a
runtime key blocks only what replacing a value blocks — an intrinsic called by name, and a
script-scope name keeping its spelled value.

SECURITY: every program here is hand-authored in this file and benign. No sample and no stored
obfuscator fixture may be fed to this.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import a_program, before_and_after_in_a_host, folded, prints

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
    'a decoder function executed through the write': (
        a_program("""
            var k = process.env.KEY;
            globalThis[k] = 0;
            function d(s) {
              return s.charAt(1);
            }
            console.log(d('abc'));
            """),
        a_program("""
            var k = process.env.KEY;
            globalThis[k] = 0;
            function d(s) {
              return s.charAt(1);
            }
            console.log('b');
            """).rstrip(chr(10)),
    ),
}
"""
Each program stores a property on the global object under a key the analysis cannot read, and each
must still fold across it: a write cannot run code or read a value, so the decoder sitting behind it
folds as it would without the write. The write and its key are what stay — the recall cost of a
sound design, pinned here so it is a cost and not a regression.
"""

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


class TestAWriteThatNamesNothingStillFolds(TestBase):
    """
    The recall side: what the surface split buys. Each row must fold across the write to the text
    pinned beside it, or the deadlock is back.
    """

    def test_each_program_folds_to_the_pinned_text(self):
        for label, (source, expected) in _A_WRITE_NO_LONGER_BLOCKS_A_METHOD_CALL.items():
            with self.subTest(label):
                self.assertEqual(folded(source), expected)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAGlobalWrittenUnderARuntimeKeyStillBinds(TestBase):
    """
    The soundness side, read under the script execution model — the one in which a top-level
    declaration is a property of the global object at all.
    """

    def test_every_program_behaves_the_way_the_host_does(self):
        for label, source in _A_GLOBAL_WRITTEN_UNDER_A_RUNTIME_KEY.items():
            with self.subTest(label):
                before, after = before_and_after_in_a_host(source)
                self.assertEqual(after, before)

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

#: The first row's program, whose fold is the one the write's position has to justify.
_A_READ_BEFORE_THE_WRITE = a_program("""
    var s = 'abcdef';
    var k = process.env.KEY || 's';
    var t = s.charAt(2);
    globalThis[k] = 0;
    console.log(t);
    """)

#: The same program with the store moved ahead of the read, which the write's replacement then
#: reaches first: a host running it as a script ends it with a `TypeError` on both sides.
_A_READ_THE_WRITE_HAS_REACHED = a_program("""
    var s = 'abcdef';
    var k = process.env.KEY || 's';
    globalThis[k] = 0;
    var t = s.charAt(2);
    console.log(t);
    """)


class TestAReadTheWriteHasNotReachedYetFolds(TestBase):
    """
    The located form of the write fact. A store under a runtime key may replace a script-scope
    name, so it is a kill — but a kill at the statement that spells it, which a read standing before
    it, or inside the operands that statement evaluates before storing, is not reached by. The recall
    the volatile-everywhere reading refused: each of these stayed standing whole before the kill was
    located, the third deadlocked — its key folds only once the read inside it is answered, and the
    read is answered only once the write stops being volatile everywhere.
    """

    def test_each_program_folds_to_the_pinned_text(self):
        for label, (source, expected) in _A_READ_THE_WRITE_HAS_NOT_REACHED.items():
            with self.subTest(label):
                self.assertEqual(folded(source), expected)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReadTheWriteHasReachedStaysStanding(TestBase):
    """
    The soundness half the located kill owes: a read standing after the store may observe the
    written value, so it stays standing, and a host running the file as a script — the model in
    which the store really does replace the name — ends it the same way on both sides.
    """

    def test_each_program_still_prints_and_throws_what_the_host_does(self):
        self.assertEqual(
            before_and_after_in_a_host(_A_READ_BEFORE_THE_WRITE),
            (prints('c'), prints('c')),
        )
        self.assertEqual(
            before_and_after_in_a_host(_A_READ_THE_WRITE_HAS_REACHED),
            (('', 'TypeError'), ('', 'TypeError')),
        )
