"""
A second run over a tree whose write scan does not follow every write.

A value a program reads off a built-in without spelling its owner, handed to code the scan cannot
read, may write that built-in under no name, so every fold that reads a built-in's chain refuses:
`console.log([][k])` stops the fold of `false + []` that would read `k`. Where a run ends on such a
tree, the deobfuscation runs again on it, assuming that every write the scan does not follow writes
nothing, and checks the assumption at every build of the scan. It keeps that run where a build
follows every write without recording more than the one before it, and the tree of the first run
everywhere else.

Every program here is written so that a fold made under the assumption shows: one that writes a
built-in through a value the assumption reads away, one whose result still hands such a value on,
and one only the second run decodes. Every answer is Node's, under the deobfuscation that suspects
code it cannot read (`-s`), the default one, and the default one in Node.

SECURITY: every program here is written out by the module itself and Node runs only those. Nothing
from `samples` may ever be handed to the engine.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.units.scripting.djs import djs

_K = "('constr' + ([] + []) + 'uctor')"

#: A program whose only write the scan does not follow is a hand-off a fold reads away, mapped to
#: what it prints and to the text every deobfuscation writes for it.
_A_HAND_OFF_A_FOLD_READS_AWAY: dict[str, tuple[str, str]] = {
    "console.log([][(false + [])[0] + 'oo']);": (
        'undefined\n',
        'console.log(void 0);',
    ),
    "console.log(false + [], [][(false + [])[0] + 'oo']);": (
        'false undefined\n',
        "console.log('false', void 0);",
    ),
}

#: A program writing a built-in through a value the assumption would read away, mapped to what it
#: prints and to the read the write decides: a fold made under the assumption writes the key the
#: build after it records.
_A_WRITE_THE_ASSUMPTION_WOULD_HIDE: dict[str, tuple[str, str]] = {
    F'function show(t) {{ console.log(t, [].x); }} [][{_K}].prototype.x = 5; show(1); show(2);': ('1 5\n2 5\n', '[].x'),
    F'for (var i = 0; i < 2; i++) {{ console.log(i, [].x); [][{_K}].prototype.x = 5; }}': ('0 undefined\n1 5\n', '[].x'),
    F'var o = {{h: function (A) {{ A.prototype.x = 5; }}}}; o.h([][{_K}]); console.log(1, [].x);': ('1 5\n', '[].x'),
    "[][('__pro' + ([] + []) + 'to__')].x = 5; console.log(1, [].x);": ('1 5\n', '[].x'),
    F'for (var n = 0; n < 9; n++) {{ if ([].x === 5) break; [][{_K}].prototype.x = 5; }} console.log(n);': ('1\n', '[].x'),
    F"for (;;) {{ if ([].x === 5) break; [][{_K}].prototype.x = 5; }} console.log('done');": ('done\n', '[].x'),
    "[][[] + '__proto__'].x = 5; console.log([].x);": ('5\n', '[].x'),
    "var p = [][[] + '__proto__']; p.x = 5; console.log([].x);": ('5\n', '[].x'),
    "var P = Object.getPrototypeOf([]); (P['pus' + 'ah'[1]])(5); console.log([][0]);": ('5\n', '[][0]'),
}

#: A program whose result still hands a built-in to code that writes it, mapped to what it prints
#: and to the read the write decides.
_A_RESULT_THAT_STILL_HANDS_A_BUILT_IN_ON: dict[str, tuple[str, str]] = {
    inspect.cleandoc("""
        var h = {};
        var k = Math.random() < 2 ? 'a' : 'b';
        h[k] = function (o) { o.x = 5; };
        h[k]([].__proto__);
        console.log([].x, [].at.name);
    """): ('5 at\n', '[].x'),
    '[].at.constructor("return function (f) { f.__proto__.x = 5; }")()([]); console.log([].x);': ('5\n', '[].x'),
}

#: A program whose hand-off a fold of the first run proves unreachable, mapped to what it prints and
#: to the text every deobfuscation writes for it.
_A_HAND_OFF_NO_EXECUTION_REACHES: dict[str, tuple[str, str]] = {
    "var k = 'x'; if ([].x === void 0) { console.log(1, [].at.name); } else { h([][k]); }": (
        '1 at\n',
        "console.log(1, 'at');",
    ),
}

#: Each model and host a deobfuscation below is asked under.
_EVERY_MODE = [
    (True, 'universal'),
    (False, 'universal'),
    (False, 'node'),
]


def _deobfuscated(source: str, strict: bool, environment: str) -> str:
    return source.encode('utf8') | djs(strict=strict, environment=environment) | str


class TestTheSecondRunDecodesWhatTheHandOffBlocked(TestBase):

    def test_each_deobfuscation_writes_the_folded_text(self):
        rows = _A_HAND_OFF_A_FOLD_READS_AWAY | _A_HAND_OFF_NO_EXECUTION_REACHES
        for source, (_, folded) in rows.items():
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertEqual(_deobfuscated(source, strict, environment), folded)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_for_the_program_and_for_the_folded_text(self):
        rows = _A_HAND_OFF_A_FOLD_READS_AWAY | _A_HAND_OFF_NO_EXECUTION_REACHES
        for source, (prints, folded) in rows.items():
            with self.subTest(source=source):
                self.assertEqual((behavior(source), behavior(folded)), ((prints, None), (prints, None)))


class TestTheSecondRunKeepsNoFoldTheWriteDisproves(TestBase):

    def test_each_deobfuscation_leaves_standing_the_read_the_write_decides(self):
        rows = _A_WRITE_THE_ASSUMPTION_WOULD_HIDE | _A_RESULT_THAT_STILL_HANDS_A_BUILT_IN_ON
        for source, (_, read) in rows.items():
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertIn(read, _deobfuscated(source, strict, environment))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_what_each_row_records(self):
        rows = _A_WRITE_THE_ASSUMPTION_WOULD_HIDE | _A_RESULT_THAT_STILL_HANDS_A_BUILT_IN_ON
        for source, (prints, _) in rows.items():
            with self.subTest(source=source):
                self.assertEqual(behavior(source), (prints, None))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_deobfuscation_of_a_write_the_assumption_would_hide_prints_it_too(self):
        for source, (prints, _) in _A_WRITE_THE_ASSUMPTION_WOULD_HIDE.items():
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertEqual(behavior(_deobfuscated(source, strict, environment)), (prints, None))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_deobfuscation_of_a_result_still_handing_a_built_in_on_prints_it_too(self):
        for source, (prints, _) in _A_RESULT_THAT_STILL_HANDS_A_BUILT_IN_ON.items():
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertEqual(behavior(_deobfuscated(source, strict, environment)), (prints, None))
