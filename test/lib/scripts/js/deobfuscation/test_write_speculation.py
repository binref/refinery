"""
A value read off a built-in and handed to code the deobfuscation cannot read may write that
built-in, which blocks every fold that reads one. The deobfuscation then runs a second time,
assuming such a hand-off writes nothing, and keeps that run only where no write it finds disproves
the assumption.

SECURITY: every program here is written out by the module itself and Node runs only those. Nothing
from `samples` may ever be handed to the engine.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.pipeline import PipelineObserver
from refinery.units.scripting.djs import djs

_K = "('constr' + ([] + []) + 'uctor')"

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

_A_HAND_OFF_NO_EXECUTION_REACHES: dict[str, tuple[str, str]] = {
    "var k = 'x'; if ([].x === void 0) { console.log(1, [].at.name); } else { h([][k]); }": (
        '1 at\n',
        "console.log(1, 'at');",
    ),
}

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


class _PassCounter(PipelineObserver):

    def __init__(self):
        self.passes = 0

    def before(self, group: str, transformer: type, ast) -> None:
        self.passes += 1

    def fork(self) -> PipelineObserver:
        return self


class TestASecondRunNoFoldCanUseIsNotRun(TestBase):

    @staticmethod
    def _passes(source: str) -> int:
        counter = _PassCounter()
        deobfuscate(JsParser(source).parse(), observer=counter)
        return counter.passes

    def test_a_hand_off_no_fold_can_decide_costs_no_passes(self):
        head = "var k = Math.random() < 2 ? 'a' : 'b';"
        self.assertEqual(self._passes(F'{head} h([][k]);'), self._passes(F'{head} h([]);'))
