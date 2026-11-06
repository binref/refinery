"""
SECURITY: every program here is written out by the module itself and Node runs only those. Nothing
from `samples` may ever be handed to the engine.
"""
from __future__ import annotations

import contextlib
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints

from refinery.lib.scripts.modelcache import ModelCacheBase
from refinery.units.scripting.djs import djs

_A_KEY_A_FOLD_SPELLS: dict[str, tuple[str, str | None]] = {
    "var w = (function () { return this; })(); w[1 ? 'eval' : 'x']('g()'); var o = {}; o.x = 1;"
    " globalThis[Math.random()]; g(); function g() { console.log('x' in o); }": ('', 'ReferenceError'),
    "var e = globalThis[String.fromCharCode(101, 118, 97, 108)];"
    " e('Math.floor = function () { return 7; }'); console.log(Math.floor(1.5));": ('7\n', None),
    "var P = Object['#getPrototypeOf'.slice(1)]([]); P.x = 5; console.log([].x);": ('5\n', None),
    "Object['#setPrototypeOf'.slice(1)](Array.prototype, {x: 5}); console.log([].x);": ('5\n', None),
    'var C = new ([][String.fromCharCode(99, 111, 110, 115, 116, 114, 117, 99, 116, 111, 114)])(3);'
    ' console.log(C.length);': ('3\n', None),
    "function f() { return f['#caller'.slice(1)]; } function h() { return f(); } console.log(h() === h);": (
        'true\n',
        None,
    ),
    'function f() { this[String.fromCharCode(77, 97, 116, 104)] = {floor: function () { return 7; }}; }'
    ' f(); console.log(Math.floor(1.5));': ('7\n', None),
    'globalThis.__defineGetter__(String.fromCharCode(77, 97, 116, 104),'
    ' function () { return {floor: function () { return 7; }}; }); console.log(Math.floor(1.5));': ('7\n', None),
    "[]['#constructor'.slice(1)].prototype.x = 5; console.log([].x);": ('5\n', None),
    "[]['#__proto__'.slice(1)].x = 5; console.log([].x);": ('5\n', None),
}

_A_FUNCTION_BUILT_UNDER_A_CONCATENATED_KEY = {
    "var F = []['constr' + 'uctor']['constr' + 'uctor'];"
    " F('Math.floor = function () { return 7; }')(); console.log(Math.floor(1.5));": '7\n',
}

_EVERY_MODEL = [False, True]


@contextlib.contextmanager
def _holding_nothing(self):
    yield self


def _deobfuscated(source: str, strict: bool) -> str:
    return source.encode('utf8') | djs(strict=strict) | str


def _deobfuscated_as_a_commonjs_file(source: str, strict: bool) -> str:
    return source.encode('utf8') | djs(strict=strict, commonjs=True) | str


def _deobfuscated_rebuilding_the_models(source: str, strict: bool) -> str:
    pinned = ModelCacheBase.pinned
    ModelCacheBase.pinned = _holding_nothing  # type: ignore
    try:
        return _deobfuscated(source, strict)
    finally:
        ModelCacheBase.pinned = pinned  # type: ignore


class TestAKeyAFoldSpellsRenewsTheModels(TestBase):

    def test_the_held_and_the_rebuilt_models_write_the_same_text(self):
        for source in _A_KEY_A_FOLD_SPELLS:
            for strict in _EVERY_MODEL:
                with self.subTest(source=source, strict=strict):
                    self.assertEqual(
                        _deobfuscated(source, strict),
                        _deobfuscated_rebuilding_the_models(source, strict),
                    )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_does_what_each_row_records(self):
        for source, does in _A_KEY_A_FOLD_SPELLS.items():
            with self.subTest(source=source):
                self.assertEqual(behavior(source), does)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_does_the_same_with_each_deobfuscation_written_for_a_commonjs_file(self):
        for source, does in _A_KEY_A_FOLD_SPELLS.items():
            for strict in _EVERY_MODEL:
                with self.subTest(source=source, strict=strict):
                    self.assertEqual(behavior(_deobfuscated_as_a_commonjs_file(source, strict)), does)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAConcatenatedKeyIsReadAsTheStringItSpells(TestBase):

    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = _A_FUNCTION_BUILT_UNDER_A_CONCATENATED_KEY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
