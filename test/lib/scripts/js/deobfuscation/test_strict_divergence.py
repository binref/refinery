from __future__ import annotations

import unittest

from test import TestBase

from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.strict import collect_strict_violations
from refinery.lib.scripts.js.deobfuscation.strict_divergence import diverges_under_strict

from test.lib.scripts.js.analysis.differential import behavior, node_executable


class TestStrictDivergence(TestBase):

    def _diverges(self, source: str) -> bool:
        parsed = JsParser(source).parse()
        return diverges_under_strict(parsed, build_semantic_model(parsed))

    def test_direct_eval_diverges(self):
        for source in ['eval("var zz = 1");', '(eval)("zz");']:
            with self.subTest(source=source):
                self.assertTrue(self._diverges(source))

    def test_strict_parse_error_diverges(self):
        for source in ['010;', 'with (x) {}', 'delete x;', 'var eval = 1;']:
            with self.subTest(source=source):
                self.assertTrue(self._diverges(source))

    def test_this_reference_diverges(self):
        for source in [
            'console.log(this === undefined);',
            'console.log((function () { return this; })() === undefined);',
            'this.foo = 1;',
        ]:
            with self.subTest(source=source):
                self.assertTrue(self._diverges(source))

    def test_free_name_write_diverges(self):
        for source in ['x = 5;', 'undefined = 5;', '[a] = [5];']:
            with self.subTest(source=source):
                self.assertTrue(self._diverges(source))

    def test_unsafe_member_write_diverges(self):
        for source in [
            '(1).x = 2;',
            '(function () {}).name = "z";',
            'var g = { get p() { return 1; } }; g.p = 2;',
            'delete Object.prototype;',
            'o.p = 2;',
        ]:
            with self.subTest(source=source):
                self.assertTrue(self._diverges(source))

    def test_block_function_diverges(self):
        for source in [
            'if (true) { function h() {} }',
            'switch (1) { case 1: function s() {} }',
            '{ function b() {} }',
        ]:
            with self.subTest(source=source):
                self.assertTrue(self._diverges(source))

    def test_mapped_arguments_diverges(self):
        for source in [
            'function f(a) { arguments[0] = 9; return a; }',
            'function f(a) { a = 9; return arguments[0]; }',
        ]:
            with self.subTest(source=source):
                self.assertTrue(self._diverges(source))

    def test_poison_pill_read_diverges(self):
        for source in [
            'function f() {} f.caller;',
            'function f() {} f["caller"];',
            'function f() { return arguments.callee; }',
        ]:
            with self.subTest(source=source):
                self.assertTrue(self._diverges(source))

    def test_mode_invariant_body_does_not_diverge(self):
        for source in [
            'a.b.c;',
            '1 + 1;',
            'var y = 1; y = 2;',
            '({}).x = 1;',
            '[][0] = 1;',
            '({ a: 1 }).b = 2;',
            '({}).x++;',
            'var f = function (a) { return a; };',
            'function m(a) { return a + 1; }',
        ]:
            with self.subTest(source=source):
                self.assertFalse(self._diverges(source))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestStrictDivergenceDifferential(TestBase):
    """
    Cross-check the detector against Node: every payload the strict-vs-sloppy oracle shows behaving
    differently — or that is a strict parse error — must be flagged. This guards the no-false-negative
    property soundness rests on. A payload runs inside an immediately invoked function under both modes so
    a function-level `this`, an `arguments` object, and an eval scope are exercised faithfully; over-refusal
    (flagging a mode-invariant body) is permitted and not checked here.
    """

    CORPUS = [
        'x = 5;',
        'undefined = 5;',
        '[a] = [5];',
        '(1).x = 2;',
        '"s".x = 2;',
        '(function () {}).name = "z";',
        '(function () {}).length = 9;',
        'var g = { get p() { return 1; } }; g.p = 2;',
        'var o = ({}); Object.freeze(o); o.p = 1;',
        'delete Object.prototype;',
        'function f(a) { arguments[0] = 9; return a; } console.log(f(1));',
        'function f(a) { a = 9; return arguments[0]; } console.log(f(1));',
        'function f() { return arguments.callee; } console.log(typeof f());',
        'function f() {} console.log(f.caller);',
        'function f() {} console.log(f["caller"]);',
        'if (true) { function h() {} } console.log(typeof h);',
        'switch (1) { case 1: function s() {} } console.log(typeof s);',
        '{ function b() {} } console.log(typeof b);',
        'eval("var zz = 1"); console.log(typeof zz);',
        'console.log(this === undefined);',
        'console.log((function () { return this; })() === undefined);',
    ]

    DIVERGENT_FRAGMENTS = [
        'zz = 5;',
        'undefined = 5;',
        '(1).px = 2;',
        '(function () {}).name = "z";',
        'delete Object.prototype;',
        'eval("var qq = 1"); console.log(typeof qq);',
        'if (1) { function gg() {} } console.log(typeof gg);',
        'console.log((function (a) { a = 9; return arguments[0]; })(3));',
        'console.log(this === undefined);',
        'function ff() {} console.log(ff.caller);',
    ]

    NESTING_CONTEXTS = [
        '(function () {{ {frag} }})();',
        '(function () {{ return (function () {{ {frag} }})(); }})();',
        '(() => {{ {frag} }})();',
    ]

    def _diverges(self, source: str) -> bool:
        parsed = JsParser(source).parse()
        return diverges_under_strict(parsed, build_semantic_model(parsed))

    def _oracle_diverges(self, source: str) -> bool:
        sloppy = behavior(F'(function () {{ {source} }})();')
        strict = behavior(F"(function () {{ 'use strict'; {source} }})();")
        return sloppy != strict

    def test_no_false_negative(self):
        for source in self.CORPUS:
            with self.subTest(source=source):
                if collect_strict_violations(JsParser(source).parse(), strict=True):
                    self.assertTrue(self._diverges(source))
                elif self._oracle_diverges(source):
                    self.assertTrue(self._diverges(source))

    def test_no_false_negative_in_nested_scopes(self):
        """
        The mode flip reaches every nested scope, so each divergent fragment must still be flagged when
        wrapped in a nested function, a doubly nested function, or an arrow — a rule that stopped at a
        scope boundary would inline an unsound body.
        """
        for frag in self.DIVERGENT_FRAGMENTS:
            for context in self.NESTING_CONTEXTS:
                source = context.format(frag=frag)
                with self.subTest(source=source):
                    if collect_strict_violations(JsParser(source).parse(), strict=True):
                        self.assertTrue(self._diverges(source))
                    elif self._oracle_diverges(source):
                        self.assertTrue(self._diverges(source))
