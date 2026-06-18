from __future__ import annotations

import unittest

from test import TestBase

from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    node_executable,
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationDifferential(TestBase):
    """
    Each case runs a benign snippet and its deobfuscation through Node.js and asserts they behave
    identically. These guard the semantics-preservation invariant against the substrate migration.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_closure_counter(self):
        self._check(
            'function mk(){ var c = 0; return function(){ return ++c; }; }'
            ' var f = mk(); console.log(f(), f(), f());')

    def test_function_and_var_hoisting(self):
        self._check('console.log(g()); function g(){ var r = 41; return r + 1; }')

    def test_dead_variable_and_constant_folding(self):
        self._check('var a = 1 + 2; var unused = 5; console.log(a * 2);')

    def test_block_scoped_for_let(self):
        self._check('var out = []; for (let i = 0; i < 3; i++) { out.push(i); }'
                    ' console.log(out.join(","));')

    def test_try_catch_error_name(self):
        self._check('try { null.x; } catch (e) { console.log(e.name, e instanceof TypeError); }')

    def test_iife(self):
        self._check('console.log((function(x){ return x * x; })(7));')

    def test_parameter_shadows_outer(self):
        self._check('var x = 1; function f(x){ return x + 1; } console.log(f(10), x);')

    def test_module_pattern_private_state(self):
        self._check(
            'var C = (function(){ var n = 0; return { inc: function(){ return ++n; } }; })();'
            ' console.log(C.inc(), C.inc());')

    def test_dynamic_eval_reading_global_preserved(self):
        self._check(
            'var data; data = 123;'
            ' var name = String.fromCharCode(100, 97, 116, 97);'
            ' console.log(eval(name));')

    def test_function_called_only_through_eval_preserved(self):
        self._check("function greet(){ return 'hi'; } console.log(eval('greet()'));")

    @unittest.expectedFailure
    def test_nested_closures_share_binding(self):
        """
        Pre-existing pipeline bug surfaced by the harness: `outer()` is folded to its initial
        `s = ""`, dropping the mutations that the nested closure `add` makes to the captured `s`, so
        the deobfuscation prints "" instead of "ab". An unsound purity judgment in function evaluation
        that the Stage 2 effect/escape analysis is meant to eliminate; tracked here until then.
        """
        self._check(
            'function outer(){ var s = ""; function add(x){ s += x; } add("a"); add("b");'
            ' return s; } console.log(outer());')
