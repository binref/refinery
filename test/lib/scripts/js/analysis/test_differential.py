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

    def test_global_alias_not_collapsed_into_catch_binding(self):
        """
        `globalThis.X` inside a `catch (X)` names the global property, not the caught exception, so
        simplification must keep the alias rather than collapse it to the catch-bound `X`.
        """
        self._check(
            "globalThis.X = 'global';"
            ' function probe(){ try { throw "caught"; } catch (X) { return globalThis.X; } }'
            ' console.log(probe());')

    def test_namespace_flatten_preserves_block_scoped_shadow(self):
        """
        Flattening `NS.x` to a script-level `var x` must respect a `let x` that block-scopes a
        different value: the inner read stays bound to the block's `x`, the outer read to the
        flattened one, so the observed sequence is unchanged.
        """
        self._check(
            'var NS = {}; NS.x = 1; var r = [];'
            ' { let x = 9; r.push(x); } r.push(NS.x); console.log(r.join(","));')

    def test_const_not_inlined_past_inherited_param_shadow(self):
        """
        `B` reads `k` through the parameter of its enclosing `A`, not the outer `const k`. Constant
        inlining must respect that inherited shadow rather than substituting the constant's value, so
        `A(9)` keeps returning the argument.
        """
        self._check(
            'const k = 5; function A(k) { function B() { return k; } return B(); }'
            ' console.log(A(9));')

    def test_dead_const_removed_only_when_truly_unreferenced(self):
        """
        Inside `wrap` the `var x` hoists over `g`'s read, so the outer `const x` is referenced only by
        `f`. Removing `f` and the now-dead `const x` must not disturb `wrap`'s own `x`, so both reads
        keep their values.
        """
        self._check(
            "const x = 'outer';"
            ' const f = () => x;'
            ' function wrap(){ const g = () => x; if (true) { var x = "inner"; } return g(); }'
            ' console.log(f(), wrap());')

    def test_nested_closures_share_binding(self):
        """
        `outer` calls a nested `add` that mutates the captured `s`. A nested call runs in an isolated
        child interpreter with no write-back, so the evaluator refuses to fold `outer` rather than
        dropping the mutation — the call is left for the engine and the behavior ("ab") is preserved.
        """
        self._check(
            'function outer(){ var s = ""; function add(x){ s += x; } add("a"); add("b");'
            ' return s; } console.log(outer());')

    def test_function_constructor_return_this_is_global_object(self):
        """
        `new Function("return this")()` yields the global object (a Function-constructed function is
        sloppy and called with no receiver), so reflection inlining must resolve it to `globalThis`
        rather than the caller's `this`, which under Node is the empty module export object.
        """
        self._check(
            'var g = new Function("return this")();'
            ' console.log(g === globalThis, typeof g.Array);')

    def test_function_constructor_body_var_does_not_capture_caller_scope(self):
        """
        A `Function`-constructed body runs in its own scope, so its `var x` is local to the constructed
        function and never reaches the caller; inlining it must not redeclare the caller's `x`, which
        would change the value observed after the call.
        """
        self._check('var x = 1; new Function("var x = 2;")(); console.log(x);')

    def test_function_constructor_body_lexical_does_not_redeclare_caller_block(self):
        """
        A `let` in a `Function`-constructed body is local to it; inlining it into the caller's block
        where a same-named `let` already lives would be a duplicate-declaration SyntaxError rather than
        the original's two independent bindings.
        """
        self._check(
            '{ let y = 1; new Function("let y = 2; console.log(y);")(); console.log(y); }')

    def test_function_constructor_body_var_does_not_cross_block_let(self):
        """
        A `Function`-constructed body's `var x` is local to the constructed function; a `var` spliced
        into a block that already lexically binds `x` would hoist across that `let`, a redeclaration
        SyntaxError rather than the original's two independent bindings.
        """
        self._check('{ let x = 9; new Function("var x = 2;")(); console.log(x); }')

    def test_function_constructor_in_strict_caller_not_inlined(self):
        """
        A `Function`-constructed body is always sloppy, so its octal literal is legal; splicing the
        body into a strict-mode caller would subject the octal to strict mode, a SyntaxError. The body
        must stay an un-inlined call so the caller's strictness never reaches it.
        """
        self._check('function f(){ "use strict"; return new Function("return 010")(); } console.log(f());')
