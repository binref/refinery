from __future__ import annotations

import inspect
import json
import unittest

from typing import NamedTuple

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    JsEvaluation,
    behavior,
    completion_values,
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints
from test.lib.scripts.js.test_directive_prologue import NOT_A_PROGRAM

from refinery.lib.scripts import tree_version
from refinery.lib.scripts.js.options import DeobfuscationOptions
from refinery.lib.scripts.js.deobfuscation.reflection import JsReflectionInlining
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


#: The default-preset string array (rotation IIFE, self-overwriting array function, accessor) a
#: common obfuscator emits, with the non-checksum string at index 0xac set to `return this` and the
#: trailing usage
#: replaced by a separated `Function` global finder. The finder's code is a literal only after the
#: string-array resolver decodes `_0xe6abe5(0xac)` — a decode the reflection pass cannot perform
#: itself — so folding it exercises reflection re-running once that surface is revealed.
_STRING_ARRAY_REVEALS_A_GLOBAL_FINDER = (
    r"var _0xe6abe5=_0x1b07;"
    r"(function(_0x13a108,_0x20b5f6){var _0x2bca43=_0x1b07,_0x36965a=_0x13a108();while(!![]){try{var _0x29"
    r"3699=-parseInt(_0x2bca43(0xa7))/0x1+-parseInt(_0x2bca43(0xa1))/0x2*(-parseInt(_0x2bca43(0xab))/0x3)+"
    r"parseInt(_0x2bca43(0xa3))/0x4*(-parseInt(_0x2bca43(0xa9))/0x5)+parseInt(_0x2bca43(0xa6))/0x6+parseIn"
    r"t(_0x2bca43(0xaa))/0x7*(parseInt(_0x2bca43(0xa2))/0x8)+-parseInt(_0x2bca43(0xa4))/0x9*(-parseInt(_0x"
    r"2bca43(0xa5))/0xa)+-parseInt(_0x2bca43(0xa0))/0xb;if(_0x293699===_0x20b5f6)break;else _0x36965a['pus"
    r"h'](_0x36965a['shift']());}catch(_0x35acf4){_0x36965a['push'](_0x36965a['shift']());}}}(_0x2fc0,0x82"
    r"7c2));function _0x1b07(_0x3a2c1f,_0x271b5b){_0x3a2c1f=_0x3a2c1f-0xa0;var _0x2fc00e=_0x2fc0();var _0x"
    r"1b0775=_0x2fc00e[_0x3a2c1f];return _0x1b0775;}function _0x2fc0(){var _0x581e"
    r"61=['2435007zbgngY','return\x20this','12767458FlCTYp','2BveYOA','96VHQLDe','160CSMRCB','486kcIkKD','"
    r"183450npXmbZ','4067550xFhrYl','462884STmCds','log','50725EqKMLb','48769HzjsUR'];_0x2fc0=function(){r"
    r"eturn _0x581e61;};return _0x2fc0();}var _m = Function(_0xe6abe5(0xac)); sink(_m());"
)


class TestReflectionInlining(TestJsDeobfuscator):

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def _reflect_module(self, source: str) -> str:
        return self._run_transformer(
            source, JsReflectionInlining, DeobfuscationOptions(module=True))

    def test_a_constant_fold_before_a_sibling_construction_check_does_not_trip_the_pin(self):
        """
        Folding the first construction advances the tree under the held pin, and checking the second
        construction's argument then reads the establishment model for the first time — past the
        entry version. The window must have that model held from entry, or the pin's fill guard
        aborts the whole run on this valid input.
        """
        self.assertEqual(
            "var y = new Function('a', 'return a')(z);\nvar x = 1;",
            self._reflect("var y = new Function('a','return a')(z); var x = new Function('return 1')();"),
        )

    def test_eval_string_literal(self):
        self.assertEqual('var x = 1;', self._reflect("eval('var x = 1;');"))

    def test_direct_eval_var_inlined_when_reference_is_dominated(self):
        """
        A sloppy direct eval's `var` leaks to the caller, so `eval('var x = 1;')` inlines when the eval
        site dominates every reference to the name. Here `return x` runs after the eval, so hoisting the
        declaration cannot rebind it and the inlining is admitted.
        """
        source = inspect.cleandoc(
            """
            function f() {
              eval('var x = 1;');
              return x;
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  var x = 1;
                  return x;
                }
                """
            ),
            self._reflect(source))

    def test_eval_non_literal_not_inlined(self):
        self.assertEqual('eval(x);', self._reflect('eval(x);'))

    def test_eval_parenthesized(self):
        self.assertEqual('var x = 1;', self._reflect("(eval)('var x = 1;');"))

    def test_direct_eval_shadowed_not_inlined(self):
        source = inspect.cleandoc(
            """
            function f(eval) {
              return eval("1");
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_direct_eval_in_with_not_inlined(self):
        """
        Inside a `with` body a bare `eval` may resolve to a property of the `with` object.
        """
        source = inspect.cleandoc(
            """
            with (o) {
              eval("1");
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_direct_eval_strict_body_into_sloppy_site_not_inlined(self):
        """
        A direct `eval` whose body opens with `"use strict"` runs strict. Spliced below a non-directive
        position in a sloppy function the directive no longer governs the body, so an assignment to an
        undeclared name would silently create a global instead of throwing a `ReferenceError`; the
        inlining is declined.
        """
        source = inspect.cleandoc(
            """
            function f() {
              g();
              eval("'use strict'; x = 1;");
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_indirect_eval_comma_operator(self):
        self.assertEqual('var x = 1;', self._reflect("(0, eval)('var x = 1;');"))

    def test_indirect_eval_comma_operator_shadowed_not_inlined(self):
        source = inspect.cleandoc(
            """
            function f(eval) {
              return (0, eval)("1");
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_indirect_eval_through_a_host_conditional_alias_is_kept(self):
        """
        `window` is a host-conditional alias no universal host defines, so discarding it to inline
        `window.eval` would drop the `ReferenceError` a lacking host raises reading it; the call is kept.
        """
        source = "window.eval('var x = 1;');"
        self.assertEqual(source, self._reflect(source))

    def test_indirect_eval_globalthis(self):
        self.assertEqual('var x = 1;', self._reflect("globalThis.eval('var x = 1;');"))

    def test_indirect_eval_computed_alias_member(self):
        self.assertEqual('var x = 1;', self._reflect("globalThis['eval']('var x = 1;');"))

    def test_indirect_eval_shadowed_alias_base_not_inlined(self):
        """
        `window` is a local parameter, so `window.eval` is that object's method, not the global eval.
        """
        source = inspect.cleandoc(
            """
            function f(window) {
              return window.eval("1");
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_shadowed_function_pack_not_inlined(self):
        """
        A locally shadowed `Function` in the pack shape is that local's value, not the intrinsic, so the
        model-backed callee check must not treat it as a pack pattern to inline.
        """
        source = inspect.cleandoc(
            """
            function g() {
              var Function = h;
              Function(x)({ a: 1 });
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_indirect_eval_alias_base_in_with_not_inlined(self):
        """
        Inside a `with` body the base `window` may resolve to a property of the `with` object.
        """
        source = inspect.cleandoc(
            """
            with (o) {
              window.eval("1");
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_indirect_eval_prefix_read_in_with_not_inlined(self):
        """
        The bare name `e` in the comma-sequence prefix of `(e, eval)(...)` inside a `with` body fires
        the object's getter before `eval` resolves. Inlining the indirect eval discards the prefix, so
        the site is left intact rather than dropping the getter read.
        """
        source = inspect.cleandoc(
            """
            var e = 0;
            var o = { get e() {
              return 0;
            } };
            with (o) {
              (e, eval)("f()");
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_constructor_chain_base_read_in_with_not_inlined(self):
        """
        The bare base `s` of `s.constructor.constructor(...)()` inside a `with` body fires the object's
        getter before the chain resolves to `Function`. Inlining discards the base evaluation, so the
        chain is left intact rather than dropping the getter read.
        """
        source = inspect.cleandoc(
            """
            var s = '';
            var o = { get s() {
              return '';
            } };
            with (o) {
              s.constructor.constructor('f()')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_indirect_eval_established_identifier_prefix_outside_with_still_inlined(self):
        self.assertEqual(
            'var e = 1;\nf();',
            self._reflect("var e = 1; (e, eval)('f()');"))

    def test_indirect_eval_unbound_identifier_prefix_is_not_dropped(self):
        source = "(e, eval)('f()');"
        self.assertEqual(source, self._reflect(source))

    def test_settimeout_string(self):
        """
        A string timer is lowered to a deferred function call rather than inlined at the call site: its
        code is deobfuscated but still runs when the timer schedules it, not immediately.
        """
        self.assertEqual(
            'setTimeout(function() {\n  alert(1);\n}, 0);',
            self._reflect("setTimeout('alert(1)', 0);"))

    def test_setinterval_string(self):
        """
        A `setInterval` string is lowered to a deferred function so its repetition is preserved: inlining
        the body would run it once instead of on every interval.
        """
        self.assertEqual(
            'setInterval(function() {\n  doStuff();\n}, 1000);',
            self._reflect("setInterval('doStuff()', 1000);"))

    def test_settimeout_non_string_not_inlined(self):
        self.assertEqual('setTimeout(fn, 0);', self._reflect('setTimeout(fn, 0);'))

    def test_string_timer_this_rewritten_to_global(self):
        """
        A string timer's `this` is the global object, so lowering it to a function rewrites `this` to
        `globalThis` — a plain function's `this` would otherwise depend on how the timer invokes it.
        """
        self.assertEqual(
            'setTimeout(function() {\n  globalThis.foo();\n}, 0);',
            self._reflect("setTimeout('this.foo()', 0);"))

    def test_string_timer_with_shadowed_free_name_not_lowered(self):
        """
        A string timer resolves its free names in the global scope, but the wrapping function resolves
        them at the call site. A local `alert` shadowing the global there would rebind the call, so the
        timer is left as a string.
        """
        self.assertEqual(
            'function f() {\n  var alert = 1;\n  setTimeout("alert(1)", 0);\n}',
            self._reflect('function f(){ var alert = 1; setTimeout("alert(1)", 0); }'))

    def test_string_timer_in_with_body_not_lowered(self):
        """
        A `with` on the path to the timer binds the body's free names dynamically, so lowering could
        resolve them to the `with` object's properties rather than the globals the timer would reach. The
        timer is left as a string.
        """
        self.assertEqual(
            'function f() {\n  with (o) {\n    setTimeout("foo()", 0);\n  }\n}',
            self._reflect('function f(){ with (o) { setTimeout("foo()", 0); } }'))

    def test_module_indirect_eval_declaration_not_inlined(self):
        self.assertEqual(
            "(0, eval)('var x = 1;');",
            self._reflect_module("(0, eval)('var x = 1;');"))

    def test_module_timer_declaration_not_inlined(self):
        self.assertEqual(
            "setTimeout('var x = 1;', 0);",
            self._reflect_module("setTimeout('var x = 1;', 0);"))

    def test_module_direct_eval_declaration_not_inlined(self):
        """
        A module runs strict throughout, so a direct eval in it runs strict, and a strict direct eval's
        `var` lives in a fresh variable environment discarded when the eval returns. Inlining
        `eval('var x = 1;')` to `var x = 1;` would materialize a module binding that never existed, so
        the call is left standing.
        """
        self.assertEqual(
            "eval('var x = 1;');",
            self._reflect_module("eval('var x = 1;');"))

    def test_module_direct_eval_declaration_read_not_inlined(self):
        """
        The read makes the divergence observable: the strict eval's `var x` is ephemeral, so
        `typeof x` is `'undefined'`, whereas the inlined `var x = 1;` would make it `'number'`. The
        call is left standing so the read still reaches nothing.
        """
        source = "eval('var x = 1;');\nconsole.log(typeof x);"
        self.assertEqual(source, self._reflect_module(source))

    def test_module_direct_eval_strict_only_syntax_not_inlined(self):
        """
        A module runs strict throughout, so a direct eval in it parses its text as strict code, where a
        `with` statement, a legacy octal literal, and a `delete` of a bare name are each a SyntaxError
        the eval call throws at runtime. Splicing such a body into the module would make the whole file
        unparseable instead — a throw the eval site caught becoming one the file cannot survive — so the
        call is left standing whichever strict-only form the body takes.
        """
        for body in ('with ({}) { g(); }', '010;', 'delete x;'):
            with self.subTest(body=body):
                source = F"eval('{body}');"
                self.assertEqual(source, self._reflect_module(source))

    def test_module_indirect_eval_expression_still_inlined(self):
        self.assertEqual('foo();', self._reflect_module("(0, eval)('foo();');"))

    def test_module_indirect_eval_binding_await_not_inlined(self):
        """
        `await` names nothing a module binds, so a payload binding it is a `SyntaxError` once spliced
        into the module though the eval runs its text as a script where the binding is legal.
        """
        source = "(0, eval)('console.log(function (await) { return await + 2; }(1));');"
        self.assertEqual(source, self._reflect_module(source))

    def test_indirect_eval_binding_await_inlined_as_a_script(self):
        self.assertEqual(
            'console.log(function(await) {\n  return await + 2;\n}(1));',
            self._reflect("(0, eval)('console.log(function (await) { return await + 2; }(1));');"))

    def test_module_function_constructor_binding_await_not_inlined(self):
        self.assertEqual(
            "var _m = Function('return function (await) { return await; }')();\nsink(_m);",
            self._reflect_module(
                "var _m = Function('return function (await) { return await; }')(); sink(_m);"))

    def test_function_constructor_reading_top_level_var_inlined_in_script_mode(self):
        """
        A `Function`-constructed body is a sloppy global-scope function, so it resolves `out` against
        the global object. Under the script model a top-level `var` is itself a property of that object,
        so inlining `out.push(1)` preserves which binding the read reaches.
        """
        self.assertEqual(
            'var out = [];\nout.push(1);',
            self._reflect("var out = []; new Function('out.push(1)')();"))

    def test_module_function_constructor_reading_top_level_var_not_inlined(self):
        """
        Under the module model a top-level `var` is scoped to the module rather than made a property of
        the global object, so the global-scope `Function` body does not resolve `out` to it. Inlining
        would rebind the read to the module-local declaration, so the call is left intact.
        """
        self.assertEqual(
            "var out = [];\nnew Function('out.push(1)')();",
            self._reflect_module("var out = []; new Function('out.push(1)')();"))

    def test_indirect_eval_declaration_not_inlined_into_function(self):
        """
        Indirect eval runs its code in the global scope, so `var x` binds a global. Inlining it into
        the function body would rebind `x` as a function local, so the call is left intact even in the
        default script model.
        """
        source = inspect.cleandoc(
            """
            function f() {
              (0, eval)('var x = 1;');
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_indirect_eval_block_hoisted_var_not_inlined_into_function(self):
        """
        A `var` inside a nested block of the eval body hoists past the block to the eval's global
        scope, binding a global. Inlining the call into the function would hoist it into the function
        instead, so the call is left intact even in the default script model.
        """
        source = inspect.cleandoc(
            """
            function f() {
              (0, eval)('{ var g = 1; }');
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_indirect_eval_nested_lexical_declaration_still_inlined(self):
        """
        A `let` in a nested block of the eval body is block-scoped and never reaches the global scope,
        so inlining the call into the function preserves its meaning: the block is inlined intact.
        """
        source = "function f() { (0, eval)('{ let g = 1; }'); }"
        expected = inspect.cleandoc(
            """
            function f() {
              {
                let g = 1;
              }
            }
            """
        )
        self.assertEqual(expected, self._reflect(source))

    def test_function_constructor_declaration_inlined_into_function(self):
        """
        A `var` in a `Function` constructor body binds a local of the created function, not a global,
        so inlining it into the enclosing function preserves scope.
        """
        source = "function f() { new Function('var x = 1; sink(x);')(); }"
        expected = inspect.cleandoc(
            """
            function f() {
              var x = 1;
              sink(x);
            }
            """
        )
        self.assertEqual(expected, self._reflect(source))

    def test_member_form_string_timer_lowered(self):
        self.assertEqual(
            'window.setTimeout(function() {\n  alert(1);\n}, 0);',
            self._reflect("window.setTimeout('alert(1)', 0);"))

    def test_member_form_string_interval_lowered(self):
        self.assertEqual(
            'globalThis.setInterval(function() {\n  tick();\n}, 100);',
            self._reflect("globalThis.setInterval('tick()', 100);"))

    def test_execscript_string_inlined_in_place(self):
        self.assertEqual(
            'run();',
            self._reflect("execScript('run()');"))

    def test_execscript_in_expression_position_not_inlined(self):
        self.assertEqual(
            "var x = execScript('run()');",
            self._reflect("var x = execScript('run()');"))

    def test_member_form_function_timer_not_inlined(self):
        self.assertEqual(
            'window.setTimeout(fn, 0);', self._reflect('window.setTimeout(fn, 0);'))

    def test_member_form_string_timer_shadowed_base_not_lowered(self):
        """
        `window` is a local parameter, so `window.setTimeout` is that object's method, not the timer.
        """
        source = inspect.cleandoc(
            """
            function f(window) {
              window.setTimeout("g()", 0);
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_bare_string_timer_shadowed_not_lowered(self):
        source = inspect.cleandoc(
            """
            function f(setTimeout) {
              setTimeout("g()", 0);
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_top_alias_indirect_eval_is_kept(self):
        """
        `top` names another realm's global object in a framed document, so `top.eval` runs its code in
        that realm; inlining it where the fold stands would move the code into this realm, so it is kept.
        """
        source = "top.eval('var x = 1;');"
        self.assertEqual(source, self._reflect(source))

    def test_new_function_body_invoked(self):
        self.assertEqual('42;', self._reflect("new Function('return 42')();"))

    def test_function_constructor_body_invoked(self):
        self.assertEqual('42;', self._reflect("Function('return 42')();"))

    def test_function_constructor_shadowed_not_inlined(self):
        source = inspect.cleandoc(
            """
            function f(Function) {
              return Function("return 1")();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_new_function_shadowed_not_inlined(self):
        source = inspect.cleandoc(
            """
            function f(Function) {
              return new Function("return 1")();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_constructor_chain_string(self):
        self.assertEqual('1;', self._reflect("''.constructor.constructor('return 1')();"))

    def test_constructor_chain_array(self):
        self.assertEqual('1;', self._reflect("[].constructor.constructor('return 1')();"))

    def test_single_constructor_hop_function_literal_returns_this(self):
        """
        A plain function literal's own `.constructor` is `Function`, so a single
        `(function(){}).constructor(code)` hop constructs a function from `code`, like the double hop.
        """
        self.assertEqual(
            'var g = globalThis;',
            self._reflect("var g = (function(){}).constructor('return this')();"))

    def test_single_constructor_hop_arrow_literal_returns_this(self):
        self.assertEqual(
            'var g = globalThis;',
            self._reflect("var g = (() => {}).constructor('return this')();"))

    def test_single_constructor_hop_function_literal_returns_value(self):
        self.assertEqual(
            'var x = 1;', self._reflect("var x = (function(){}).constructor('return 1')();"))

    def test_single_constructor_hop_async_base_not_inlined(self):
        """
        An `async` function literal's `.constructor` is `AsyncFunction`, which builds a coroutine, not
        the plain function `Function` builds, so a single hop from it is not the `Function` idiom.
        """
        source = "var g = (async function() {}).constructor('return this')();"
        self.assertEqual(source, self._reflect(source))

    def test_single_constructor_hop_generator_base_not_inlined(self):
        source = "var g = (function*() {}).constructor('return this')();"
        self.assertEqual(source, self._reflect(source))

    def test_separated_function_constructor_folds_and_retires_temporary(self):
        """
        A `Function` construction bound to a single-use local and then invoked folds like the immediate
        `Function(code)()`, and the temporary — now read nowhere — is dropped.
        """
        self.assertEqual(
            'var g = globalThis;',
            self._reflect("const m = Function('return this'); var g = m();"))

    def test_separated_constructor_chain_folds_and_retires_temporary(self):
        self.assertEqual(
            'var x = 1;',
            self._reflect("const m = (function(){}).constructor('return 1'); var x = m();"))

    def test_a_constructor_alias_off_a_function_name_inlines(self):
        """
        A `.constructor` read off a name the model pins to one plain function hands out the `Function`
        intrinsic, so a call through the alias is a construction and inlines like the named spelling.
        The alias declarator stays: retirement wants a construction initializer, and the folded key
        escaping into the name is a surface the dead sweep keeps.
        """
        self.assertEqual(
            'function d() {}\nvar g = d.constructor;\nvar x = 42;',
            self._reflect('function d() {} var g = d.constructor; var x = g("return 42")();'))

    def test_a_constructor_alias_through_a_resolved_computed_key_inlines(self):
        self.assertEqual(
            "function d() {}\nvar g = d['con' + 'structor'];\nvar x = 42;",
            self._reflect(
                "function d() {} var g = d['con' + 'structor']; var x = g('return 42')();"))

    def test_a_constructor_alias_through_a_name_chain_inlines(self):
        self.assertEqual(
            'function d() {}\nvar g = d.constructor;\nvar h = g;\nvar x = 42;',
            self._reflect(
                'function d() {} var g = d.constructor; var h = g; var x = h("return 42")();'))

    def test_a_construction_held_through_an_alias_folds_and_retires_the_temporary(self):
        self.assertEqual(
            'function d() {}\nvar x = 42;',
            self._reflect("function d() {} var c = d.constructor('return 42'); var x = c();"))

    def test_a_constructor_alias_off_an_async_function_declines(self):
        """
        An `async` function's `.constructor` is `AsyncFunction`, which builds a coroutine rather than
        the plain function `Function` builds — the refusal the literal bases get, applied to a name.
        """
        source = 'async function d() {} var g = d.constructor; var x = g("return 42")();'
        self.assertEqual(
            'async function d() {}\nvar g = d.constructor;\nvar x = g("return 42")();',
            self._reflect(source))

    def test_a_constructor_alias_off_a_generator_function_declines(self):
        source = 'function* d() {} var g = d.constructor; var x = g("return 42")();'
        self.assertEqual(
            'function* d() {}\nvar g = d.constructor;\nvar x = g("return 42")();',
            self._reflect(source))

    def test_a_constructor_alias_read_before_its_base_holds_its_value_declines(self):
        """
        The member read may see the base's temporal-dead-zone value, so the alias is not proven to
        hold the intrinsic when it is called.
        """
        source = 'var g = d.constructor; let d = function () {}; var x = g("return 42")();'
        self.assertEqual(
            'var g = d.constructor;\nlet d = function() {};\nvar x = g("return 42")();',
            self._reflect(source))

    def test_a_constructor_alias_off_a_reassigned_base_declines(self):
        source = 'var d = function () {}; d = function () {}; var g = d.constructor;'
        self.assertEqual(
            'var d = function() {};\nd = function() {};\nvar g = d.constructor;\n'
            'var x = g("return 42")();',
            self._reflect(source + ' var x = g("return 42")();'))

    def test_a_constructor_alias_that_may_hold_another_value_declines(self):
        source = 'var e = function () {}; var g = d.constructor; g = e; var x = g("return 42")();'
        self.assertEqual(
            'var e = function() {};\nvar g = d.constructor;\ng = e;\nvar x = g("return 42")();',
            self._reflect(source))

    def test_a_bare_call_through_a_constructor_alias_is_not_an_invocation(self):
        """
        A call through a name holding the intrinsic constructor *builds* a function and never runs
        it, so nothing is invoked and no route resolves it: the value of the construction is a
        function, not what its body would answer.
        """
        source = "function d() {} var g = d.constructor; var f = g('return 42');"
        self.assertEqual(
            'function d() {}\nvar g = d.constructor;\nvar f = g(\'return 42\');',
            self._reflect(source))

    def test_a_bare_constructor_alias_call_at_statement_position_is_not_run(self):
        source = "function d() {} var g = d.constructor; g('console.log(1)');"
        self.assertEqual(
            'function d() {}\nvar g = d.constructor;\ng(\'console.log(1)\');',
            self._reflect(source))

    def test_a_single_empty_parameter_argument_names_no_parameters(self):
        """
        `Function(" ", code)` builds a zero-parameter function — the parameter text is trimmed before
        the list is parsed — so an empty leading argument binds nothing and the construction inlines
        like the one-argument form.
        """
        self.assertEqual(
            'var x = 42;',
            self._reflect("var x = Function(' ', 'return 42')();"))

    def test_two_empty_parameter_arguments_name_a_comma(self):
        """
        `Function("", "", code)` has parameter text `","`, a `SyntaxError` the construction raises
        itself; the construction stays so the program keeps throwing what it threw.
        """
        source = "var x = Function('', '', 'return 42')();"
        self.assertEqual(source, self._reflect(source))

    def test_a_constructor_alias_with_a_named_parameter_folds_by_evaluation(self):
        """
        The alias names the intrinsic constructor, so the call resolves to a construction whose body
        binds a parameter — the shape the inline route declines and the evaluation route resolves by
        executing the body over the call's argument value.
        """
        self.assertEqual(
            "function d() {}\nvar g = d.constructor;\nvar x = 42;",
            self._reflect("function d() {} var g = d.constructor; var x = g('a', 'return 42')(1);"))

    def test_separated_temporary_with_another_read_is_kept(self):
        """
        The invocation folds, but the temporary keeps its declarator: retirement requires that every
        read of the binding was an invocation this pass inlined, and `use(m)` is a read that was not.
        """
        self.assertEqual(
            "const m = Function('return 1');\nuse(m);\nvar x = 1;",
            self._reflect("const m = Function('return 1'); use(m); var x = m();"))

    def test_separated_temporary_named_in_with_body_is_kept(self):
        """
        A reference inside a `with` body is recorded as a dynamic reference, not a plain read, so the
        count of invocations this pass inlined can equal every plain read while a use still observes
        the binding. The invocation folds, but the declarator must be kept: dropping it would leave
        `use(m)` naming a binding no longer declared.
        """
        self.assertEqual(
            "const m = Function('return 1');\nwith (obj) {\n  use(m);\n}\nvar x = 1;",
            self._reflect("const m = Function('return 1'); with (obj) { use(m); } var x = m();"))

    def test_a_site_naming_an_earlier_splices_declaration_waits_a_pass(self):
        """
        The second eval's body reads `a`, a name the first splice declared, so every pinned answer
        about it is stale and the site defers to the next pass; the fixpoint then completes it.
        """
        source = "eval('var a = 1;'); eval('console.log(a);');"
        self.assertEqual("var a = 1;\neval('console.log(a);');", self._reflect(source))
        self.assertEqual('console.log(1);', self._deobfuscate(source))

    def test_fold_of_a_temporary_a_same_pass_splice_rebinds_is_declined(self):
        self.assertEqual(
            "var m = Function('return 1');\nm = function() {\n  return 2;\n};\nconsole.log(m());",
            self._reflect(
                "var m = Function('return 1');"
                " eval('m = function () { return 2; };');"
                " console.log(m());"))

    def test_separated_temporary_a_lowered_timer_body_names_is_kept(self):
        """
        The lowered timer body names `m`, a read no model taken before the lowering contains, so the
        declarator must survive the same pass that lowered the timer. The shape has no engine witness:
        Node rejects string timer arguments outright.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var m = Function('return 41');
                41;
                setTimeout(function() {
                  console.log(m.name);
                }, 0);
                """
            ),
            self._reflect("var m = Function('return 41'); m(); setTimeout('console.log(m.name)', 0);"))

    def test_separated_temporary_the_analyst_names_an_entrypoint_is_kept(self):
        self.assertEqual(
            "var m = Function('return 41');\nconsole.log(41);",
            self._run_transformer(
                "var m = Function('return 41'); console.log(m());",
                JsReflectionInlining,
                DeobfuscationOptions(entrypoints=('m',))))

    def test_separated_reassigned_temporary_not_inlined(self):
        source = "let m = Function('return 1');\nm = other;\nvar x = m();"
        self.assertEqual(
            source, self._reflect("let m = Function('return 1'); m = other; var x = m();"))

    def test_separated_temporary_binding_parameters_evaluate(self):
        """
        The body binds a parameter, so the inline route declines and the evaluation route executes it
        over the call's argument value, folding the invocation and retiring the temporary.
        """
        self.assertEqual(
            "var x = 1;",
            self._reflect("const m = Function('a','return a'); var x = m(1);"))

    def test_separated_temporary_used_before_established_not_inlined(self):
        """
        The invocation is not folded when the construction is not established before it runs, so the
        constructed function is never read out of its temporal dead zone.
        """
        source = "var x = m();\nconst m = Function('return 1');"
        self.assertEqual(source, self._reflect("var x = m(); const m = Function('return 1');"))

    def test_an_alias_hop_read_before_its_declarator_runs_does_not_fold(self):
        """
        `var a = b;` before `var b = function() {}.constructor;` leaves `a` holding `undefined`,
        so the construction `a('return 1')` throws at runtime and the body it would splice never
        ran. The alias chain has to be ordered hop by hop, not merely resolved.
        """
        source = (
            'var a = b; var b = function() {}.constructor;'
            " var c = a('return 1'); c();"
        )
        self.assertEqual(
            "var a = b;\nvar b = function() {}.constructor;\nvar c = a('return 1');\nc();",
            self._reflect(source))

    def test_a_callee_read_before_its_declarator_runs_does_not_fold(self):
        """
        The construction's own callee is a name read at the construction, so a declarator that has
        not run yet leaves the callee `undefined` and the construction throwing: the recognized
        body is not what the call runs.
        """
        source = "var c = g('return 1'); c(); var g = Function;"
        self.assertEqual(
            "var c = g('return 1');\nc();\nvar g = Function;",
            self._reflect(source))

    def test_payload_clashing_with_the_consumed_temporaries_folds_atomically(self):
        """
        The one-shot wrapper: the payload's injected dead code declares the holder's
        name and reads the construction's name, so the splice preserves meaning only when the two
        declarations it collides with are consumed by the same edit. The invocation is replaced by
        the payload and both temporaries go with it.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                function w() {
                  print(1);
                  var h;
                  f;
                }
                w();
                """
            ),
            self._reflect(inspect.cleandoc(
                """
                function w() {
                  var h = function() {}.constructor;
                  var f = h('print(1); var h; f;');
                  f();
                }
                w();
                """
            )))

    def test_payload_clashing_with_consumed_temporaries_at_script_scope_folds_atomically(self):
        self.assertEqual(
            'print(1);\nvar h;\nf;',
            self._reflect(
                "var h = function() {}.constructor;"
                " var f = h('print(1); var h; f;');"
                ' f();'))

    def test_a_second_read_of_the_holder_refuses_the_atomic_fold(self):
        source = inspect.cleandoc(
            """
            function w() {
              var h = function() {}.constructor;
              var f = h('print(1); var h; f;');
              var g = h('print(2);');
              f();
            }
            w();
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_a_second_read_of_the_construction_refuses_the_atomic_fold(self):
        source = inspect.cleandoc(
            """
            function w() {
              var h = function() {}.constructor;
              var f = h('print(1); var h; f;');
              use(f);
              f();
            }
            w();
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_a_payload_free_name_the_site_function_keeps_refuses_the_atomic_fold(self):
        source = inspect.cleandoc(
            """
            function w() {
              var t = 1;
              var h = function() {}.constructor;
              var f = h('print(t); var h; f;');
              f();
            }
            w();
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_a_payload_free_name_resolving_past_the_temporaries_refuses_the_atomic_fold(self):
        source = inspect.cleandoc(
            """
            function outer() {
              var f = 1;
              function w() {
                var h = function() {}.constructor;
                var f = h('print(f); var h; f;');
                f();
              }
              w();
            }
            outer();
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_a_direct_eval_in_the_owner_function_refuses_the_atomic_fold(self):
        source = inspect.cleandoc(
            """
            function w() {
              var h = function() {}.constructor;
              var f = h('print(1); var h; f;');
              f();
              eval(x);
            }
            w();
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_a_tampered_prototype_chain_refuses_the_atomic_fold(self):
        """
        Deleting the holder drops its `.constructor` read, which is droppable only while the
        prototype chain it consults is intact: a program that has written any key on the chain
        could have installed a getter the read would run.
        """
        source = inspect.cleandoc(
            """
            Object.prototype.q = 1;
            function w() {
              var h = function() {}.constructor;
              var f = h('print(1); var h; f;');
              f();
            }
            w();
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_a_body_redeclaring_an_unused_lexical_name_at_the_site_is_refused(self):
        """
        A `var` the body declares cannot land in a scope that already binds the name lexically:
        the merged output redeclares it, a `SyntaxError` no input spelled. The capture check
        alone cannot see a binding nothing reads.
        """
        source = "let x; var f = Function('var x; print(1);'); f();"
        self.assertEqual(
            "let x;\nvar f = Function('var x; print(1);');\nf();",
            self._reflect(source))


    def test_string_array_revealed_separated_finder_folds_to_globalthis(self):
        """
        A separated `Function` global finder whose code is produced only by the string-array resolver
        folds to `globalThis` under the full pipeline, which requires the reflection pass to run again
        once the resolver reveals the literal argument. The string-array scaffold collapses, but the
        finder temporary must stay declared: the fold hands the global object to `sink`, a callee the
        model cannot resolve, and under the script model the temporary is a property of that object —
        `function sink(o) { console.log(typeof o._m); }` prints `function` for the original and would
        print `undefined` once the declaration is retired.
        """
        self.assertEqual(
            "var _m = Function('return this');\nsink(globalThis);",
            self._deobfuscate(_STRING_ARRAY_REVEALS_A_GLOBAL_FINDER))

    def test_eval_expression_position_single_expr(self):
        self.assertEqual("var x = 'hello';", self._reflect("var x = eval(\"'hello'\");"))

    def test_eval_multi_statement_expression_position_not_inlined(self):
        self.assertEqual(
            "var x = eval('a = 1; b = 2;');",
            self._reflect("var x = eval('a = 1; b = 2;');"),
        )

    def test_new_function_return_expression_position(self):
        self.assertEqual('var x = 42;', self._reflect("var x = new Function('return 42')();"))

    def test_pack_simple_getter(self):
        source = inspect.cleandoc(
            """
            Function("o", "o['a'].log('hello');")(
            { get 'a'() { return console; } });
            """
        )
        self.assertEqual("console.log('hello');", self._reflect(source))

    def test_pack_getter_and_setter(self):
        source = inspect.cleandoc(
            """
            Function("o", "o['a'].log('hello'); o['b'] = 1;")(
            { get 'a'() { return console; },
              set 'b'(v) { return b = v; },
              get 'b'() { return b; } });
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log('hello');
                b = 1;
                """
            ),
            self._reflect(source),
        )

    def test_pack_typeof_getter(self):
        source = inspect.cleandoc(
            """
            Function("o", "o['t'];")(
            { get 't'() { return typeof myVar; } });
            """
        )
        self.assertEqual('typeof myVar;', self._reflect(source))

    def test_pack_proxy_mapping_failure_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                Function('o', 'o.x;')({ get 'a'() {
                  return something();
                } });
                """
            ),
            self._reflect("Function('o', 'o.x;')({ get 'a'() { return something(); } });"),
        )

    def test_pack_compound_assignment_through_proxy_not_inlined(self):
        source = inspect.cleandoc(
            """
            Function('o', "o['b'] += 1;")({ set 'b'(v) {
              return s = v;
            }, get 'b'() {
              return g;
            } });
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_pack_nested_function_own_parameter_name_left_alone(self):
        source = inspect.cleandoc(
            """
            Function('p', 'function g(p) { console.log(p); } g(7); p.out = 1;')(
            { set out(x) { return s = x; }, get out() { return s; } });
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function g(p) {
                  console.log(p);
                }
                g(7);
                s = 1;
                """
            ),
            self._reflect(source),
        )

    def test_pack_getter_target_captured_by_a_body_binding_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 2;
                Function('o', 'var x = 1; o.a;')({ get 'a'() {
                  return x;
                } });
                """
            ),
            self._reflect(
                inspect.cleandoc(
                    """
                    var x = 2;
                    Function('o', 'var x = 1; o.a;')({ get 'a'() { return x; } });
                    """
                )
            ),
        )

    def test_pack_this_receiver_and_substituted_name_still_inlined(self):
        source = inspect.cleandoc(
            """
            Function('o', 'this.f(o.a);')({ get 'a'() { return x; } });
            """
        )
        self.assertEqual('globalThis.f(x);', self._reflect(source))

    def test_module_pack_setter_target_naming_a_module_var_still_inlined(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            Function('p', 'p.out = 2;')(
            { set out(v) { return x = v; }, get out() { return x; } });
            console.log(x);
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 1;
                x = 2;
                console.log(x);
                """
            ),
            self._reflect_module(source),
        )

    def test_eval_multi_statement_inlined_in_statement_position(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = 1;
                var b = 2;
                """
            ),
            self._reflect("eval('var a = 1; var b = 2;');"),
        )

    def test_pack_full_pipeline(self):
        source = inspect.cleandoc(
            """
            Function("o", "o['a'].log('hello');")(
            { get 'a'() { return console; } });
            """
        )
        self.assertEqual("console.log('hello');", self._deobfuscate(source))

    def test_await_eval_single_expression_preserves_await(self):
        source = inspect.cleandoc(
            """
            async function run() {
              await eval("foo()");
            }
            run();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                async function run() {
                  await foo();
                }
                run();
                """
            ),
            self._reflect(source),
        )

    def test_await_eval_multi_statement_not_inlined(self):
        source = inspect.cleandoc(
            """
            async function run() {
              await eval("var a = 1; var b = 2;");
            }
            run();
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_global_eval_await_used_as_identifier_not_misparsed(self):
        self.assertEqual('await(fn);', self._reflect('(0, eval)("await(fn)");'))

    def test_eval_atob(self):
        import base64
        code = base64.b64encode(b'var x = 1;').decode()
        self.assertEqual('var x = 1;', self._reflect(F"eval(atob('{code}'));"))

    def test_new_function_atob_invoked(self):
        import base64
        code = base64.b64encode(b'return 42').decode()
        self.assertEqual('42;', self._reflect(F"new Function(atob('{code}'))();"))

    def test_eval_unescape(self):
        self.assertEqual(
            'var x = 1;',
            self._reflect("eval(unescape('%76%61%72%20%78%20%3d%20%31%3b'));"),
        )

    def test_eval_chained_decode(self):
        import base64
        encoded = base64.b64encode('var x = 1;'.encode()).decode()
        self.assertEqual(
            'var x = 1;',
            self._reflect(F"eval(decodeURIComponent(atob('{encoded}')));"),
        )

    def test_eval_unknown_callee_not_inlined(self):
        self.assertEqual("eval(decode('abc'));", self._reflect("eval(decode('abc'));"))

    def test_constructor_chain_atob(self):
        import base64
        code = base64.b64encode(b'var y = 2;').decode()
        self.assertEqual(
            'var y = 2;',
            self._reflect(F"''.constructor.constructor(atob('{code}'))();"),
        )

    def test_new_function_return_this_becomes_globalthis_expression(self):
        self.assertEqual(
            'var g = globalThis;',
            self._reflect("var g = new Function('return this')();"),
        )

    def test_new_function_return_this_becomes_globalthis_statement(self):
        self.assertEqual('globalThis;', self._reflect("new Function('return this')();"))

    def test_constructor_chain_return_this_becomes_globalthis(self):
        self.assertEqual(
            'var g = globalThis;',
            self._reflect("var g = ''.constructor.constructor('return this')();"),
        )

    def test_function_constructor_with_parameter_folds_by_evaluation(self):
        self.assertEqual(
            '5;',
            self._reflect("new Function('a', 'return a')(5);"),
        )

    def test_function_constructor_this_member_becomes_globalthis(self):
        """
        The constructed function is invoked with no receiver, so its `this` is the global object; a
        member access on it becomes the same access on `globalThis`, which the body then inlines.
        """
        self.assertEqual(
            'globalThis.x;',
            self._reflect("new Function('return this.x')();"),
        )

    def test_function_constructor_multi_statement_this_becomes_globalthis(self):
        """
        Every `this` bound to the constructed function's own receiver becomes `globalThis`, not only a
        single `return this`, so a multi-statement body using `this` inlines.
        """
        self.assertEqual(
            'globalThis.x = 1;\nglobalThis.y = 2;',
            self._reflect("new Function('this.x = 1; this.y = 2;')();"),
        )

    def test_function_constructor_nested_function_this_preserved(self):
        """
        A `this` inside a nested regular function is that function's own receiver, not the constructed
        function's, so it is left intact while the outer body inlines.
        """
        self.assertEqual(
            '(function() {\n  return this;\n});',
            self._reflect("new Function('return function(){ return this; }')();"),
        )

    def test_function_constructor_referencing_arguments_not_inlined(self):
        self.assertEqual(
            "new Function('return arguments[0]')();",
            self._reflect("new Function('return arguments[0]')();"),
        )

    def test_function_constructor_free_name_captured_by_local_not_inlined(self):
        source = inspect.cleandoc(
            """
            function f(x) {
              return new Function('return x')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_free_global_inlined(self):
        self.assertEqual(
            'var pi = Math;',
            self._reflect("var pi = new Function('return Math')();"),
        )

    def test_function_constructor_free_script_var_inlined(self):
        """
        A body's free `out` resolves to the script-level `var out`, which in a global script scope is
        the same global-object property the global-scope constructor body reads, so the fold preserves
        meaning (Node-verified: both leave `out === [1]`).
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var out = [];
                {
                  out.push(1);
                }
                """
            ),
            self._reflect("var out = []; { new Function('out.push(1)')(); }"),
        )

    def test_function_constructor_free_script_let_not_inlined(self):
        """
        A top-level `let` is a lexical binding, not a global-object property, so a global-scope body's
        free `out` would not resolve to it; the inlining is declined.
        """
        source = inspect.cleandoc(
            """
            let out = [];
            {
              new Function('out.push(1)')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_statement_free_name_captured_by_block_local_not_inlined(self):
        source = inspect.cleandoc(
            """
            {
              let foo = function() {};
              new Function('foo()')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_return_this_shadowed_globalthis_not_inlined(self):
        source = inspect.cleandoc(
            """
            {
              let globalThis = {};
              var g = new Function('return this')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_body_var_redeclaring_the_caller_folds_by_evaluation(self):
        """
        The body's `var x` is local to the constructed function — a scope the caller never sees — so
        executing the body answers `undefined` and leaves the caller's `x` untouched. The inline
        route declines: splicing the declaration would redeclare the caller's binding.
        """
        source = inspect.cleandoc(
            """
            var x = 1;
            void 0;
            console.log(x);
            """
        )
        self.assertEqual(source, self._reflect("var x = 1; new Function('var x = 2;')(); console.log(x);"))

    def test_function_constructor_body_function_declaration_folds_by_evaluation(self):
        """
        Same locality as a body `var`: the declared function is the constructed function's own, so the
        caller's `g` still returns 1 after the invocation folds.
        """
        source = inspect.cleandoc(
            """
            function g() {
              return 1;
            }
            void 0;
            g();
            """
        )
        self.assertEqual(source, self._reflect(
            "function g() { return 1; } new Function('function g(){ return 2; }')(); g();"))

    def test_function_constructor_body_lexical_redeclaration_not_inlined(self):
        source = inspect.cleandoc(
            """
            {
              let y = 1;
              new Function('let y = 2; sink(y);')();
              use(y);
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_body_var_a_caller_closure_reads_folds_by_evaluation(self):
        """
        The body's `var x` is the constructed function's own, so the closure the caller returns reads
        the caller's `x` — unbound, exactly as before the fold.
        """
        source = inspect.cleandoc(
            """
            function f() {
              void 0;
              return function() {
                return x;
              };
            }
            """
        )
        self.assertEqual(source, self._reflect(
            "function f() { new Function('var x = 1;')(); return function() { return x; }; }"))

    def test_function_constructor_body_fresh_declarations_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = 1;
                var b = 2;
                combine(a, b);
                """
            ),
            self._reflect("new Function('var a = 1; var b = 2; combine(a, b);')();"),
        )

    def test_function_constructor_body_sibling_local_not_captured_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  var x = 1;
                  sink(x);
                  function g() {
                    var x = 2;
                    return x;
                  }
                  g();
                }
                """
            ),
            self._reflect(
                "function f(){ new Function('var x = 1; sink(x);')();"
                ' function g(){ var x = 2; return x; } g(); }'),
        )

    def test_function_constructor_body_return_does_not_escape_enclosing_function(self):
        """
        A `Function`-constructor body's trailing `return` is discarded at statement position — the
        call's value was already unused — so inlining it into a function body lowers `return x` to a
        bare `x` rather than returning from the enclosing function and stranding the statements after.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  Math;
                  other();
                }
                """
            ),
            self._reflect("function f(){ new Function('return Math')(); other(); }"),
        )

    def test_function_constructor_body_non_trailing_return_not_inlined(self):
        """
        A `return` before the last statement cannot be reproduced at statement position without
        reordering, so the inlining is declined rather than letting the early exit escape the caller.
        """
        source = inspect.cleandoc(
            """
            function f() {
              new Function('a(); return b(); c();')();
              other();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_body_nested_control_flow_return_not_inlined(self):
        """
        A `return` nested in a body's control flow — here inside an `if` — is not a top-level statement,
        so scanning only the statement list would miss it. Splicing the `if` into statement position
        would let the `return` exit the caller (or be a SyntaxError at script level), so the inlining is
        declined.
        """
        source = inspect.cleandoc(
            """
            function f() {
              new Function('if (a) { return b(); } c();')();
              other();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_body_lexical_in_inner_block_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  {
                    let q = 1;
                    sink(q);
                  }
                  use(q);
                }
                """
            ),
            self._reflect("function f(){ { new Function('let q = 1; sink(q);')(); } use(q); }"),
        )

    def test_function_constructor_strict_body_not_inlined(self):
        self.assertEqual(
            "new Function('\"use strict\"; undeclared = 1;')();",
            self._reflect("new Function('\"use strict\"; undeclared = 1;')();"),
        )

    def test_function_constructor_body_var_crossing_a_block_let_folds_by_evaluation(self):
        """
        The body's `var x` stays inside the constructed function, so the block's `let x` is untouched
        by the fold; the inline route declines because splicing the declaration would collide.
        """
        source = inspect.cleandoc(
            """
            {
              let x = 9;
              void 0;
            }
            """
        )
        self.assertEqual(source, self._reflect("{ let x = 9; new Function('var x = 1;')(); }"))

    def test_function_constructor_body_var_crossing_a_for_let_folds_by_evaluation(self):
        source = inspect.cleandoc(
            """
            function f() {
              for (let i = 0; i < 3; i++) {
                void 0;
              }
            }
            """
        )
        self.assertEqual(source, self._reflect(
            "function f() { for (let i = 0; i < 3; i++) { new Function('var i = 99;')(); } }"))

    def test_function_constructor_body_function_decl_crosses_catch_param_not_inlined(self):
        source = inspect.cleandoc(
            """
            function f() {
              try {} catch (g) {
                new Function('function g(){ return 2; } use(g);')();
              }
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_octal_body_folds_to_its_value_in_strict_function(self):
        """
        The constructed body is sloppy however strict its destination is, so its octal literal spells
        eight; the inline route declines — splicing `010` into strict code would spell an early
        error — but the evaluation route answers the value, which no mode changes.
        """
        source = inspect.cleandoc(
            """
            function f() {
              'use strict';
              return 8;
            }
            """
        )
        self.assertEqual(source, self._reflect(
            "function f() { 'use strict'; return new Function('return 010')(); }"))

    def test_function_constructor_octal_body_folds_to_its_value_in_strict_script(self):
        source = "'use strict';\nvar x = 8;"
        self.assertEqual(
            source, self._reflect("'use strict';\nvar x = new Function('return 010')();"))

    def test_function_constructor_pure_body_inlined_in_strict_function(self):
        """
        A body that behaves identically under strict mode — a pure `return 1 + 1` — inlines into a
        strict function.
        """
        source = inspect.cleandoc(
            """
            function f() {
              'use strict';
              return new Function('return 1 + 1')();
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  'use strict';
                  return 1 + 1;
                }
                """
            ),
            self._reflect(source))

    def test_function_constructor_reads_inlined_in_strict_script(self):
        """
        A read-only body inlines into a strict script: reading a free name throws in both modes, so the
        body cannot diverge under strict mode.
        """
        source = inspect.cleandoc(
            """
            'use strict';
            var x = new Function('return a.b.c')();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                'use strict';
                var x = a.b.c;
                """
            ),
            self._reflect(source))

    def test_function_constructor_free_write_not_inlined_in_strict_context(self):
        source = inspect.cleandoc(
            """
            function f() {
              'use strict';
              new Function('x = 1')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_member_write_not_inlined_in_strict_context(self):
        source = inspect.cleandoc(
            """
            function f() {
              'use strict';
              new Function('o.p = 1')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_block_function_not_inlined_in_strict_context(self):
        source = inspect.cleandoc(
            """
            function f() {
              'use strict';
              new Function('if (1) { function g() {} }')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_direct_eval_not_inlined_in_strict_context(self):
        source = inspect.cleandoc(
            """
            function f() {
              'use strict';
              new Function('eval("var x = 1")')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_mapped_arguments_not_inlined_in_strict_context(self):
        source = inspect.cleandoc(
            """
            function f() {
              'use strict';
              return new Function('return function (a) { arguments[0] = 9; return a; }')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_pure_body_inlined_in_class_method(self):
        """
        A class body is always strict, so the gate applies inside a method; a non-diverging body still
        inlines there.
        """
        source = inspect.cleandoc(
            """
            class C {
              m() {
                return new Function('return 1 + 1')();
              }
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                class C {
                  m() {
                    return 1 + 1;
                  }
                }
                """
            ),
            self._reflect(source))

    def test_function_constructor_diverging_body_not_inlined_in_class_method(self):
        source = inspect.cleandoc(
            """
            class C {
              m() {
                return new Function('x = 1')();
              }
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_body_new_target_not_inlined(self):
        source = inspect.cleandoc(
            """
            function f() {
              return new Function('return new.target')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))


#: A payload spelling an early error in a function's signature: a name repeated in a list the
#: grammar requires to be unique, an accessor written with the wrong number of parameters, a Use
#: Strict Directive under a parameter list that may hold none, a name repeated in a list that is not
#: simple, a word the kind of function reserves in its parameter list, and the same word naming a
#: function expression, whose name is bound inside it and read under its own kind. Node reads none
#: of them, under either mode.
A_PAYLOAD_NO_ENGINE_READS = [
    '((a, a) => 0);',
    '({ m(a, a) {} });',
    '({ get g(a) {} });',
    '({ set s() {} });',
    "(function (a = 1) { 'use strict'; });",
    '(function (a, ...a) {});',
    '(function* (yield) {});',
    '(async function (await) {});',
    '(function* yield() {});',
    '(async function await() {});',
]

#: The same signatures written the way the language permits, one for each rule above but the
#: directive, whose control declares a mode and is therefore declined for a reason of its own. The
#: last three name a function expression with a word some other kind reserves, which its own kind
#: does not. Each is spelled the way the printer spells it, so the text a site is replaced by is the
#: payload itself.
A_PAYLOAD_EVERY_ENGINE_READS = [
    '((a, b) => 0);',
    '({ m(a, b) {} });',
    '({ get g() {} });',
    '({ set s(v) {} });',
    '(function(a, ...b) {});',
    '(function*(a) {});',
    '(async function(a) {});',
    '(function yield() {});',
    '(async function yield() {});',
    '(function* await() {});',
]

#: A surface that takes a payload as a string and evaluates it, as the template writing one there.
#: All four run the payload in a scope of their own and hand a `SyntaxError` back to the call site.
A_SURFACE_THAT_EVALUATES_A_STRING = {
    'indirect eval'            : '(0, eval)({code});',
    'direct eval'              : 'eval({code});',
    'the Function constructor' : 'Function({code})();',
    'a constructed Function'   : 'new Function({code})();',
}

#: The pack shape, whose payload reaches the proxy object beside it through a getter or a setter,
#: mapped to the text `refinery.js` writes for it. Two of these payloads hold an early error, so
#: those two calls are left standing; the other two differ from them in a single character and are
#: unpacked as before.
A_PACK_WHOSE_PAYLOAD_IS_READ_OR_REFUSED = {
    'Function("p", "((a, a) => p.k);")({ get k() {\n  return x;\n} });':
        'Function("p", "((a, a) => p.k);")({ get k() {\n  return x;\n} });',
    'Function("p", "((a, b) => p.k);")({ get k() {\n  return x;\n} });':
        '((a, b) => x);',
    'Function("p", "p.k = ((a, a) => 0);")({ set k(v) {\n  x = v;\n} });':
        'Function("p", "p.k = ((a, a) => 0);")({ set k(v) {\n  x = v;\n} });',
    'Function("p", "p.k = ((a, b) => 0);")({ set k(v) {\n  x = v;\n} });':
        'x = ((a, b) => 0);',
}


def _a_site_evaluating(template: str, payload: str) -> str:
    return template.format(code=json.dumps(payload))


def _a_program_catching_what_each_payload_throws(template: str) -> str:
    """
    A program that evaluates every payload of `A_PAYLOAD_NO_ENGINE_READS` through *template*, each
    inside a `try` that names what came out of it, and reports that it reached the end.

    That last line is the whole point of the shape. A payload the language refuses is a
    `SyntaxError` the call site catches, and the program runs on; written into the file instead, it
    is the file that no longer parses, and nothing runs at all.
    """
    attempts = [
        F'try {{ {_a_site_evaluating(template, payload)} console.log(1); }}'
        F' catch (e) {{ console.log(e.constructor.name); }}'
        for payload in A_PAYLOAD_NO_ENGINE_READS
    ]
    return '\n'.join([*attempts, "console.log('done');"]) + '\n'


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichPayloadsTheEngineReads(TestJsDeobfuscator):

    def _refused(self, payloads: list[str]) -> dict[str, bool]:
        values = completion_values(payloads, JsEvaluation.SCRIPT)
        return {
            payload: value == NOT_A_PROGRAM
            for payload, value in zip(payloads, values)
        }

    def test_node_refuses_every_payload_recorded_as_unreadable(self):
        rows = A_PAYLOAD_NO_ENGINE_READS
        self.assertEqual(self._refused(rows), {payload: True for payload in rows})

    def test_node_reads_every_payload_recorded_as_readable(self):
        rows = A_PAYLOAD_EVERY_ENGINE_READS
        self.assertEqual(self._refused(rows), {payload: False for payload in rows})


class TestAPayloadTheLanguageRefusesIsNotInlined(TestJsDeobfuscator):
    """
    A payload that holds an early error is a `SyntaxError` wherever it is read, and where it is read
    decides everything about what that costs. Evaluated, it throws at the one call site, which a
    program is free to catch and go on from. Spliced into the file, it is the file that no engine
    reads, and every statement in it is lost along with the payload.

    The rules at stake hold in either mode, so no destination has to be consulted to see them, and
    a payload the language does read is inlined exactly as before.
    """

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def test_no_surface_inlines_a_payload_no_engine_reads(self):
        for surface, template in A_SURFACE_THAT_EVALUATES_A_STRING.items():
            sources = [
                _a_site_evaluating(template, payload)
                for payload in A_PAYLOAD_NO_ENGINE_READS
            ]
            with self.subTest(surface=surface):
                self.assertEqual(
                    {source: self._reflect(source) for source in sources},
                    {source: source for source in sources},
                )

    def test_every_surface_inlines_a_payload_every_engine_reads(self):
        for surface, template in A_SURFACE_THAT_EVALUATES_A_STRING.items():
            rows = {
                _a_site_evaluating(template, payload): payload
                for payload in A_PAYLOAD_EVERY_ENGINE_READS
            }
            with self.subTest(surface=surface):
                self.assertEqual({s: self._reflect(s) for s in rows}, dict(rows))

    def test_the_pack_shape_answers_each_payload_the_way_the_corpus_records(self):
        rows = A_PACK_WHOSE_PAYLOAD_IS_READ_OR_REFUSED
        self.assertEqual({source: self._reflect(source) for source in rows}, dict(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAProgramThatCatchesASyntaxErrorStillCatchesOne(TestJsDeobfuscator):

    def _programs(self) -> list[str]:
        return [
            _a_program_catching_what_each_payload_throws(template)
            for template in A_SURFACE_THAT_EVALUATES_A_STRING.values()
        ]

    def test_node_names_a_syntax_error_for_every_payload_and_reaches_the_end(self):
        caught = 'SyntaxError\n' * len(A_PAYLOAD_NO_ENGINE_READS) + 'done\n'
        sources = self._programs()
        self.assertEqual(
            {source: behavior(source) for source in sources},
            {source: (caught, None) for source in sources},
        )

    def test_the_deobfuscation_of_each_program_does_the_same(self):
        caught = 'SyntaxError\n' * len(A_PAYLOAD_NO_ENGINE_READS) + 'done\n'
        sources = self._programs()
        self.assertEqual(
            {source: behavior(deobfuscate_source(source)) for source in sources},
            {source: (caught, None) for source in sources},
        )


#: A payload spelling syntax only module code may hold: an `import` declaration, an `export`
#: declaration of each shape, and `import.meta`. Every surface above evaluates its text as a Script,
#: where each of these is a `SyntaxError` the call site catches. Node reads none of them.
A_PAYLOAD_ONLY_MODULE_CODE_MAY_HOLD = [
    'export var q = 1;',
    'export default 1;',
    "export * from 'fs';",
    "import * as m from 'fs';",
    'import.meta;',
]


def _a_program_naming_what_one_payload_throws(template: str, payload: str) -> str:
    """
    A program that evaluates *payload* through *template* inside a `try` that names what came out of
    it. The payload is a `SyntaxError` the call site catches and the program names; written into the
    file instead, it is the file that no longer parses and nothing is named at all.
    """
    return (
        F'try {{ {_a_site_evaluating(template, payload)} }}'
        F' catch (e) {{ console.log(e.name); }}'
    )


class TestAPayloadOnlyModuleCodeMayHoldIsNotInlined(TestJsDeobfuscator):
    """
    Every surface that takes a payload as a string evaluates it as a Script, so an `import` or
    `export` declaration in one is a `SyntaxError` the call site throws whatever the file around it
    is. Spliced into that file it is a declaration the program never made, and one the file cannot
    even be read with; and where the host does load the file as a module, it is a declaration the
    program never made.

    No mode decides any of it, which is why the refusal costs nothing: the call is left standing to
    throw exactly what it threw before.
    """

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def test_no_surface_inlines_a_payload_only_module_code_may_hold(self):
        for surface, template in A_SURFACE_THAT_EVALUATES_A_STRING.items():
            sources = [
                _a_site_evaluating(template, payload)
                for payload in A_PAYLOAD_ONLY_MODULE_CODE_MAY_HOLD
            ]
            with self.subTest(surface=surface):
                self.assertEqual(
                    {source: self._reflect(source) for source in sources},
                    {source: source for source in sources},
                )

    def test_a_string_timer_does_not_inline_one_either(self):
        sources = [
            F'setTimeout({json.dumps(payload)}, 0);'
            for payload in A_PAYLOAD_ONLY_MODULE_CODE_MAY_HOLD
        ]
        self.assertEqual(
            {source: self._reflect(source) for source in sources},
            {source: source for source in sources},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAProgramCatchingAModulePayloadStillCatchesIt(TestJsDeobfuscator):
    """
    The string timer is not among the surfaces asked here: Node's timers refuse a string argument
    outright, so the engine cannot be asked what a payload evaluated through one does.
    """

    def _programs(self) -> list[str]:
        return [
            _a_program_naming_what_one_payload_throws(template, payload)
            for template in A_SURFACE_THAT_EVALUATES_A_STRING.values()
            for payload in A_PAYLOAD_ONLY_MODULE_CODE_MAY_HOLD
        ]

    def test_node_names_a_syntax_error_for_every_one_of_them(self):
        sources = self._programs()
        self.assertEqual(
            {source: behavior(source) for source in sources},
            {source: ('SyntaxError\n', None) for source in sources},
        )

    def test_the_deobfuscation_of_each_program_names_the_same_error(self):
        sources = self._programs()
        self.assertEqual(
            {source: behavior(deobfuscate_source(source)) for source in sources},
            {source: ('SyntaxError\n', None) for source in sources},
        )


#: An indirect eval whose payload binds `await`, which a script binds freely and a module refuses
#: everywhere its goal symbol reaches. The eval runs its text as a script wherever it stood, so the
#: binding is legal there; the payload returns 3.
_A_PAYLOAD_BINDING_AWAIT = "(0, eval)('console.log(function (await) { return await + 2; }(1));');"


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPayloadBindingAwaitStaysBehindTheEvalInAModule(TestJsDeobfuscator):
    """
    Unlike a payload spelling `import` or `export`, one binding `await` is a program a script reads:
    the word is module-reserved and not strict-reserved. Splicing it into a module is a `SyntaxError`
    the file cannot survive, where the eval it replaces threw one the call site caught, so the gate
    refuses the splice at a module destination and leaves the eval standing. At a script destination
    the same payload inlines, and the program behaves the same across the rewrite either way.
    """

    def test_a_module_keeps_printing_what_the_eval_printed(self):
        source = 'export {};\n' + _A_PAYLOAD_BINDING_AWAIT
        self.assertEqual(
            (
                behavior(source, module=True),
                behavior(deobfuscate_source(source, module=True), module=True),
            ),
            (('3\n', None), ('3\n', None)),
        )

    def test_the_script_twin_inlines_and_prints_the_same(self):
        self.assertEqual(
            (
                behavior(_A_PAYLOAD_BINDING_AWAIT),
                behavior(deobfuscate_source(_A_PAYLOAD_BINDING_AWAIT)),
            ),
            (('3\n', None), ('3\n', None)),
        )


class APayloadCutShort(NamedTuple):
    """
    A payload that stops where the language still requires something, together with the text that
    would have finished it and what the finished payload prints. `cut` is what a call site is
    handed and `whole` is the payload the cut was taken from, so the text the cut took is the whole
    of the difference between the two.
    """
    opened: str
    closing: str
    prints: str

    @property
    def cut(self) -> str:
        return self.opened

    @property
    def whole(self) -> str:
        return F'{self.opened}{self.closing}'


#: A payload that stops in the middle of a construct, keyed by the construct it stops inside of. A
#: string carved out of a buffer or assembled from a source that was itself truncated ends this
#: way. Node refuses every `cut` below and reads every `whole`, and each `whole` is spelled the way
#: the printer spells it, so the text a site is replaced by is the finished payload itself.
A_PAYLOAD_CUT_SHORT = {
    'an argument list': APayloadCutShort(
        'console.log(1, 2', ');', '1 2\n'),
    'a nested argument list': APayloadCutShort(
        'console.log(Math.max(1, 2), 3', ');', '2 3\n'),
    'a parenthesized operand': APayloadCutShort(
        'console.log((1 + 2', ') * 3);', '9\n'),
    'a catch clause': APayloadCutShort(
        'try {\n  console.log(1);\n} catch', ' (e) {}', '1\n'),
    'a catch body': APayloadCutShort(
        'try {\n  console.log(1);\n} catch (e) {\n  console.log(2);', '\n}', '1\n'),
    'an object literal': APayloadCutShort(
        'console.log({ a: 1, b: 2', ' });', '{ a: 1, b: 2 }\n'),
    'an object property value': APayloadCutShort(
        'console.log({ a: [1, 2], b:', ' 3 });', '{ a: [ 1, 2 ], b: 3 }\n'),
    'an array literal': APayloadCutShort(
        'console.log([1, 2', ']);', '[ 1, 2 ]\n'),
    'a function body': APayloadCutShort(
        '(function() {\n  console.log(1);', '\n})();', '1\n'),
    'a parameter list': APayloadCutShort(
        '(function(a, b', ') {\n  console.log(a + b);\n})(1, 2);', '3\n'),
    'an arrow body': APayloadCutShort(
        '(() => {\n  console.log(1);', '\n})();', '1\n'),
    'a template literal': APayloadCutShort(
        'console.log(`a${1}b', '`);', 'a1b\n'),
    'a block statement': APayloadCutShort(
        'if (1) {\n  console.log(1);', '\n}', '1\n'),
    'a switch body': APayloadCutShort(
        'switch (1) {\n  case 1:\n    console.log(1);', '\n}', '1\n'),
    'a statement following a complete one': APayloadCutShort(
        'console.log(1);\nconsole.log(2', ');', '1\n2\n'),
}


def _a_program_reporting_what_each_payload_did(template: str, payloads: list[str]) -> str:
    """
    A program that evaluates every payload of *payloads* through *template*, each inside a `try`
    that reports either what came out of it or that the site was reached, and reports that it got
    to the end.

    That last line is the whole point of the shape. A payload the engine refuses is a `SyntaxError`
    the call site catches, and the program runs on; written into the file instead, it is the file
    that no longer parses, and nothing runs at all.
    """
    attempts = [
        F'try {{ {_a_site_evaluating(template, payload)} console.log("read"); }}'
        F' catch (e) {{ console.log(e.name); }}'
        for payload in payloads
    ]
    return '\n'.join([*attempts, "console.log('done');"]) + '\n'


class TestAPayloadCutShortIsNotInlined(TestJsDeobfuscator):
    """
    A payload that stops in the middle of a construct is a program no engine reads, and where it is
    read decides what that costs. Evaluated, it is a `SyntaxError` at the one call site, which the
    program around it is free to catch and go on from. Spliced into the file, the tokens the
    payload stops before have to be written by whoever reads it, and the file then holds a program
    the payload never spelled.

    Writing the text each cut took turns the same payload into one every engine reads, and that one
    is inlined exactly as before.
    """

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def test_no_surface_inlines_a_payload_cut_short(self):
        for surface, template in A_SURFACE_THAT_EVALUATES_A_STRING.items():
            sources = [
                _a_site_evaluating(template, row.cut)
                for row in A_PAYLOAD_CUT_SHORT.values()
            ]
            with self.subTest(surface=surface):
                self.assertEqual(
                    {source: self._reflect(source) for source in sources},
                    {source: source for source in sources},
                )

    def test_a_string_timer_does_not_lower_one_either(self):
        sources = [
            F'setTimeout({json.dumps(row.cut)}, 0);'
            for row in A_PAYLOAD_CUT_SHORT.values()
        ]
        self.assertEqual(
            {source: self._reflect(source) for source in sources},
            {source: source for source in sources},
        )

    def test_every_surface_inlines_the_payload_each_cut_was_taken_from(self):
        for surface, template in A_SURFACE_THAT_EVALUATES_A_STRING.items():
            rows = {
                _a_site_evaluating(template, row.whole): row.whole
                for row in A_PAYLOAD_CUT_SHORT.values()
            }
            with self.subTest(surface=surface):
                self.assertEqual({s: self._reflect(s) for s in rows}, dict(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAProgramAroundAPayloadCutShortRunsOn(TestJsDeobfuscator):

    def _programs(self, payloads: list[str]) -> list[str]:
        return [
            _a_program_reporting_what_each_payload_did(template, payloads)
            for template in A_SURFACE_THAT_EVALUATES_A_STRING.values()
        ]

    def test_node_catches_a_syntax_error_at_every_cut_site_and_reaches_the_end(self):
        rows = A_PAYLOAD_CUT_SHORT.values()
        caught = 'SyntaxError\n' * len(rows) + 'done\n'
        sources = self._programs([row.cut for row in rows])
        self.assertEqual(
            {source: behavior(source) for source in sources},
            {source: (caught, None) for source in sources},
        )

    def test_the_deobfuscation_of_each_program_catches_the_same_and_reaches_the_end(self):
        rows = A_PAYLOAD_CUT_SHORT.values()
        caught = 'SyntaxError\n' * len(rows) + 'done\n'
        sources = self._programs([row.cut for row in rows])
        self.assertEqual(
            {source: behavior(deobfuscate_source(source)) for source in sources},
            {source: (caught, None) for source in sources},
        )

    def test_node_prints_what_every_payload_a_cut_was_taken_from_holds(self):
        rows = A_PAYLOAD_CUT_SHORT.values()
        printed = ''.join(F'{row.prints}read\n' for row in rows) + 'done\n'
        sources = self._programs([row.whole for row in rows])
        self.assertEqual(
            {source: behavior(source) for source in sources},
            {source: (printed, None) for source in sources},
        )

    def test_the_deobfuscation_of_each_program_prints_the_same(self):
        rows = A_PAYLOAD_CUT_SHORT.values()
        printed = ''.join(F'{row.prints}read\n' for row in rows) + 'done\n'
        sources = self._programs([row.whole for row in rows])
        self.assertEqual(
            {source: behavior(deobfuscate_source(source)) for source in sources},
            {source: (printed, None) for source in sources},
        )


#: Programs that locate the global object through a `Function` construction — a single-`.constructor`
#: hop on a function literal, and a construction bound to a temporary and then invoked — and print
#: through it. Each is folded by the changes under test; Node runs the original and the deobfuscation
#: to confirm the fold preserves what the program does.
_A_GLOBAL_FINDER_THAT_PRINTS = {
    'single hop function literal':
        "var g = (function(){}).constructor('return this')(); g.console.log('finder-ok');",
    'single hop arrow literal':
        "var g = (() => {}).constructor('return this')(); g.console.log('finder-ok');",
    'separated function constructor':
        "var m = Function('return this'); var g = m(); g.console.log('finder-ok');",
    'separated constructor chain':
        "var m = (function(){}).constructor('return this'); var g = m(); g.console.log('finder-ok');",
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestGlobalFinderFoldPreservesBehavior(TestJsDeobfuscator):

    def test_node_prints_the_same_before_and_after_deobfuscation(self):
        sources = list(_A_GLOBAL_FINDER_THAT_PRINTS.values())
        self.assertEqual(
            {source: behavior(source) for source in sources},
            {source: behavior(deobfuscate_source(source)) for source in sources},
        )

    def test_each_finder_reaches_the_global_object(self):
        sources = list(_A_GLOBAL_FINDER_THAT_PRINTS.values())
        self.assertEqual(
            {source: behavior(source) for source in sources},
            {source: ('finder-ok\n', None) for source in sources},
        )


#: Programs with a reflective site whose splice must be declined, each mapped to the behavior an
#: engine gives the original. The first three are `Function`-constructor packs whose body, once
#: substituted, would resolve a name differently at the call site than the constructed function
#: does: a packed `var` a site read would bind to, a packed free name a site parameter shadows, and
#: a setter assigning its own parameter, which names nothing outside the setter.
A_REFLECTIVE_SPLICE_THE_SITE_WOULD_REBIND = {
    'a packed var the site reads': Program(
        a_program("""
            var r = 'outer';
            function f() {
              Function('p', 'var v = 1; p.out = v;')({
                get out() { return r; },
                set out(x) { r = x; }
              });
              return v;
            }
            f();
            console.log(r);
            """),
        ('', 'ReferenceError'),
    ),
    'a packed free name a site parameter shadows': Program(
        a_program("""
            var q = 'global';
            var r = 0;
            function f(q) {
              Function('p', 'p.out = q;')({
                get out() { return r; },
                set out(x) { r = x; }
              });
              return r;
            }
            console.log(f('local'));
            """),
        prints('global'),
        Reading.SCRIPT,
    ),
    'a setter assigning its own parameter': Program(
        a_program("""
            Function('p', 'p.out = 1;')({
              set out(x) { return x = x; },
              get out() { return g; }
            });
            console.log(typeof x);
            """),
        prints('undefined'),
    ),
    'a bare use of the proxy parameter': Program(
        a_program("""
            Function('p', 'console.log(typeof p); p.out = 1;')({
              set out(x) { return s = x; },
              get out() { return s; }
            });
            """),
        prints('object'),
    ),
    'a packed var capturing a setter target': Program(
        a_program("""
            var r = 0;
            function f() {
              Function('p', 'var r = 9; p.out = 5;')({
                set out(x) { return r = x; },
                get out() { return r; }
              });
            }
            f();
            console.log(r);
            """),
        prints('5'),
    ),
    'a packed var aliasing the proxy parameter': Program(
        a_program("""
            var r = 5;
            Function('p', 'var p = 0; p.out = 1;')({
              set out(x) { return r = x; },
              get out() { return r; }
            });
            console.log(r);
            """),
        prints('5'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReflectiveSpliceTheSiteWouldRebindIsDeclined(TestBase):

    def test_every_program_behaves_the_way_the_engine_does(self):
        for label, row in A_REFLECTIVE_SPLICE_THE_SITE_WOULD_REBIND.items():
            with self.subTest(label):
                self.assertEqual(row.read(), row.required())


#: Programs in which something still names the single-use `Function`-constructor temporary the pass
#: is consuming — a same-pass eval splice reading or rebinding it, an eval the pass declines, the
#: global object a folded finder hands away, or the construction argument's own effect — mapped to
#: the behavior an engine gives them: the name keeps answering, so the declaration must survive and
#: no fold may read the value a spliced rebind replaced.
A_CONSUMED_TEMPORARY_SOMETHING_STILL_NAMES = {
    'an eval splice rebinds it before the read': Program(
        a_program("""
            var m = Function('return 1');
            eval('m = function () { return 2; };');
            console.log(m());
            """),
        prints('2'),
    ),
    'an eval splice reads it in expression position': Program(
        a_program("""
            const m = Function('return 41');
            console.log(m());
            eval('console.log(m.name)');
            """),
        prints('41', 'anonymous'),
    ),
    'an eval splice reads it in statement position': Program(
        a_program("""
            var m = Function('return 41');
            m();
            eval('console.log(m.name);');
            """),
        prints('anonymous'),
    ),
    'a declined direct eval reads it': Program(
        a_program("""
            var m = Function('return 41');
            console.log(m());
            function run(src) { eval(src); }
            run('console.log(typeof m);');
            """),
        prints('41', 'function'),
    ),
    'a declined indirect eval reads it': Program(
        a_program("""
            var m = Function('return 41');
            console.log(m());
            function run(src) { (0, eval)(src); }
            run('console.log(typeof m);');
            """),
        prints('41', 'function'),
        Reading.SCRIPT,
    ),
    'the handed-away global reads it as a property': Program(
        a_program("""
            function sink(o) { console.log(typeof o._m); }
            var _m = Function('return this');
            sink(_m());
            """),
        prints('function'),
        Reading.SCRIPT,
    ),
    'the construction argument writes what the program reads': Program(
        a_program("""
            var seen = 0;
            var m = Function((seen = 1, 'return 41'));
            console.log(m());
            console.log(seen);
            """),
        prints('41', '1'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAConsumedTemporaryStillNamedKeepsItsDeclaration(TestBase):

    def test_every_program_behaves_the_way_the_engine_does(self):
        for label, row in A_CONSUMED_TEMPORARY_SOMETHING_STILL_NAMES.items():
            with self.subTest(label):
                self.assertEqual(row.read(), row.required())


class TestAStatementSpliceMovesTheTreeVersion(TestBase):
    """
    The statement inliner splices the resolved statements into the container's body in place. The
    version counter every model cache reads has to move with that splice: a cache whose pin read no
    change on exit keeps the models built before the splice, and those describe a program in which
    the spliced statements do not exist.
    """

    def test_inlining_a_statement_position_eval_advances_the_counter(self):
        script = JsParser("eval('var v = 1;'); SINK(v);").parse()
        before = tree_version(script)
        JsReflectionInlining().visit(script)
        self.assertEqual('var v = 1;\nSINK(v);', JsSynthesizer().convert(script))
        self.assertGreater(tree_version(script), before)

    def test_inlining_a_statement_position_execscript_advances_the_counter(self):
        script = JsParser("execScript('var v = 1;'); SINK(v);").parse()
        before = tree_version(script)
        JsReflectionInlining().visit(script)
        self.assertEqual('var v = 1;\nSINK(v);', JsSynthesizer().convert(script))
        self.assertGreater(tree_version(script), before)


class TestAPayloadIsWeighedAgainstTheContextOfItsSite(TestJsDeobfuscator):
    """
    A payload is read as a script, where `await`, `yield` and `arguments` are names, and is spliced
    into a site that may read them otherwise: a static block or a static initializer refuses `await`
    in every position, a field initializer refuses a reference to `arguments` through any arrow, an
    `async` body reads `await` as the operator and a generator's body `yield`. Node refuses every
    file the splice would write, so the call is left standing to do what it did; the same payload
    at a site reading the words as a script does is inlined.
    """

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def test_a_static_initializer_refuses_an_await_operator_payload(self):
        source = 'async function f() { class C { static p = eval("await 1;"); } }'
        self.assertEqual(
            inspect.cleandoc(
                """
                async function f() {
                  class C {
                    static p = eval("await 1;");
                  }
                }
                """
            ),
            self._reflect(source),
        )

    def test_a_static_initializer_refuses_arguments(self):
        source = 'function g() { class C { static p = eval("arguments"); } }'
        self.assertEqual(
            inspect.cleandoc(
                """
                function g() {
                  class C {
                    static p = eval("arguments");
                  }
                }
                """
            ),
            self._reflect(source),
        )

    def test_an_instance_initializer_refuses_arguments(self):
        self.assertEqual(
            'class C {\n  p = eval("arguments");\n}',
            self._reflect('class C { p = eval("arguments"); }'),
        )

    def test_an_initializer_refuses_arguments_through_an_arrow(self):
        source = 'function f() { class C { p = () => eval("arguments"); } }'
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  class C {
                    p = () => eval("arguments");
                  }
                }
                """
            ),
            self._reflect(source),
        )

    def test_a_static_block_refuses_a_binding_named_await(self):
        source = 'class C { static { eval("var await = 1;"); } }'
        self.assertEqual(
            inspect.cleandoc(
                """
                class C {
                  static {
                    eval("var await = 1;");
                  }
                }
                """
            ),
            self._reflect(source),
        )

    def test_a_generator_body_refuses_yield_as_a_name(self):
        self.assertEqual(
            'function* g() {\n  (0, eval)("typeof yield");\n}',
            self._reflect('function* g() { (0, eval)("typeof yield"); }'),
        )

    def test_a_generator_body_refuses_yield_as_a_name_from_a_function_body(self):
        source = 'function* g() { var h = Function("return typeof yield"); console.log(h()); }'
        self.assertEqual(
            inspect.cleandoc(
                """
                function* g() {
                  var h = Function("return typeof yield");
                  console.log(h());
                }
                """
            ),
            self._reflect(source),
        )

    def test_an_async_body_refuses_await_as_a_name_from_a_function_body(self):
        source = (
            'async function f() { var g = Function("return typeof await"); console.log(g()); } f();'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                async function f() {
                  var g = Function("return typeof await");
                  console.log(g());
                }
                f();
                """
            ),
            self._reflect(source),
        )

    def test_a_site_reading_the_words_as_a_script_does_takes_the_same_payloads(self):
        rows = {
            'class C { static { console.log(eval("1 + 1")); } }':
                'class C {\n  static {\n    console.log(1 + 1);\n  }\n}',
            'class C { p = eval("1 + 1"); }':
                'class C {\n  p = 1 + 1;\n}',
            'function g() { class C { m() { return eval("arguments"); } } }':
                'function g() {\n  class C {\n    m() {\n      return arguments;\n    }\n  }\n}',
            'function* g() { (0, eval)("typeof x"); }':
                'function* g() {\n  typeof x;\n}',
            'function g() { var h = Function("return typeof yield"); console.log(h()); }':
                'function g() {\n  console.log(typeof yield);\n}',
            'function f() { var g = Function("return typeof await"); console.log(g()); } f();':
                'function f() {\n  console.log(typeof await);\n}\nf();',
            'async function f() { var g = Function("return typeof x"); console.log(g()); } f();':
                'async function f() {\n  console.log(typeof x);\n}\nf();',
        }
        self.assertEqual({source: self._reflect(source) for source in rows}, rows)


class TestAFileSpellingModuleSyntaxIsAModuleDestination(TestJsDeobfuscator):
    """
    A file with an `import` or `export` in it is module code whatever the options say, so a payload
    a module refuses — one binding `await` — is left standing at both surfaces under the script
    model too, where the same payload in a file spelling no module syntax is inlined. A payload the
    module reads is still inlined there.
    """

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def test_an_indirect_eval_binding_await_is_left_standing_beside_an_export(self):
        source = (
            'export const tag = 1;\n'
            '(0, eval)("console.log(function (await) { return await + 2; }(1));");'
        )
        self.assertEqual(source, self._reflect(source))

    def test_a_function_body_binding_await_is_left_standing_beside_an_export(self):
        source = (
            'export const tag = 1;\n'
            "var _m = Function('return function (await) { return await; }')();\n"
            'sink(_m);'
        )
        self.assertEqual(source, self._reflect(source))

    def test_the_same_function_body_is_inlined_where_no_module_syntax_is_spelled(self):
        self.assertEqual(
            'var _m = function(await) {\n  return await;\n};\nsink(_m);',
            self._reflect(
                "var _m = Function('return function (await) { return await; }')(); sink(_m);"
            ),
        )

    def test_a_function_body_the_module_reads_is_still_inlined_beside_an_export(self):
        self.assertEqual(
            'export const tag = 1;\nvar _m = 1;\nsink(_m);',
            self._reflect('export const tag = 1;\nvar _m = Function("return 1")(); sink(_m);'),
        )

    def test_a_payload_referring_to_await_is_left_standing_beside_an_export(self):
        rows = [
            'export const tag = 1;\n(0, eval)("console.log(typeof await);");',
            'export const tag = 1;\nvar g = Function("return typeof await");\nconsole.log(g());',
        ]
        self.assertEqual(
            {source: self._reflect(source) for source in rows},
            {source: source for source in rows},
        )

    def test_a_global_declaration_an_indirect_eval_makes_is_left_standing_beside_an_export(self):
        source = 'export const t = 1;\n(0, eval)("var x = 1;");\nconsole.log(globalThis.x);'
        self.assertEqual(source, self._reflect(source))


class TestAnHtmlCommentPayloadInlinesOnlyAtAScriptDestination(TestJsDeobfuscator):
    """
    Script code reads `<!--` and a line-head `-->` as comment openers and module code refuses both
    (§B.1.1), so a payload holding one is inlined where the destination is a script and left
    standing where it is a module, whether the module is asked for or spelled by the file's own
    syntax.
    """

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def _reflect_module(self, source: str) -> str:
        return self._run_transformer(
            source, JsReflectionInlining, DeobfuscationOptions(module=True)
        )

    def test_an_opener_payload_is_inlined_into_a_script(self):
        rows = {
            'eval("<!-- x\\nconsole.log(1);");': '<!-- x\nconsole.log(1);',
            '(0, eval)("<!-- x\\nconsole.log(1);");': '<!-- x\nconsole.log(1);',
            'var f = Function("<!-- x\\nreturn 1"); console.log(f());': 'console.log(1);',
        }
        self.assertEqual({source: self._reflect(source) for source in rows}, rows)

    def test_a_closer_payload_is_inlined_into_a_script(self):
        self.assertEqual(
            '1;\n--> x\nconsole.log(2);',
            self._reflect('eval("1;\\n--> x\\nconsole.log(2);");'),
        )

    def test_a_payload_holding_either_is_left_standing_where_a_module_is_asked_for(self):
        """
        The `eval` rows stay standing: inlining would splice comment text into module code, which
        refuses it. The `Function` row folds — the payload is the constructed body's own text, which
        the Function constructor reads with the Script goal however the destination is parsed.
        """
        rows = {
            'eval("<!-- x\\nconsole.log(1);");': 'eval("<!-- x\\nconsole.log(1);");',
            '(0, eval)("<!-- x\\nconsole.log(1);");': '(0, eval)("<!-- x\\nconsole.log(1);");',
            'eval("1;\\n--> x\\nconsole.log(2);");': 'eval("1;\\n--> x\\nconsole.log(2);");',
            'var f = Function("<!-- x\\nreturn 1");\nconsole.log(f());': 'console.log(1);',
        }
        self.assertEqual(
            {source: self._reflect_module(source) for source in rows},
            rows,
        )

    def test_a_payload_holding_either_is_left_standing_beside_an_export(self):
        rows = {
            'export const tag = 1;\neval("<!-- x\\nconsole.log(1);");':
                'export const tag = 1;\neval("<!-- x\\nconsole.log(1);");',
            'export const tag = 1;\n(0, eval)("<!-- x\\nconsole.log(1);");':
                'export const tag = 1;\n(0, eval)("<!-- x\\nconsole.log(1);");',
            'export const tag = 1;\neval("1;\\n--> x\\nconsole.log(2);");':
                'export const tag = 1;\neval("1;\\n--> x\\nconsole.log(2);");',
            'export const tag = 1;\nvar f = Function("<!-- x\\nreturn 1");\nconsole.log(f());':
                'export const tag = 1;\nconsole.log(1);',
        }
        self.assertEqual(
            {source: self._reflect(source) for source in rows},
            rows,
        )

    def test_a_payload_holding_one_where_no_statement_carries_it_is_left_standing(self):
        rows = [
            'export const tag = 1;\neval("f(<!-- x\\n1);");',
            'export const tag = 1;\n(0, eval)("console.log(1); <!-- x");',
        ]
        self.assertEqual(
            {source: self._reflect_module(source) for source in rows},
            {source: source for source in rows},
        )


class TestAPayloadIsScriptCodeWhereverItIsEvaluated(TestJsDeobfuscator):
    """
    Every reflective surface evaluates its text with the Script goal, a direct `eval` inside an
    `async` function included, so an `await` operator or a `for await` head at the payload's own
    top level is a `SyntaxError` the call site catches, whatever the site itself reads `await` as.
    The same text inlined would run, so the call is left standing to throw as it did; a head inside
    an `async` function the payload writes is the payload's own and is inlined.
    """

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def test_an_await_operator_payload_is_left_standing_in_an_async_body(self):
        source = inspect.cleandoc(
            """
            async function f() {
              try {
                eval("await 1");
                console.log("ran");
              } catch (e) {
                console.log(e.name);
              }
            }
            f();
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_an_await_operator_payload_is_left_standing_in_an_arrow_parameter_of_an_async_body(self):
        source = inspect.cleandoc(
            """
            async function f() {
              return ((x = eval("await 1")) => x)();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_a_for_await_payload_is_left_standing_at_every_site(self):
        rows = [
            'function f() {\n  eval("for await (const x of []) {}");\n}',
            'async function f() {\n  eval("for await (const x of []) {}");\n}',
            'async function f() {\n  (0, eval)("for await (const x of []) {}");\n}',
            'async function f() {\n  var g = Function("for await (const x of []) {}");\n  g();\n}',
            '(0, eval)("for await (const x of []) {}");',
        ]
        self.assertEqual(
            {source: self._reflect(source) for source in rows},
            {source: source for source in rows},
        )

    def test_a_for_await_head_inside_an_async_function_of_the_payload_is_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                (async () => {
                  for await (const x of []) {}
                })();
                """
            ),
            self._reflect('eval("(async () => { for await (const x of []) {} })();");'),
        )


class TestAStringTimerBodyIsWeighedAgainstItsWrapper(TestJsDeobfuscator):
    """
    A string timer's body is lowered into a plain function of its own rather than spliced at the
    site, so the words it is weighed against are the wrapper's: `await` and `yield` are names in it
    whatever function encloses the timer, and a body naming them is lowered where a splice at the
    site would have been refused.
    """

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def test_a_body_naming_await_is_lowered_inside_an_async_function(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                async function f() {
                  setTimeout(function() {
                    console.log(typeof await);
                  }, 10);
                }
                """
            ),
            self._reflect('async function f() { setTimeout("console.log(typeof await)", 10); }'),
        )

    def test_a_body_naming_yield_is_lowered_inside_a_generator(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function* g() {
                  setInterval(function() {
                    console.log(typeof yield);
                  }, 10);
                }
                """
            ),
            self._reflect('function* g() { setInterval("console.log(typeof yield)", 10); }'),
        )


#: Every spelling of a `Function` construction whose callee is reached by `.constructor` navigation,
#: each preceded by a write replacing what that navigation hands out. The write cannot reach the
#: named intrinsic — `Function("return 42")()` still answers `42` under it — but every navigation
#: spellings answers what was installed, and each program prints what the replacement returns.
_NAVIGATION_SPELLINGS_A_REPLACED_CONSTRUCTOR_REACHES = [
    "console.log((function(){}).constructor('return 42')());",
    "console.log(''.constructor.constructor('return 42')());",
    'function d() {} console.log(d.constructor("return 42")());',
    'function d() {} var g = d.constructor; console.log(g("return 42")());',
]

_EVIL_CONSTRUCTOR = (
    'var evil = function (code) { return function () { return 999; }; };'
    ' Function.prototype.constructor = evil;'
)
"""
A write that redirects `.constructor` navigation to a constructor of the program's own.
"""


@unittest.skipUnless(node_executable() is not None, 'node.js is required')
class TestAReplacedFunctionPrototypeConstructorRedirectsNavigation(TestJsDeobfuscator):
    """
    A program that writes the `constructor` key on a chain rooted at `Function` has replaced the
    intrinsic every `.constructor` navigation hands out, so no spelling of a construction reached
    that way inlines as the named one — the replaced constructor runs instead, and what it returns
    is what both the program and its deobfuscation print.
    """

    def test_each_navigation_spelling_keeps_what_the_replacement_returns(self):
        for spelling in _NAVIGATION_SPELLINGS_A_REPLACED_CONSTRUCTOR_REACHES:
            source = F'{_EVIL_CONSTRUCTOR} {spelling}'
            deobfuscated = deobfuscate_source(source)
            with self.subTest(spelling):
                self.assertEqual(behavior(source), behavior(deobfuscated))


#: Every write form a constructed body can use to store a free name, each holding the call the
#: route would otherwise resolve. An execution that replaced the call would drop the store the real
#: program performs, so each form is one the route refuses before anything runs.
_EVERY_WRITE_FORM_A_CONSTRUCTED_BODY_CAN_STORE = [
    "var r = Function('q = 1; return 2')();",
    "var r = Function('q += 1; return 2')();",
    "var r = Function('q++; return 2')();",
    "var r = Function('for (q in o); return 2')();",
    "var r = Function('[q] = [1]; return 2')();",
]

#: A constructed body reading a name the real tree binds at root scope, mapped to the normalized
#: text the route leaves standing. A script-level `let` is a spelling the old calls gate never saw,
#: and a root-scope `undefined` is a name no fragment model resolves the way the real program does.
_A_ROOT_BINDING_A_CONSTRUCTED_BODY_READS = {
    "var g = 5; var f = Function('a', 'return g + arguments[0]'); var r = f(1);":
        "var g = 5;\nvar f = Function('a', 'return g + arguments[0]');\nvar r = f(1);",
    "let g = 5; var f = Function('a', 'return g + arguments[0]'); var r = f(1);":
        "let g = 5;\nvar f = Function('a', 'return g + arguments[0]');\nvar r = f(1);",
    "var undefined = 4; var f = Function('a', 'return undefined + arguments[0]'); var r = f(1);":
        "var undefined = 4;\nvar f = Function('a', 'return undefined + arguments[0]');\nvar r = f(1);",
}

#: A fragment storing to a global builtin under a spelling neither static gate names — `this`
#: dispatch, the `globalThis` registry entry, and an alias off it are all refused incidentally by
#: the execution itself, and these rows pin that reliance.
_A_GLOBAL_STORE_NO_STATIC_GATE_NAMES = [
    "var r = Function('this.String = 9; return 1')();",
    "var r = Function('globalThis.String = 9; return 1')();",
    "var r = Function('var w = globalThis; w.String = 9; return 1')();",
]


class TestAConstructionCallTheEvaluationRouteExecutes(TestJsDeobfuscator):
    """
    A call to a name a `Function` construction resolves to, where the inline route declines — the
    body binds parameters or reads its `arguments` — is executed over the call's argument values
    and replaced by the value it answers. Every decline row is a gate the route refuses through and
    the call stays standing; every fold row's value is Node's.
    """

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def test_every_write_form_a_constructed_body_stores_a_free_name_with_declines(self):
        rows = _EVERY_WRITE_FORM_A_CONSTRUCTED_BODY_CAN_STORE
        self.assertEqual(
            {source: self._reflect(source) for source in rows},
            {source: source for source in rows},
        )

    def test_a_root_binding_a_constructed_body_reads_declines(self):
        rows = _A_ROOT_BINDING_A_CONSTRUCTED_BODY_READS
        self.assertEqual(
            {source: self._reflect(source) for source in rows},
            rows,
        )

    def test_a_strict_prologue_declines(self):
        source = "var r = Function(\"'use strict'; return 1;\")();"
        self.assertEqual(source, self._reflect(source))

    def test_non_simple_parameter_text_declines(self):
        source = 'var r = Function("a = 1", "return a;")();'
        self.assertEqual(source, self._reflect(source))

    def test_a_body_that_does_not_parse_declines(self):
        source = "var r = Function('return 1; }{')();"
        self.assertEqual(source, self._reflect(source))

    def test_a_non_constant_argument_declines(self):
        source = 'var r = Function("a", "return a")(sink());'
        self.assertEqual(source, self._reflect(source))

    def test_an_argument_whose_read_may_throw_declines(self):
        source = 'var r = Function("a", "return a")(oo.x);'
        self.assertEqual(source, self._reflect(source))

    def test_a_global_store_no_static_gate_names_declines(self):
        rows = _A_GLOBAL_STORE_NO_STATIC_GATE_NAMES
        self.assertEqual(
            {source: self._reflect(source) for source in rows},
            {source: source for source in rows},
        )

    def test_a_name_an_earlier_site_of_the_same_pass_spliced_in_declines(self):
        """
        The write an inlined `eval` carried is one no model the pass pinned records, so a fragment
        reading the name would answer the value the program replaced — Node prints `99` for this
        program — and the spliced-name record is what refuses it.
        """
        source = (
            "eval('String = function (x) { return 99; };');"
            " var f = Function('a', 'return String(arguments[0]);'); console.log(f(97));"
        )
        expected = (
            'String = function(x) {\n  return 99;\n};\n'
            "var f = Function('a', 'return String(arguments[0]);');\nconsole.log(f(97));"
        )
        self.assertEqual(expected, self._reflect(source))

    def test_a_rebound_intrinsic_inside_an_eval_argument_stays_standing(self):
        """
        A `String` the program has replaced is not one a fold of the argument text may consult.
        Node throws a `TypeError` for this program, and the call stays standing so it still does.
        """
        source = 'String = 5; var r = eval(String(97));'
        self.assertEqual('String = 5;\nvar r = eval(String(97));', self._reflect(source))

    def test_a_constant_argument_folds_to_the_value_the_body_answers(self):
        self.assertEqual(
            'var r = 42;',
            self._reflect("var f = Function('a', 'b', 'return (a + b) * 2'); var r = f(19, 2);"))

    def test_an_arguments_element_folds_to_the_value_the_call_passed(self):
        self.assertEqual(
            'var r = 2;',
            self._reflect("var f = Function('a', 'b', 'return arguments[1];'); var r = f(1, 2);"))

    def test_the_arguments_length_folds_to_the_arity_of_the_call(self):
        self.assertEqual(
            'var r = 2;',
            self._reflect("var f = Function('return arguments.length'); var r = f(1, 2);"))

    def test_an_opaque_write_the_text_never_resolves_declines(self):
        """
        The decline leg of the composition below: a top-level write under a key only the runtime
        resolves is a tampering site ordered before the call, so nothing about the call is resolved
        while it stands.
        """
        source = (
            "var k = 'q'; global[k] = 5;"
            ' var f = Function(\'a\', \'return arguments[0].split(",")\');'
            " console.log(f('x,y,z')[1]);"
        )
        self.assertEqual(
            'var k = \'q\';\nglobal[k] = 5;\n'
            'var f = Function(\'a\', \'return arguments[0].split(",")\');\n'
            'console.log(f(\'x,y,z\')[1]);',
            self._deobfuscate(source))

    def test_a_write_an_earlier_fold_attributed_lets_the_call_fold(self):
        """
        The distilled shape of the sample: a top-level write whose key an earlier fold resolves,
        and a construction whose body folds its argument through `arguments`. The write becomes an
        attributed one no oracle counts as a site, and the route answers the value Node answers.
        """
        source = (
            "global[['q'][0]] = 5;"
            ' var f = Function(\'a\', \'return arguments[0].split(",")\');'
            " console.log(f('x,y,z')[1]);"
        )
        self.assertEqual("global.q = 5;\nconsole.log('y');", self._deobfuscate(source))


class TestAnInvocationPassingArgumentsToAConstruction(TestJsDeobfuscator):
    """
    A call to a name a `Function` construction resolves to may pass arguments the body never
    observes — the construction binds no parameters and reads no `arguments` — so the invocation
    inlines like the argument-less spelling, the call's arguments evaluated before it and droppable
    where the splice replaces them. Every argument must be a literal: anything that reads a name or
    runs a call is an evaluation no splice of the body reproduces, so the call stays standing.
    """

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def test_a_literal_argument_inlines(self):
        self.assertEqual(
            'console.log(42);',
            self._reflect("var f = Function('', 'return 42'); console.log(f(3400));"))

    def test_a_literal_argument_at_statement_position_splices_the_body(self):
        self.assertEqual(
            'var a = 1;\nvar b = 2;\ncombine(a, b);',
            self._reflect(
                "var f = Function('', 'var a = 1; var b = 2; combine(a, b);'); f(3400);"))

    def test_an_identifier_argument_stays_standing(self):
        source = "var x = 1; var f = Function('', 'return 42'); console.log(f(x));"
        self.assertEqual(
            'var x = 1;\nvar f = Function(\'\', \'return 42\');\nconsole.log(f(x));',
            self._reflect(source))

    def test_a_side_effectful_argument_stays_standing(self):
        source = "var f = Function('', 'return 42'); console.log(f(sink()));"
        self.assertEqual(
            'var f = Function(\'\', \'return 42\');\nconsole.log(f(sink()));',
            self._reflect(source))

    def test_an_argument_whose_read_may_throw_stays_standing(self):
        source = "var f = Function('', 'return 42'); console.log(f(oo.x));"
        self.assertEqual(
            'var f = Function(\'\', \'return 42\');\nconsole.log(f(oo.x));',
            self._reflect(source))

    def test_a_body_reading_arguments_through_a_nested_arrow_stays_standing(self):
        source = "var f = Function('', 'return (() => arguments.length)()'); console.log(f(42));"
        self.assertEqual(
            'var f = Function(\'\', \'return (() => arguments.length)()\');\nconsole.log(f(42));',
            self._reflect(source))

    def test_a_body_reading_arguments_with_a_literal_argument_folds_by_evaluation(self):
        """
        The argument a body reads through `arguments` is one the inline route declines, and the
        evaluation route answers the value it was passed — the D2 territory this row keeps pinned
        beside the inline route's own.
        """
        self.assertEqual(
            'console.log(42);',
            self._reflect("var f = Function('', 'return arguments[0]'); console.log(f(42));"))


#: The sample's shape, distilled benignly: a decoder alias read once inside an anonymous
#: immediately-invoked function, a dead construction spelled through that alias, and an async
#: sibling carrying a direct `eval` whose argument only the runtime resolves. The decoder folds
#: where ordering proves the alias read safe — with the eval still standing — and whatever the
#: pipeline does from there, the program the file spells is the one that runs.
_A_DECODER_UNDER_A_LATER_EVAL: list[str] = [
    (
        'var out;\n'
        'var q = (function () {\n'
        '  function jCb(l) { return l; }\n'
        '  var xTe = jCb.constructor;\n'
        "  var Urn = xTe('', 'return 9;');\n"
        "  var _a = function (e, r) { return e.split('*').join(''); }('o*ut*5', 0);\n"
        "  (async function () { await eval(_a[4]); console.log('late'); })();\n"
        '  return _a;\n'
        '})();\n'
        'console.log(q);'
    ),
    (
        'var out;\n'
        'var q = (function () {\n'
        '  function jCb(l) { return l; }\n'
        "  var xTe = jCb['constructor'];\n"
        "  var Urn = xTe('', 'return 9;');\n"
        "  var _a = function (e, r) { return e.split('*').join(''); }('o*ut*5', 0);\n"
        "  (async function () { await eval(_a[4]); console.log('late'); })();\n"
        '  return _a;\n'
        '})();\n'
        'console.log(q);'
    ),
]

#: The loop shape the positioned repair refuses: a volatile read a cycle re-executes, with the
#: eval that rebinds it between its iterations. Nothing folds, so the second iteration reads the
#: value the first one's eval wrote — the behavior a repair that froze the first value would
#: break.
_A_VOLATILE_READ_ON_A_CYCLE: list[str] = [
    (
        'var out = [];\n'
        'var q = (function () {\n'
        '  var x = 1;\n'
        '  for (var i = 0; i < 2; i++) {\n'
        '    out.push(x);\n'
        "    eval('x = 2;');\n"
        '  }\n'
        '  return x;\n'
        '})();\n'
        "console.log(q, out.join(','));"
    ),
]


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheDecoderFoldUnderAnEvalSiblingPreservesBehavior(TestJsDeobfuscator):
    """
    The differential net over the positioned alias repair: Node answers each program and the text
    the deobfuscation produces, and the two must agree. The sample-shape rows show the fold the
    repair buys — a decoder reached through a volatile alias folding with the eval sibling still
    standing; the loop row is the net's other half, the shape the repair refuses so that the second
    iteration still reads what the first one's eval wrote.
    """

    def test_the_sample_shape_behaves_as_the_original(self):
        sources = _A_DECODER_UNDER_A_LATER_EVAL
        self.assertEqual(
            {source: behavior(source) for source in sources},
            {source: behavior(deobfuscate_source(source)) for source in sources},
        )

    def test_a_read_on_a_cycle_behaves_as_the_original(self):
        sources = _A_VOLATILE_READ_ON_A_CYCLE
        self.assertEqual(
            {source: behavior(source) for source in sources},
            {source: behavior(deobfuscate_source(source)) for source in sources},
        )
