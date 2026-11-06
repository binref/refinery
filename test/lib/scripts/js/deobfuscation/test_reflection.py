from __future__ import annotations

import inspect
import json
import unittest

from typing import NamedTuple

from test import TestBase, opportunity, todo
from test.lib.scripts.js.analysis.differential import (
    JsEvaluation,
    behavior,
    completion_values,
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import Program, Reading, a_program, printed, prints
from test.lib.scripts.js.test_directive_prologue import NOT_A_PROGRAM

from refinery.lib.scripts import tree_version
from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.options import DeobfuscationOptions, ExecutionModel
from refinery.lib.scripts.js.deobfuscation.reflection import JsReflectionInlining
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


#: A string array whose entry `0xac` decodes to `return this`, followed by a `Function` global
#: finder that takes its code from that entry.
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
            source, JsReflectionInlining, DeobfuscationOptions(execution=ExecutionModel.module)
        )

    def _reflect_in_a_browser(self, source: str) -> str:
        return self._run_transformer(
            source, JsReflectionInlining, DeobfuscationOptions(environment=HostEnvironment.browser)
        )

    def test_a_constant_fold_before_a_sibling_construction_check_does_not_trip_the_pin(self):
        self.assertEqual(
            "var y = new Function('a', 'return a')(z);\nvar x = 1;",
            self._reflect("var y = new Function('a','return a')(z); var x = new Function('return 1')();"),
        )

    def test_eval_string_literal(self):
        self.assertEqual('var x = 1;', self._reflect("eval('var x = 1;');"))

    def test_direct_eval_var_inlined_when_reference_is_dominated(self):
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
        source = inspect.cleandoc(
            """
            with (o) {
              eval("1");
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_direct_eval_strict_body_into_sloppy_site_not_inlined(self):
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
        source = "window.eval('var x = 1;');"
        self.assertEqual(source, self._reflect(source))

    def test_indirect_eval_globalthis(self):
        self.assertEqual('var x = 1;', self._reflect("globalThis.eval('var x = 1;');"))

    def test_indirect_eval_computed_alias_member(self):
        self.assertEqual('var x = 1;', self._reflect("globalThis['eval']('var x = 1;');"))

    def test_indirect_eval_shadowed_alias_base_not_inlined(self):
        source = inspect.cleandoc(
            """
            function f(window) {
              return window.eval("1");
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_shadowed_function_pack_not_inlined(self):
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
        source = inspect.cleandoc(
            """
            with (o) {
              window.eval("1");
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_indirect_eval_prefix_read_in_with_not_inlined(self):
        source = inspect.cleandoc(
            """
            var e = 0;
            var o = { get e() { console.log('e'); return 0; } };
            with (o) {
              (e, eval)("f()");
            }
            """
        )
        self.assertEqual(printed(source), self._reflect(source))

    def test_constructor_chain_base_read_in_with_not_inlined(self):
        source = inspect.cleandoc(
            """
            var s = '';
            var o = { get s() { console.log('s'); return ''; } };
            with (o) {
              s.constructor.constructor('f()')();
            }
            """
        )
        self.assertEqual(printed(source), self._reflect(source))

    def test_indirect_eval_established_identifier_prefix_outside_with_still_inlined(self):
        self.assertEqual(
            'var e = 1;\nf();',
            self._reflect("var e = 1; (e, eval)('f()');"))

    def test_indirect_eval_unbound_identifier_prefix_is_not_dropped(self):
        source = "(e, eval)('f()');"
        self.assertEqual(source, self._reflect(source))

    def test_settimeout_string_lowered_in_a_browser(self):
        self.assertEqual(
            'setTimeout(function() {\n  alert(1);\n}, 0);',
            self._reflect_in_a_browser("setTimeout('alert(1)', 0);"))

    def test_setinterval_string_lowered_in_a_browser(self):
        self.assertEqual(
            'setInterval(function() {\n  doStuff();\n}, 1000);',
            self._reflect_in_a_browser("setInterval('doStuff()', 1000);"))

    def test_settimeout_non_string_not_inlined(self):
        self.assertEqual('setTimeout(fn, 0);', self._reflect('setTimeout(fn, 0);'))

    def test_string_timer_this_rewritten_to_global_in_a_browser(self):
        self.assertEqual(
            'setTimeout(function() {\n  globalThis.foo();\n}, 0);',
            self._reflect_in_a_browser("setTimeout('this.foo()', 0);"))

    def test_string_timer_with_shadowed_free_name_not_lowered(self):
        self.assertEqual(
            'function f() {\n  var alert = 1;\n  setTimeout("alert(1)", 0);\n}',
            self._reflect('function f(){ var alert = 1; setTimeout("alert(1)", 0); }'))

    def test_string_timer_in_with_body_not_lowered(self):
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

    def test_module_direct_eval_declaration_read_not_inlined(self):
        source = "eval('var x = 1;');\nconsole.log(typeof x);"
        self.assertEqual(source, self._reflect_module(source))

    def test_module_direct_eval_strict_only_syntax_not_inlined(self):
        for body in ('with ({}) { g(); }', '010;', 'delete x;'):
            with self.subTest(body=body):
                source = F"eval('{body}');"
                self.assertEqual(source, self._reflect_module(source))

    def test_module_indirect_eval_expression_still_inlined(self):
        self.assertEqual('foo();', self._reflect_module("(0, eval)('foo();');"))

    def test_module_indirect_eval_binding_await_not_inlined(self):
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
        self.assertEqual(
            'var out = [];\nout.push(1);',
            self._reflect("var out = []; new Function('out.push(1)')();"))

    def test_module_function_constructor_reading_top_level_var_not_inlined(self):
        self.assertEqual(
            "var out = [];\nnew Function('out.push(1)')();",
            self._reflect_module("var out = []; new Function('out.push(1)')();"))

    def test_indirect_eval_declaration_not_inlined_into_function(self):
        source = inspect.cleandoc(
            """
            function f() {
              (0, eval)('var x = 1;');
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_indirect_eval_block_hoisted_var_not_inlined_into_function(self):
        source = inspect.cleandoc(
            """
            function f() {
              (0, eval)('{ var g = 1; }');
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_indirect_eval_nested_lexical_declaration_still_inlined(self):
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

    def test_member_form_string_interval_lowered_in_a_browser(self):
        self.assertEqual(
            'globalThis.setInterval(function() {\n  tick();\n}, 100);',
            self._reflect_in_a_browser("globalThis.setInterval('tick()', 100);"))

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
        In a framed document `top` is another window, so `top.eval` runs its code in that window's
        realm.
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
        source = "var g = (async function() {}).constructor('return this')();"
        self.assertEqual(source, self._reflect(source))

    def test_single_constructor_hop_generator_base_not_inlined(self):
        source = "var g = (function*() {}).constructor('return this')();"
        self.assertEqual(source, self._reflect(source))

    def test_separated_function_constructor_folds_and_retires_temporary(self):
        self.assertEqual(
            'var g = globalThis;',
            self._reflect("const m = Function('return this'); var g = m();"))

    def test_separated_constructor_chain_folds_and_retires_temporary(self):
        self.assertEqual(
            'var x = 1;',
            self._reflect("const m = (function(){}).constructor('return 1'); var x = m();"))

    def test_a_constructor_alias_off_a_function_name_inlines(self):
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
        source = 'var g = d.constructor; let d = function () {}; var x = g("return 42")();'
        self.assertEqual(
            'var g = d.constructor;\nlet d = function() {};\nvar x = g("return 42")();',
            self._reflect(source))

    def test_a_constructor_alias_off_a_base_reassigned_to_a_string_declines(self):
        source = 'var d = function () {}; d = \'\'; var g = d.constructor; var x = g("return 42")();'
        self.assertEqual(
            inspect.cleandoc(
                """
                var d = function() {};
                d = '';
                var g = d.constructor;
                var x = g("return 42")();
                """
            ),
            self._reflect(source))

    @opportunity
    def test_a_constructor_alias_off_a_base_reassigned_to_another_plain_function_inlines(self):
        source = 'var d = function () {}; d = function () {}; var g = d.constructor; var x = g("return 42")();'
        self.assertEqual(
            inspect.cleandoc(
                """
                var d = function() {};
                d = function() {};
                var g = d.constructor;
                var x = 42;
                """
            ),
            self._reflect(source))

    def test_a_constructor_alias_that_may_hold_another_value_declines(self):
        source = 'var e = function () {}; var g = d.constructor; g = e; var x = g("return 42")();'
        self.assertEqual(
            'var e = function() {};\nvar g = d.constructor;\ng = e;\nvar x = g("return 42")();',
            self._reflect(source))

    def test_a_bare_call_through_a_constructor_alias_is_not_an_invocation(self):
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
        self.assertEqual(
            'var x = 42;',
            self._reflect("var x = Function(' ', 'return 42')();"))

    def test_two_empty_parameter_arguments_name_a_comma(self):
        source = "var x = Function('', '', 'return 42')();"
        self.assertEqual(source, self._reflect(source))

    def test_a_constructor_alias_with_a_named_parameter_folds_by_evaluation(self):
        self.assertEqual(
            "function d() {}\nvar g = d.constructor;\nvar x = 42;",
            self._reflect("function d() {} var g = d.constructor; var x = g('a', 'return 42')(1);"))

    def test_separated_temporary_with_another_read_is_kept(self):
        self.assertEqual(
            "const m = Function('return 1');\nuse(m);\nvar x = 1;",
            self._reflect("const m = Function('return 1'); use(m); var x = m();"))

    def test_separated_temporary_named_in_with_body_is_kept(self):
        self.assertEqual(
            "const m = Function('return 1');\nwith (obj) {\n  use(m);\n}\nvar x = 1;",
            self._reflect("const m = Function('return 1'); with (obj) { use(m); } var x = m();"))

    def test_a_site_reading_an_earlier_splices_declaration_folds_by_the_fixpoint(self):
        source = "eval('var a = 1;'); eval('console.log(a);');"
        self.assertIn(
            self._reflect(source),
            (
                inspect.cleandoc(
                    """
                    var a = 1;
                    eval('console.log(a);');
                    """
                ),
                inspect.cleandoc(
                    """
                    var a = 1;
                    console.log(a);
                    """
                ),
            ),
        )
        self.assertEqual('console.log(1);', self._deobfuscate(source))

    def test_fold_of_a_temporary_a_same_pass_splice_rebinds_is_declined(self):
        self.assertEqual(
            "var m = Function('return 1');\nm = function() {\n  return 2;\n};\nconsole.log(m());",
            self._reflect(
                "var m = Function('return 1');"
                " eval('m = function () { return 2; };');"
                " console.log(m());"))

    def test_separated_temporary_a_lowered_timer_body_names_is_kept_in_a_browser(self):
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
            self._reflect_in_a_browser(
                "var m = Function('return 41'); m(); setTimeout('console.log(m.name)', 0);"))

    def test_separated_temporary_the_analyst_names_an_entrypoint_is_kept(self):
        self.assertEqual(
            "var m = Function('return 41');\nconsole.log(41);",
            self._run_transformer(
                "var m = Function('return 41'); console.log(m());",
                JsReflectionInlining,
                DeobfuscationOptions(entrypoints=('m',))))

    def test_a_body_declaration_a_pattern_names_under_every_suffix_stays_packed(self):
        source = "Function('var main = 1; print(main);')();"
        self.assertEqual(
            source,
            self._run_transformer(
                source, JsReflectionInlining, DeobfuscationOptions(entrypoints=('m*',))))

    def test_separated_reassigned_temporary_not_inlined(self):
        source = "let m = Function('return 1');\nm = other;\nvar x = m();"
        self.assertEqual(
            source, self._reflect("let m = Function('return 1'); m = other; var x = m();"))

    def test_separated_temporary_binding_parameters_evaluate(self):
        self.assertEqual(
            "var x = 1;",
            self._reflect("const m = Function('a','return a'); var x = m(1);"))

    def test_separated_temporary_used_before_established_not_inlined(self):
        source = "var x = m();\nconst m = Function('return 1');"
        self.assertEqual(source, self._reflect("var x = m(); const m = Function('return 1');"))

    def test_an_alias_hop_read_before_its_declarator_runs_does_not_fold(self):
        source = (
            'var a = b; var b = function() {}.constructor;'
            " var c = a('return 1'); c();"
        )
        self.assertEqual(
            "var a = b;\nvar b = function() {}.constructor;\nvar c = a('return 1');\nc();",
            self._reflect(source))

    def test_a_callee_read_before_its_declarator_runs_does_not_fold(self):
        source = "var c = g('return 1'); c(); var g = Function;"
        self.assertEqual(
            "var c = g('return 1');\nc();\nvar g = Function;",
            self._reflect(source))

    def test_payload_clashing_with_the_consumed_temporaries_folds_atomically(self):
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

    @todo
    def test_a_payload_reading_its_construction_at_script_scope_is_left_standing(self):
        source = "var h = function() {}.constructor; var f = h('print(1); var h; f;'); f();"
        self.assertEqual(printed(source), self._reflect(source))

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

    def test_a_getter_on_the_constructor_chain_refuses_the_atomic_fold(self):
        source = inspect.cleandoc(
            """
            Object.defineProperty(Function.prototype, 'constructor', {
              get: function () { print(0); return Function; }
            });
            function w() {
              var h = function() {}.constructor;
              var f = h('print(1); var h; f;');
              f();
            }
            w();
            """
        )
        self.assertEqual(printed(source), self._reflect(source))

    @opportunity
    def test_a_write_of_another_key_on_the_chain_still_allows_the_atomic_fold(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                Object.prototype.q = 1;
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
                Object.prototype.q = 1;
                function w() {
                  var h = function() {}.constructor;
                  var f = h('print(1); var h; f;');
                  f();
                }
                w();
                """
            )))

    def test_another_key_written_on_the_chain_leaves_the_program_or_folds_temporaries_away(self):
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
        folded_with_the_temporaries_gone = inspect.cleandoc(
            """
            Object.prototype.q = 1;
            function w() {
              print(1);
              var h;
              f;
            }
            w();
            """
        )
        self.assertIn(self._reflect(source), (source, folded_with_the_temporaries_gone))

    def test_a_body_redeclaring_an_unused_lexical_name_at_the_site_is_refused(self):
        source = "let x; var f = Function('var x; print(1);'); f();"
        self.assertEqual(
            "let x;\nvar f = Function('var x; print(1);');\nf();",
            self._reflect(source))


    def test_string_array_revealed_separated_finder_folds_to_globalthis(self):
        """
        The declaration of `_m` stays: in a script it is a property of the global object, and the
        fold hands that object to `sink`, which may read it.
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

    def test_pack_this_receiver_shadowed_by_a_body_binding_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                Function('o', 'var globalThis = 1; this.f(o.a);')({ get 'a'() {
                  return x;
                } });
                """
            ),
            self._reflect(
                inspect.cleandoc(
                    """
                    Function('o', 'var globalThis = 1; this.f(o.a);')({ get 'a'() { return x; } });
                    """
                )
            ),
        )

    def test_pack_this_receiver_inside_a_with_body_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                Function('o', 'with(z){ this.f(o.a); }')({ get 'a'() {
                  return x;
                } });
                """
            ),
            self._reflect(
                inspect.cleandoc(
                    """
                    Function('o', 'with(z){ this.f(o.a); }')({ get 'a'() { return x; } });
                    """
                )
            ),
        )

    def test_pack_getter_target_outside_a_with_body_still_inlined(self):
        source = inspect.cleandoc(
            """
            Function('o', 'with(z){ 1; } o.a;')({ get 'a'() { return x; } });
            """
        )
        self.assertEqual('with (z) {\n  1;\n}\nx;', self._reflect(source))

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
        self.assertEqual(
            'globalThis.x;',
            self._reflect("new Function('return this.x')();"),
        )

    def test_function_constructor_multi_statement_this_becomes_globalthis(self):
        self.assertEqual(
            'globalThis.x = 1;\nglobalThis.y = 2;',
            self._reflect("new Function('this.x = 1; this.y = 2;')();"),
        )

    def test_function_constructor_nested_function_this_preserved(self):
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

    @opportunity
    def test_function_constructor_free_script_let_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                let out = [];
                {
                  out.push(1);
                }
                """
            ),
            self._reflect("let out = []; { new Function('out.push(1)')(); }"),
        )

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
        source = inspect.cleandoc(
            """
            var x = 1;
            void 0;
            console.log(x);
            """
        )
        self.assertEqual(source, self._reflect("var x = 1; new Function('var x = 2;')(); console.log(x);"))

    def test_function_constructor_body_function_declaration_folds_by_evaluation(self):
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
        A body made by `Function` is sloppy however strict its caller is, so `010` in it is the
        number 8.
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
              new Function('if (1) { function g() {} } use(g);')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_direct_eval_not_inlined_in_strict_context(self):
        source = inspect.cleandoc(
            """
            function f() {
              'use strict';
              new Function('eval("var x = 1"); use(x);')();
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

#: Each payload is spelled the way the printer spells it, since a site evaluating it is expected to
#: print as exactly this text.
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

A_SURFACE_THAT_EVALUATES_A_STRING = {
    'indirect eval'            : '(0, eval)({code});',
    'direct eval'              : 'eval({code});',
    'the Function constructor' : 'Function({code})();',
    'a constructed Function'   : 'new Function({code})();',
}

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


A_PAYLOAD_ONLY_MODULE_CODE_MAY_HOLD = [
    'export var q = 1;',
    'export default 1;',
    "export * from 'fs';",
    "import * as m from 'fs';",
    'import.meta;',
]


def _a_program_naming_what_one_payload_throws(template: str, payload: str) -> str:
    return (
        F'try {{ {_a_site_evaluating(template, payload)} }}'
        F' catch (e) {{ console.log(e.name); }}'
    )


class TestAPayloadOnlyModuleCodeMayHoldIsNotInlined(TestJsDeobfuscator):

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


#: An indirect `eval` runs its text as a script even in a module, where binding `await` is legal.
_A_PAYLOAD_BINDING_AWAIT = "(0, eval)('console.log(function (await) { return await + 2; }(1));');"


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPayloadBindingAwaitStaysBehindTheEvalInAModule(TestJsDeobfuscator):

    def test_a_module_keeps_printing_what_the_eval_printed(self):
        source = 'export {};\n' + _A_PAYLOAD_BINDING_AWAIT
        self.assertEqual(
            (
                behavior(source, module=True),
                behavior(deobfuscate_source(source, execution=ExecutionModel.module), module=True),
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
    opened: str
    closing: str
    prints: str

    @property
    def cut(self) -> str:
        return self.opened

    @property
    def whole(self) -> str:
        return F'{self.opened}{self.closing}'


#: Each `whole` is spelled the way the printer spells it, since a site evaluating it is expected to
#: print as exactly this text.
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
    attempts = [
        F'try {{ {_a_site_evaluating(template, payload)} console.log("read"); }}'
        F' catch (e) {{ console.log(e.name); }}'
        for payload in payloads
    ]
    return '\n'.join([*attempts, "console.log('done');"]) + '\n'


class TestAPayloadCutShortIsNotInlined(TestJsDeobfuscator):

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


A_LOCAL_A_SPLICED_EVAL_REBINDS = {
    'an indirect eval of a string read through a closure': Program(
        a_program(r"""
            function k(p) { var q = p(); return q(); }
            function f() {
              var g = function () { return 'console.log("A")'; };
              var h = function () { return g; };
              eval('g = function () { return \'console.log("B")\'; }');
              (0, eval)(k(h));
            }
            f();
            """),
        prints('B'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestALocalASplicedEvalRebindsIsNotReadAtItsFormerValue(TestBase):

    def test_every_program_behaves_the_way_the_engine_does(self):
        for label, row in A_LOCAL_A_SPLICED_EVAL_REBINDS.items():
            with self.subTest(label):
                self.assertEqual(row.read(), row.required())


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
    Script code reads `<!--`, and `-->` at the head of a line, as opening a comment; module code
    refuses both.
    """

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def _reflect_module(self, source: str) -> str:
        return self._run_transformer(
            source, JsReflectionInlining, DeobfuscationOptions(execution=ExecutionModel.module)
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
        The `Function` row folds: the constructor reads its body as a script in any file, and only
        the value the body returns is written into the module.
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

    def _reflect(self, source: str) -> str:
        return self._run_transformer(
            source, JsReflectionInlining, DeobfuscationOptions(environment=HostEnvironment.browser)
        )

    def test_a_body_naming_await_is_lowered_inside_an_async_function_in_a_browser(self):
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

    def test_a_body_naming_yield_is_lowered_inside_a_generator_in_a_browser(self):
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

    def test_each_navigation_spelling_keeps_what_the_replacement_returns(self):
        for spelling in _NAVIGATION_SPELLINGS_A_REPLACED_CONSTRUCTOR_REACHES:
            source = F'{_EVIL_CONSTRUCTOR} {spelling}'
            deobfuscated = deobfuscate_source(source)
            with self.subTest(spelling):
                self.assertEqual(behavior(source), behavior(deobfuscated))


_EVERY_WRITE_FORM_A_CONSTRUCTED_BODY_CAN_STORE = [
    "var r = Function('q = 1; return 2')();",
    "var r = Function('q += 1; return 2')();",
    "var r = Function('q++; return 2')();",
    "var r = Function('for (q in o); return 2')();",
    "var r = Function('[q] = [1]; return 2')();",
]

_A_ROOT_BINDING_A_CONSTRUCTED_BODY_READS = {
    "var g = 5; var f = Function('a', 'return g + arguments[0]'); var r = f(1);":
        "var g = 5;\nvar f = Function('a', 'return g + arguments[0]');\nvar r = f(1);",
    "let g = 5; var f = Function('a', 'return g + arguments[0]'); var r = f(1);":
        "let g = 5;\nvar f = Function('a', 'return g + arguments[0]');\nvar r = f(1);",
    "var undefined = 4; var f = Function('a', 'return undefined + arguments[0]'); var r = f(1);":
        "var undefined = 4;\nvar f = Function('a', 'return undefined + arguments[0]');\nvar r = f(1);",
}

_A_GLOBAL_STORE_NO_STATIC_GATE_NAMES = [
    "var r = Function('this.String = 9; return 1')();",
    "var r = Function('globalThis.String = 9; return 1')();",
    "var r = Function('var w = globalThis; w.String = 9; return 1')();",
]


class TestAConstructionCallTheEvaluationRouteExecutes(TestJsDeobfuscator):

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

    def test_a_strict_body_is_left_standing_or_answered_as_strict_code(self):
        source = "var r = Function(\"'use strict'; return typeof this;\")();"
        self.assertIn(self._reflect(source), (source, "var r = 'undefined';"))

    @opportunity
    def test_a_strict_body_whose_answer_no_mode_changes_folds(self):
        self.assertEqual('var r = 1;', self._reflect("var r = Function(\"'use strict'; return 1;\")();"))

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
        source = (
            'global[process.argv[2]] = 5;'
            ' var f = Function(\'a\', \'return String(arguments[0]).split(",")\');'
            " console.log(f('x,y,z')[1]);"
        )
        self.assertEqual(printed(source), self._deobfuscate(source))

    def test_a_write_an_earlier_fold_attributed_lets_the_call_fold(self):
        source = (
            "global[['q'][0]] = 5;"
            ' var f = Function(\'a\', \'return arguments[0].split(",")\');'
            " console.log(f('x,y,z')[1]);"
        )
        self.assertEqual("global.q = 5;\nconsole.log('y');", self._deobfuscate(source))


class TestAnInvocationPassingArgumentsToAConstruction(TestJsDeobfuscator):

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

    def test_an_identifier_argument_is_left_standing_or_dropped_with_the_call(self):
        source = "var x = 1; var f = Function('', 'return 42'); console.log(f(x));"
        self.assertIn(
            self._reflect(source),
            (
                inspect.cleandoc(
                    """
                    var x = 1;
                    var f = Function('', 'return 42');
                    console.log(f(x));
                    """
                ),
                inspect.cleandoc(
                    """
                    var x = 1;
                    console.log(42);
                    """
                ),
            ),
        )

    @opportunity
    def test_an_initialized_variable_argument_is_dropped_with_the_call(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 1;
                console.log(42);
                """
            ),
            self._reflect("var x = 1; var f = Function('', 'return 42'); console.log(f(x));"))

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
        self.assertEqual(
            'console.log(42);',
            self._reflect("var f = Function('', 'return arguments[0]'); console.log(f(42));"))


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


class TestACommonJsFileRunsAPayloadAsSloppyCode(TestJsDeobfuscator):

    def _reflect(self, source: str, execution: ExecutionModel) -> str:
        return self._run_transformer(
            source, JsReflectionInlining, DeobfuscationOptions(execution=execution)
        )

    def test_a_payload_only_sloppy_code_runs_as_written_is_inlined_into_a_commonjs_file(self):
        rows = {
            'Function("leak = 5;")();': 'leak = 5;',
            'Function("with ({a: 1}) console.log(a);")();': 'with ({ a: 1 }) {\n  console.log(a);\n}',
            'console.log(Function("return 010")());': 'console.log(010);',
        }
        self.assertEqual(
            {source: self._reflect(source, ExecutionModel.commonjs) for source in rows},
            rows,
        )

    def test_the_same_payload_is_left_standing_where_the_file_may_be_an_es_module(self):
        rows = ['Function("leak = 5;")();', 'Function("with ({a: 1}) console.log(a);")();']
        self.assertEqual(
            {source: self._reflect(source, ExecutionModel.module) for source in rows},
            {source: source for source in rows},
        )

    def test_a_payload_holding_an_html_comment_is_inlined_into_a_commonjs_file(self):
        rows = {
            'eval("<!-- x\\nconsole.log(1);");': '<!-- x\nconsole.log(1);',
            '(0, eval)("<!-- x\\nconsole.log(1);");': '<!-- x\nconsole.log(1);',
        }
        self.assertEqual(
            {source: self._reflect(source, ExecutionModel.commonjs) for source in rows},
            rows,
        )

    def test_a_payload_is_left_standing_where_the_text_of_a_commonjs_file_makes_the_site_strict(self):
        rows = [
            inspect.cleandoc(
                """
                'use strict';
                Function("leak = 5;")();
                """
            ),
            inspect.cleandoc(
                """
                export const t = 1;
                Function("leak = 5;")();
                """
            ),
            inspect.cleandoc(
                """
                function f() {
                  'use strict';
                  Function("leak = 5;")();
                }
                f();
                """
            ),
        ]
        self.assertEqual(
            {source: self._reflect(source, ExecutionModel.commonjs) for source in rows},
            {source: source for source in rows},
        )

    def test_a_direct_eval_declaring_a_name_the_file_declares_otherwise_is_left_standing(self):
        rows = [
            inspect.cleandoc(
                """
                eval("var q = 1;");
                let q = 0;
                """
            ),
            inspect.cleandoc(
                """
                eval("var q = 1;");
                class q {}
                """
            ),
            inspect.cleandoc(
                """
                eval("function q() {}");
                function q() {}
                """
            ),
        ]
        for execution in (ExecutionModel.commonjs, ExecutionModel.script):
            with self.subTest(execution.name):
                self.assertEqual(
                    {source: self._reflect(source, execution) for source in rows},
                    {source: source for source in rows},
                )

    def test_a_payload_holding_a_direct_eval_is_left_standing_where_the_file_runs_as_a_module(self):
        rows = [
            'console.log(Function("return eval(\'typeof require\')")());',
            '(0, eval)("eval(\'var q = 1\')");',
        ]
        for execution in (ExecutionModel.commonjs, ExecutionModel.module):
            with self.subTest(execution.name):
                self.assertEqual(
                    {source: self._reflect(source, execution) for source in rows},
                    {source: source for source in rows},
                )


class TestAPayloadReadingANameTheCommonJsWrapperBinds(TestJsDeobfuscator):
    """
    A CommonJS file runs as the body of a function whose parameters are `require`, `module`,
    `exports`, `__filename` and `__dirname`. Code run by a `Function` construction, an indirect
    `eval` or a string timer is global code, where none of these names is bound.
    """

    WRAPPER_NAME_READS = {
        'console.log(Function("return typeof require")());': 'console.log(typeof require);',
        'console.log(Function("return typeof module")());': 'console.log(typeof module);',
        'console.log(Function("return typeof exports")());': 'console.log(typeof exports);',
        'console.log((0, eval)("typeof __dirname"));': 'console.log(typeof __dirname);',
        'console.log((0, eval)("typeof __filename"));': 'console.log(typeof __filename);',
        'setTimeout("console.log(typeof module)", 0);':
            'setTimeout(function() {\n  console.log(typeof module);\n}, 0);',
    }

    def _reflect(
        self,
        source: str,
        execution: ExecutionModel,
        environment: HostEnvironment = HostEnvironment.universal,
    ) -> str:
        return self._run_transformer(
            source, JsReflectionInlining, DeobfuscationOptions(execution=execution, environment=environment)
        )

    def test_a_payload_reading_a_wrapper_name_is_read_as_global_code_where_the_file_may_be_commonjs(self):
        rows = self.WRAPPER_NAME_READS
        read_as_global_code = {
            'console.log(Function("return typeof require")());': "console.log((0, eval)('typeof require'));",
            'console.log(Function("return typeof module")());': "console.log((0, eval)('typeof module'));",
            'console.log(Function("return typeof exports")());': "console.log((0, eval)('typeof exports'));",
            'console.log((0, eval)("typeof __dirname"));': 'console.log((0, eval)("typeof __dirname"));',
            'console.log((0, eval)("typeof __filename"));': 'console.log((0, eval)("typeof __filename"));',
            'setTimeout("console.log(typeof module)", 0);': 'setTimeout("console.log(typeof module)", 0);',
        }
        for execution in (ExecutionModel.commonjs, ExecutionModel.module):
            with self.subTest(execution.name):
                self.assertEqual(
                    {source: self._reflect(source, execution) for source in rows},
                    read_as_global_code,
                )

    def test_the_same_payload_is_inlined_into_a_script_a_browser_runs(self):
        rows = self.WRAPPER_NAME_READS
        self.assertEqual(
            {source: self._reflect(source, ExecutionModel.script, HostEnvironment.browser) for source in rows},
            rows,
        )

    def test_the_same_payload_is_inlined_into_a_file_spelling_export(self):
        self.assertEqual(
            'export const t = 1;\nconsole.log(typeof require);',
            self._reflect(
                'export const t = 1;\nconsole.log(Function("return typeof require")());',
                ExecutionModel.commonjs,
            ),
        )

    def test_a_wrapper_name_read_through_an_accessor_of_the_file_is_unpacked(self):
        source = (
            'Function("p", "var r = p.r; console.log(typeof r)")'
            '({ get r() { return require; } });'
        )
        for execution in (ExecutionModel.commonjs, ExecutionModel.module):
            with self.subTest(execution.name):
                self.assertEqual(
                    'var r = require;\nconsole.log(typeof r);',
                    self._reflect(source, execution),
                )

    def test_a_payload_reading_a_wrapper_name_the_file_assigns_is_read_as_global_code(self):
        source = inspect.cleandoc(
            """
            exports = module.exports = {};
            console.log(Function("return typeof exports")());
            """
        )
        for execution in (ExecutionModel.commonjs, ExecutionModel.module):
            with self.subTest(execution.name):
                self.assertEqual(
                    self._reflect(source, execution),
                    "exports = module.exports = {};\nconsole.log((0, eval)('typeof exports'));",
                )

    def test_a_payload_declaring_a_wrapper_name_is_left_standing_at_the_top_of_the_file(self):
        rows = [
            'Function("let module = 1; console.log(module)")();',
            'Function("var exports = 3; console.log(exports)")();',
            'eval("const require = 2; console.log(require)");',
        ]
        for execution in (ExecutionModel.commonjs, ExecutionModel.module):
            with self.subTest(execution.name):
                self.assertEqual(
                    {source: self._reflect(source, execution) for source in rows},
                    {source: source for source in rows},
                )

    def test_a_payload_declaring_a_wrapper_name_is_inlined_into_a_function(self):
        source = inspect.cleandoc(
            """
            function g() {
              Function("let module = 1; console.log(module)")();
            }
            """
        )
        self.assertEqual(
            self._reflect(source, ExecutionModel.commonjs),
            inspect.cleandoc(
                """
                function g() {
                  let module = 1;
                  console.log(module);
                }
                """
            ),
        )

    def test_a_payload_declaring_a_wrapper_name_is_inlined_at_the_top_of_a_script(self):
        self.assertEqual(
            self._reflect('Function("let module = 1; console.log(module)")();', ExecutionModel.script),
            inspect.cleandoc(
                """
                let module = 1;
                console.log(module);
                """
            ),
        )


class TestAPackedTypeofThroughAGetterReturningAName(TestJsDeobfuscator):

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def test_typeof_of_a_key_whose_getter_returns_a_name_is_left_packed(self):
        rows = [
            'Function("p", "console.log(typeof p.g)")({ get g() {\n  return someGlobal;\n} });',
            'Function("p", "console.log(typeof (p.g))")({ get g() {\n  return someGlobal;\n} });',
        ]
        self.assertEqual(
            {source: self._reflect(source) for source in rows},
            {source: source for source in rows},
        )

    def test_a_key_whose_getter_returns_typeof_of_a_name_is_unpacked(self):
        self.assertEqual(
            'console.log(typeof someGlobal);',
            self._reflect(
                'Function("p", "console.log(p.t)")({ get t() { return typeof someGlobal; } });'
            ),
        )


class TestAPackedCompoundWriteBecomesTheSameOperatorOnTheName(TestJsDeobfuscator):

    ACCESSORS = '({ get k() { return counter; }, set k(v) { return counter = v; } })'
    LOOP_HEADS = (
        'Function("p", "for (p.k in {a: 1}); console.log(p.k); for (p.k of [2]); console.log(p.k);")'
        F'{ACCESSORS};'
    )

    def _reflect(self, source: str) -> str:
        return self._run_transformer(
            source, JsReflectionInlining, DeobfuscationOptions(execution=ExecutionModel.commonjs)
        )

    def test_each_compound_write_and_update_becomes_the_same_operator_on_the_name(self):
        body = 'p.k = 0; p.k += 15; p.k++; --p.k; p.k ||= 3; (p.k) **= 2; console.log(p.k);'
        source = F'Function("p", "{body}"){self.ACCESSORS};'
        self.assertEqual(
            self._reflect(source),
            inspect.cleandoc(
                """
                counter = 0;
                counter += 15;
                counter++;
                --counter;
                counter ||= 3;
                (counter) **= 2;
                console.log(counter);
                """
            ),
        )

    def test_a_compound_write_through_a_getter_and_a_setter_naming_different_variables_stays_packed(self):
        source = 'Function("p", "p.k += 1;")({ get k() {\n  return a;\n}, set k(v) {\n  return b = v;\n} });'
        self.assertEqual(self._reflect(source), source)

    def test_a_compound_write_through_a_key_with_no_setter_stays_packed(self):
        source = 'Function("p", "p.k += 1;")({ get k() {\n  return a;\n} });'
        self.assertEqual(self._reflect(source), source)

    def test_a_delete_through_the_accessor_object_stays_packed(self):
        source = (
            'Function("p", "console.log(delete p.k);")'
            '({ get k() {\n  return counter;\n}, set k(v) {\n  return counter = v;\n} });'
        )
        self.assertEqual(self._reflect(source), source)

    def test_a_for_in_and_a_for_of_head_through_the_accessor_object_become_heads_on_the_name(self):
        self.assertEqual(
            self._reflect(self.LOOP_HEADS),
            inspect.cleandoc(
                """
                for (counter in { a: 1 }) {
                  ;
                }
                console.log(counter);
                for (counter of [2]) {
                  ;
                }
                console.log(counter);
                """
            ),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_for_the_loop_heads_on_the_name(self):
        self.assertEqual(
            [behavior(self.LOOP_HEADS), behavior(self._reflect(self.LOOP_HEADS))],
            [('a\n2\n', None), ('a\n2\n', None)],
        )

    def test_a_write_to_a_target_the_language_refuses_stays_packed(self):
        rows = [
            F'Function("p", "p?.k += 1;"){self.ACCESSORS};',
            F'Function("p", "[p.k] += 1;"){self.ACCESSORS};',
            F'Function("p", "p?.k = 1;"){self.ACCESSORS};',
        ]
        self.assertEqual(
            {source: self._reflect(source) for source in rows},
            {source: printed(source) for source in rows},
        )


class TestAPackTheBareNamesDoNotReproduce(TestJsDeobfuscator):

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def test_a_pack_whose_parameter_text_is_no_single_name_stays_packed(self):
        rows = [
            'Function("a,b", "console.log(typeof a, typeof b);")({});',
            'Function("...p", "console.log(p.length);")({});',
            'Function("p = 1", "console.log(p);")({});',
        ]
        self.assertEqual(
            {source: self._reflect(source) for source in rows},
            {source: printed(source) for source in rows},
        )

    def test_a_pack_whose_parameter_is_padded_with_whitespace_is_unpacked(self):
        self.assertEqual(
            self._reflect('Function(" p ", "console.log(p.k);")({ get k() { return x; } });'),
            'console.log(x);',
        )

    def test_a_call_through_a_getter_returning_eval_stays_packed(self):
        source = 'Function("p", "console.log(p.e(\'typeof y\'));")({ get e() { return eval; } });'
        self.assertEqual(self._reflect(source), printed(source))
