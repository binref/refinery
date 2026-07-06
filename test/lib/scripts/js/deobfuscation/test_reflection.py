from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.options import DeobfuscationOptions
from refinery.lib.scripts.js.deobfuscation.reflection import JsReflectionInlining


class TestReflectionInlining(TestJsDeobfuscator):

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def _reflect_module(self, source: str) -> str:
        return self._run_transformer(
            source, JsReflectionInlining, DeobfuscationOptions(module=True))

    def test_eval_string_literal(self):
        self.assertEqual('var x = 1;', self._reflect("eval('var x = 1;');"))

    def test_eval_non_literal_not_inlined(self):
        self.assertEqual('eval(x);', self._reflect('eval(x);'))

    def test_eval_parenthesized(self):
        self.assertEqual('var x = 1;', self._reflect("(eval)('var x = 1;');"))

    def test_indirect_eval_comma_operator(self):
        self.assertEqual('var x = 1;', self._reflect("(0, eval)('var x = 1;');"))

    def test_indirect_eval_window(self):
        self.assertEqual('var x = 1;', self._reflect("window.eval('var x = 1;');"))

    def test_indirect_eval_globalthis(self):
        self.assertEqual('var x = 1;', self._reflect("globalThis.eval('var x = 1;');"))

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

    def test_indirect_eval_identifier_prefix_outside_with_still_inlined(self):
        self.assertEqual('f();', self._reflect("(e, eval)('f()');"))

    def test_settimeout_string(self):
        self.assertEqual('alert(1);', self._reflect("setTimeout('alert(1)', 0);"))

    def test_setinterval_string(self):
        self.assertEqual('doStuff();', self._reflect("setInterval('doStuff()', 1000);"))

    def test_settimeout_non_string_not_inlined(self):
        self.assertEqual('setTimeout(fn, 0);', self._reflect('setTimeout(fn, 0);'))

    def test_module_indirect_eval_declaration_not_inlined(self):
        self.assertEqual(
            "(0, eval)('var x = 1;');",
            self._reflect_module("(0, eval)('var x = 1;');"))

    def test_module_timer_declaration_not_inlined(self):
        self.assertEqual(
            "setTimeout('var x = 1;', 0);",
            self._reflect_module("setTimeout('var x = 1;', 0);"))

    def test_module_direct_eval_declaration_still_inlined(self):
        self.assertEqual('var x = 1;', self._reflect_module("eval('var x = 1;');"))

    def test_module_indirect_eval_expression_still_inlined(self):
        self.assertEqual('foo();', self._reflect_module("(0, eval)('foo();');"))

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

    def test_member_form_string_timer_inlined(self):
        self.assertEqual('alert(1);', self._reflect("window.setTimeout('alert(1)', 0);"))

    def test_member_form_string_interval_inlined(self):
        self.assertEqual('tick();', self._reflect("globalThis.setInterval('tick()', 100);"))

    def test_execscript_string_inlined(self):
        self.assertEqual('run();', self._reflect("execScript('run()');"))

    def test_member_form_function_timer_not_inlined(self):
        self.assertEqual(
            'window.setTimeout(fn, 0);', self._reflect('window.setTimeout(fn, 0);'))

    def test_top_alias_indirect_eval_inlined(self):
        self.assertEqual('var x = 1;', self._reflect("top.eval('var x = 1;');"))

    def test_new_function_body_invoked(self):
        self.assertEqual('42;', self._reflect("new Function('return 42')();"))

    def test_function_constructor_body_invoked(self):
        self.assertEqual('42;', self._reflect("Function('return 42')();"))

    def test_constructor_chain_string(self):
        self.assertEqual('1;', self._reflect("''.constructor.constructor('return 1')();"))

    def test_constructor_chain_array(self):
        self.assertEqual('1;', self._reflect("[].constructor.constructor('return 1')();"))

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

    def test_await_eval_inlined(self):
        source = inspect.cleandoc(
            """
            async function run() {
              await eval("var a = 1; var b = 2;");
            }
            run();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                async function run() {
                  var a = 1;
                  var b = 2;
                }
                run();
                """
            ),
            self._reflect(source),
        )

    def test_await_eval_with_top_level_await(self):
        source = inspect.cleandoc(
            """
            async function run() {
              await eval("await fetch('x'); var a = 1;");
            }
            run();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                async function run() {
                  (async () => {
                    await fetch('x');
                    var a = 1;
                  })();
                }
                run();
                """
            ),
            self._reflect(source),
        )

    def test_await_eval_nested_async_not_wrapped(self):
        source = inspect.cleandoc(
            """
            async function run() {
              await eval("const g = async () => { await fetch('x'); }; g();");
            }
            run();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                async function run() {
                  const g = async () => {
                    await fetch('x');
                  };
                  g();
                }
                run();
                """
            ),
            self._reflect(source),
        )

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

    def test_function_constructor_with_parameter_not_inlined(self):
        self.assertEqual(
            "new Function('a', 'return a')(5);",
            self._reflect("new Function('a', 'return a')(5);"),
        )

    def test_function_constructor_referencing_this_not_inlined(self):
        self.assertEqual(
            "new Function('return this.x')();",
            self._reflect("new Function('return this.x')();"),
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

    def test_function_constructor_body_var_redeclares_caller_not_inlined(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            new Function('var x = 2;')();
            console.log(x);
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_body_function_declaration_hoists_not_inlined(self):
        source = inspect.cleandoc(
            """
            function g() {
              return 1;
            }
            new Function('function g(){ return 2; }')();
            g();
            """
        )
        self.assertEqual(source, self._reflect(source))

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

    def test_function_constructor_body_var_captured_by_caller_closure_not_inlined(self):
        source = inspect.cleandoc(
            """
            function f() {
              new Function('var x = 1;')();
              return function() {
                return x;
              };
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

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

    def test_function_constructor_body_var_crosses_block_let_not_inlined(self):
        source = inspect.cleandoc(
            """
            {
              let x = 9;
              new Function('var x = 1;')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_body_var_crosses_for_let_not_inlined(self):
        source = inspect.cleandoc(
            """
            function f() {
              for (let i = 0; i < 3; i++) {
                new Function('var i = 99;')();
              }
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

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

    def test_function_constructor_in_strict_function_not_inlined(self):
        source = inspect.cleandoc(
            """
            function f() {
              'use strict';
              return new Function('return 010')();
            }
            """
        )
        self.assertEqual(source, self._reflect(source))

    def test_function_constructor_in_strict_script_not_inlined(self):
        source = inspect.cleandoc(
            """
            'use strict';
            var x = new Function('return 010')();
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
