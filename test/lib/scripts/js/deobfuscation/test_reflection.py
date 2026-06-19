from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.reflection import JsReflectionInlining


class TestReflectionInlining(TestJsDeobfuscator):

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

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

    def test_settimeout_string(self):
        self.assertEqual('alert(1);', self._reflect("setTimeout('alert(1)', 0);"))

    def test_setinterval_string(self):
        self.assertEqual('doStuff();', self._reflect("setInterval('doStuff()', 1000);"))

    def test_settimeout_non_string_not_inlined(self):
        self.assertEqual('setTimeout(fn, 0);', self._reflect('setTimeout(fn, 0);'))

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
