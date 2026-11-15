from __future__ import annotations

import inspect

from test import opportunity
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.singleuse import JsSingleUseFunctionInliner
from refinery.lib.scripts.js.options import DeobfuscationOptions, ExecutionModel


class TestSingleUseFunctionInliner(TestJsDeobfuscator):

    def _singleuse(self, source: str) -> str:
        return self._run_transformer(source, JsSingleUseFunctionInliner)

    def test_a_top_level_function_called_once_at_a_bare_statement_folds(self):
        self.assertEqual(
            'print(1);',
            self._singleuse(inspect.cleandoc("""
                function w() {
                  print(1);
                }
                w();
            """)))

    def test_a_free_name_of_the_body_keeps_resolving_to_the_same_binding(self):
        self.assertEqual(
            inspect.cleandoc("""
                var g = 1;
                print(g);
            """),
            self._singleuse(inspect.cleandoc("""
                var g = 1;
                function w() {
                  print(g);
                }
                w();
            """)))

    def test_a_trailing_return_becomes_the_expression_its_value_fed(self):
        source = inspect.cleandoc(
            """
            function w() {
              print(1);
              return print(2);
            }
            w();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                print(1);
                print(2);
                """
            ),
            self._singleuse(source),
        )

    def test_a_valueless_trailing_return_is_dropped(self):
        self.assertEqual(
            'print(1);',
            self._singleuse(inspect.cleandoc("""
                function w() {
                  print(1);
                  return;
                }
                w();
            """)))

    def test_an_empty_body_folds_to_nothing(self):
        self.assertEqual('', self._singleuse(inspect.cleandoc("""
            function w() {
            }
            w();
        """)))

    def test_a_function_declaration_inside_the_body_folds_with_it(self):
        self.assertEqual(
            inspect.cleandoc("""
                function inner() {
                  print(1);
                }
                inner();
            """),
            self._singleuse(
                inspect.cleandoc("""
                    function w() {
                      function inner() {
                        print(1);
                      }
                      inner();
                    }
                    w();
                """)))

    def test_two_wrappers_fold_within_two_passes(self):
        once = self._singleuse(
            inspect.cleandoc("""
                function a() {
                  print(1);
                }
                a();
                function b() {
                  print(2);
                }
                b();
            """))
        self.assertEqual(
            inspect.cleandoc(
                """
                print(1);
                print(2);
                """
            ),
            self._singleuse(once),
        )

    def test_a_commonjs_wrapper_name_declared_in_the_body_keeps_the_wrapper(self):
        rows = [
            inspect.cleandoc(
                """
                function w() {
                  let module = [];
                  print(module.length);
                }
                w();
                """
            ),
            inspect.cleandoc(
                """
                function w() {
                  var exports;
                  print(typeof exports);
                }
                w();
                """
            ),
        ]
        for execution in (ExecutionModel.commonjs, ExecutionModel.module):
            options = DeobfuscationOptions(execution=execution)
            with self.subTest(execution.name):
                self.assertEqual(
                    {
                        source: self._run_transformer(source, JsSingleUseFunctionInliner, options)
                        for source in rows
                    },
                    {source: source for source in rows},
                )

    def test_a_commonjs_wrapper_name_declared_in_the_body_folds_into_a_script(self):
        source = inspect.cleandoc(
            """
            function w() {
              let module = [];
              print(module.length);
            }
            w();
            """
        )
        self.assertEqual(
            self._singleuse(source),
            inspect.cleandoc(
                """
                let module = [];
                print(module.length);
                """
            ),
        )

    def test_a_reflection_surface_that_runs_unread_code_refuses_the_fold(self):
        source = inspect.cleandoc(
            """
            var e = eval;
            function w() {
              print(1);
            }
            w();
            e(code);
            """
        )
        self.assertEqual(source, self._singleuse(source))

    @opportunity
    def test_an_eval_alias_nothing_calls_does_not_refuse_the_fold(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var e = eval;
                print(1);
                """
            ),
            self._singleuse(inspect.cleandoc(
                """
                var e = eval;
                function w() {
                  print(1);
                }
                w();
                """
            )),
        )

    def test_a_wrapper_invoked_before_its_declaration_folds(self):
        self.assertEqual(
            'print(1);',
            self._singleuse(inspect.cleandoc("""
                w();
                function w() {
                  print(1);
                }
            """)))

    def test_a_second_read_of_the_name_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function w() {
              print(1);
            }
            w();
            w();
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_read_handing_the_function_elsewhere_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function w() {
              print(1);
            }
            var g = w;
            w();
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_write_of_the_name_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function w() {
              print(1);
            }
            w = 1;
            w();
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_conditional_invocation_refuses_the_fold(self):
        source = inspect.cleandoc("""
            var c = 1;
            function w() {
              print(1);
            }
            if (c) {
              w();
            }
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_an_invocation_inside_a_loop_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function w() {
              print(1);
            }
            for (var i = 0; i < 2; i++) {
              w();
            }
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_function_bound_elsewhere_than_the_script_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function outer(c) {
              function w() {
                print(1);
              }
              if (c) {
                w();
              }
            }
            outer(1);
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_parameterized_wrapper_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function w(a) {
              print(a);
            }
            w(1);
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_an_async_wrapper_refuses_the_fold(self):
        source = inspect.cleandoc("""
            async function w() {
              print(1);
            }
            w();
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_generator_wrapper_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function* w() {
              yield 1;
            }
            w();
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_body_reading_arguments_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function w() {
              print(arguments);
            }
            w();
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_body_reading_this_refuses_the_fold_in_a_commonjs_file(self):
        source = inspect.cleandoc("""
            function w() {
              print(this);
            }
            w();
        """)
        options = DeobfuscationOptions(execution=ExecutionModel.commonjs)
        self.assertEqual(source, self._run_transformer(source, JsSingleUseFunctionInliner, options))

    @opportunity
    def test_a_body_reading_this_folds_into_a_classic_script(self):
        self.assertEqual('print(this);', self._singleuse(inspect.cleandoc("""
            function w() {
              print(this);
            }
            w();
        """)))

    def test_a_body_reading_new_target_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function w() {
              print(new.target);
            }
            w();
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_body_declaring_use_strict_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function w() {
              'use strict';
              print(1);
            }
            w();
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_nested_return_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function w() {
              if (1) {
                return;
              }
              print(1);
            }
            w();
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_direct_eval_of_unread_code_in_the_body_refuses_the_fold(self):
        source = inspect.cleandoc(
            """
            function w() {
              eval(code);
            }
            w();
            """
        )
        self.assertEqual(source, self._singleuse(source))

    def test_a_body_declaration_clashing_at_the_script_refuses_the_fold(self):
        source = inspect.cleandoc("""
            var h = 1;
            function w() {
              var h = 2;
              print(h);
            }
            w();
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_nested_function_clashing_at_the_script_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function h() {
              print(1);
            }
            function w() {
              function h() {
                print(2);
              }
              h();
            }
            w();
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_body_declaration_under_a_surface_running_unread_code_refuses_the_fold(self):
        source = inspect.cleandoc("""
            var e = eval;
            function w() {
              var q = 1;
              print(q);
            }
            w();
            e(code);
        """)
        self.assertEqual(source, self._singleuse(source))

    @opportunity
    def test_a_body_declaration_beside_an_eval_alias_nothing_calls_folds(self):
        source = inspect.cleandoc(
            """
            var e = eval;
            function w() {
              var q = 1;
              print(q);
            }
            w();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var e = eval;
                var q = 1;
                print(q);
                """
            ),
            self._singleuse(source),
        )

    def test_an_effectful_invocation_argument_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function w() {
              print(1);
            }
            w(print(2));
        """)
        self.assertEqual(source, self._singleuse(source))

    def test_a_body_declaration_the_analyst_names_an_entrypoint_is_renamed_where_it_lands(self):
        source = inspect.cleandoc("""
            function w() {
              var m = 1;
              print(m);
            }
            w();
        """)
        self.assertEqual(
            inspect.cleandoc("""
                var m_1 = 1;
                print(m_1);
            """),
            self._run_transformer(
                source, JsSingleUseFunctionInliner, DeobfuscationOptions(entrypoints=('m',))))

    def test_a_body_declaration_a_pattern_names_under_every_suffix_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function w() {
              var m = 1;
              print(m);
            }
            w();
        """)
        self.assertEqual(
            source,
            self._run_transformer(
                source, JsSingleUseFunctionInliner, DeobfuscationOptions(entrypoints=('m*',))))

    def test_a_body_declaration_read_through_the_shorthand_proto_refuses_the_fold(self):
        source = inspect.cleandoc("""
            function w() {
              var __proto__ = 1;
              print({ __proto__ });
            }
            w();
        """)
        self.assertEqual(
            source,
            self._run_transformer(
                source, JsSingleUseFunctionInliner, DeobfuscationOptions(entrypoints=('__proto__',))))

    def test_a_wrapper_declared_under_a_name_a_browser_reads_folds(self):
        self.assertEqual('print(1);', self._singleuse(inspect.cleandoc("""
            function name() {
              print(1);
            }
            name();
        """)))
