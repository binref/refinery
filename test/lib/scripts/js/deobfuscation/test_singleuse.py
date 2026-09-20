from __future__ import annotations

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.singleuse import JsSingleUseFunctionInliner
from refinery.lib.scripts.js.options import DeobfuscationOptions


class TestSingleUseFunctionInliner(TestJsDeobfuscator):

    def _singleuse(self, source: str) -> str:
        return self._run_transformer(source, JsSingleUseFunctionInliner)

    def test_a_top_level_function_called_once_at_a_bare_statement_folds(self):
        self.assertEqual(
            'print(1);',
            self._singleuse('function w() {\n  print(1);\n}\nw();'))

    def test_a_free_name_of_the_body_keeps_resolving_to_the_same_binding(self):
        self.assertEqual(
            'var g = 1;\nprint(g);',
            self._singleuse('var g = 1;\nfunction w() {\n  print(g);\n}\nw();'))

    def test_a_trailing_return_becomes_the_expression_its_value_fed(self):
        self.assertEqual(
            'print(1);\n2;',
            self._singleuse('function w() {\n  print(1);\n  return 2;\n}\nw();'))

    def test_a_valueless_trailing_return_is_dropped(self):
        self.assertEqual(
            'print(1);',
            self._singleuse('function w() {\n  print(1);\n  return;\n}\nw();'))

    def test_an_empty_body_folds_to_nothing(self):
        self.assertEqual('', self._singleuse('function w() {\n}\nw();'))

    def test_a_function_declaration_inside_the_body_folds_with_it(self):
        self.assertEqual(
            'function inner() {\n  print(1);\n}\ninner();',
            self._singleuse(
                'function w() {\n'
                '  function inner() {\n'
                '    print(1);\n'
                '  }\n'
                '  inner();\n'
                '}\n'
                'w();'))

    def test_two_wrappers_fold_one_per_pass(self):
        once = self._singleuse(
            'function a() {\n'
            '  print(1);\n'
            '}\n'
            'a();')
        self.assertEqual('print(1);', self._singleuse(once))

    def test_a_reflection_surface_refuses_the_fold(self):
        source = 'var e = eval;\nfunction w() {\n  print(1);\n}\nw();'
        self.assertEqual(source, self._singleuse(source))

    def test_a_wrapper_invoked_before_its_declaration_folds(self):
        self.assertEqual(
            'print(1);',
            self._singleuse('w();\nfunction w() {\n  print(1);\n}'))

    def test_a_second_read_of_the_name_refuses_the_fold(self):
        source = 'function w() {\n  print(1);\n}\nw();\nw();'
        self.assertEqual(source, self._singleuse(source))

    def test_a_read_handing_the_function_elsewhere_refuses_the_fold(self):
        source = 'function w() {\n  print(1);\n}\nvar g = w;\nw();'
        self.assertEqual(source, self._singleuse(source))

    def test_a_write_of_the_name_refuses_the_fold(self):
        source = 'function w() {\n  print(1);\n}\nw = 1;\nw();'
        self.assertEqual(source, self._singleuse(source))

    def test_a_conditional_invocation_refuses_the_fold(self):
        source = (
            'var c = 1;\n'
            'function w() {\n'
            '  print(1);\n'
            '}\n'
            'if (c) {\n'
            '  w();\n'
            '}')
        self.assertEqual(source, self._singleuse(source))

    def test_an_invocation_inside_a_loop_refuses_the_fold(self):
        source = (
            'function w() {\n'
            '  print(1);\n'
            '}\n'
            'for (var i = 0; i < 2; i++) {\n'
            '  w();\n'
            '}')
        self.assertEqual(source, self._singleuse(source))

    def test_a_function_bound_elsewhere_than_the_script_refuses_the_fold(self):
        source = (
            'function outer(c) {\n'
            '  function w() {\n'
            '    print(1);\n'
            '  }\n'
            '  if (c) {\n'
            '    w();\n'
            '  }\n'
            '}\n'
            'outer(1);')
        self.assertEqual(source, self._singleuse(source))

    def test_a_parameterized_wrapper_refuses_the_fold(self):
        source = 'function w(a) {\n  print(a);\n}\nw(1);'
        self.assertEqual(source, self._singleuse(source))

    def test_an_async_wrapper_refuses_the_fold(self):
        source = 'async function w() {\n  print(1);\n}\nw();'
        self.assertEqual(source, self._singleuse(source))

    def test_a_generator_wrapper_refuses_the_fold(self):
        source = 'function* w() {\n  yield 1;\n}\nw();'
        self.assertEqual(source, self._singleuse(source))

    def test_a_body_reading_arguments_refuses_the_fold(self):
        source = 'function w() {\n  print(arguments);\n}\nw();'
        self.assertEqual(source, self._singleuse(source))

    def test_a_body_reading_this_refuses_the_fold(self):
        source = 'function w() {\n  print(this);\n}\nw();'
        self.assertEqual(source, self._singleuse(source))

    def test_a_body_reading_new_target_refuses_the_fold(self):
        source = 'function w() {\n  print(new.target);\n}\nw();'
        self.assertEqual(source, self._singleuse(source))

    def test_a_body_declaring_use_strict_refuses_the_fold(self):
        source = 'function w() {\n  \'use strict\';\n  print(1);\n}\nw();'
        self.assertEqual(source, self._singleuse(source))

    def test_a_nested_return_refuses_the_fold(self):
        source = (
            'function w() {\n'
            '  if (1) {\n'
            '    return;\n'
            '  }\n'
            '  print(1);\n'
            '}\n'
            'w();')
        self.assertEqual(source, self._singleuse(source))

    def test_a_direct_eval_in_the_body_refuses_the_fold(self):
        source = 'function w() {\n  eval(\'print(1);\');\n}\nw();'
        self.assertEqual(source, self._singleuse(source))

    def test_a_body_declaration_clashing_at_the_script_refuses_the_fold(self):
        source = 'var h = 1;\nfunction w() {\n  var h = 2;\n  print(h);\n}\nw();'
        self.assertEqual(source, self._singleuse(source))

    def test_a_nested_function_clashing_at_the_script_refuses_the_fold(self):
        source = (
            'function h() {\n'
            '  print(1);\n'
            '}\n'
            'function w() {\n'
            '  function h() {\n'
            '    print(2);\n'
            '  }\n'
            '  h();\n'
            '}\n'
            'w();')
        self.assertEqual(source, self._singleuse(source))

    def test_a_body_declaration_under_a_reflection_surface_refuses_the_fold(self):
        source = (
            'var e = eval;\n'
            'function w() {\n'
            '  var q = 1;\n'
            '  print(q);\n'
            '}\n'
            'w();')
        self.assertEqual(source, self._singleuse(source))

    def test_an_effectful_invocation_argument_refuses_the_fold(self):
        source = 'function w() {\n  print(1);\n}\nw(print(2));'
        self.assertEqual(source, self._singleuse(source))

    def test_a_body_declaration_the_analyst_names_an_entrypoint_refuses_the_fold(self):
        source = 'function w() {\n  var m = 1;\n  print(m);\n}\nw();'
        self.assertEqual(
            source,
            self._run_transformer(
                source, JsSingleUseFunctionInliner, DeobfuscationOptions(entrypoints=('m',))))
