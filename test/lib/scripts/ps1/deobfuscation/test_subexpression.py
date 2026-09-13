from __future__ import annotations

import unittest

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import (
    Ps1FunctionEvaluator,
    Ps1SubExpressionEvaluator,
)

#: The key and bytes that spell the two characters the XOR idiom test builds, so that the fold has
#: a real exclusive-or to run rather than one against zero.
XOR_KEY = 152
XOR_BYTES = (211, 204)
XOR_TEXT = 'KT'


class TestPs1SubExpressionEvaluator(TestPs1):

    def test_the_xor_idiom_folds_to_its_value(self):
        source = cleandoc(F"""
            $m = $($a = @{XOR_BYTES!r}
            $r = ''
            for ($i = 0; $i -lt $a.Count; $i++) {{
              $r = $r + [char]($a[$i] -bxor {XOR_KEY})
            }}
            $r)
        """)
        self.assertEqual(self._deobfuscate(source), F'$m = {XOR_TEXT!r}')

    def test_the_fold_lands_as_one_literal_statement(self):
        source = cleandoc(F"""
            $m = $($a = @{XOR_BYTES!r}
            $r = ''
            for ($i = 0; $i -lt $a.Count; $i++) {{
              $r = $r + [char]($a[$i] -bxor {XOR_KEY})
            }}
            $r)
        """)
        self.assertEqual(
            self._apply(source, Ps1SubExpressionEvaluator),
            F'$m = $({XOR_TEXT!r})',
        )

    def test_a_bare_literal_body_is_left_to_the_value_domain(self):
        self._assertUnchanged("$x = $('a')", Ps1SubExpressionEvaluator)

    def test_an_operator_bearing_expression_body_folds(self):
        self.assertEqual(
            self._apply("$x = $('a' + 'b')", Ps1SubExpressionEvaluator),
            "$x = $('ab')",
        )

    def test_a_read_of_a_name_written_outside_refuses(self):
        self._assertUnchanged(cleandoc("""
            $q = 5
            $x = $($q + 1)
        """), Ps1SubExpressionEvaluator)

    def test_a_read_of_an_enclosing_functions_parameter_refuses(self):
        self._assertUnchanged(cleandoc("""
            function f {
              Param($p)
              $x = $($p + 1)
            }
        """), Ps1SubExpressionEvaluator)

    def test_a_read_of_an_enclosing_loop_variable_refuses(self):
        self._assertUnchanged(cleandoc("""
            foreach ($i in 1..2) {
              $x = $($i + 1)
            }
        """), Ps1SubExpressionEvaluator)

    def test_a_read_of_an_automatic_variable_refuses(self):
        self._assertUnchanged('$x = $($args + 1)', Ps1SubExpressionEvaluator)

    def test_a_read_of_a_session_variable_refuses(self):
        # `$FormatEnumerationLimit` is `4` in every session, so this body is `5`; reading it as the
        # `$null` an isolated fold sees would fold the sub-expression to `$(1)`.
        self._assertUnchanged('$x = $($FormatEnumerationLimit + 1)', Ps1SubExpressionEvaluator)

    def test_a_call_without_arguments_reading_args_is_refused(self):
        self._assertUnchanged(cleandoc("""
            function f {
              ,$args
            }
            $t = f
        """), Ps1FunctionEvaluator)

    def test_a_command_addressed_write_refuses_the_read(self):
        self._assertUnchanged(cleandoc("""
            Set-Variable s 'A'
            $x = $($s + 'B')
        """), Ps1SubExpressionEvaluator)

    def test_a_command_addressed_reader_of_a_body_write_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $($w = 'a'
            $w)
            Get-Variable w -ValueOnly
        """), Ps1SubExpressionEvaluator)

    def test_a_computed_name_write_refuses_never_bound_reads(self):
        self._assertUnchanged(cleandoc("""
            Set-Variable $n 'v' -Scope Global
            $x = $($q + 'x')
        """), Ps1SubExpressionEvaluator)

    def test_a_command_addressed_write_refuses_a_function_reading_it(self):
        self._assertUnchanged(cleandoc("""
            Set-Variable q 5
            function fq {
              $q + 1
            }
            fq
        """), Ps1FunctionEvaluator)

    def test_a_never_bound_read_folds_where_nothing_runs_data(self):
        self.assertEqual(
            self._apply("$x = $($q + 'x')", Ps1SubExpressionEvaluator),
            "$x = $('x')",
        )

    def test_a_never_bound_read_refuses_where_code_runs_from_data(self):
        self._assertUnchanged(cleandoc("""
            iex '$u = 5'
            $x = $($u + 'x')
        """), Ps1SubExpressionEvaluator)

    @unittest.expectedFailure
    def test_a_body_write_a_later_iex_could_read_is_not_dropped(self):
        """
        A `$(...)` runs in the scope it is written in, so `$w` survives it and code `iex` runs in
        that scope can read the value the body left. Folding the body away drops the `$w = 'PAYLOAD'`
        store, so the `iex`'d code reads the `$null` of a fresh scope where 5.1 gives it `'PAYLOAD'`.
        The reads side already refuses a body read of a never-written name when data-code runs; the
        symmetric write-leak guard would refuse this, but it would also refuse the scratch writes of
        the canonical decode-then-`iex` fold, a tradeoff not yet made.
        """
        self._assertUnchanged(cleandoc("""
            $x = $($w = 'PAYLOAD'
            $w)
            iex $stager
        """), Ps1SubExpressionEvaluator)

    def test_a_self_reading_accumulator_refuses(self):
        self._assertUnchanged(cleandoc("""
            foreach ($j in 1..2) {
              $y = $($c = $c + 'x'
              $c)
            }
        """), Ps1SubExpressionEvaluator)

    def test_a_compound_self_assignment_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $($c += 'x'
            $c)
        """), Ps1SubExpressionEvaluator)

    def test_an_increment_of_the_accumulated_name_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $($c++
            $c)
        """), Ps1SubExpressionEvaluator)

    def test_a_conditional_first_write_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $(if (0) {
              $m = 'A'
            }
            $o = "${m}"
            $m = 'B'
            $o)
        """), Ps1SubExpressionEvaluator)

    def test_a_zero_iteration_foreach_binding_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $(foreach ($e in @()) {}
            $o = "${e}"
            $e = 'B'
            $o)
        """), Ps1SubExpressionEvaluator)

    def test_a_for_initializer_self_read_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $(for ($c = $c + 'x'; $c -lt 2; $c++) {}
            $c)
        """), Ps1SubExpressionEvaluator)

    def test_a_read_after_a_certain_store_folds_inside_a_loop(self):
        self.assertEqual(
            self._apply(cleandoc("""
                foreach ($j in 1..3) {
                  $x = $($s = ''
                  $s = $s + 'a'
                  $s)
                }
            """), Ps1SubExpressionEvaluator),
            cleandoc("""
                foreach ($j in 1..3) {
                  $x = $('a')
                }
            """),
        )

    def test_a_foreach_binding_read_inside_its_own_body_folds(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $(foreach ($e in 'a', 'b') {
                  $e
                })
            """), Ps1SubExpressionEvaluator),
            "$x = $('a', 'b')",
        )

    def test_a_dropped_null_emission_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $('a'
            $z
            'b')
        """), Ps1SubExpressionEvaluator)

    def test_a_body_emitting_nothing_stays(self):
        self._assertUnchanged(cleandoc("""
            $x = $(if (0) {
              'a'
            })
        """), Ps1SubExpressionEvaluator)

    def test_a_loop_exit_or_return_in_the_body_refuses(self):
        for word in ('return', 'break', 'continue'):
            with self.subTest(word):
                self._assertUnchanged(cleandoc(F"""
                    $x = $('a'
                    {word}
                    'b')
                """), Ps1SubExpressionEvaluator)

    def test_an_invoke_expression_in_the_body_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $(iex '5'
            'a')
        """), Ps1SubExpressionEvaluator)

    def test_a_redirected_pipeline_in_the_body_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $('a'
            >
            $Null
            'b')
        """), Ps1SubExpressionEvaluator)

    def test_a_write_read_outside_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $($w = 'a'
            $w)
            Write-Output $w
        """), Ps1SubExpressionEvaluator)

    def test_a_write_read_outside_through_a_function_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $($w = 'a'
            $w)
            function g {
              Write-Output $w
            }
        """), Ps1SubExpressionEvaluator)

    def test_a_match_body_refuses_because_it_refills_the_engine_matches(self):
        self._assertUnchanged(cleandoc("""
            $x = $('abc' -match 'b'
            'v')
        """), Ps1SubExpressionEvaluator)

    def test_a_replace_with_an_outside_matches_reader_folds(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $('abc' -replace 'b', 'x')
                $y = $Matches[1]
            """), Ps1SubExpressionEvaluator),
            cleandoc("""
                $x = $('axc')
                $y = $Matches[1]
            """),
        )

    def test_an_engine_variable_write_refuses(self):
        for name, value in (('OFS', "'-'"), ('ErrorActionPreference', "'Stop'")):
            with self.subTest(name):
                self._assertUnchanged(cleandoc(F"""
                    $x = $(${name} = {value}
                    'ok')
                """), Ps1SubExpressionEvaluator)

    def test_a_string_part_folds_to_its_interpolated_text(self):
        self.assertEqual(
            self._deobfuscate('''"$($s = 'a'
$s)x"'''),
            "'ax'",
        )

    def test_a_double_in_a_string_part_folds_as_its_text(self):
        self.assertEqual(
            self._deobfuscate('''"$($r = 1.5
$r)x"'''),
            "'1.5x'",
        )

    def test_a_user_function_call_inside_the_body_declines(self):
        self._assertUnchanged(cleandoc("""
            function g {
              'a'
            }
            $x = $(g
            'b')
        """), Ps1SubExpressionEvaluator)


if __name__ == '__main__':
    unittest.main()
