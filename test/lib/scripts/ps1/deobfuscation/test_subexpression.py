from __future__ import annotations

import unittest

from inspect import cleandoc

from test import backlog, opportunity, todo
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import (
    Ps1FunctionEvaluator,
    Ps1SubExpressionEvaluator,
)

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

    def test_a_char_result_folds_at_its_own_type(self):
        self.assertEqual(
            self._apply('$x = $($r = [char]66\n$r)', Ps1SubExpressionEvaluator),
            '$x = $([char]66)',
        )

    def test_a_char_array_body_folds_to_the_collection_it_collapses_to(self):
        self.assertEqual(
            self._apply('$x = $($r = [char[]]\'AB\'\n$r)', Ps1SubExpressionEvaluator),
            '$x = $([char]65, [char]66)',
        )

    def test_a_byte_result_folds_at_its_own_width(self):
        self.assertEqual(
            self._apply('$x = $($r = [byte]77\n$r)', Ps1SubExpressionEvaluator),
            '$x = $([byte]77)',
        )

    def test_the_xor_idiom_retains_its_stores_where_code_runs_from_data(self):
        source = cleandoc(F"""
            $m = $($a = @{XOR_BYTES!r}
            $r = ''
            for ($i = 0; $i -lt $a.Count; $i++) {{
              $r = $r + [char]($a[$i] -bxor {XOR_KEY})
            }}
            $r)
            iex $stager
        """)
        self.assertEqual(
            self._apply(source, Ps1SubExpressionEvaluator),
            cleandoc(F"""
                $a = {XOR_BYTES[0]}, {XOR_BYTES[1]}
                $i = 2
                $r = '{XOR_TEXT}'
                $m = $('{XOR_TEXT}')
                iex $stager
            """),
        )

    def test_the_xor_idiom_retains_its_stores_where_a_created_block_runs(self):
        source = cleandoc(F"""
            $m = $($a = @{XOR_BYTES!r}
            $r = ''
            for ($i = 0; $i -lt $a.Count; $i++) {{
              $r = $r + [char]($a[$i] -bxor {XOR_KEY})
            }}
            $r)
            & ([System.Management.Automation.ScriptBlock]::Create($q))
        """)
        self.assertEqual(
            self._apply(source, Ps1SubExpressionEvaluator),
            cleandoc(F"""
                $a = {XOR_BYTES[0]}, {XOR_BYTES[1]}
                $i = 2
                $r = '{XOR_TEXT}'
                $m = $('{XOR_TEXT}')
                & ([System.Management.Automation.ScriptBlock]::Create($q))
            """),
        )

    def test_a_trusted_run_folds_the_idiom_without_retained_stores(self):
        source = cleandoc(F"""
            $m = $($a = @{XOR_BYTES!r}
            $r = ''
            for ($i = 0; $i -lt $a.Count; $i++) {{
              $r = $r + [char]($a[$i] -bxor {XOR_KEY})
            }}
            $r)
            iex $stager
        """)
        self.assertEqual(
            self._deobfuscate(source, trust_eval=True),
            'Invoke-Expression $stager',
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

    def test_a_command_addressed_reader_of_a_body_write_retains_its_store(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $($w = 'a'
                $w)
                Get-Variable w -ValueOnly
            """), Ps1SubExpressionEvaluator),
            cleandoc("""
                $w = 'a'
                $x = $('a')
                Get-Variable w -ValueOnly
            """),
        )

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

    def test_a_body_write_a_later_iex_could_read_is_retained(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $($w = 'PAYLOAD'
                $w)
                iex $stager
            """), Ps1SubExpressionEvaluator),
            cleandoc("""
                $w = 'PAYLOAD'
                $x = $('PAYLOAD')
                iex $stager
            """),
        )

    def test_a_self_reading_accumulator_refuses(self):
        self._assertUnchanged(cleandoc("""
            foreach ($j in 1..2) {
              $y = $($c = $c + 'x'
              $c)
            }
        """), Ps1SubExpressionEvaluator)

    @opportunity
    def test_a_compound_self_assignment_of_a_name_nothing_bound_folds_once_outside_a_loop(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $($c += 'x'
                $c)
            """), Ps1SubExpressionEvaluator),
            "$x = $('x')",
        )

    def test_a_compound_self_assignment_of_a_name_nothing_bound_is_left_alone_or_folded_once(self):
        source = cleandoc("""
            $x = $($c += 'x'
            $c)
        """)
        self.assertIn(self._apply(source, Ps1SubExpressionEvaluator), (source, "$x = $('x')"))

    @opportunity
    def test_an_increment_of_a_name_nothing_bound_folds_once_outside_a_loop(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $($c++
                $c)
            """), Ps1SubExpressionEvaluator),
            '$x = $(1)',
        )

    def test_an_increment_of_a_name_nothing_bound_is_left_alone_or_folded_once(self):
        source = cleandoc("""
            $x = $($c++
            $c)
        """)
        self.assertIn(self._apply(source, Ps1SubExpressionEvaluator), (source, '$x = $(1)'))

    @opportunity
    def test_a_read_before_a_conditional_first_write_folds_once_outside_a_loop(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $(if (0) {
                  $m = 'A'
                }
                $o = "${m}"
                $m = 'B'
                $o)
            """), Ps1SubExpressionEvaluator),
            "$x = $('')",
        )

    def test_a_read_before_a_conditional_first_write_is_left_alone_or_folded_once(self):
        source = cleandoc("""
            $x = $(if (0) {
              $m = 'A'
            }
            $o = "${m}"
            $m = 'B'
            $o)
        """)
        self.assertIn(self._apply(source, Ps1SubExpressionEvaluator), (source, "$x = $('')"))

    @opportunity
    def test_a_read_after_a_zero_iteration_foreach_binding_folds_once_outside_a_loop(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $(foreach ($e in @()) {}
                $o = "${e}"
                $e = 'B'
                $o)
            """), Ps1SubExpressionEvaluator),
            "$x = $('')",
        )

    def test_a_read_after_a_zero_iteration_foreach_binding_is_left_alone_or_folded_once(self):
        source = cleandoc("""
            $x = $(foreach ($e in @()) {}
            $o = "${e}"
            $e = 'B'
            $o)
        """)
        self.assertIn(self._apply(source, Ps1SubExpressionEvaluator), (source, "$x = $('')"))

    @opportunity
    def test_a_for_initializer_self_read_of_a_name_nothing_bound_folds_once_outside_a_loop(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $(for ($c = $c + 'x'; $c -lt 2; $c++) {}
                $c)
            """), Ps1SubExpressionEvaluator),
            "$x = $('x')",
        )

    def test_a_for_initializer_self_read_of_a_name_nothing_bound_is_left_alone_or_folded_once(self):
        source = cleandoc("""
            $x = $(for ($c = $c + 'x'; $c -lt 2; $c++) {}
            $c)
        """)
        self.assertIn(self._apply(source, Ps1SubExpressionEvaluator), (source, "$x = $('x')"))

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

    def test_a_write_read_outside_retains_its_store(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $($w = 'a'
                $w)
                Write-Output $w
            """), Ps1SubExpressionEvaluator),
            cleandoc("""
                $w = 'a'
                $x = $('a')
                Write-Output $w
            """),
        )

    def test_a_spelled_reader_survives_the_trusting_model(self):
        source = cleandoc(F"""
            $m = $($a = @{XOR_BYTES!r}
            $r = ''
            for ($i = 0; $i -lt $a.Count; $i++) {{
              $r = $r + [char]($a[$i] -bxor {XOR_KEY})
            }}
            $r)
            Write-Output $r
            iex $stager
        """)
        self.assertEqual(
            self._deobfuscate(source, trust_eval=True),
            F"Write-Output {XOR_TEXT!r}\nInvoke-Expression $stager",
        )

    def test_a_tochararray_write_read_outside_refuses_its_store(self):
        self._assertUnchanged(cleandoc("""
            $x = $($w = 'AB'.ToCharArray()
            'v')
            Write-Output $w
        """), Ps1SubExpressionEvaluator)

    def test_a_capture_variable_that_copies_a_body_array_may_be_retained(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $($a = 1, 2, 3
                $a)
                [Array]::Reverse($x)
                Write-Output $a
            """), Ps1SubExpressionEvaluator),
            cleandoc("""
                $a = 1, 2, 3
                $x = $(1, 2, 3)
                [Array]::Reverse($x)
                Write-Output $a
            """),
        )

    @todo
    def test_two_retained_names_aliasing_one_array_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $($a = 1, 2, 3
            $b = $a
            'v')
            [Array]::Reverse($a)
            Write-Output $b
        """), Ps1SubExpressionEvaluator)

    @todo
    def test_a_retained_new_object_byte_array_refuses(self):
        self._assertUnchanged(cleandoc("""
            $len = $($b = New-Object byte[] 2
            $b.Length)
            $b -is [byte[]]
        """), Ps1SubExpressionEvaluator)

    @todo
    def test_a_retained_decoded_byte_array_refuses(self):
        self._assertUnchanged(cleandoc("""
            $len = $($b = [Convert]::FromBase64String('aGk=')
            $b.Length)
            $b -is [byte[]]
        """), Ps1SubExpressionEvaluator)

    @backlog
    def test_a_retained_integer_keeps_its_declared_width(self):
        for producer, spelled, cast in [
            ("[Convert]::ToInt16('FF', 16)", '[int16]255', '[int16]'),
            ("[Convert]::ToInt64('FF', 16)", '255L', '[int64]'),
            ('1L', '1L', '[int64]'),
        ]:
            with self.subTest(producer):
                self.assertEqual(
                    self._apply(cleandoc(F"""
                        $x = $($v = {producer}
                        'done')
                        $v -is {cast}
                    """), Ps1SubExpressionEvaluator),
                    cleandoc(F"""
                        $v = {spelled}
                        $x = $('done')
                        $v -is {cast}
                    """),
                )

    def test_a_write_read_outside_through_a_function_retains_its_store(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $($w = 'a'
                $w)
                function g {
                  Write-Output $w
                }
            """), Ps1SubExpressionEvaluator),
            cleandoc("""
                $w = 'a'
                $x = $('a')
                function g {
                  Write-Output $w
                }
            """),
        )

    @opportunity
    def test_a_compound_assignment_to_another_name_retains_the_store_before_it(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $c = 'z'
                $c += $($w = 'a'
                $w)
                Write-Output $w
            """), Ps1SubExpressionEvaluator),
            cleandoc("""
                $c = 'z'
                $w = 'a'
                $c += $('a')
                Write-Output $w
            """),
        )

    def test_a_compound_assignment_to_another_name_is_left_or_keeps_the_store_before_it(self):
        source = cleandoc("""
            $c = 'z'
            $c += $($w = 'a'
            $w)
            Write-Output $w
        """)
        self.assertIn(self._apply(source, Ps1SubExpressionEvaluator), (source, cleandoc("""
            $c = 'z'
            $w = 'a'
            $c += $('a')
            Write-Output $w
        """)))

    def test_a_compound_assignment_to_the_retained_name_refuses(self):
        self._assertUnchanged(cleandoc("""
            $w = 'z'
            $w += $($w = 'a'
            $w)
            Write-Output $w
        """), Ps1SubExpressionEvaluator)

    def test_an_index_assignment_needing_retention_refuses(self):
        self._assertUnchanged(cleandoc("""
            $c = 'z'
            $c[0] = $($w = 'a'
            $w)
            Write-Output $w
        """), Ps1SubExpressionEvaluator)

    def test_an_argument_position_needing_retention_refuses(self):
        self._assertUnchanged(cleandoc("""
            Write-Output $w $($w = 'a'
            $w)
            Write-Output $w
        """), Ps1SubExpressionEvaluator)

    def test_a_name_written_null_retains_a_null_store(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $($w = $null
                'v')
                Write-Output $w
            """), Ps1SubExpressionEvaluator),
            cleandoc("""
                $w = $Null
                $x = $('v')
                Write-Output $w
            """),
        )

    def test_a_name_written_on_a_path_not_taken_is_not_stored(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $(if (0) {
                  $w = 'a'
                }
                'v')
                Write-Output $w
            """), Ps1SubExpressionEvaluator),
            cleandoc("""
                $x = $('v')
                Write-Output $w
            """),
        )

    def test_a_retained_store_with_no_spelling_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $($w = [char[]]'AB'
            'v')
            Write-Output $w
        """), Ps1SubExpressionEvaluator)

    def test_a_scope_qualified_write_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $($script:w = 'a'
            'v')
            Write-Output $w
        """), Ps1SubExpressionEvaluator)

    def test_a_command_addressed_write_refuses(self):
        self._assertUnchanged(cleandoc("""
            $x = $(Set-Variable w 'a'
            'v')
            Write-Output $w
        """), Ps1SubExpressionEvaluator)

    def test_nested_sub_expressions_compose_by_replacement(self):
        self.assertEqual(
            self._apply(cleandoc("""
                $x = $($w = $($u = 'a'
                $u)
                $w)
                Write-Output $u
                Write-Output $w
            """), Ps1SubExpressionEvaluator),
            cleandoc("""
                $u = 'a'
                $w = 'a'
                $x = $('a')
                Write-Output $u
                Write-Output $w
            """),
        )

    def test_a_match_body_refuses_because_it_refills_the_engine_matches(self):
        self._assertUnchanged(cleandoc("""
            $x = $('abc' -match 'b'
            'v')
            $y = $Matches[0]
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
