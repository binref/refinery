from __future__ import annotations

import unittest

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import Ps1PrefixEvaluator


class TestPs1PrefixEvaluator(TestPs1):

    def test_a_top_level_decode_loop_folds_to_its_value(self):
        source = cleandoc("""
            $b = 'def'
            $o = ''
            for ($i = 0; $i -lt $b.Length; $i++) {
              $o += [char](+$b[$i] - 3)
            }
            $x = $o
            f $x
        """)
        self.assertEqual(self._deobfuscate(source), "f 'abc'")

    def test_the_decode_loop_folds_to_one_retained_store_in_one_pass(self):
        source = cleandoc("""
            $b = 'def'
            $o = ''
            for ($i = 0; $i -lt $b.Length; $i++) {
              $o += [char](+$b[$i] - 3)
            }
            $x = $o
            f $x
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $x = 'abc'
                f $x
            """),
        )

    def test_the_retained_store_keeps_only_the_name_a_reader_outside_observes(self):
        source = cleandoc("""
            $b = 'def'
            $o = ''
            for ($i = 0; $i -lt $b.Length; $i++) {
              $o += [char](+$b[$i] - 3)
            }
            f $o
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $o = 'abc'
                f $o
            """),
        )

    def test_the_prefix_stops_at_a_statement_that_emits(self):
        source = cleandoc("""
            $c = 1 + 1
            $c
            $d = 2 + 2
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $c = 2
                $c
                $d = 2 + 2
            """),
        )

    def test_the_prefix_stops_at_a_statement_that_emits_a_null(self):
        source = cleandoc("""
            $c = 1 + 1
            $null
            $d = $c + 1
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $c = 2
                $null
                $d = $c + 1
            """),
        )

    def test_a_statement_the_interpreter_refuses_is_never_skipped_past(self):
        source = cleandoc("""
            $a = 1 + 1
            f 2
            $b = $a + 1
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $a = 2
                f 2
                $b = $a + 1
            """),
        )

    def test_a_read_before_the_prefix_writes_it_is_refused(self):
        self._assertUnchanged("$r = $r + 'x'", Ps1PrefixEvaluator)

    def test_an_engine_variable_write_refuses_the_fold(self):
        self._assertUnchanged("$OFS = '-'", Ps1PrefixEvaluator)

    def test_an_engine_variable_write_refuses_the_fold_where_code_runs_from_data(self):
        self._assertUnchanged(cleandoc("""
            $OFS = '-' + 'x'
            sal e iex
            e 'x'
        """), Ps1PrefixEvaluator)

    def test_a_qualified_store_ends_the_prefix(self):
        source = cleandoc("""
            $o = 'a' + 'b'
            $function:f = $o
            f 1
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $o = 'ab'
                $function:f = $o
                f 1
            """),
        )

    def test_a_store_no_reader_observes_is_dropped(self):
        source = cleandoc("""
            $x = 'a'
            $y = 'b'
            f $x
        """)
        self.assertEqual(self._apply(source, Ps1PrefixEvaluator), cleandoc("""
            $x = 'a'
            f $x
        """))

    def test_a_reader_inside_code_an_alias_of_the_script_runs_keeps_every_written_name(self):
        source = cleandoc("""
            $j = 700
            $dead = 1
            sal e iex
            e '$j'
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $j = 700
                $dead = 1
                sal e iex
                e '$j'
            """),
        )

    def test_a_library_script_is_left_entirely_alone(self):
        self._assertUnchanged(
            cleandoc("""
                $t = ,'a'
                $u = 'b'
            """),
            Ps1PrefixEvaluator,
        )

    def test_a_class_a_branch_that_never_runs_registers_still_ends_the_prefix(self):
        self._assertUnchanged(
            cleandoc("""
                $dead = 'payload'
                if ($False) {
                  class Foo {}
                }
                f $dead
            """),
            Ps1PrefixEvaluator,
        )

    def test_a_prefix_whose_stores_spell_it_is_left_alone(self):
        self._assertUnchanged(cleandoc("""
            $x = 'a'
            f $x
        """), Ps1PrefixEvaluator)

    def test_a_container_two_names_hold_is_not_spelled(self):
        self._assertUnchanged(
            cleandoc("""
                $a = 1, 2
                $b = $a
                $b[0] = 9
                Write-Output $a
            """),
            Ps1PrefixEvaluator,
        )

    def test_a_container_one_value_holds_twice_is_not_spelled(self):
        self._assertUnchanged(
            cleandoc("""
                $x = 1, 2
                $c = $x, $x
                $c[0][0] = 9
                Write-Output $x
            """),
            Ps1PrefixEvaluator,
        )

    def test_containers_no_route_shares_are_still_spelled(self):
        source = cleandoc("""
            $x = 1, 2
            $y = 1, 2
            $y[0] = 9
            Write-Output $x
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $x = 1, 2
                Write-Output $x
            """),
        )

    def test_a_statement_that_mutates_a_container_and_cannot_fold_keeps_the_store_it_wrote(self):
        source = cleandoc("""
            $x = 1, 2
            foreach ($i in 1, 2) {
              $x[0] = $x[0] + 1
              f 2
            }
            f $x
        """)
        self._assertUnchanged(source, Ps1PrefixEvaluator)

    def test_a_typed_array_the_prefix_stores_stays_unspelled_through_the_snapshot(self):
        self._assertUnchanged(cleandoc("""
            $d = [byte[]](0, 0, 0)
            [Buffer]::BlockCopy($s, 0, $d, 0, 3)
            Write-Output $d
        """), Ps1PrefixEvaluator)

    def test_a_nesting_deeper_than_the_bound_ends_the_prefix_rather_than_the_run(self):
        self._assertUnchanged(
            cleandoc("""
                $a = @()
                for ($i = 0; $i -lt 2000; $i++) {
                  $a = ,$a
                }
                f $a
            """),
            Ps1PrefixEvaluator,
        )

    def test_a_value_built_by_doubling_one_shared_container_is_measured_once_per_container(self):
        source = '\n'.join(
            ['$a = @()'] + ['$a = @($a, $a)'] * 60 + ['f $a']
        )
        self.assertEqual(self._apply(source, Ps1PrefixEvaluator), source)

    def test_a_switch_whose_clauses_write_nothing_folds_and_keeps_the_pipeline_read(self):
        self.assertEqual(
            self._apply(
                cleandoc("""
                    $x = 5
                    switch ($x) {
                      5 {}
                    }
                    f $_
                """),
                Ps1PrefixEvaluator,
            ),
            'f $_',
        )

    def test_a_switch_binds_the_pipeline_variable_for_the_clause_it_runs(self):
        source = cleandoc("""
            $o = $(switch ('abc') { 'abc' { $_.Length } })
            f $o
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $o = 3
                f $o
            """),
        )

    def test_a_switch_a_route_the_fold_never_runs_does_not_end_the_prefix(self):
        source = cleandoc("""
            $a = 1 + 1
            foreach ($i in @()) {
              switch (1) {
                default { $a = 9 }
              }
            }
            f $a
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $a = 2
                f $a
            """),
        )

    def test_a_switch_over_a_non_ascii_value_ends_the_prefix(self):
        self._assertUnchanged(
            cleandoc("""
                switch ([char]0x00DF) {
                  'ss' {
                    'hit'
                  }
                }
                f 1
            """),
            Ps1PrefixEvaluator,
        )

    def test_a_contains_over_a_non_ascii_value_ends_the_prefix(self):
        self._assertUnchanged(
            cleandoc("""
                $t = @('ss') -contains [char]0x00DF
                f $t
            """),
            Ps1PrefixEvaluator,
        )

    def test_an_increment_of_a_qualified_name_ends_the_prefix(self):
        self._assertUnchanged(cleandoc("""
            $o = $env:zq++
            f $o
        """), Ps1PrefixEvaluator)

    def test_an_increment_of_a_caller_bound_name_ends_the_prefix(self):
        self._assertUnchanged(cleandoc("""
            $o = $i++
            f $o
        """), Ps1PrefixEvaluator)

    def test_an_increment_folds_the_values_the_host_computes(self):
        source = cleandoc("""
            $i = 5
            $o = $i++
            f $o
            f $i
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $i = 6
                $o = 5
                f $o
                f $i
            """),
        )

    def test_an_increment_of_a_string_ends_the_prefix(self):
        self._assertUnchanged(cleandoc("""
            $s = '5'
            $o = $s++
            f $o
        """), Ps1PrefixEvaluator)

    def test_an_increment_of_a_boolean_ends_the_prefix(self):
        self._assertUnchanged(cleandoc("""
            $b = $true
            $o = $b++
            f $o
        """), Ps1PrefixEvaluator)

    def test_an_increment_of_a_null_folds_to_the_values_the_host_computes(self):
        source = cleandoc("""
            $n = $null
            $o = $n++
            f $o
            f $n
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $n = 1
                $o = 0
                f $o
                f $n
            """),
        )

    def test_a_foreach_header_bound_to_a_qualified_name_ends_the_prefix(self):
        self._assertUnchanged(
            cleandoc("""
                foreach ($env:zq in 'a', 'b') {}
                f $zq
            """),
            Ps1PrefixEvaluator,
        )

    def test_a_store_of_a_name_only_braces_spell_keeps_its_braces(self):
        source = cleandoc("""
            ${a-b} = 'x' + 'y'
            f ${a-b}
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                ${a-b} = 'xy'
                f ${a-b}
            """),
        )

    def test_a_store_of_a_name_ending_in_a_newline_keeps_its_braces(self):
        source = cleandoc("""
            ${a
            } = 'x' + 'y'
            f ${a
            }
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                ${a
                } = 'xy'
                f ${a
                }
            """),
        )

    def test_a_store_of_a_name_the_lexer_reads_only_braced_keeps_its_braces(self):
        source = cleandoc("""
            ${aΩ} = 'x' + 'y'
            f ${aΩ}
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                ${aω} = 'xy'
                f ${aΩ}
            """),
        )

    def test_a_labelled_break_folds_to_the_value_the_host_computes(self):
        source = cleandoc("""
            $o = ''
            :outer foreach ($i in 1, 2) {
              foreach ($j in 1, 2) { break outer }
              $o = $o + 'inner'
            }
            $x = $o + 'end'
            f $x
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $x = 'end'
                f $x
            """),
        )

    def test_a_labelled_continue_folds_to_the_value_the_host_computes(self):
        source = cleandoc("""
            $k = 0
            :outer foreach ($i in 1, 2) {
              foreach ($j in 1, 2) { continue outer }
              $k = $k + 100
            }
            $k = $k + 2
            f $k
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $k = 2
                f $k
            """),
        )

    def test_an_array_of_unsigned_sixteen_bit_cells_folds_like_plain_cells(self):
        source = cleandoc("""
            $a = New-Object uint16[] 2
            $t = $a[0] + 1
            f $t
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $t = 1
                f $t
            """),
        )

    def test_a_comparison_of_unsigned_sixteen_bit_cells_does_not_fold_to_false(self):
        source = cleandoc("""
            $a = New-Object uint16[] 2
            $t = $a[0] -eq '0'
            f $t
        """)
        self.assertEqual(
            self._apply(source, Ps1PrefixEvaluator),
            cleandoc("""
                $a = 0, 0
                $t = $a[0] -eq '0'
                f $t
            """),
        )

    def test_a_replace_whose_template_number_is_above_the_hosts_parse_ends_the_prefix(self):
        self._assertUnchanged(
            cleandoc("""
                $o = 'a' -replace 'a', '$2147483648'
                f $o
            """),
            Ps1PrefixEvaluator,
        )


if __name__ == '__main__':
    unittest.main()
