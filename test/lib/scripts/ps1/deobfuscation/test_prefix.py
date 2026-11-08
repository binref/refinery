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
        self._assertUnchanged("$OFS = '-' + 'x'\nsal e iex\ne 'x'", Ps1PrefixEvaluator)

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
        self.assertEqual(self._apply(source, Ps1PrefixEvaluator), "$x = 'a'\nf $x")

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
        self._assertUnchanged("$x = 'a'\nf $x", Ps1PrefixEvaluator)

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


if __name__ == '__main__':
    unittest.main()
