from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1


class TestPs1AFinallyRunsOnEveryWayOutOfItsTry(TestPs1):
    """
    5.1 runs a `finally` body when a `break`, `continue`, `return` or `exit` leaves its `try`, and
    when an error does, and then goes on where the jump or the error goes.
    """

    def test_a_store_in_the_finally_a_break_leaves_is_read_after_the_loop(self):
        output = self._deobfuscate(cleandoc("""
            $x = 'a'
            foreach ($i in 1, 2) {
              try { break } finally { $x = 'b' }
              return
            }
            Write-Host $x
        """))
        self.assertIn("$x = 'b'", output)
        self.assertNotIn("Write-Host 'a'", output)

    def test_a_store_in_the_finally_an_error_passes_is_read_by_the_catch(self):
        output = self._deobfuscate(cleandoc("""
            $x = 'a'
            try {
              try { throw 'x' } finally { $x = 'b' }
            } catch {
              Write-Host $x
            }
        """))
        self.assertIn("Write-Host 'b'", output)

    def test_a_trap_resuming_past_a_try_a_jump_leaves_is_kept(self):
        for source in (
            """
            foreach ($i in 1, 2) {
              trap { continue }
              if ($args[0]) { $null = [int]$args[1]; try { break } finally { } }
              Write-Host 'm1'
            }
            Write-Host 'm2'
            """,
            """
            foreach ($i in 1, 2) {
              trap { continue }
              if ($args[0]) { $null = [int]$args[1]; try { continue } finally { } }
              Write-Host 'm1'
            }
            Write-Host 'm2'
            """,
            """
            foreach ($i in 1, 2) {
              trap { continue }
              if ($args[0]) { $null = [int]$args[1]; try { break } finally { Write-Host 'm3' } }
              Write-Host 'm1'
            }
            Write-Host 'm2'
            """,
            """
            foreach ($i in 1, 2) {
              trap { continue }
              if ($args[0]) { $null = [int]$args[1]; try { break } finally { $junk = 'x' } }
              Write-Host 'm1'
            }
            Write-Host 'm2'
            """,
            """
            foreach ($i in 1, 2) {
              trap { continue }
              if ($args[0]) { $null = [int]$args[1]; try { break } catch { } finally { } }
              Write-Host 'm1'
            }
            Write-Host 'm2'
            """,
            """
            switch (1, 2) {
              default {
                trap { continue }
                if ($args[0]) { $null = [int]$args[1]; try { break } finally { } }
                Write-Host 'm1'
              }
            }
            Write-Host 'm2'
            """,
            """
            $p = $args
            function f1 {
              trap { continue }
              if ($p[0]) { $null = [int]$p[1]; try { return } finally { } }
              Write-Host 'm1'
            }
            f1
            Write-Host 'm2'
            """,
            """
            trap { continue }
            if ($args[0]) { $null = [int]$args[1]; try { return } finally { } }
            Write-Host 'm1'
            """,
            """
            trap { continue }
            if ($args[0]) { $null = [int]$args[1]; try { exit } finally { } }
            Write-Host 'm1'
            """,
        ):
            with self.subTest(source):
                output = self._deobfuscate(cleandoc(source))
                self.assertIn('continue', output)
                self.assertIn('[int]', output)


class TestPs1AnErrorGoesWhereTheEvaluatorSendsIt(TestPs1):
    """
    The graphs route an error out of a `trap` set and out of a failing point as 5.1 does, so a
    store the error skips and a line it abandons stay as written.
    """

    def test_a_trap_whose_body_runs_off_its_end_hands_the_error_on_under_stop(self):
        output = self._deobfuscate(cleandoc("""
            $ErrorActionPreference = 'Stop'
            $x = 'a'
            try {
              trap { }
              $x = 'b'
              $null = [int]'z'
              $x = 'c'
            } catch {
              Write-Host 'caught'
            }
            Write-Host $x
        """))
        self.assertIn("$x = 'b'", output)
        self.assertNotIn("Write-Host 'c'", output)

    def test_the_head_of_a_foreach_whose_variable_rejects_the_value_ends_the_catch_body(self):
        output = self._deobfuscate(cleandoc("""
            [int]$i = 0
            try { throw 'x' } catch {
              foreach ($i in 'a') { }
              $y = 'r'
            }
            Write-Host $y
        """))
        self.assertNotIn("Write-Host 'r'", output)


class TestPs1ASpliceUnderATrapThatCarriesOnKeepsAnErrorFromCarryingOnInsideIt(TestPs1):
    """
    A `trap` set that carries the run on resumes after the statement that raised. Inlining a payload
    puts its lines in that statement's place, and an error in one of them would carry the run on at
    the next line of the payload, which 5.1 never runs.
    """

    def test_a_payload_whose_line_before_the_last_may_fail_is_not_run_line_by_line(self):
        for payload in (
            'throw "e"; Write-Host "tail"',
            '$null = [int]$Host.Name; Write-Host "tail"',
            'if ($true) { throw "e" }; Write-Host "tail"',
            'if ($true) { $null = [int]$Host.Name }; Write-Host "tail"',
            '& { throw "e" }; Write-Host "tail"',
            'try { throw "e" } finally { }; Write-Host "tail"',
            'foreach ($i in 1) { throw "e" }; Write-Host "tail"',
            'switch (1) { 1 { throw "e" } }; Write-Host "tail"',
            'while ($true) { throw "e" }; Write-Host "tail"',
            'function g { throw "e" }; g; Write-Host "tail"',
            '$null = $(throw "e"); Write-Host "tail"',
            '. { throw "e" }; Write-Host "tail"',
        ):
            for handler in ('continue', "Write-Host 'trapped'"):
                source = F"trap {{ {handler} }}; iex '{payload}'; Write-Host 'next'"
                with self.subTest(source):
                    self.assertNotIn('Write-Host "tail"', self._deobfuscate(source).splitlines())

    def test_a_payload_whose_only_line_that_may_fail_is_its_last_is_inlined(self):
        output = self._deobfuscate("trap { continue }; iex \"'head'; throw 'e'\"; Write-Host 'next'")
        self.assertNotIn('Invoke-Expression', output)

    def test_a_store_in_a_subexpression_under_a_resuming_trap_stays_inside_it(self):
        for source in (
            "[int]$x = 0; trap { continue }; Write-Host $($x = 'v'; 'r'); Write-Host $x",
            "trap { continue }; Write-Host $($x = 'v'; 'r'); Write-Host $x",
            "trap { continue }; Write-Host $($x = 'v'; $y = 'w'; 'r'); Write-Host $x $y",
            "function f { param([int]$x) trap { continue }; Write-Host $($x = 'v'; 'r'); Write-Host $x }; f 1",
        ):
            with self.subTest(source):
                self.assertIn("Write-Host $($x = 'v'", self._deobfuscate(source))
