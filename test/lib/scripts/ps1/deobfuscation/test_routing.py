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
