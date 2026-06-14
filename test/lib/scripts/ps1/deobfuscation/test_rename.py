from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import Ps1VariableRenaming


class TestPs1VariableRenaming(TestPs1):

    def test_all_obfuscated_variables_are_renamed(self):
        long_a = 'a' * 100
        long_b = 'b' * 100
        source = (
            F'${long_a} = New-Object Net.WebClient\n'
            F'${long_b} = ${long_a}.DownloadData("http://x")\n'
            F'Write-Host ${long_b}'
        )
        result = self._deobfuscate(source)
        self.assertNotIn(long_a, result)
        self.assertNotIn(long_b, result)
        self.assertIn('$var1', result)
        self.assertIn('$var2', result)

    def test_short_variable_prevents_renaming(self):
        long_a = 'a' * 100
        source = (
            F'${long_a} = New-Object Net.WebClient\n'
            F'$short = ${long_a}.DownloadData("http://x")\n'
            F'Write-Host $short'
        )
        result = self._deobfuscate(source)
        self.assertIn(long_a, result)

    def test_assignment_order_numbering(self):
        long_x = 'x' * 100
        long_y = 'y' * 100
        long_z = 'z' * 100
        source = (
            F'${long_x} = New-Object Net.WebClient\n'
            F'${long_y} = ${long_x}.DownloadData("http://x")\n'
            F'${long_z} = ${long_x}.DownloadData("http://y")\n'
            F'Write-Host ${long_y} ${long_z}'
        )
        result = self._deobfuscate(source)
        lines = [ln.strip() for ln in result.strip().splitlines()]
        self.assertTrue(lines[0].startswith('$var1'))
        self.assertTrue(lines[1].startswith('$var2'))
        self.assertTrue(lines[2].startswith('$var3'))


class TestPs1RenameExtra(TestPs1):

    def test_rename_read_only_variables_are_sorted(self):
        # Read-only variables are numbered in sorted name order ($b -> $var2, $c -> $var3), making
        # the renaming deterministic across hash seeds.
        a, b, c = 'a' * 100, 'b' * 100, 'c' * 100
        result = self._apply(cleandoc(F"""
            ${a} = ${c} + ${b}
            Write-Output ${a}
        """), Ps1VariableRenaming)
        self.assertEqual(result, cleandoc("""
            $var1 = $var3 + $var2
            Write-Output $var1
        """))
