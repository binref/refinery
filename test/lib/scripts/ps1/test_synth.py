from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


class TestPs1Synthesizer(TestBase):

    def _round_trip(self, source: str):
        """
        Parse source, synthesize back, re-parse, synthesize again.
        The two synthesized forms must be identical.
        """
        synth = Ps1Synthesizer()
        ast1 = Ps1Parser(source).parse()
        out1 = synth.convert(ast1)
        ast2 = Ps1Parser(out1).parse()
        out2 = synth.convert(ast2)
        self.assertEqual(out1, out2, f'Round-trip failed:\nInput: {source!r}\nFirst: {out1!r}\nSecond: {out2!r}')
        return out1

    def test_roundtrip_assignment(self):
        self._round_trip('$x = 1 + 2')

    def test_roundtrip_if(self):
        self._round_trip('if ($x -eq 1) { $y = 2 }')

    def test_roundtrip_if_else(self):
        self._round_trip('if ($x) { 1 } else { 2 }')

    def test_roundtrip_while(self):
        self._round_trip('while ($true) { $x++ }')

    def test_roundtrip_do_while(self):
        self._round_trip('do { $x++ } while ($x -lt 10)')

    def test_roundtrip_do_until(self):
        self._round_trip('do { $x-- } until ($x -eq 0)')

    def test_roundtrip_for(self):
        self._round_trip('for ($i=0; $i -lt 10; $i++) { $x += $i }')

    def test_roundtrip_foreach(self):
        self._round_trip('foreach ($i in 1..10) { Write-Host $i }')

    def test_roundtrip_switch(self):
        self._round_trip(
            'switch ($x) { 1 { "one" } 2 { "two" } default { "other" } }')

    def test_roundtrip_try_catch(self):
        self._round_trip('try { Get-Item $p } catch { Write-Error $_ }')

    def test_roundtrip_try_catch_finally(self):
        self._round_trip(
            'try { $x } catch [System.Exception] { "err" } finally { cleanup }')

    def test_roundtrip_trap(self):
        self._round_trip('trap [System.IO.IOException] { continue }')

    def test_roundtrip_function(self):
        self._round_trip('function Get-Data { param($x) return $x }')

    def test_roundtrip_filter(self):
        self._round_trip('filter Even { if ($_ % 2 -eq 0) { $_ } }')

    def test_roundtrip_pipeline(self):
        self._round_trip('$x | Sort-Object | Select-Object -First 1')

    def test_roundtrip_command(self):
        self._round_trip('Write-Host "hello world"')

    def test_roundtrip_hash_literal(self):
        self._round_trip('@{ a = 1; b = 2 }')

    def test_roundtrip_array_expression(self):
        self._round_trip('$a = @(1, 2, 3)')

    def test_roundtrip_cast(self):
        self._round_trip('[int]$x = "42"')

    def test_roundtrip_member_access(self):
        self._round_trip('$s.Length')

    def test_roundtrip_method_call(self):
        self._round_trip('$s.ToUpper()')

    def test_roundtrip_static_call(self):
        self._round_trip('[System.Text.Encoding]::UTF8.GetBytes("test")')

    def test_roundtrip_index(self):
        self._round_trip('$arr[0]')

    def test_roundtrip_range(self):
        self._round_trip('1..10')

    def test_roundtrip_unary_not(self):
        self._round_trip('-not $x')

    def test_roundtrip_return(self):
        self._round_trip('return 42')

    def test_roundtrip_throw(self):
        self._round_trip('throw "error"')

    def test_roundtrip_break(self):
        self._round_trip('break outer')

    def test_roundtrip_exit(self):
        self._round_trip('exit 0')

    def test_roundtrip_data_section(self):
        self._round_trip('data mydata { "test" }')

    def test_roundtrip_complex_expression(self):
        self._round_trip('$result = ($a + $b) * ($c - $d)')

    def test_roundtrip_format_operator(self):
        self._round_trip('"hello {0}" -f "world"')

    def test_roundtrip_multiline(self):
        src = '$x = 1\n$y = 2\n$z = $x + $y'
        self._round_trip(src)

    def test_roundtrip_nested_if(self):
        self._round_trip(
            'if ($a) { if ($b) { 1 } else { 2 } } else { 3 }')

    def test_roundtrip_chained_methods(self):
        self._round_trip('$s.Trim().ToLower().Replace("a", "b")')

    def test_roundtrip_dotted_command_name(self):
        self._round_trip('powershell.exe -windowstyle hidden "test"')

    def test_roundtrip_nested_index(self):
        self._round_trip('$a[0][1]')
