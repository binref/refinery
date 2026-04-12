from __future__ import annotations

from .. import TestUnitBase


class TestCmdArg(TestUnitBase):

    def test_encoded_command(self):
        b64 = 'VwByAGkAdABlAC0ASABvAHMAdAAgAGgAZQBsAGwAbwA='
        data = F'powershell.exe -EncodedCommand {b64}'.encode()
        result = data | self.load() | str
        self.assertEqual(result, 'Write-Host hello')

    def test_encoded_command_abbreviated(self):
        b64 = 'VwByAGkAdABlAC0ASABvAHMAdAAgAGgAZQBsAGwAbwA='
        data = F'powershell.exe -enc {b64}'.encode()
        result = data | self.load() | str
        self.assertEqual(result, 'Write-Host hello')

    def test_encoded_command_minimal_prefix(self):
        b64 = 'VwByAGkAdABlAC0ASABvAHMAdAAgAGgAZQBsAGwAbwA='
        data = F'powershell -e {b64}'.encode()
        result = data | self.load() | str
        self.assertEqual(result, 'Write-Host hello')

    def test_command_explicit(self):
        data = b'powershell.exe -Command Write-Host hello'
        result = data | self.load() | str
        self.assertEqual(result, 'Write-Host hello')

    def test_command_abbreviated(self):
        data = b'powershell.exe -c Write-Host hello'
        result = data | self.load() | str
        self.assertEqual(result, 'Write-Host hello')

    def test_command_joins_remaining_args(self):
        data = b'powershell.exe -nop -w 1 -Command $x = 1; $y = 2'
        result = data | self.load() | str
        self.assertEqual(result, '$x = 1; $y = 2')

    def test_command_with_crt_escapes(self):
        data = b'powershell.exe -Command "& {\\"hello\\"}"'
        result = data | self.load() | str
        self.assertEqual('& {"hello"}', result)

    def test_switches_with_args_skipped(self):
        data = b'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command Get-Process'
        result = data | self.load() | str
        self.assertEqual(result, 'Get-Process')

    def test_abbreviated_switches(self):
        data = b'powershell.exe -nop -nol -w 1 -ex bypass -Command whoami'
        result = data | self.load() | str
        self.assertEqual(result, 'whoami')

    def test_no_executable_prefix(self):
        data = b'-nop -Command Get-Date'
        result = data | self.load() | str
        self.assertEqual(result, 'Get-Date')

    def test_implicit_command(self):
        data = b'powershell.exe -nop -nol Get-ChildItem'
        result = data | self.load() | str
        self.assertEqual(result, 'Get-ChildItem')

    def test_slash_prefix_switches(self):
        data = b'powershell.exe /nop /w 1 /Command Write-Output test'
        result = data | self.load() | str
        self.assertEqual(result, 'Write-Output test')

    def test_pwsh_executable(self):
        data = b'pwsh -Command Get-Process'
        result = data | self.load() | str
        self.assertEqual(result, 'Get-Process')

    def test_encoded_command_no_padding(self):
        b64 = 'VwByAGkAdABlAC0ASABvAHMAdAAgAGgAZQBsAGwAbwA'
        data = F'powershell.exe -enc {b64}'.encode()
        result = data | self.load() | str
        self.assertEqual(result, 'Write-Host hello')

    def test_cmd_c_powershell(self):
        b64 = 'VwByAGkAdABlAC0ASABvAHMAdAAgAGgAZQBsAGwAbwA='
        data = F'cmd /c "powershell -enc {b64}"'.encode()
        result = data | self.load() | str
        self.assertEqual(result, 'Write-Host hello')

    def test_cmd_k_powershell(self):
        data = b'cmd /k powershell -Command whoami'
        result = data | self.load() | str
        self.assertEqual(result, 'whoami')

    def test_cmd_with_switches(self):
        data = b'cmd /s /c "powershell -Command Get-Process"'
        result = data | self.load() | str
        self.assertEqual(result, 'Get-Process')

    def test_wmic_process_create_powershell(self):
        b64 = 'VwByAGkAdABlAC0ASABvAHMAdAAgAGgAZQBsAGwAbwA='
        data = F'wmic process call create "powershell -enc {b64}"'.encode()
        result = data | self.load() | str
        self.assertEqual(result, 'Write-Host hello')

    def test_wmic_single_quoted_keywords(self):
        data = b"WmiC 'PrOcesS' call 'CrEaTe' \"powershell -Command whoami\""
        result = data | self.load() | str
        self.assertEqual(result, 'whoami')

    def test_wmic_with_path_keyword(self):
        data = b'wmic path process call create "powershell -Command whoami"'
        result = data | self.load() | str
        self.assertEqual(result, 'whoami')

    def test_wmic_case_insensitive(self):
        data = b'WMIC PROCESS CALL CREATE "powershell -Command Get-Date"'
        result = data | self.load() | str
        self.assertEqual(result, 'Get-Date')

    def test_triple_chain_cmd_wmic_powershell(self):
        b64 = 'VwByAGkAdABlAC0ASABvAHMAdAAgAGgAZQBsAGwAbwA='
        data = F'cmd /c wmic process call create "powershell -enc {b64}"'.encode()
        result = data | self.load() | str
        self.assertEqual(result, 'Write-Host hello')

    def test_wmic_wrapping_cmd(self):
        data = b'wmic process call create "cmd /c powershell -Command whoami"'
        result = data | self.load() | str
        self.assertEqual(result, 'whoami')

    def test_cmd_without_powershell(self):
        data = b'cmd /c echo hello'
        result = data | self.load() | str
        self.assertEqual(result, 'echo hello')

    def test_unrecognized_command(self):
        data = b'notepad.exe foo.txt'
        result = data | self.load() | str
        self.assertEqual(result, 'notepad.exe foo.txt')

    def test_wmic_global_switches(self):
        data = (
            b'wmic /node:localhost process call create'
            b' "powershell -Command whoami"'
        )
        result = data | self.load() | str
        self.assertEqual(result, 'whoami')

    def test_wmic_preserves_inner_crt_escapes(self):
        data = (
            b'wmic process call create'
            b' "powershell -ep bypass "\\"$x=1;$y=2\\"" "'
        )
        result = data | self.load() | str
        self.assertIn('"$x=1;$y=2"', result)

    def test_wmic_double_quoted_keywords(self):
        data = (
            b"wmIC  'ProcESS'  \"Call\"  crEatE"
            b'   "powershell -Command whoami"'
        )
        result = data | self.load() | str
        self.assertEqual(result, 'whoami')

    def test_wmic_char44_comma_pattern(self):
        data = (
            b"WmiC 'PrOcesS' call 'CrEaTe'"
            b' "pOWERsHElL -EP bYPaSs'
            b' "\\"hello\\""+([ChAr]44).TOStRing()+"\\"world\\""'
            b'"'
        )
        result = data | self.load() | str
        self.assertIn('"hello"', result)
        self.assertIn('([ChAr]44).TOStRing()', result)
        self.assertIn('"world"', result)

    def test_comspec_start_powershell(self):
        b64 = 'VwByAGkAdABlAC0ASABvAHMAdAAgAGgAZQBsAGwAbwA='
        cmdline = F'%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -noni -enc {b64}'
        result = cmdline.encode() | self.load() | str
        self.assertEqual(result, 'Write-Host hello')

    def test_start_strips_switches(self):
        data = b'start /b /min powershell.exe -Command whoami'
        result = data | self.load() | str
        self.assertEqual(result, 'whoami')

    def test_cmd_unknown_switch_before_c(self):
        data = b'cmd /b /c echo hello'
        result = data | self.load() | str
        self.assertEqual(result, 'echo hello')

    def test_start_with_d_switch(self):
        data = b'start /d C:\\Windows /b powershell.exe -Command whoami'
        result = data | self.load() | str
        self.assertEqual(result, 'whoami')

    def test_start_with_title(self):
        data = b'start "My Window" powershell.exe -Command whoami'
        result = data | self.load() | str
        self.assertEqual(result, 'whoami')

    def test_format_operator_not_matched_as_file_switch(self):
        data = b'PoweRsHeLl &( \'SV\' ) x ( \\"hello\\" -f \'world\' )'
        result = data | self.load() | str
        self.assertIn('-f', result)
        self.assertIn('&(', result)
