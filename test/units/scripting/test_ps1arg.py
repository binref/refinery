from __future__ import annotations

from .. import TestUnitBase


class TestPs1Arg(TestUnitBase):

    def test_encoded_command(self):
        # base64 of 'Write-Host hello' in UTF-16LE
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
