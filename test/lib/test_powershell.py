from refinery.lib.powershell import (
    NotWindows,
    get_parent_processes,
    shell_supports_binref,
    Ps1Wrapper,
    PS1OutputWrapper,
    PS1InputWrapper,
    _detect_powershell,
    _detect_binref_support,
    _PS1_MAGIC,
)

import io
import os

from .. import TestBase


class TestPowerShellDetection(TestBase):

    def setUp(self):
        super().setUp()
        self.addCleanup(setattr, Ps1Wrapper, 'WRAPPED', Ps1Wrapper.WRAPPED)

    def test_process_trace(self):
        try:
            processes = list(get_parent_processes())
        except NotWindows:
            pass
        else:
            self.assertTrue(any('python' in p for p in processes))

    def test_shell_supports_binref(self):
        result = shell_supports_binref()
        if os.name != 'nt':
            self.assertTrue(result)
        else:
            self.assertIsInstance(result, bool)

    def test_ps1_magic_is_bytes(self):
        self.assertIsInstance(_PS1_MAGIC, bytes)
        self.assertTrue(len(_PS1_MAGIC) > 0)

    def test_ps1_output_wrapper_write(self):
        import base64
        buffer = io.BytesIO()
        # PS1OutputWrapper.__new__ requires a stream arg, so we construct manually
        wrapper = object.__new__(PS1OutputWrapper)
        wrapper.stream = buffer
        wrapper._header_written = True
        Ps1Wrapper.WRAPPED = True
        wrapper.write(b'\xDE\xAD')
        output = buffer.getvalue()
        self.assertEqual(base64.b16decode(output), b'\xDE\xAD')

    def test_ps1_output_wrapper_empty_write(self):
        buffer = io.BytesIO()
        wrapper = object.__new__(PS1OutputWrapper)
        wrapper.stream = buffer
        wrapper._header_written = True
        wrapper.write(b'')
        self.assertEqual(buffer.getvalue(), b'')

    def test_ps1_input_wrapper_non_magic(self):
        data = b'Hello, World! This is regular data.'
        stream_buffer = io.BytesIO(data)
        wrapper = object.__new__(PS1InputWrapper)
        wrapper.stream = stream_buffer
        wrapper._init = True
        Ps1Wrapper.WRAPPED = False
        result = wrapper.read1(-1)
        self.assertEqual(result, data)

    def test_ps1_input_wrapper_zero_read(self):
        wrapper = object.__new__(PS1InputWrapper)
        wrapper.stream = io.BytesIO(b'test')
        wrapper._init = False
        Ps1Wrapper.WRAPPED = False
        result = wrapper.read1(0)
        self.assertEqual(result, b'')

    def test_ps1_input_wrapper_magic_prefix(self):
        import base64
        payload = b'\xDE\xAD\xBE\xEF'
        encoded = base64.b16encode(payload)
        stream_buffer = io.BytesIO(_PS1_MAGIC + encoded)
        wrapper = object.__new__(PS1InputWrapper)
        wrapper.stream = stream_buffer
        wrapper._init = True
        Ps1Wrapper.WRAPPED = False
        result = wrapper.read1(-1)
        self.assertTrue(Ps1Wrapper.WRAPPED)
        self.assertEqual(result, payload)

    def test_ps1_output_wrapper_writes_header_once(self):
        buffer = io.BytesIO()
        wrapper = object.__new__(PS1OutputWrapper)
        wrapper.stream = buffer
        wrapper._header_written = False
        Ps1Wrapper.WRAPPED = True
        wrapper.write(b'\x01')
        wrapper.write(b'\x02')
        output = buffer.getvalue()
        self.assertEqual(output.count(_PS1_MAGIC), 1)
        self.assertTrue(output.startswith(_PS1_MAGIC))

    def test_detect_powershell_classification(self):
        self.assertEqual(_detect_powershell(
            [R'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe']), True)
        self.assertEqual(_detect_powershell(
            [R'C:\Program Files\PowerShell\7\pwsh.exe']), True)
        self.assertEqual(_detect_powershell(
            [R'C:\Windows\System32\cmd.exe']), False)
        self.assertEqual(_detect_powershell(
            [R'C:\Program Files\Git\usr\bin\bash.exe']), False)
        self.assertEqual(_detect_powershell([]), False)

    def test_detect_binref_support_terminal_shells(self):
        self.assertEqual(_detect_binref_support(
            [R'C:\Windows\System32\cmd.exe']), True)
        self.assertEqual(_detect_binref_support(
            [R'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe']), False)

    def test_detect_binref_support_store_pwsh_version(self):
        path = R'C:\Program Files\WindowsApps\Microsoft.PowerShell_{}_x64__8wekyb3d8bbwe\pwsh.exe'
        self.assertEqual(_detect_binref_support([path.format('7.4.1.0')]), True)
        self.assertEqual(_detect_binref_support([path.format('7.3.9.0')]), False)

    def test_detect_binref_support_bash_outranks_parent_pwsh(self):
        paths = [
            R'C:\Program Files\Git\usr\bin\bash.exe',
            R'C:\Program Files\PowerShell\7\pwsh.exe',
        ]
        self.assertEqual(_detect_binref_support(paths), True)

    def test_ps1_output_wrapper_write_returns_count(self):
        buffer = io.BytesIO()
        wrapper = object.__new__(PS1OutputWrapper)
        wrapper.stream = buffer
        wrapper._header_written = True
        Ps1Wrapper.WRAPPED = True
        self.assertEqual(wrapper.write(b'\xDE\xAD\xBE'), 3)
        self.assertEqual(wrapper.write(b''), 0)

    def test_ps1_input_wrapper_magic_prefix_with_interior_whitespace(self):
        import base64
        payload = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'
        encoded = base64.b16encode(payload)
        encoded = encoded[:6] + b'\r\n' + encoded[6:10] + b'  ' + encoded[10:]
        stream_buffer = io.BytesIO(_PS1_MAGIC + encoded)
        wrapper = object.__new__(PS1InputWrapper)
        wrapper.stream = stream_buffer
        wrapper._init = True
        Ps1Wrapper.WRAPPED = False
        result = wrapper.read1(-1)
        self.assertEqual(result, payload)
