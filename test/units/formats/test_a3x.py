from .. import TestUnitBase

import pytest

from refinery.units.formats.a3x import (
    A3X_APICALLS,
    A3xScript,
    A3xType,
    _PRETTY,
    a3x_decompile,
    a3x_decompress,
    a3x_decrypt,
)


def _bytecode(sample: bytes | bytearray) -> bytearray:
    """
    The decrypted and decompressed bytecode of the compiled script in the given sample.
    """
    script = A3xScript.Parse(memoryview(sample)[sample.find(A3xScript.MAGIC):])
    record = next(record for record in script.body if record.type == A3xType.SCRIPT)
    code = record.data
    seed = record.encryption_type.data
    if record.is_encrypted:
        code = a3x_decrypt(code, seed if record.encryption_type.is_current else seed + 0x849, record.encryption_type.is_current)
    if record.is_compressed:
        code = a3x_decompress(code, record.encryption_type.is_current)
    return bytearray(code)


def _name(name: str) -> bytes:
    """
    A name as the bytecode stores it: its length, then each character xor the length.
    """
    n = len(name)
    return n.to_bytes(4, 'little') + b''.join(((ord(c) ^ n) & 0xFFFF).to_bytes(2, 'little') for c in name)


@pytest.mark.cythonized
class TestA3X(TestUnitBase):

    def test_ea06(self):
        sample = self.download_sample(
            '3b775e678568cd3d55187443a3f7aae2116b7e9762b3c3879f5e1c6225434b25')
        taint = sample.replace(
            b'\xA3\x48\x4B\xBE\x98\x6C\x4A\xA9\x99\x4C\x53\x0A\x86\xD6\x48\x7D',
            b'\xDE\xFA\xCE\xD0\xDE\xFA\xCE\xD0\xDE\xFA\xCE\xD0\xDE\xFA\xCE\xD0'
        )
        for data in [taint, sample]:
            out = data | self.load() | {'path': [...]}
            self.assertEqual(len(out), 4)
            for key, value in out.items():
                self.assertEqual(len(value), 1)
                out[key], = value
            self.assertSetEqual(set(out), {'script.au3', 'msc.exe', 'MSWINSCK.OCX', 'DrWatson.exe'})
            self.assertContains(out['script.au3'], Br'FileInstall("msc.exe", @SYSTEMDIR & "\msc0nfig.exe")')
            self.assertContains(out['script.au3'], Br'FileInstall("MSWINSCK.OCX", @SYSTEMDIR & "\MSWINSCK.OCX")')
            self.assertContains(out['script.au3'], Br'FileInstall("DrWatson.exe", @SYSTEMDIR & "\1096\DrWatson.exe")')
            self.assertContains(out['script.au3'], b'jan1_milan'b'@yahoo'b'.com')

    def test_a_volatile_function_is_decompiled(self):
        code = _bytecode(self.download_sample('3b775e678568cd3d55187443a3f7aae2116b7e9762b3c3879f5e1c6225434b25'))
        start = code.find(B'\x30' + _name('FUNC') + B'\x34' + _name('_PROCESSGETNAME'))
        code[start:start] = B'\x30' + _name('VOLATILE')
        lines = [line for _, line in a3x_decompile(code)]
        self.assertIn('Volatile Func _PROCESSGETNAME($I_PID)', lines)

    def test_a_statement_that_calls_a_function_whose_name_starts_with_end_is_decompiled(self):
        code = _bytecode(self.download_sample('3b775e678568cd3d55187443a3f7aae2116b7e9762b3c3879f5e1c6225434b25'))
        call = B'\x7F\x34' + _name('_SECURITY__SETPRIVILEGE')
        start = code.find(call) + 2
        code[start:start + len(call) - 2] = _name('ENDCURITY__SETPRIVILEGE')
        lines = [line for _, line in a3x_decompile(code)]
        self.assertIn('ENDCURITY__SETPRIVILEGE($HTOKEN, "SeDebugPrivilege", True)', lines)

    def test_ea05(self):
        sample = self.download_sample(
            '9b66a8ea0f1c64965b06e7a45afbe56f2d4e6d5ef65f32446defccbebe730813')
        out = sample | self.load() | {'path': [...]}
        self.assertEqual(len(out), 1)
        for key, value in out.items():
            self.assertEqual(len(value), 1)
            out[key], = value
        self.assertSetEqual(set(out), {'unicode-script.au3'})
        self.assertContains(out['unicode-script.au3'], B"new ActiveXObject('WScript.Shell').Run")

    def test_the_interpreters_call_names_and_the_analysis_table_agree(self):
        """
        The interpreter's compiled call names and the deobfuscation pipeline's builtin table
        describe the same functions, so neither may grow without the other being reconsidered.
        The one exception is `DummySpeedTest`, which the interpreter knows but no documentation
        page describes: the table transcribes the docs, so it leaves the name to the conservative
        path.
        """
        from refinery.lib.scripts.au3.analysis.builtins import AUTOIT_FUNCTION_NAMES
        self.assertEqual(
            {name.lower() for name in A3X_APICALLS},
            set(AUTOIT_FUNCTION_NAMES) | {'dummyspeedtest'},
        )

    def test_the_pretty_table_prints_the_official_function_spellings(self):
        """
        The decompiler's pretty table takes its function spellings from the analysis table, so a
        name in the bytecode that the two spell differently comes out documented. The names only
        the interpreter knows — `DummySpeedTest` — keep its spelling, and the keyword spellings
        are unchanged.
        """
        from refinery.lib.scripts.au3.analysis.builtins import AUTOIT_FUNCTION_NAMES
        self.assertEqual(
            {name: _PRETTY[name] for name in AUTOIT_FUNCTION_NAMES},
            AUTOIT_FUNCTION_NAMES,
        )
