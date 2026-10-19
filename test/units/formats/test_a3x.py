from .. import TestUnitBase

import base64
import pytest

from refinery.units.formats.a3x import (
    A3X_APICALLS,
    A3xScript,
    A3xType,
    _pretty,
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


#: The test script every `casing-*` sample compiles, as the decompiler prints it back: each of
#: the nine builtins whose spelling the interpreter's call table and the documentation disagree
#: on, spelled the documented way.
_DECOMPILED_CASING = [
    B'Local $A = ACos(1)',
    B'Local $B = BitAND(6, 3)',
    B'Local $C = BitNOT(0)',
    B'Local $D = DriveGetFileSystem("C:\\")',
    B'Local $E = HWnd(0)',
    B'Local $F = IsHWnd($E)',
    B'Local $G = StatusbarGetText("x")',
    B'',
    B'Func SHOW()',
    B'    ProgressOn("t", FuncName(SHOW))',
    B'EndFunc',
    B'ConsoleWrite($A & $B & $C & $D & $F & $G & @CRLF)',
]

#: The test script compiled to an `.a3x` by the official compiler of the AutoIt release in each
#: key.
_CASING_SAMPLES = {
    '3.2.0.0': base64.b64decode(
        'o0hLvphsSqmZTFMKhtZIfUFVMyFFQTA11B2M2Y8AsgTpgAmY7PhCfv9tsM6zKQAAFyXQyeHW7YojJkfdskQPgSkA'
        'ABA23A/70OBB3nzBtsriltAgbRyqphCxxpKy8dH0xWmSsbbqgM3Z7ggV+N6kOQHQRAAAjkYAAPdN6+P2X90BgZe7'
        'APZf3QGkLr8AbnJH15wVcVpBEb0ha3wBnqZ5ht5JzfI5OLJCOMO3HxvOZ/DzADMd/zTeERGD21FspLVBaw7NpaSM'
        'U0sQY5pVI5Fn5KBR6c0jrzE+5vttxOmyIs8Ef1v8u6JdFIQGQ6S0rR6qJPncELAZ8fmMumvNZxBVblXVnaEwQ1FX'
        'PH+Vf6zo8ptLgCOOcccQQR9QiUm4PP7DfeBSanWQWHDRtyGmUg7EfG+u1pX0x+jwVXmi3r4IX9urtnAOpbSzpGi+'
        '/fhlU2Ic0D1ZKlwXYbBR8+3auKF28hAx4g34mWdReiUccIYOWHA5nOxZIkhYYDZ2efDTS2ud0UkwVmU1xA4brl37'
        'zob4g0KNkdNy0M2J4OtrIme51XV4igoHMR5OXHjDtuYbR55sFjXSltpstDMtI/nRO20WO/kIyvC2oixW6tpv8DR1'
        '6mR7vhP+w5tFcIXlo5qGn1jOCZ8ZS4BVrTs+paddBGcnjWv5l6MADEKTBRDukgjXFDFgNmEpRw6aQVUzIUVBMDU='
    ),
    '3.2.4.0': base64.b64decode(
        'o0hLvphsSqmZTFMKhtZIfUFVMyFFQTA11B2M2Y8AsgTpgAmY7PhCfv9tsM6rKQAAwEkXMmIeLtVMGShJkeRyg5E9'
        'k4OzYTiBKQAAEDbcD/vQ4EHefMG2yuKW0CBtHKqmELHGkrLx0fTFaZKxtuqAzdnrf2743qQ5AapHAACcQwAAw1bw'
        'RvZf3QELCT0B9l/dATR4QAFuckfXnBV0SCMmPcV41VGC43UXkOyte3H6+0crT+UeA/YDiGsNv14dxPaZG7nTXRyl'
        'XrkHP06u5TYbA5ZGsMwnM7ad8Oe77S1rKm3vi6JLcCotOSxBvmLK2OUZq3VorVTxZKWpLdu5Nj8s1hg2ONtWqPuK'
        '1epdF7I1MNhIWJgNwODZoyRWu+fvZjLGb21LWccaCVz9g53qKXOSdYdOOUhuHIWssJ9AnIy3W/ykr746q9l1iS2o'
        'gmiXxIJgOD9+C/uhyVGk3q7XBlFdvrHg/Jo3l0xdHpUzgl1wQ9h/km3LBs1nlGjZZwviJNuubJea6/NEqQdhi/Zk'
        'A3mw5EPc8/D9Iv+x6dxq0U/UgKHuuEM8A+ERB7Z1IljDY05+GM3htSEMMB9/9Z7AVQ1W7hUzvZGKChHNEaAGL/8i'
        'IW7aRvx2yBBHN7Hp/M3gZNrVQjQRAOKKmJ7yO+eYWWhcuDob7x27qkufUhsVdQRWrE8m22wUF6Q4V0isPif4t5y+'
        '6jjj0/IGNoHyrCNuwlud0Pm9IvmluMUN3PjNWdokmKTNI4hSlVDbVdxQMBYo+bDR6aNaihSrpRqJk1Pv+y9IC87l'
        'Wu8Jy1ayqlsx9oW+pg10UyxF9aXjF+jWcWSs8QeRrNBSUT0PPSabUlETr8a3jFTUeMlgWM7IQT7WojyC5I5/uEsY'
        'o0FVMyFFQTA1'
    ),
    '3.2.6.0': base64.b64decode(
        'o0hLvphsSqmZTFMKhtZIfUFVMyFFQTA2vDsAL8Gj5DB+im0JR3Br02tDylKvrQAA5vsleMjiE/l9He3dcQCwVS2s'
        'mtUoFdTwzyXkzxGOVsLOP3DvuWgN+AAAY7W0hxqVfyhQx0NH3zogEir93m1rbXt5AHSQgEy09yWv1NTPSV6Y0gzq'
        'N7sDK6Yq+s7WOJ3afbHR5UDHuDwQdS2uTnuf+E4ztW5yb/8ca+yXd2cdnJEEEeX5AcqGAADihQAA9M8HafZf3QEC'
        'hF8D9l/dAc1KYgNt+/oDs4s859T3eI415tANbPZzu2zMZK/jwGW5IBI+0XAjsmYDXAmIhfingaJ8Co2VkY58vE+i'
        'VTP6eq2mTV7ylR95H46r470p1amR32KTJ/DU19NmKeAVVxJegOdYJgDZb4zY5zmZMT2tb4BEhouokF6HIsUmL979'
        'HInnkVky6TMhwXmX9CIWuhVBs/+nGBmUE3A7rEz1iw3Id4+5pd+TBU8p8F0LWe3OT/AcEhrpiG2up3UfrIsV8jY5'
        'GSNb9OD2yx9HOlt2bB1T6s0GtbyHr7HCwWXyMIz8GVEoezHCMN8+7uR0oK4YVIlgGQOUnLYxGD9/TaEquwUyptya'
        'HM/B+aW1tplIGdBfr7JeVCq5nPvdzMX8gy+BoZLasHt/sxnDEkAWMPqDeQpRqyBKirdIM4upSv5aodKGQIzQNN8y'
        'lIION8WvoN7A7lX97GNeYBnVfdMHxtvu3A9LyGsvgFAYNBIab0OFNlYoBqlj8NVrWZS2f8n0QEFVMyFFQTA2'
    ),
    '3.3.18.0': base64.b64decode(
        'o0hLvphsSqmZTFMKhtZIfUFVMyFFQTA2Taj/cySnPPZ6EvFnrMGT52tDylKmrQAA4bs6IaUp4+znC5guQL3hmt6A'
        'RrGdazsh1LHWdTrIPcbQM/cUr8sXopQBjROI/mSVYee2TRr4AAAN1e3EKx+XTR4XhUa0ZrJx/rt5LC+GQ6k8PsJy'
        'g253+GlAG6q6LznjnQrQd+42CeY7n8YkZHKPCnlPgm7Ypw0S3rUt/cIaAudxSLjhT/GWkA/a8j9Alqz9HEzUOSIG'
        'opRdZ5SIxAR7pHJf1zFOKBOZ5IcrpgC8hwAAvIcAAISmAAD2X90BMCzvBfZf3QEwLO8Fa0PKUq+tAADm+yV4yOIT'
        '+X0d7d1xALBVLaya1SgV1PDPJeTPEY5Wws4/cO+5aB74AAD/bCkii066I+9S+LwdLub4dsVAQDLnT8+zGF3Pj7Ha'
        'iUnnhmiBjtUlRCc3DpOxWeAQp97bNiin+Cl3yPuf5yuPmhvX/bKPpJy48De6YLei+7Y4i3WOzpfqxWgG3bEwcI1S'
        'JekgXxwXivteXohCC+U9SPCwe9pY/8DjsLALAcqGAADihQAAbsoVxPZf3QGVt+4F9l/dARUF7wVt+/oDs4s859T3'
        'eI415tANbPZzu2zMZK/jwGW5IBI+0XAjsmYDXAmIhfingaJ8Co2VkY58vE+iVTP6eq2mTV7ylR95H46r470p1amR'
        '32KTJ/DU19NmKeAVVxJegOdYJgDZb4zY5zmZMT2tb4BEhouokF6HIsUmL979HInnkVky6TMhwXmX9CIWuhVBs/+n'
        'GBmUE3A7rEz1iw3Id4+5pd+TBU8p8F0LWe3OT/AcEhrpiG2up3UfrIsV8jY5GSNb9OD2y5YHSllGRhwj600ztaSG'
        'PvKups1yumGqKQ2K02XJrtrY3fxu/UZQmrxLYYsOkdpke7OR2di1OMPWRwCyndXs746ntfR8KId4Odl+3kevmxYa'
        'nsQ4+ieR+hsfapTe9FLLRCk8n5edP+j5D0VY+sv7TR9jLu47lUrHnBDtsgX3oLEKyXu3DI7L6//l/uj+FMvmIuFH'
        '4Ahawj1ozcE/DMcwliBEzMtMStplOWXa2D9JFLAlk0QboEFVMyFFQTA2'
    ),
}


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

    def test_the_interpreters_call_names_and_the_builtin_table_agree(self):
        """
        The interpreter's compiled call names and the deobfuscation pipeline's builtin table
        describe the same functions, so neither may grow without the other being reconsidered.
        The one exception is `DummySpeedTest`, which the interpreter knows but no documentation
        page describes: the table transcribes the docs, so it leaves the name to the conservative
        path.
        """
        from refinery.lib.scripts.au3.functions import AUTOIT_FUNCTION_NAMES
        self.assertEqual(
            {name.lower() for name in A3X_APICALLS},
            set(AUTOIT_FUNCTION_NAMES) | {'dummyspeedtest'},
        )

    def test_the_name_lookup_prints_the_documented_function_spellings(self):
        """
        Nine builtins are spelled differently in the interpreter's call table and in the
        documentation; the decompiler's name lookup prints the documented spelling.
        `DummySpeedTest` has no documentation page and keeps the interpreter's spelling, and a
        keyword keeps its own.
        """
        self.assertEqual(
            {
                name: _pretty(name) for name in [
                    'Acos',
                    'BitAnd',
                    'BitNot',
                    'DriveGetFilesystem',
                    'Funcname',
                    'Hwnd',
                    'IsHwnd',
                    'Progresson',
                    'StatusBarGetText',
                    'DummySpeedTest',
                    'EndFunc',
                ]
            },
            {
                'Acos'               : 'ACos',
                'BitAnd'             : 'BitAND',
                'BitNot'             : 'BitNOT',
                'DriveGetFilesystem' : 'DriveGetFileSystem',
                'Funcname'           : 'FuncName',
                'Hwnd'               : 'HWnd',
                'IsHwnd'             : 'IsHWnd',
                'Progresson'         : 'ProgressOn',
                'StatusBarGetText'   : 'StatusbarGetText',
                'DummySpeedTest'     : 'DummySpeedTest',
                'EndFunc'            : 'EndFunc',
            },
        )

    def test_a_name_python_folds_into_a_builtin_keeps_its_stored_spelling(self):
        """
        U+212A KELVIN SIGN lowercases to ASCII `k` for Python; whether AutoIt folds it too is
        unpinned, so only the ASCII spelling of the name prints as the builtin.
        """
        self.assertEqual(
            {name: _pretty(name) for name in ['WINKILL', 'WIN\u212aILL']},
            {'WINKILL': 'WinKill', 'WIN\u212aILL': 'WIN\u212aILL'},
        )

    def _script_lines(self, version: str, path: str) -> list[bytes]:
        """
        The lines of the one script the test script compiled by the given AutoIt release unpacks
        to, at the given path.
        """
        out = _CASING_SAMPLES[version] | self.load() | {'path': [...]}
        self.assertEqual(set(out), {path})
        script, = out[path]
        return bytes(script).split(B'\n')

    def test_an_ea05_ansi_script_record_is_extracted_as_its_source(self):
        """
        AutoIt 3.2.0.0 compiled this sample. The older format stores the script source as ANSI
        text in the `AUTOIT SCRIPT` record, the record type that holds bytecode in the current
        format; the compiler wraps the source in its own comment lines.
        """
        self.assertEqual(
            self._script_lines('3.2.0.0', 'script.au3'),
            [
                B'; <AUT2EXE VERSION: 3.2.0.0>',
                B'',
                B'; ' + B'-' * 76,
                B'; <AUT2EXE INCLUDE-START: W:\\projects\\refinery\\temp\\a3x_casing\\casing.au3>',
                B'; ' + B'-' * 76,
                B'',
                B'Local $a = ACos(1)',
                B'Local $b = BitAND(6, 3)',
                B'Local $c = BitNOT(0)',
                B'Local $d = DriveGetFileSystem("C:\\")',
                B'Local $e = HWnd(0)',
                B'Local $f = IsHWnd($e)',
                B'Local $g = StatusbarGetText("x")',
                B'',
                B'Func Show()',
                B'    ProgressOn("t", FuncName(Show))',
                B'EndFunc',
                B'',
                B'ConsoleWrite($a & $b & $c & $d & $f & $g & @CRLF)',
                B'',
                B'; ' + B'-' * 76,
                B'; <AUT2EXE INCLUDE-END: W:\\projects\\refinery\\temp\\a3x_casing\\casing.au3>',
                B'; ' + B'-' * 76,
                B'',
            ],
        )

    def test_an_ea05_unicode_script_record_is_extracted_as_its_source(self):
        """
        AutoIt 3.2.4.0 compiled this sample. Its compiler drops the blank lines of the source
        and wraps the rest in its own comment lines.
        """
        self.assertEqual(
            self._script_lines('3.2.4.0', 'unicode-script.au3'),
            [
                B'; <AUT2EXE VERSION: 3.2.4.0>',
                B'; ' + B'-' * 76,
                B'; <AUT2EXE INCLUDE-START: W:\\projects\\refinery\\temp\\a3x_casing\\casing.au3>',
                B'; ' + B'-' * 76,
                B'Local $a = ACos(1)',
                B'Local $b = BitAND(6, 3)',
                B'Local $c = BitNOT(0)',
                B'Local $d = DriveGetFileSystem("C:\\")',
                B'Local $e = HWnd(0)',
                B'Local $f = IsHWnd($e)',
                B'Local $g = StatusbarGetText("x")',
                B'Func Show()',
                B'    ProgressOn("t", FuncName(Show))',
                B'EndFunc',
                B'ConsoleWrite($a & $b & $c & $d & $f & $g & @CRLF)',
                B'; ' + B'-' * 76,
                B'; <AUT2EXE INCLUDE-END: W:\\projects\\refinery\\temp\\a3x_casing\\casing.au3>',
                B'; ' + B'-' * 76,
                B'',
            ],
        )

    def test_the_first_ea06_compiler_prints_the_documented_builtin_spellings(self):
        """
        AutoIt 3.2.6.0 compiled this sample, the oldest release that writes bytecode: it writes
        no `AUTOIT NO CMDEXECUTE` record, and it compiles `FuncName` as a call to a script
        function rather than to a builtin.
        """
        self.assertEqual(
            self._script_lines('3.2.6.0', 'script.au3'),
            _DECOMPILED_CASING,
        )

    def test_the_current_ea06_compiler_prints_the_documented_builtin_spellings(self):
        """
        AutoIt 3.3.18.0 compiled this sample; its compiler also writes an empty
        `AUTOIT NO CMDEXECUTE` record, which unpacks to nothing.
        """
        self.assertEqual(
            self._script_lines('3.3.18.0', 'script.au3'),
            _DECOMPILED_CASING,
        )
