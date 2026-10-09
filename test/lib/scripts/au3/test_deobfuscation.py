from __future__ import annotations

import inspect

from test import TestBase
from test.units.pattern.test_resub import AUTOIT_OBFUSCATED

from refinery.lib.scripts.au3.deobfuscation import deobfuscate
from refinery.lib.scripts.au3.parser import Au3Parser
from refinery.lib.scripts.au3.synth import Au3Synthesizer


#: The decoder bodies the obfuscated sample carries in front of its payload function: every
#: decoder call the fixture holds resolves through them, in both the single and the composed form.
FIXTURE_HELPERS = inspect.cleandoc('''
Func sjwakhwbtxwwb($s)
    Local $r = ""
    For $i = 1 To StringLen($s) - 1 Step 2
        $r &= StringMid($s, $i + 1, 1) & StringMid($s, $i, 1)
    Next
    If Mod(StringLen($s), 2) = 1 Then $r &= StringRight($s, 1)
    Return $r
EndFunc

Func nvbjtycmyxlfrdbypxqk($s, $n)
    Local $r = ""
    For $i = 1 To StringLen($s) Step $n
        $r &= StringMid($s, $i, 1)
    Next
    Return $r
EndFunc
''')

#: The obfuscated sample fixture of the `resub` tests, with its decoder bodies in front of it.
FIXTURE_OBFUSCATED = FIXTURE_HELPERS + '\n\n' + inspect.cleandoc(AUTOIT_OBFUSCATED.decode('ASCII'))

#: The pipeline output over `FIXTURE_OBFUSCATED`. Every decoded literal equals the cleaned
#: fixture's (`test_resub.AUTOIT_CLEANED`): the decoders fold away entirely, the payload function
#: keeps the cleaned fixture's statements. Two shapes stay one step behind the cleaned fixture:
#: the statements whose spliced code calls outside the evaluated builtins (`DllCall`,
#: `DllStructCreate`, `DllStructSetData`, `BinaryMid` over `DllStructGetData`) remain an `Execute`
#: around that code, and the decoder-alias initializer names `Execute` directly once the alias
#: rewrite has resolved the chain through it.
FIXTURE_DEOBFUSCATED = (
    'Func sjwakhwbtxwwb($s)\n'
    '    Local $r = ""\n'
    '    For $i = 1 To StringLen($s) - 1 Step 2\n'
    '        $r &= StringMid($s, $i + 1, 1) & StringMid($s, $i, 1)\n'
    '    Next\n'
    '    If Mod(StringLen($s), 2) = 1 Then\n'
    '        $r &= StringRight($s, 1)\n'
    '    EndIf\n'
    '    Return $r\n'
    'EndFunc\n'
    'Func nvbjtycmyxlfrdbypxqk($s, $n)\n'
    '    Local $r = ""\n'
    '    For $i = 1 To StringLen($s) Step $n\n'
    '        $r &= StringMid($s, $i, 1)\n'
    '    Next\n'
    '    Return $r\n'
    'EndFunc\n'
    'Func lwmmqmcfqg($vdata, $vcryptkey)\n'
    '    Local $__g_acryptinternaldata["3"]\n'
    '    Local $tbuff\n'
    '    Local $ttempstruct\n'
    '    Local $iplaintextsize\n'
    '    Local $vreturn\n'
    '    Local $e = Execute\n'
    '    Local $b = Execute("BinaryToString")\n'
    '    $vdata = BinaryToString($vData)\n'
    '    Local $aret = Execute("DllCall(""Advapi32.dll"", ""bool"", ""CryptAcquireContext"", '
    '""handle*"", ""0"", ""ptr"", ""0"", ""ptr"", ""0"", ""dword"", ""24"", ""dword"", '
    '""0xF0000000"")")\n'
    '    $__g_acryptinternaldata["2"] = $aret["1"]\n'
    '    $aret = Execute("DllCall(""Advapi32.dll"", ""bool"", ""CryptCreateHash"", '
    '""handle"", $__g_aCryptInternalData[""2""], ""uint"", ""0x00008003"", ""ptr"", ""0"", '
    '""dword"", ""0"", ""handle*"", ""0"")")\n'
    '    $hcrypthash = $aret["5"]\n'
    '    $tbuff = Execute("DllStructCreate(""byte["" & BinaryLen($vCryptKey) & ""]"")")\n'
    '    Execute("DllStructSetData($tBuff, Execute(""1""), $vCryptKey)")\n'
    '    $aret = Execute("DllCall(""Advapi32.dll"", ""bool"", ""CryptHashData"", '
    '""handle"", $hCryptHash, ""struct*"", $tBuff, ""dword"", DllStructGetSize($tBuff), '
    '""dword"", ""1"")")\n'
    '    $aret = Execute("DllCall(""Advapi32.dll"", ""bool"", ""CryptDeriveKey"", '
    '""handle"",$__g_aCryptInternalData[""2""], ""uint"", ""0x00006610"", ""handle"", '
    '$hCryptHash, ""dword"", ""0x00000001"", ""handle*"", ""0"")")\n'
    '    $vreturn = $aret["5"]\n'
    '    Execute("DllCall(""Advapi32.dll"", ""bool"", ""CryptDestroyHash"", '
    '""handle"", $hCryptHash)")\n'
    '    $vcryptkey = $vreturn\n'
    '    $tbuff = Execute("DllStructCreate(""byte["" & BinaryLen($vData) + ""1000"" & '
    '""]"")")\n'
    '    Execute("DllStructSetData($tBuff, Execute(""1""), $vData)")\n'
    '    $aret = Execute("DllCall(""Advapi32.dll"", ""bool"", ""CryptDecrypt"", '
    '""handle"", $vCryptKey, ""handle"", ""0"", ""bool"", Execute(""1""), ""dword"", ""0"", '
    '""struct*"", $tBuff, ""dword*"", BinaryLen($vData))")\n'
    '    $iplaintextsize = $aret["6"]\n'
    '    $ttempstruct = Execute("DllStructCreate(""byte["" & $iPlainTextSize + ""1"" & '
    '""]"", DllStructGetPtr($tBuff))")\n'
    '    $vreturn = Execute("BinaryMid(DllStructGetData($tTempStruct, Execute(""1"")), '
    '""1"", $iPlainTextSize)")\n'
    '    $aret = Execute("DllCall(""Advapi32.dll"", ""bool"", ""CryptDestroyKey"", '
    '""handle"", $vCryptKey)")\n'
    '    Execute("DllCall(""Advapi32.dll"", ""bool"", ""CryptDestroyKey"", '
    '""handle"", $vCryptKey)")\n'
    '    Execute("DllCall(""Advapi32.dll"", ""bool"", ""CryptReleaseContext"", '
    '""handle"", $__g_aCryptInternalData[""2""], ""dword"", ""0"")")\n'
    '    Return Binary($vReturn)\n'
    'EndFunc\n'
)


class TestAu3Deobfuscation(TestBase):
    """
    The pipeline over whole scripts: each group's changes re-run the groups that depend on
    them, which is what resolves the chains no single pass can — an alias rewrite unmasking the
    builtin a fold then evaluates, a fold unmasking the literal an `Execute` splice then reads.
    """

    SOURCES = [
        '$x = 1 + 2 * 3\nMsgBox(0, "", $x)\n',
        'Func f($a)\nReturn $a * 2\nEndFunc\n',
        'For $i = 0 To 10 Step 2\n    $s &= Hex($i, 2)\nNext\n',
        '#include <String.au3>\n$s = StringReverse("abc")\n',
    ]

    def test_constant_soup_folds_and_propagates(self):
        ast = Au3Parser(self.SOURCES[0]).parse()
        self.assertGreater(deobfuscate(ast), 0)
        self.assertEqual(Au3Synthesizer().convert(ast), '$x = 7\nMsgBox(0, "", 7)\n')

    def test_an_execute_call_splices_and_the_result_folds(self):
        ast = Au3Parser('$x = Execute("1 + 2 * 3")\n').parse()
        self.assertGreater(deobfuscate(ast), 0)
        self.assertEqual(Au3Synthesizer().convert(ast), '$x = 7\n')

    def test_an_alias_chain_resolves_through_the_groups(self):
        """
        The distilled decoder shape: a variable naming `Execute` through one more variable
        naming the decoder builtin, so no single pass sees the whole chain — the alias rewrite
        unmasks the second alias, the fold produces the literal the `Execute` splice reads, and
        the splice result is the string the decoder returned. The first alias then leaves as
        dead code while the second stays: `e` is spelled in no string the tree holds, and `b` is
        a substring of `"BinaryToString"` — the spelling rule's honest output.
        """
        ast = Au3Parser(
            'Local $e = Execute\n'
            'Local $b = $e("BinaryToString")\n'
            '$v = $e($b("0x22414243" & "4422"))\n'
        ).parse()
        self.assertGreater(deobfuscate(ast), 0)
        self.assertEqual(Au3Synthesizer().convert(ast), (
            'Local $b = Execute("BinaryToString")\n'
            '$v = "ABCD"\n'
        ))

    def test_declarations_the_passes_do_not_own_stay_standing(self):
        """
        The multiply-defined variables the passes cannot prove a value for are left alone, and
        every name the loop binds is read by the statement that follows it.
        """
        ast = Au3Parser(self.SOURCES[2]).parse()
        deobfuscate(ast)
        self.assertEqual(Au3Synthesizer().convert(ast), self.SOURCES[2])

    def test_running_the_pipeline_again_changes_nothing(self):
        for source in self.SOURCES:
            ast = Au3Parser(source).parse()
            deobfuscate(ast)
            once = Au3Synthesizer().convert(ast)
            self.assertEqual(deobfuscate(ast), 0)
            self.assertEqual(Au3Synthesizer().convert(ast), once)

    def test_no_parse_errors_on_wellformed_input(self):
        for source in self.SOURCES:
            ast = Au3Parser(source).parse()
            self.assertEqual(ast.errors, [])

    def test_parse_errors_on_malformed_input(self):
        ast = Au3Parser('$x = = 1\n').parse()
        self.assertNotEqual(ast.errors, [])

    def test_the_obfuscated_fixture_decodes_to_its_cleaned_form(self):
        ast = Au3Parser(FIXTURE_OBFUSCATED).parse()
        self.assertEqual(ast.errors, [])
        self.assertGreater(deobfuscate(ast), 0)
        self.assertEqual(Au3Synthesizer().convert(ast), FIXTURE_DEOBFUSCATED)

    def test_the_decoded_fixture_is_stable(self):
        ast = Au3Parser(FIXTURE_OBFUSCATED).parse()
        deobfuscate(ast)
        self.assertEqual(deobfuscate(ast), 0)
        self.assertEqual(Au3Synthesizer().convert(ast), FIXTURE_DEOBFUSCATED)
