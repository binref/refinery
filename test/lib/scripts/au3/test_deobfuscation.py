from __future__ import annotations

import inspect

from test import TestBase
from test.units.pattern.test_resub import AUTOIT_OBFUSCATED

from refinery.lib.scripts.au3.deobfuscation import deobfuscate
from refinery.lib.scripts.au3.limits import MAX_PIECE_SPELLING
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
#: fixture's (`test_resub.AUTOIT_CLEANED`): the decoders fold away entirely, and the payload
#: function's calls into `DllCall`, `DllStructCreate`, `DllStructSetData`, and `BinaryMid` over
#: `DllStructGetData` resolve through the wide builtin name table and splice out of their
#: `Execute` wrapper, matching the cleaned fixture's calls directly. Two shapes still differ from
#: the cleaned fixture, both ahead of it: the decoder-alias initializer names `Execute` directly
#: once the alias rewrite has resolved the chain through it, where the cleaned fixture's regex
#: pass leaves the alias standing; and every `Execute("1")` argument the splice exposes folds to
#: the literal `1`, which the cleaned fixture's non-semantic rewrite cannot do.
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
    '    Local $aret = DllCall("Advapi32.dll", "bool", "CryptAcquireContext", "handle*", "0", '
    '"ptr", "0", "ptr", "0", "dword", "24", "dword", "0xF0000000")\n'
    '    $__g_acryptinternaldata["2"] = $aret["1"]\n'
    '    $aret = DllCall("Advapi32.dll", "bool", "CryptCreateHash", "handle", '
    '$__g_aCryptInternalData["2"], "uint", "0x00008003", "ptr", "0", "dword", "0", "handle*", '
    '"0")\n'
    '    $hcrypthash = $aret["5"]\n'
    '    $tbuff = DllStructCreate("byte[" & BinaryLen($vCryptKey) & "]")\n'
    '    DllStructSetData($tBuff, 1, $vCryptKey)\n'
    '    $aret = DllCall("Advapi32.dll", "bool", "CryptHashData", "handle", $hCryptHash, '
    '"struct*", $tBuff, "dword", DllStructGetSize($tBuff), "dword", "1")\n'
    '    $aret = DllCall("Advapi32.dll", "bool", "CryptDeriveKey", "handle", '
    '$__g_aCryptInternalData["2"], "uint", "0x00006610", "handle", $hCryptHash, "dword", '
    '"0x00000001", "handle*", "0")\n'
    '    $vreturn = $aret["5"]\n'
    '    DllCall("Advapi32.dll", "bool", "CryptDestroyHash", "handle", $hCryptHash)\n'
    '    $vcryptkey = $vreturn\n'
    '    $tbuff = DllStructCreate("byte[" & BinaryLen($vData) + "1000" & "]")\n'
    '    DllStructSetData($tBuff, 1, $vData)\n'
    '    $aret = DllCall("Advapi32.dll", "bool", "CryptDecrypt", "handle", $vCryptKey, '
    '"handle", "0", "bool", 1, "dword", "0", "struct*", $tBuff, "dword*", BinaryLen($vData))\n'
    '    $iplaintextsize = $aret["6"]\n'
    '    $ttempstruct = DllStructCreate("byte[" & $iPlainTextSize + "1" & "]", '
    'DllStructGetPtr($tBuff))\n'
    '    $vreturn = BinaryMid(DllStructGetData($tTempStruct, 1), "1", $iPlainTextSize)\n'
    '    $aret = DllCall("Advapi32.dll", "bool", "CryptDestroyKey", "handle", $vCryptKey)\n'
    '    DllCall("Advapi32.dll", "bool", "CryptDestroyKey", "handle", $vCryptKey)\n'
    '    DllCall("Advapi32.dll", "bool", "CryptReleaseContext", "handle", '
    '$__g_aCryptInternalData["2"], "dword", "0")\n'
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
        self.assertEqual(Au3Synthesizer().convert(ast), 'MsgBox(0, "", 7)\n')

    def test_an_execute_call_splices_and_the_result_folds(self):
        ast = Au3Parser('MsgBox(0, 0, Execute("1 + 2 * 3"))\n').parse()
        self.assertGreater(deobfuscate(ast), 0)
        self.assertEqual(Au3Synthesizer().convert(ast), 'MsgBox(0, 0, 7)\n')

    def test_a_computed_name_payload_splices_folds_and_eliminates(self):
        """
        The cascade the wide builtin table buys end to end: the payload splices out of its
        `Execute` wrapper, the computed name folds to a literal one, the `Call` flattens to the
        function it names, and the elimination cascade takes the call and every store only it
        kept alive with it — the emptied function stays, spelled in its own declaration.
        """
        ast = Au3Parser(
            'Func checkip()\n'
            'EndFunc\n'
            'Execute("Call(""che"" & ""ckip"")")\n'
        ).parse()
        self.assertGreater(deobfuscate(ast), 0)
        self.assertEqual(
            Au3Synthesizer().convert(ast),
            'Func checkip()\nEndFunc\n',
        )
        ast = Au3Parser(
            'Global $g = 0\n'
            'Func checkip()\n'
            '    $g = 1\n'
            'EndFunc\n'
            'Execute("Call(""che"" & ""ckip"")")\n'
        ).parse()
        self.assertGreater(deobfuscate(ast), 0)
        self.assertEqual(
            Au3Synthesizer().convert(ast),
            'Func checkip()\nEndFunc\n',
        )

    def test_an_alias_chain_resolves_through_the_groups(self):
        """
        The distilled decoder shape: a variable naming `Execute` through one more variable
        naming the decoder builtin, so no single pass sees the whole chain — the alias rewrite
        unmasks the second alias, the fold produces the literal the `Execute` splice reads, and
        the splice result is the string the decoder returned. The first alias then leaves as
        dead code while the second stays: `e` is spelled in no string the tree holds, and `b` is
        a substring of `"BinaryToString"` — the spelling rule's honest output. The decoded store
        leaves with it, nothing reading `$v`, so the hex payload leaving the output is what
        shows the decoder ran.
        """
        ast = Au3Parser(
            'Local $e = Execute\n'
            'Local $b = $e("BinaryToString")\n'
            '$v = $e($b("0x22414243" & "4422"))\n'
        ).parse()
        self.assertGreater(deobfuscate(ast), 0)
        self.assertEqual(
            Au3Synthesizer().convert(ast),
            'Local $b = Execute("BinaryToString")\n',
        )

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

    def test_a_deep_concatenation_chain_in_a_decoder_settles(self):
        """
        The decoder shape obfuscated scripts spell: a parameter concatenated with hundreds of
        constant pieces. The run resolves the call over it without exhausting the interpreter
        stack, and the chain that stays standing still prints.
        """
        chain = ' & '.join(F'"a{i}"' for i in range(300))
        resolved = 'x' + ''.join(F'a{i}' for i in range(300))
        source = (
            'Func dec($p)\n'
            F'    Local $q = $p & {chain}\n'
            '    Return $q\n'
            'EndFunc\n'
            'Local $x = dec("x")\n'
        )
        ast = Au3Parser(source).parse()
        self.assertGreater(deobfuscate(ast), 0)
        self.assertEqual(
            Au3Synthesizer().convert(ast),
            'Func dec($p)\n'
            F'    Local $q = $p & {chain}\n'
            '    Return $q\n'
            'EndFunc\n'
            F'Local $x = "{resolved}"\n'
        )

    def test_a_nul_heavy_value_settles_with_its_call_standing(self):
        """
        A value whose every character needs its own chain piece would spell a `Chr` chain
        hundreds of levels deep, so the renderer refuses it and the pipeline settles with the
        producing call standing instead of exhausting the stack printing it. The call stands
        alone: every store that held its chain of aliases leaves as write-only once the value
        settles.
        """
        payload = 'x' * 250
        source = (
            'Global $s\n'
            'Global $c\n'
            F'$s = "{payload}"\n'
            '$c = StringReplace($s, "x", Chr(0))\n'
            '$y = $c\n'
        )
        ast = Au3Parser(source).parse()
        self.assertGreater(deobfuscate(ast), 0)
        self.assertEqual(
            Au3Synthesizer().convert(ast),
            F'StringReplace("{payload}", "x", Chr(0))\n',
        )

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

    def test_the_pipeline_output_fits_the_interpreters_line_limit(self):
        """
        The interpreter refuses a physical line past 4094 characters, so a value the pipeline
        folds into one longer than a line is spelled as pieces the synthesizer continues behind —
        through every shape that produces one: a folded chain, a multibyte payload, an accumulator
        run, a call with thousands of arguments, an array literal holding a folded chain, and a
        For limit followed by a `Step`, the widest separator a placed atom answers for.
        """
        chain = ' & '.join(
            [F'"{"a" * 100}"' for _ in range(40)] + [F'"{"a" * 90}"'])
        multibyte = ' & '.join(
            [F'"{"é" * 100}"' for _ in range(40)] + [F'"{"é" * 90}"'])
        accumulator = '\n'.join(
            ['Global $v = ""']
            + [F'$v = $v & "{"a" * 1363}"' for _ in range(3)]
            + ['$w = $v'])
        for_limit = F'Global $v = "{"a" * (MAX_PIECE_SPELLING - 2)}"\nFor $i = 0 To $v Step 1\nNext\n'
        for label, source in (
            ('a folded chain', F'Local $x = {chain}\n'),
            ('a folded multibyte chain', F'Local $x = {multibyte}\n'),
            ('a padded accumulator run', F'Global Const $pad = "{"p" * 80000}"\n{accumulator}\n'),
            ('a call with thousands of arguments', F'f({", ".join(str(i) for i in range(3000))})\n'),
            ('an array literal over a folded chain', F'Local $a = [{chain}, 1]\n'),
            ('a For limit followed by a step', F'Global Const $pad = "{"p" * 80000}"\n{for_limit}'),
        ):
            with self.subTest(label=label):
                ast = Au3Parser(source).parse()
                deobfuscate(ast)
                out = Au3Synthesizer().convert(ast)
                for line in out.splitlines():
                    self.assertLessEqual(len(line), 4094, F'in output:\n{out}')

    def test_the_line_limit_fixtures_settle(self):
        chain = ' & '.join(
            [F'"{"a" * 100}"' for _ in range(40)] + [F'"{"a" * 90}"'])
        accumulator = '\n'.join(
            ['Global $v = ""']
            + [F'$v = $v & "{"a" * 1363}"' for _ in range(3)]
            + ['$w = $v'])
        for_limit = F'Global $v = "{"a" * (MAX_PIECE_SPELLING - 2)}"\nFor $i = 0 To $v Step 1\nNext\n'
        for source in (
            F'Local $x = {chain}\n',
            F'Global Const $pad = "{"p" * 80000}"\n{accumulator}\n',
            F'Local $a = [{chain}, 1]\n',
            F'Global Const $pad = "{"p" * 80000}"\n{for_limit}',
        ):
            with self.subTest(source=len(source)):
                ast = Au3Parser(source).parse()
                deobfuscate(ast)
                once = Au3Synthesizer().convert(ast)
                self.assertEqual(deobfuscate(ast), 0)
                self.assertEqual(Au3Synthesizer().convert(ast), once)
