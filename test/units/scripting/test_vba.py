from .. import TestUnitBase


class TestVBAASTDeobfuscator(TestUnitBase):

    def test_real_world_01(self):
        data = BR'''Execute chr(311-(&HF1))&chr(1112-(&H3E3))&chr(422-(&H138))&chr(1064-(&H3C5))'''
        result = self.load().process(data)
        self.assertEqual(result, b'Execute "Func"')

    def test_real_world_02(self):
        data = self.download_sample(
            '07e25cb7d427ac047f53b3badceacf6fc5fb395612ded5d3566a09800499cd7d')
        unit = self.load()
        self.assertIn(
            r'POwerShell.exe -noProfilE -ExEcutionPolicy Bypass'
            r' -Command C:\ProgramData\UPFCRQOFGHVNBVUABXGFIW\UPFCRQOFGHVNBVUABXGFIW.bat',
            data | unit | str
        )


class TestVBAArithmetic(TestUnitBase):

    def test_xor_operator(self):
        result = self.load().deobfuscate('CLng((0 Xor 0))')
        self.assertEqual(result, 'CLng((0 Xor 0))')


class TestVBACommentRemoval(TestUnitBase):

    def test_simple(self):
        result = self.load().deobfuscate('''
            ' Test
            b = a
            ' Test''')
        self.assertIn('b = a', result)
        self.assertNotIn("' Test", result)


class TestVBAConstantReplacer(TestUnitBase):

    def test_regex_matchgroup_regression(self):
        result = self.load().deobfuscate(r'''
            const a = "\3"
            b = a
        ''')
        self.assertIn(r'b = "\3"', result)


class TestVBADummyVariableRemoval(TestUnitBase):

    def test_overeager_removal_regression(self):
        data = 'a.Close\nb = z.function(x)\n'
        result = self.load().deobfuscate(data)
        self.assertIn('a.Close', result)
        self.assertIn('b = z.function(x)', result)


class TestVBAStringReplace(TestUnitBase):

    def test_trivial(self):
        result = self.load().deobfuscate(
            '''impairingsgutta = Replace("ADs@j|P3FODBs@j|P3F.Sts@j|P3Fs@j|P3Fs@j|P3Fream", "s@j|P3F", "")'''
        )
        self.assertIn('ADODB.Stream', result)
