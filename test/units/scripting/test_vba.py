from .. import TestUnitBase


class TestVBAASTDeobfuscator(TestUnitBase):

    def test_real_world_01(self):
        data = BR'''Execute chr(311-(&HF1))&chr(1112-(&H3E3))&chr(422-(&H138))&chr(1064-(&H3C5))'''
        result = data | self.load() | bytearray
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

    def test_trivial_string_replace(self):
        result = (
            '''impairingsgutta = Replace("ADs@j|P3FODBs@j|P3F.Sts@j|P3Fs@j|P3Fs@j|P3Fream", "s@j|P3F", "")'''
        ) | self.load() | str
        self.assertIn('ADODB.Stream', result)
