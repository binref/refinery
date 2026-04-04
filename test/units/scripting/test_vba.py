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

    def test_for_loop_variable_not_inlined(self):
        data = (
            'Function test()\n'
            'k = 0\n'
            'For k = 0 To 10\n'
            'x = x + k\n'
            'Next k\n'
            'End Function'
        )
        result = data | self.load() | str
        self.assertIn('For k =', result)
        self.assertNotIn('For 0', result)

    def test_blank_lines_between_toplevel_blocks(self):
        data = (
            'Attribute VB_Name = "Module1"\n'
            'Dim x As Long\n'
            'Sub Foo()\n'
            'x = 1\n'
            'End Sub\n'
            'Function Bar() As Long\n'
            'Bar = x\n'
            'End Function'
        )
        result = data | self.load() | str
        self.assertIn('Module1"\n\nDim', result)
        self.assertIn('Long\n\nSub', result)
        self.assertIn('End Sub\n\nFunction', result)

    def test_redim_with_to_range_bounds(self):
        data = (
            'Sub Test()\n'
            'Dim a() As Byte\n'
            'ReDim a(LBound(x) To UBound(x))\n'
            'End Sub'
        )
        result = data | self.load() | str
        self.assertNotIn(')', result.split('ReDim')[0].split('\n')[-1])
        self.assertIn('ReDim a(LBound(x) To UBound(x))', result)

    def test_redim_multidimensional_to_range(self):
        data = (
            'Sub Test()\n'
            'ReDim arr(0 To 10, 1 To 5)\n'
            'End Sub'
        )
        result = data | self.load() | str
        self.assertIn('ReDim arr(0 To 10, 1 To 5)', result)
