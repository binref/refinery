from ... import TestUnitBase


class TestRabbit(TestUnitBase):

    def test_rabbit_01(self):
        unit = self.load(bytes.fromhex(
            '00000000000000000000000000000000'
        ))
        data = bytearray(48)
        self.assertEqual(unit(data), bytes.fromhex(
            '02F74A1C26456BF5ECD6A536F05457B1'
            'A78AC689476C697B390C9CC515D8E888'
            '96D6731688D168DA51D40C70C3A116F4'
        ))

    def test_rabbit_02(self):
        unit = self.load(0x_9128_1329_2E3D_36FE_3BFC_62F1_DC51_C3AC.to_bytes(16, 'little'))
        data = bytearray(48)
        self.assertEqual(unit(data), bytes.fromhex(
            '9C51E28784C37FE9A127F63EC8F32D3D'
            '19FC5485AA53BF96885B40F461CD76F5'
            '5E4C4D20203BE58A5043DBFB737454E5'
        ))

    def test_rabbit_03(self):
        unit = self.load(0x_8395_7415_87E0_C733_E9E9_AB01_C09B_0043.to_bytes(16, 'little'))
        data = bytearray(48)
        self.assertEqual(unit(data), bytes.fromhex(
            '9B60D002FD5CEB32ACCD41A0CD0DB10C'
            'AD3EFF4C1192707B5A01170FCA9FFC95'
            '2874943AAD4741923F7FFC8BDEE54996'
        ))

    def test_rabbit_iv_01(self):
        unit = self.load(0x00.to_bytes(16, 'big'), iv=0x0000000000000000.to_bytes(8, 'little'))
        data = bytearray(48)
        self.assertEqual(unit(data), bytes.fromhex(
            'EDB70567375DCD7CD89554F85E27A7C6'
            '8D4ADC7032298F7BD4EFF504ACA6295F'
            '668FBF478ADB2BE51E6CDE292B82DE2A'
        ))

    def test_rabbit_iv_02(self):
        unit = self.load(0x00.to_bytes(16, 'big'), iv=0xC373F575C1267E59.to_bytes(8, 'little'))
        data = bytearray(48)
        self.assertEqual(unit(data), bytes.fromhex(
            '6D7D012292CCDCE0E2120058B94ECD1F'
            '2E6F93EDFF99247B012521D1104E5FA7'
            'A79B0212D0BD56233938E793C312C1EB'
        ))

    def test_rabbit_iv_03(self):
        unit = self.load(0x00.to_bytes(16, 'big'), iv=0xA6EB561AD2F41727.to_bytes(8, 'little'))
        data = bytearray(48)
        self.assertEqual(unit(data), bytes.fromhex(
            '4D1051A123AFB670BF8D8505C8D85A44'
            '035BC3ACC667AEAE5B2CF44779F2C896'
            'CB5115F034F03D31171CA75F89FCCB9F'
        ))
