from ... import TestUnitBase


class TestSM3(TestUnitBase):

    def test_empty_string(self):
        unit = self.load(text=True)
        test = b'' | unit | bytes
        self.assertEqual(test, b'1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b')

    def test_abc(self):
        unit = self.load(text=True)
        test = b'abc' | unit | bytes
        self.assertEqual(test, b'66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')

    def test_binary_output(self):
        unit = self.load()
        test = b'abc' | unit | bytes
        self.assertEqual(test.hex(), '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')

    def test_repeated_hashing(self):
        unit = self.load(reps=2)
        single = self.load()
        data = b'test data'
        first_hash = data | single | bytes
        double_hash = first_hash | single | bytes
        self.assertEqual(data | unit | bytes, double_hash)

    def test_abcd_times_16(self):
        unit = self.load(text=True)
        test = (b'abcd' * 16) | unit | str
        self.assertEqual(test, 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')

    def test_sm2_za_message_digest(self):
        data = bytes.fromhex('F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A6D65737361676520646967657374')
        unit = self.load(text=True)
        test = data | unit | str
        self.assertEqual(test, 'b524f552cd82b8b028476e005c377fb19a87e6fc682d48bb5d42e3d9b9effe76')

    def test_65_bytes(self):
        # 65-byte input from GB/T 32918.3-2016 Appendix B.8
        data = bytes.fromhex(
            '022AF86EFE732CF12AD0E09A1F2556CC650D9CCCE3E249866BBB5C6846A4C4A2'
            '95FF49D95BD45FCE99ED54A8AD7A7091109F51394442916BD154D1DE4379D976'
            '47'
        )
        unit = self.load(text=True)
        test = data | unit | str
        self.assertEqual(test, '284c8f198f141b502e81250f1581c7e9eeb4ca6990f9e02df388b45471f5bc5c')

    def test_cyberchef_comparison(self):
        data = B'The Binary Refinery refines the Finest Binaries.'
        unit = self.load(text=True)
        test = data | unit | str
        self.assertEqual(test, '7d6aa2c2cd26fa59124d46e2641f01646a6f701380f3f5095fb63990f994fee7')
