from ... import TestUnitBase


class TestTEA(TestUnitBase):

    def test_example_little_endian(self):
        data = bytes.fromhex('518c4bf6048edaaeb5c760dd797f6f010c87feec5c7e3a08c942a4540ed494b3')
        unit = self.load(key=b'0123456789abcdef')
        self.assertEqual(data | unit | str, 'This is a secret message.')

    def test_example_big_endian(self):
        data = bytes.fromhex('18381cf66f04b5430236afbb34e8fc97878ef127b31b29356525faf2978a2726')
        unit = self.load(key=b'0123456789abcdef', swap=True)
        self.assertEqual(data | unit | str, 'This is a secret message.')
