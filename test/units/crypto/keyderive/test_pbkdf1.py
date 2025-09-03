from ... import TestUnitBase


class TestPBKDF1(TestUnitBase):

    def test_real_world_01(self):
        data = B'Onions'
        wish = bytes.fromhex('BD24EA73978A41E76B0E204A74DC57E8')
        unit = self.load(16, B'SALTYEGG')
        self.assertEqual(unit(data), wish)
