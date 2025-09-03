from ... import TestUnitBase


class TestHKDF(TestUnitBase):

    def test_real_world_01(self):
        data = B'Onions'
        wish = bytes.fromhex('2b1949e08d2a0cbb478bc0f9270f05b4')
        unit = self.load(16, bytes.fromhex('8e94ef805b93e683ff18'))
        self.assertEqual(unit(data), wish)
