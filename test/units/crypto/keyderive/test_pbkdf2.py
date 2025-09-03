from ... import TestUnitBase


class TestPBKDF2(TestUnitBase):

    def test_real_world_01(self):
        data = B'Onions'
        wish = bytes.fromhex('0F8577CE3EBABADD264411530B9F6710DF881A755338C2897178DC8A7D3E60D9')
        unit = self.load(32, B'SALTYSALTYSALTYSALTYPEPPERMINT', iter=1000)
        self.assertEqual(unit(data), wish)
