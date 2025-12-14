from ... import TestUnitBase


class TestRPAExtractor(TestUnitBase):

    def test_real_world_01(self):
        data = self.download_sample('df5a5f715046ab396044c6c939a1a9437172fb3ba9af60a2f9df606f0bec127b')
        test = data | self.load() | [bytes]
        self.assertEqual(len(test), 4)
        for file in test:
            self.assertTrue(file.startswith(B'RENPY RPC2'))
        self.assertSetEqual({len(t) for t in test}, {104306, 25910, 7848, 5382})
