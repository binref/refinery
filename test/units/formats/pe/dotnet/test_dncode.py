from .... import TestUnitBase


class TestDotNetCodeExtractor(TestUnitBase):

    def test_real_world_01(self):
        data = self.download_sample('2579bc4cd0d5f76d1a2937a0e0eb0256f2a9f2f8a30c1da694be66bfa04dc740')
        test = data | self.load('filecrypt') | bytes
        self.assertEqual(test, bytes.fromhex(
            '0003281F00000A0A282000000A046F2100000A0B282200000A076F2300000A0B040628030000060C0308282400000A00'
            '03037201000070282500000A282600000A002A'))
