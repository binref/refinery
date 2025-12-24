from .. import TestUnitBase


class TestJPG(TestUnitBase):

    def test_real_world_guloader(self):
        data = self.download_sample('3b1b945750892b2feea1f296d34b600811ffe02931f604ea48a819f47d3a8e14')
        test = data | self.load('app12') | bytes
        self.assertTrue(test.startswith(b'Ducky'))
        test = data | self.load('scans/0') | self.ldu('sha256', text=True) | str
        self.assertEqual(test, '49480541d70cb44f59526555f7c81e67dd9df0918f4cfbba89f0046d518b4226')
