from .. import TestUnitBase


class TestSWF(TestUnitBase):

    def test_real_world(self):
        data = self.download_sample('76b19c1e705328cab4d98e546095eb5eb601d23d8102e6e0bfb0a8a6ab157366')
        test = data | self.ldu('xt', 'swf') | self.load() | bytes
        self.assertIn(B'http:'B'//'B'code.flashdynamix'B'.com/AES/aes-decrypt.php', test)
