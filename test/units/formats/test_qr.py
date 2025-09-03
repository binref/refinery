from .. import TestUnitBase


class TestQRDecoder(TestUnitBase):

    def test_real_world_qr_code_phishing(self):
        data = self.download_sample('6bc6d99524b46def23295d8a52c8973651338053d142386fd5d4e9c25501c071')
        test = data | self.ldu('xt', 'word/media/image2.png') | self.load() | self.ldu('urlfix') | str
        self.assertEqual(test, 'https:''//''tolviaes''.''ru''.''com/MdsopLs/')
