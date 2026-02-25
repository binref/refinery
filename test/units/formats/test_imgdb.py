from .. import TestUnitBase


class TestImgDB(TestUnitBase):

    def test_flareOn12_PDF(self):
        data = self.download_sample('7824f6f7644f9e29a77c25e525a4d235d8fdcb66664961745bfa735c13179832')
        test = data | self.ldu('xtpdf', 'Pages/Kids/0/Contents') | self.ldu('csd', 'hex') | self.load() | str
        self.assertEqual(test, 'Puzzl1ng-D3vilish-F0rmat@flare-on.com')
