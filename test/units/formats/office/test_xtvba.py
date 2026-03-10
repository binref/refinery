from ... import TestUnitBase


class TestVBAExtractor(TestUnitBase):

    def test_maldoc_01(self):
        data = self.download_sample('4bdc8e660ff4fb05e5b6c0a2dd70c537817f46ac3270d779fdddc8e459829c08')
        unit = self.load()
        code = list(data | unit)
        self.assertIn(B'http://109.94.209'B'.91/12340.txt', code[0])

    def test_maldoc_02(self):
        data = self.download_sample('ee103f8d64cd8fa884ff6a041db2f7aa403c502f54e26337c606044c2f205394')
        unit = self.load()
        code = list(data | unit)
        self.assertIn(B'ActiveDocument.Content.Find.Execute FindText:="$1", ReplaceWith:=dowKarolYou, Replace:=wdReplaceAll', code[0])

    def test_do_not_extract_plaintext(self):
        data = b"some plaintext data"
        unit = self.load()
        self.assertEqual(bytes(data | unit), b'')
