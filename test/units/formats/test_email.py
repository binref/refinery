from .. import TestUnitBase


class TestEmailUnpacker(TestUnitBase):

    def test_ascii_01(self):
        data = self.download_sample('a370a9c5defdd25da62ccb33539e6741f1545057f66b59392ffe094157c5fce8')
        unit = self.load(list=True)
        listing = [t.decode('latin1') for t in data | unit]
        for k in range(1, 4):
            self.assertIn(F'body.txt/{k}', listing)
            self.assertIn(F'body.rtf/{k}', listing)
        self.assertIn('attachments/request.zip', listing)

    def test_ascii_02(self):
        data = self.download_sample('a370a9c5defdd25da62ccb33539e6741f1545057f66b59392ffe094157c5fce8')
        extract1 = self.load('body.txt/2')
        extract2 = self.load('*.zip')
        self.assertIn(B'If you are unsure LKQ IT Security advises deleting the email.', extract1(data))
        zipfile = extract2(data)
        self.assertEqual(zipfile[:2], B'PK')
        self.assertIn(B'require.05.21.doc', zipfile)
        self.assertEqual(len(zipfile), 77_848)

    def test_cdfv2_01(self):
        data = self.download_sample('f4d5353552501b7aa0f9bb400e0d0349487dc45cbe5ce82fe5e7de526d37f301')
        out = data | self.load() | {'path': ...}
        self.assertTrue(set(out) >= {
            'headers.txt',
            'headers.json',
            'body.txt',
            'attachments/request.zip',
        })
        self.assertIn(b'figures,12.18.2020.doc', out['attachments/request.zip'])

    def test_embedded_attachment_extraction(self):
        data = self.download_sample('8f567c5fe40e15394ccf158356e445ea6b9afcbab8a225ad1c6c697f95ce36b9')
        unit = self.load('*.htm')
        html = str(data | unit)
        self.assertIn('<label for="username" class="sr-only">Email address</label>', html)
