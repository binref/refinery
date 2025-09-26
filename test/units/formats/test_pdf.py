from .. import TestUnitBase


class TestPDF(TestUnitBase):

    def test_pdf_maldoc_with_embedded_flash(self):
        data = self.download_sample('76b19c1e705328cab4d98e546095eb5eb601d23d8102e6e0bfb0a8a6ab157366')

        test = data | self.load('raw/*', list=True) | {str}
        self.assertLessEqual({
            'raw/Root/Metadata',
            'raw/Root/OpenAction/JS',
            'raw/Root/Pages/Kids/0/Annots/0/NM',
            'raw/Root/Pages/Kids/0/Annots/0/RichMediaContent/Assets/Names/1/fqMBgzoMVutzNwk.swf',
        }, test)

        unit = self.load('Pages/*NM', 'Pages/*.swf')
        name, swf = data | unit
        self.assertEqual(name, B'fqMBgzoMVutzNwk.swf')
        self.assertEqual(swf[:3], B'CWS')

        unit = self.load('fqMBgzoMVutzNwk') | self.ldu('sha256', text=True)
        self.assertEqual(data | unit | str,
            'c2b666a3ef4c191b77b78c037656e50477b8ba3d35fd61ae843a3a1f4d41c5c1')
