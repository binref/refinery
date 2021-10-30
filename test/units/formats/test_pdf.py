#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestPDF(TestUnitBase):

    def test_pdf_maldoc_with_embedded_flash(self):
        data = self.download_sample('76b19c1e705328cab4d98e546095eb5eb601d23d8102e6e0bfb0a8a6ab157366')

        unit = self.load(list=True)
        self.assertEqual(list(data | unit), [
            B'/Metadata',
            B'/OpenAction/JS',
            B'/Pages/Kids/0/Annots/0/NM',
            B'/Pages/Kids/0/Annots/0/RichMediaContent/Assets/Names/fq#4dB#67#7a#6f#4dV#75t#7a#4ew#6b.#73#77#66',
        ])

        unit = self.load('/Pages/*')
        name, swf = data | unit
        self.assertEqual(name, B'fqMBgzoMVutzNwk.swf')
        self.assertEqual(swf[:3], B'CWS')

        unit = self.load('4dB') | self.ldu('sha256', text=True)
        self.assertEqual(str(data | unit), 'c2b666a3ef4c191b77b78c037656e50477b8ba3d35fd61ae843a3a1f4d41c5c1')
