#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import hashlib

from .. import TestUnitBase


class TestMSI(TestUnitBase):

    def test_real_world_01(self):
        data = self.download_sample('5316330427de98c60661233369909132f6b838b5ff111f7f29efe3e90636a34a')
        msi = data | self.load() | {'path': ...}
        meta = json.loads(msi['MsiTables.json'])
        self.assertEqual(meta['Property'][19]['Value'], "Típica")
        self.assertContains(msi['Action/basicsmarch.js'], b'FDWPLOVWRX(PIENNNAXXI+ QRQHCMZIEY,NAXXIPIENN+ BJHZRJLZFX)')
        self.assertEqual(hashlib.sha256(msi['Binary/aicustact.dll']).hexdigest(),
            'f2f3ae8ca06f5cf320ca1d234a623bf55cf2b84c1d6dea3d85d5392e29aaf437')

    def test_cab_extraction(self):
        data = self.download_sample('5c698edeba5260b1eb170c375015273324b86bae82722d85d2f013b22ae52d0c')
        msi = data | self.load() | {'path': ...}
        cab = '_A43DCF057E5B03E2396812E1C2F1D349'
        for t in '123de':
            self.assertIn(F'{cab}/{t}', msi)
        self.assertEqual(msi[F'{cab}/1'], B'M')
        self.assertEqual(msi[F'{cab}/2'], B'Z')
