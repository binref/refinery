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
