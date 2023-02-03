#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_pipeline as L
from .. import TestUnitBase


class TestJCALG(TestUnitBase):

    def test_vnc_backdoor_sample(self):
        data = self.download_sample('6d9e2f54382ea697203d714424caefdacf1524c001efbaa7c33320738301808d')
        pipe = L('vsnip 0x00403020: | xor h:760000006E00 | jcalg | carve-pe | xtp -ff')
        result = data | pipe | {str}
        self.assertSetEqual(result, {'185.82.202''.132:443'})
