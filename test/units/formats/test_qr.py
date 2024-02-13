#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestQRDecoder(TestUnitBase):

    def test_espionage_ctf(self):
        data = self.download_sample('42633ccc32939dc999e4d962a1c34ad9ae42eef43a958c9dac820987c1275800')
        flag = data | self.load_pipeline('rc4 Encrypt0r_K3yMast3r! | qr | b64 | xtzip file.txt | b64') | str
        self.assertEqual(flag, r'EspionageCTF{Gl1tch_1n_Th3_M4tr1x}')
