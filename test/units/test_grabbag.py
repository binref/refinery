#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from .. import TestBase
from io import BytesIO

from refinery.lib.loader import load_commandline as L


class TestGrabBagExamples(TestBase):

    def test_example_01_maldoc(self):
        data = self.download_from_malshare('81a1fca7a1fb97fe021a1f2cf0bf9011dd2e72a5864aad674f8fea4ef009417b')

        # flake8: noqa
        pipeline = L('xlxtr 9.5:11.5 15.15 12.5:14.5') [
            L('scope -n 3') | L('chop -t 5') [
                L('sorted') | L('snip 2:') | L('sep')
            ]| L('pack 10') | L('blockop --dec -sN B-S')
        ]| L('carveb64z') | L('deob_ps1') | L('carveb64z') | L('deob_ps1') | L('xtp -f domain')

        with BytesIO(data) as sample:
            c2servers = set(sample | pipeline)

        self.assertSetEqual(
            {bytes(c2) for c2 in c2servers},
            {c2 % 0x2E for c2 in {
                b'udatapost%cred',
                b'marvellstudio%conline',
                b'sdkscontrol%cpw',
                b'abrakam%csite',
                b'hiteronak%cicu',
                b'ublaznze%conline',
                b'sutsyiekha%ccasa',
                b'makretplaise%cxyz',
            }}
        )

    def test_example_02_hawkeye_config(self):
        data = self.download_from_malshare('ee790d6f09c2292d457cbe92729937e06b3e21eb6b212bf2e32386ba7c2ff22c')
        rsrc = L('perc RCDATA')(data)

        pipeline = L('xtp guid') [
            L('PBKDF2 48 rep[8]:H:00') | self.ldu('cca', rsrc) | L('aes CBC x::32 --iv=x::16 -Q')
        ] | L('dnds')

        result = json.loads(pipeline(data))
        config = result[2]['Data']['Members']

        self.assertEqual(config['_EmailServer'], F'mail{"."}bandaichemical{"."}com')
        self.assertEqual(config['_EmailUsername'], F'cv{"@"}bandaichemical{"."}com')
        self.assertEqual(config['_EmailPassword'], F'kingqqqqqq1164')
        self.assertEqual(config['_EmailPort'], 587)
