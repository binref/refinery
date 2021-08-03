#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from .. import TestBase
from io import BytesIO

from refinery.lib.loader import load_pipeline, load_detached as L


class TestGrabBagExamples(TestBase):

    def test_example_01_maldoc(self):
        data = self.download_sample('81a1fca7a1fb97fe021a1f2cf0bf9011dd2e72a5864aad674f8fea4ef009417b')

        # flake8: noqa
        pipeline = L('xlxtr 9.5:11.5 15.15 12.5:14.5') [
            L('scope -n 3') | L('chop -t 5') [
                L('sorted') | L('snip 2:') | L('sep')
            ]| L('pack 10') | L('blockop --dec -sN B-S')
        ]| L('carveb64z') | L('deob-ps1') | L('carveb64z') | L('deob-ps1') | L('xtp -f domain')

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
        data = self.download_sample('ee790d6f09c2292d457cbe92729937e06b3e21eb6b212bf2e32386ba7c2ff22c')
        rsrc = L('perc RCDATA')(data)

        pipeline = L('xtp guid') [
            L('PBKDF2 48 rep[8]:H:00') | self.ldu('cca', rsrc) | L('aes x::32 --iv=x::16 -Q')
        ] | L('dnds')

        result = json.loads(pipeline(data))
        config = result[2]['Data']['Members']

        self.assertEqual(config['_EmailServer'], F'mail{"."}bandaichemical{"."}com')
        self.assertEqual(config['_EmailUsername'], F'cv{"@"}bandaichemical{"."}com')
        self.assertEqual(config['_EmailPassword'], F'kingqqqqqq1164')
        self.assertEqual(config['_EmailPort'], 587)

    def test_warzone_sample(self):
        data = self.download_sample('4537fab9de768a668ab4e72ae2cce3169b7af2dd36a1723ddab09c04d31d61a5')
        pipeline = L('vsect .bss') | L('struct L{key:{0}}$') [
            L('rc4 xvar:key') | L('struct L{host:{}}{port:H} {host:u16}:{port}') ]
        self.assertEqual(str(data | pipeline), '165.22.5''.''66:1111')

    def test_blackmatter_sample(self):
        data = self.download_sample('c6e2ef30a86baa670590bd21acf5b91822117e0cbe6060060bc5fe0182dace99')
        pipeline = load_pipeline('push [| vsect .rsrc | struct {KS:L}$ | pop | vsect .data | struct L{:{0}}'
            '| blockop -P8 -B4 "((A*KS)>>32)^B" "take[1:]:accu[KS,4]:A*0x8088405+1" | repl h:00 | carve -n8 printable ]]')
        strings = str(data | pipeline).splitlines(False)
        self.assertIn('Safari/537.36', strings)
        self.assertIn('bcdedit /set {current} safeboot network', strings)
        self.assertTrue(any('"bot_company":"%.8x%.8x%.8x%.8x%"' in x for x in strings))
        self.assertTrue(any('BlackMatter Ransomware encrypted all your files!' in x for x in strings))
