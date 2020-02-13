#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from .. import TestBase
from io import BytesIO

from refinery import (
    aes,
    blockop,
    carve_b64z,
    cca,
    chop,
    deob_ps1,
    dnds,
    dnhdr,
    pack,
    PBKDF2,
    perc,
    scope,
    sep,
    snip,
    sorted,
    xlxtr,
    xtp,
)


class TestGrabBagExamples(TestBase):

    def test_example_01_maldoc(self):
        data = self.download_from_malshare('81a1fca7a1fb97fe021a1f2cf0bf9011dd2e72a5864aad674f8fea4ef009417b')

        pipeline = xlxtr('9.5:11.5', '15.15', '12.5:14.5') [
            scope('-n', 3) | chop('-t', 5) [
                sorted | snip('2:') | sep
            ] | pack(10) | blockop('--dec', '-sN', 'B-S')
        ] | carve_b64z | deob_ps1 | carve_b64z | deob_ps1 | xtp('domain', filter=True)

        with BytesIO(data) as sample:
            c2servers = set(sample | pipeline)

        self.assertSetEqual(
            c2servers,
            set(c2 % 0x2E for c2 in {
                b'udatapost%cred',
                b'marvellstudio%conline',
                b'sdkscontrol%cpw',
                b'abrakam%csite',
                b'hiteronak%cicu',
                b'ublaznze%conline',
                b'sutsyiekha%ccasa',
                b'makretplaise%cxyz',
            })
        )

    def test_example_02_hawkeye_config(self):
        data = self.download_from_malshare('ee790d6f09c2292d457cbe92729937e06b3e21eb6b212bf2e32386ba7c2ff22c')
        rsrc = perc('RCDATA')(data)

        pipeline = xtp('guid') [
            PBKDF2(48, 'rep[8]:H:00') | cca(rsrc) | aes('CBC', 'x::32', '--iv=x::16', quiet=True)
        ] | dnds

        result = json.loads(pipeline(data))
        config = result[2]['Data']['Members']

        self.assertEqual(config['_EmailServer'], F'mail{"."}bandaichemical{"."}com')
        self.assertEqual(config['_EmailUsername'], F'cv{"@"}bandaichemical{"."}com')
        self.assertEqual(config['_EmailPassword'], F'kingqqqqqq1164')
        self.assertEqual(config['_EmailPort'], 587)

