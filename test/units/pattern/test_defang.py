#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestDefangUnit(TestUnitBase):

    def test_url_defang(self):
        df = self.load()
        self.assertEqual(
            df(B'visit https://binref.github.io/ for some retro docs'),
            B'visit https[:]//binref.github[.]io/ for some retro docs'
        )

    def test_ipv4_defang(self):
        df = self.load()
        self.assertEqual(
            df(B'Blah foo connects to `10.0.13.11` and `192.168.102.3`'),
            B'Blah foo connects to `10.0.13[.]11` and `192.168.102[.]3`'
        )

    def test_email_allcaps(self):
        data = B'Email us at ALEXANDER.IRWIN@PROTONMAIL.COM (or) MISAEL.SHORT@TUTANOTA.COM to get the ransom amount.'
        unit = self.load()
        self.assertEqual(unit(data),
            B'Email us at ALEXANDER.IRWIN@PROTONMAIL[.]COM (or) MISAEL.SHORT@TUTANOTA[.]COM to get the ransom amount.')

    def test_hxxp_escape(self):
        data = B'Description: As seen on hxxps://caminoflamingo[.]co[.]uk, flamingos are on the rise.'
        unit = self.load(reverse=True)
        self.assertEqual(unit(data),
            B'Description: As seen on https://caminoflamingo.co.uk, flamingos are on the rise.')
