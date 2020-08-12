#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestPatternExtractor(TestUnitBase):

    def test_extraction_environment_variable(self):
        unit = self.load('evar')
        self.assertEqual(b'%TEST%', unit(B'This is a %TEST% with environment variable.'))

    def test_extraction_domain_01(self):
        unit = self.load('domain')
        self.assertEqual(b'google.com', unit(b'Just use google.com. It is the best.'))

    def test_extraction_domain_02(self):
        unit = self.load('domain')
        self.assertEqual(b'evil.c2server.com', unit(b'\x00\x00\x00evil.c2server.com\x52\x50\x00\x00\x00'))

    def test_extraction_domain_03(self):
        unit = self.load('domain')
        self.assertEqual(b'evil.c2server.com', unit(b'\x00\x00\x00evil.c2server.com\x50\x00\x00\x00\x00'))

    def test_extraction_domain_04(self):
        unit = self.load('domain')
        self.assertEqual(b'', unit(
            b'\x00ios_base::eofbit set\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'b\x00u\x00i\x00l\x00d\x00.\x00b\x00i\x00n\x00\x00\x00\x00\x00\x00\x00')
        )

    def test_extraction_domain_05(self):
        unit = self.load('domain')
        self.assertEqual(b'', unit(b'\xFA\xF0-b.app\x00\x00'))

    def test_filter_01(self):
        unit = self.load('domain', filter=True)
        self.assertEqual(b'www.evilscam-124rd23d23.notmicrosoft.com',
            unit(b'Just click <a href="www.evilscam-124rd23d23.notmicrosoft.com">here!</a>'))

    def test_extract_uppercase_guids(self):
        unit = self.load('guid')
        data = B'An uppercase GUID! A5371AF2-2000-4A4C-ADD2-5E6F1E302B41'
        self.assertEqual(unit(data), B'A5371AF2-2000-4A4C-ADD2-5E6F1E302B41')

    def test_real_domain_with_dash(self):
        data = bytes.fromhex(
            '10 10 73 61 6E 73 2D 73 65 72 69 66 2D 6C 69 67'  # ..sans-serif-lig
            '68 74 00 15 15 47 6F 6F 67 6C 65 2D 63 6F 6D 2E'  # ht...Google-com.
            '6C 69 6E 6B 70 63 2E 6E 65 74 00 05 05 31 30 37'  # linkpc.net...107
            '31 37 00 04 04 6E 75 6C 6C 00 07 07 53 65 72 76'  # 17...null...Serv
        )
        unit = self.load('domain')
        hits = list(unit.process(data))
        self.assertIn(b'Google-com.linkpc.net', hits)

    def test_email_with_dash(self):
        data = (
            B'\r\r\nBart_simpson@springfield.name\r\r\n'
            B'&nbsp;&nbsp;&nbsp;&nbsp;<small><small>or</small></small>&nbsp;&nbsp;&nbsp;&nbsp;'
            B'\r\r\nlisa_simpson02@protonmail.com'
        )
        unit = self.load('email')
        hits = list(unit.process(data))
        self.assertIn(b'Bart_simpson@springfield.name', hits)
        self.assertIn(b'lisa_simpson02@protonmail.com', hits)

    def test_email_allcaps(self):
        data = (
            B'Email us at ALEXANDER.IRWIN@PROTONMAIL.COM (or) MISAEL.SHORT@TUTANOTA.COM to get the ransom amount.'
            B'Keep our contacts safe. Disclosure can lead to impossibility of decryption.'
        )
        unit = self.load('email')
        hits = list(unit.process(data))
        self.assertIn(b'ALEXANDER.IRWIN@PROTONMAIL.COM', hits)
        self.assertIn(b'MISAEL.SHORT@TUTANOTA.COM', hits)

    def test_email_with_symbols(self):
        self.assertEqual(self.load('email', filter=True)(B'.###/.test@host.com.Q@aVw5w.tR.'), B'test@host.com')

    def test_url_with_tilde(self):
        url = B'http://www.htz.klmp.cv.gov.edu/~drjay/obbx/grades.txt'
        self.assertEqual(self.load('url')(url), url)

    def test_monero_address(self):
        addr = B'4BrL51JCc9NGQ71kWhnYoDRffsDZy7m1HUU7MRU4nUMXAHNFBEJhkTZV9HdaL4gfuNBxLPc3BeMkLGaPbF5vWtANQni58KYZqH43YSDeqY'
        data = B'payment is made to the wallet %s.' % addr
        self.assertEqual(addr, self.load('xmr')(data))
