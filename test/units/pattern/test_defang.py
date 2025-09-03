from .. import TestUnitBase


class TestDefangUnit(TestUnitBase):

    def test_url_defang(self):
        df = self.load()
        self.assertEqual(
            df(B'visit https://binref.github.io/ for some retro docs'),
            B'visit https[:]//binref.github[.]io/ for some retro docs'
        )

    def test_url_defang_protocol_01(self):
        df = self.load(url_protocol=True)
        self.assertEqual(
            df(B'visit https://binref.github.io/ for some retro docs'),
            B'visit hxxps[:]//binref.github[.]io/ for some retro docs'
        )

    def test_url_defang_protocol_02(self):
        df = self.load(url_protocol=True, dot_only=True)
        self.assertEqual(
            df(B'visit ftp://user:password@10.0.10.20/malware for some malware'),
            B'visit fxp://user:password@10.0.10[.]20/malware for some malware'
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
        data = B'Description: As seen on hxxps[://]caminoflamingo[.]co[.]uk, flamingos are on the rise.'
        unit = self.load(reverse=True)
        self.assertEqual(unit(data),
            B'Description: As seen on https://caminoflamingo.co.uk, flamingos are on the rise.')

    def test_fxp_escape(self):
        data = B'Download malware from fxps://user:password@10.10.0[.]30/malware'
        unit = self.load(reverse=True)
        self.assertEqual(unit(data),
            B'Download malware from ftps://user:password@10.10.0.30/malware')

    def test_dots_in_various_places(self):
        data = B'Maybe 12[.]67.123.12 or 12[.]67[.]123.12 or 12.67[.]123.12 or 32.67[.]123[.]12'
        unit = self.load(reverse=True)
        self.assertEqual(unit(data), data.replace(B'[.]', B'.'))

    def test_defang_defang_01(self):
        unit = self.load()
        u = b'http://www.example.com:433/'
        v = bytes(u | unit)
        w = bytes(v | unit)
        self.assertEqual(v, w)

    def test_defang_defang_02(self):
        unit = self.load()
        u = b'http://www.example.co.uk/'
        v = bytes(u | unit)
        self.assertEqual(v, b'http[:]//www.example[.]co[.]uk/')

    def test_defang_defang_03(self):
        unit = self.load()
        u = b'http://www.example.co.uk:443/'
        v = u | unit | str
        self.assertEqual(v, 'http[:]//www.example[.]co[.]uk:443/')

    def test_url_fragment(self):
        unit = self.load()
        u = b'http://alpha.beta.gamma.co.cn#foo@bar.com'
        v = u | unit | str
        self.assertEqual(v, 'http[:]//alpha.beta.gamma[.]co[.]cn#foo@bar[.]com')

    def test_protocol_relative_url_01(self):
        unit = self.load()
        u = b'//alpha.beta.gamma.co.cn/path/to/script.zip?evil=domain.ru'
        v = u | unit | str
        self.assertEqual(v, '//alpha.beta.gamma[.]co[.]cn/path/to/script[.]zip?evil=domain[.]ru')
