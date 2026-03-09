from .. import TestUnitBase


class TestBruteForce(TestUnitBase):

    def test_bit_string_brute_force(self):
        pl = self.load('t', 4, pattern='[01]') [ self.ldu('swap', 't') ] # noqa
        self.assertSetEqual({int(x, 2) for x in pl}, set(range(0b10000)))

    def test_brute_force_format(self):
        pl = self.load('t', 1, pattern='[XZ]', format='{1}{0}BAR') [ self.ldu('swap', 't') ] # noqa
        self.assertEqual(pl(B'FOO'), B'FOOXBARFOOZBAR')

    def test_bruteforce_single_char(self):
        pl = self.load('v', 1, alphabet=b'AB') [ self.ldu('swap', 'v') ] # noqa
        results = sorted(B'' | pl | [])
        self.assertEqual(results, [b'A', b'B'])

    def test_bruteforce_digits(self):
        pl = self.load('v', 1, digits=True) [ self.ldu('swap', 'v') ] # noqa
        results = sorted(B'' | pl | [])
        self.assertEqual(len(results), 10)
        self.assertEqual(results, [str(d).encode() for d in range(10)])

    def test_bruteforce_custom_alphabet(self):
        pl = self.load('v', 2, alphabet=b'XY') [ self.ldu('swap', 'v') ] # noqa
        results = sorted(B'' | pl | [])
        self.assertEqual(len(results), 4)
        self.assertEqual(results, [b'XX', b'XY', b'YX', b'YY'])
