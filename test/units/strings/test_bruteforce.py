from .. import TestUnitBase


class TestBruteForce(TestUnitBase):

    def test_bit_string_brute_force(self):
        pl = self.load('t', 4, pattern='[01]') [ self.ldu('swap', 't') ] # noqa
        self.assertSetEqual({int(x, 2) for x in pl}, set(range(0b10000)))

    def test_brute_force_format(self):
        pl = self.load('t', 1, pattern='[XZ]', format='{1}{0}BAR') [ self.ldu('swap', 't') ] # noqa
        self.assertEqual(pl(B'FOO'), B'FOOXBARFOOZBAR')
