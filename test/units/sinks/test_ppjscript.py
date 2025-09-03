from .. import TestUnitBase


class TestPPJscript(TestUnitBase):

    def test_simple_formatting(self):
        self.assertEqual('a=9;b=10;c=1;' | self.load() | str, 'a = 9;\nb = 10;\nc = 1;')
