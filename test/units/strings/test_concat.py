from .. import TestUnitBase


class TestConcatentation(TestUnitBase):

    def test_prepend(self):
        self.assertEqual(self.ldu('ccp', 's:Hello').process(B' World'), B'Hello World')

    def test_append(self):
        self.assertEqual(self.ldu('cca', 's:World').process(B'Hello '), B'Hello World')

    def test_formatter_simple(self):
        self.assertEqual(self.ldu('pf', 'Hello {} World')(B'cruel'), B'Hello cruel World')
