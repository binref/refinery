from .. import TestUnitBase


class TestNGrams(TestUnitBase):

    def test_simple_01(self):
        pl = self.load_pipeline('emit ABC | ngrams 1 []')
        self.assertEqual(pl(), B'ABC')

    def test_simple_02(self):
        pl = self.load_pipeline('emit ABC | ngrams 2 []')
        self.assertEqual(pl(), B'ABBC')

    def test_reports_the_position_of_each_block(self):
        results = b'ABCD' | self.load(size=slice(2, 2)) | []
        self.assertListEqual(
            [(bytes(r), r['start'], r['end']) for r in results],
            [(b'AB', 0, 2), (b'BC', 1, 3), (b'CD', 2, 4)])

    def test_bounds_are_inclusive(self):
        results = b'ABC' | self.load(size=slice(1, 2)) | []
        self.assertListEqual(
            [bytes(r) for r in results],
            [b'A', b'B', b'C', b'AB', b'BC'])
