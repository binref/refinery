from .. import TestUnitBase


class TestBitReversal(TestUnitBase):

    def test_idempotence(self):
        for b in (1, 2, 3, 4, 5, 7, 8, 12, 17):
            unit = self.load(blocksize=b)
            data = self.generate_random_buffer(841)
            self.assertEqual(data, unit(unit(data)), F'failed idempotence test for block size {b}')

    def test_the_unit_is_freed_without_the_collector(self):
        from refinery.units.blockwise.bitrev import bitrev
        for blocksize in (1, 2, 3):
            with self.subTest(blocksize=blocksize), self.assertNoInstanceSurvives(bitrev):
                unit = self.load(blocksize=blocksize)
                self.assertEqual(unit(unit(B'refinery')), B'refinery')
                del unit
