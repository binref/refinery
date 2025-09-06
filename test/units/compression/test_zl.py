from .. import TestUnitBase
from . import KADATH1, KADATH2


class TestZL(TestUnitBase):

    def test_decompress_two_buffers(self):
        from refinery.lib.exceptions import RefineryPartialResult
        unit = self.load()

        b1 = KADATH1
        b2 = KADATH2
        ib = [b1, b2]

        cb = ib | -unit | bytes
        db = cb | +unit | [str]

        self.assertListEqual(ib, db)

        junk = b'\x21\xC4\x04\x21AAAA'
        cb += junk

        with self.assertRaises(RefineryPartialResult) as e:
            db = cb | +unit | [str]
            self.assertEqual(e.exception.rest, junk)

        db = cb | self.load(lenient=True) | [bytes]
        self.assertListEqual(db, [b1.encode(), b2.encode(), junk])
