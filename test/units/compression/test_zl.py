from .. import TestUnitBase
from . import KADATH1, KADATH2


class TestZL(TestUnitBase):

    def test_decompress_two_buffers(self):
        unit = self.load()
        b1 = KADATH1
        b2 = KADATH2
        ib = [b1, b2]
        cb = ib | -unit | bytes
        db = cb | +unit | [str]
        self.assertListEqual(ib, db)
        cb += b'\x21\xC4\x04\x21AAAA'
        db = cb | +unit | [str]
        self.assertListEqual(ib, db)
