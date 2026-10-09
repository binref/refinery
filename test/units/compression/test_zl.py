import contextlib
import zlib

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

    def test_a_failed_decompression_leaves_nothing_to_the_collector(self):
        data = self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73')
        unit = self.load()

        def decompress():
            with contextlib.suppress(zlib.error):
                bytearray(data) | unit | bytes

        self.assertCollectorFreesLessThan(0x40000, decompress)
