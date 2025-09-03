from .. import TestUnitBase


class TestBriefLZ(TestUnitBase):

    def test_decompress_partial(self):
        D = self.load()
        C = self.load(reverse=True)
        M = b'the finest refinery of binaries refines binaries, not finery.'
        self.assertEqual(next(M | C | D), M)

    def test_compress_rle(self):
        C = self.load(reverse=True)
        D = self.load()
        M = B'B' + B'A' * 80
        X = next(M | C)
        self.assertEqual(len(X), 29)
        self.assertEqual(next(X | D), M)

    def test_malware_sample(self):
        C = self.load(reverse=True)
        D = self.load()
        M = self.download_sample('2579bc4cd0d5f76d1a2937a0e0eb0256f2a9f2f8a30c1da694be66bfa04dc740')
        self.assertEqual(next(M | C | D), M)

    def test_compress_repeated_byte(self):
        C = self.load(reverse=True)
        D = self.load()
        M = B'\0' * 20_000
        X = next(M | C)
        self.assertEqual(next(X | D), M)
        self.assertLessEqual(len(X), 24 + 8)
