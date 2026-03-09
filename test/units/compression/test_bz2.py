import bz2 as bz2_

from .. import TestUnitBase


class TestBZ2(TestUnitBase):

    def test_decompress(self):
        unit = self.load()
        data = b'Hello, BZ2 compression!'
        compressed = bz2_.compress(data)
        self.assertEqual(unit(compressed), data)

    def test_compress(self):
        unit = self.load()
        data = b'Hello, BZ2 compression!'
        compressed = data | -unit | bytes
        self.assertEqual(bz2_.decompress(compressed), data)

    def test_roundtrip(self):
        unit = self.load()
        data = b'The quick brown fox jumps over the lazy dog.' * 10
        self.assertEqual(data | -unit | unit | bytes, data)

    def test_handles_magic(self):
        from refinery.units.compression.bz2 import bz2
        self.assertTrue(bz2.handles(b'BZh91AY&SY'))
        self.assertFalse(bz2.handles(b'\x00\x00\x00'))

    def test_compression_level(self):
        data = b'BINARY!REFINERY!' * 200
        unit = self.load()
        c1 = data | -self.load(level=1) | bytes
        c9 = data | -self.load(level=9) | bytes
        self.assertEqual(unit(c1), data)
        self.assertEqual(unit(c9), data)
