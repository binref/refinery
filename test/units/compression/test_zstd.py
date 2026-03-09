from .. import TestUnitBase


class TestZStd(TestUnitBase):

    def test_roundtrip(self):
        unit = self.load()
        data = b'Hello, Zstandard compression!' * 10
        compressed = data | -unit | bytes
        self.assertEqual(unit(compressed), data)

    def test_handles_magic(self):
        from refinery.units.compression.zstd import zstd
        check = (B'FOO!BAR!' * 200) | -zstd | bytes
        self.assertTrue(zstd.handles(check))
        self.assertFalse(zstd.handles(b'\x00\x00\x00\x00'))

    def test_compress_decompress_random(self):
        unit = self.load()
        data = self.generate_random_buffer(1024)
        compressed = data | -unit | bytes
        self.assertEqual(unit(compressed), data)

    def test_empty_roundtrip(self):
        unit = self.load()
        data = b''
        compressed = data | -unit | bytes
        self.assertEqual(unit(compressed), data)
