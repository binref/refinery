from .. import TestUnitBase

import pytest


@pytest.mark.cythonized
class TestLZNT1(TestUnitBase):

    def test_roundtrip(self):
        unit = self.load()
        data = b'ABCABCABCABCABCABCABCABCABCABC' * 10
        compressed = data | -unit | bytes
        self.assertEqual(unit(compressed), data)

    def test_roundtrip_short_data(self):
        unit = self.load()
        data = b'Hello World'
        compressed = data | -unit | bytes
        self.assertEqual(unit(compressed), data)

    def test_uncompressed_chunk(self):
        unit = self.load()
        data = self.generate_random_buffer(100)
        compressed = data | -unit | bytes
        decompressed = unit(compressed)
        self.assertEqual(decompressed, data)

    def test_custom_chunk_size(self):
        unit = self.load(chunk_size=0x800)
        data = b'AAAA' * 200
        compressed = data | -unit | bytes
        decompressed = self.load()(compressed)
        self.assertEqual(decompressed, data)
