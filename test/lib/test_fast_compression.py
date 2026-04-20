import pytest
import unittest

from refinery.lib.fast.lzjb import lzjb_compress, lzjb_decompress
from refinery.lib.fast.blz import blz_decompress_chunk


@pytest.mark.cythonized
class TestLzjbFast(unittest.TestCase):

    def test_roundtrip_short(self):
        data = b'Hello, World! Hello, World!'
        compressed = lzjb_compress(data)
        decompressed = lzjb_decompress(compressed)
        self.assertEqual(decompressed, bytearray(data))

    def test_roundtrip_repeated(self):
        data = b'ABCABC' * 100
        compressed = lzjb_compress(data)
        decompressed = lzjb_decompress(compressed)
        self.assertEqual(decompressed, bytearray(data))

    def test_roundtrip_binary(self):
        data = bytes(range(256)) * 4
        compressed = lzjb_compress(data)
        decompressed = lzjb_decompress(compressed)
        self.assertEqual(decompressed, bytearray(data))

    def test_empty(self):
        self.assertEqual(lzjb_decompress(b''), bytearray())
        self.assertEqual(lzjb_compress(b''), bytearray())

    def test_all_literals(self):
        data = b'\x00' + b'ABCDEFGH'
        result = lzjb_decompress(data)
        self.assertEqual(result, bytearray(b'ABCDEFGH'))

    def test_invalid_match_offset(self):
        data = b'\x01\x00\x01'
        with self.assertRaises((RuntimeError, ValueError)):
            lzjb_decompress(data)


@pytest.mark.cythonized
class TestBlzFast(unittest.TestCase):

    def test_decompress_chunk_simple(self):
        from refinery import blz
        unit = blz()
        plaintext = b'the finest refinery of binaries refines binaries, not finery.'
        unit._begin(plaintext)
        compressed_data = bytes(unit._compress())
        unit._begin(compressed_data)
        unit._src.read_struct('>6L')
        verbatim = unit._src.tell()
        src_start = verbatim + 1
        result, _ = blz_decompress_chunk(compressed_data, src_start, verbatim, len(plaintext))
        self.assertEqual(result, plaintext)
