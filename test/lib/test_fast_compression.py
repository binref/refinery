import inspect
import pytest
import unittest

from refinery.lib.fast.lzjb import lzjb_compress, lzjb_decompress
from refinery.lib.fast.blz import blz_decompress_chunk
from refinery.lib.fast.xpress import xpress_huffman_decompress


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


@pytest.mark.cythonized
class TestXpressHuffmanFast(unittest.TestCase):

    def test_wimlib_chunk_with_long_repeats(self):
        plaintext = inspect.cleandoc("""
            Twinkle, twinkle, little star,
            How I wonder what you are!
            Up above the world so high,
            Like a diamond in the sky.
            Twinkle, twinkle, little star,
            How I wonder what you are!

            When the blazing sun is gone,
            When he nothing shines upon,
            Then you show your little light,
            Twinkle, twinkle, all the night.
            Twinkle, twinkle, little star,
            How I wonder what you are!

            Then the traveller in the dark,
            Thanks you for your tiny spark,
            He could not see which way to go,
            If you did not twinkle so.
            Twinkle, twinkle, little star,
            How I wonder what you are!
        """).encode()
        compressed_by_wimlib = bytes.fromhex(
            '0000000000050000000000000000000083000000000005080000000000000000'
            '0000000077000800000086800000000040774667556085450655645760080000'
            '0000000000000000000000000000000000000000000000000000000000000000'
            '0000000000000000000000000000000000000000000000000000000000000000'
            '0800000000000000000000000000000008000000000000000800800000000000'
            '8888000000000000868600000000000088888000000000808680880000000060'
            '0600080000000000000000000000000000000000000000000000000000000000'
            '0000000000000000000000000000000000000000000000000000000000000000'
            '8FAAB08D853630EEAC7A4D0C4D4AC466DAA09128E4ACE22882510A5EC8477BCE'
            '6E81264EC715A588C40A39D039F6E6ACA67D5608E9F261C7C8F1B7B3560EF555'
            '3A8B277F1CEE047581363EDF09F910128BDF26EF2EA2D8C7BB237BBE988BE457'
            '59FB863715C37A65DABCF36233D0AD42B901F61ECCC7383AF9AB2BC8C29CB888'
            '21C4BF29ABF65BA374F26C048FE1977CE5137020BB316C2FBD83D5623BAB679F'
            '73C2BD8085CF5459F386B7AD5E84FE47FD86AC3A8E00C0290000'
        )
        result = xpress_huffman_decompress(compressed_by_wimlib, len(plaintext))
        self.assertEqual(result, plaintext)
