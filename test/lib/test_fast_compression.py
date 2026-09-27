import inspect
import pytest
import unittest

from refinery.lib.exceptions import RefineryPartialResult
from refinery.lib.fast.lzjb import lzjb_compress, lzjb_decompress
from refinery.lib.fast.blz import blz_decompress_chunk
from refinery.lib.fast.xpress import xpress_decompress, xpress_huffman_decompress

from test.units.compression import KADATH1, KADATH1_XPRESS_CHUNK, KADATH1_XPRESS_HUFFMAN_CHUNK, KADATH2

TWINKLE_RUNS = (
    B'Twinkle, twinkle, little star, ' * 2097
    + bytes(3000)
    + B'How I wonder what you are! ' * 2350
    + B'Up above the world so high, like a diamond in the sky.'
)

TWINKLE_RUNS_BY_RTL_COMPRESS_BUFFER = bytes.fromhex(
    '0500000000000000000000000000000003000000000004000000000000000000'
    '0000000000000000000004000000000050004000405003050055035000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000050000000000000000000000000000000000000400000000000'
    '0000000000000040000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '4E7F61F4A2822365AB03603CF8F700F8FFCCFD0000FFB40B0000000000000000'
    '0000000000000000630000000000060600000000000000000000000066000000'
    '0000600000000000400645604450654506556556500000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000600000000000000'
    '0000000000000000000000000000000000000000000000000000000000000060'
    '0505000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000AAD51536B8682AE4'
    '4185F0668F14FD21D8EFFFBCF71B2E14D3B84307A5B009E54510339857E520AF'
    '2EB1B066C169FB00F00000'
)


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

    def test_windows_stream_whose_second_block_starts_after_64_kib(self):
        """
        Windows ends a Huffman block only between two matches or literals, so the run of zero
        bytes that crosses the 64 KiB mark moves the start of the second block past that mark.
        """
        result = xpress_huffman_decompress(TWINKLE_RUNS_BY_RTL_COMPRESS_BUFFER, len(TWINKLE_RUNS))
        self.assertEqual(result, TWINKLE_RUNS)

    def test_windows_stream_of_unknown_size_ends_at_its_end_marker(self):
        result = xpress_huffman_decompress(TWINKLE_RUNS_BY_RTL_COMPRESS_BUFFER, None)
        self.assertEqual(result, TWINKLE_RUNS)

    def test_zero_bytes_after_the_end_marker_are_ignored(self):
        for count in (1, 2, 3, 300):
            with self.subTest(count=count):
                result = xpress_huffman_decompress(TWINKLE_RUNS_BY_RTL_COMPRESS_BUFFER + bytes(count), None)
                self.assertEqual(result, TWINKLE_RUNS)

    def test_stream_that_ends_before_its_end_marker_is_a_partial_result(self):
        with self.assertRaises(RefineryPartialResult) as context:
            xpress_huffman_decompress(TWINKLE_RUNS_BY_RTL_COMPRESS_BUFFER[:-4], None)
        partial = bytes(context.exception.partial)
        self.assertLess(len(partial), len(TWINKLE_RUNS))
        self.assertTrue(TWINKLE_RUNS.startswith(partial))

    def test_zero_bytes_after_a_cut_stream_do_not_extend_its_partial_result(self):
        partials = set()
        for count in (16, 512, 4096):
            with self.assertRaises(RefineryPartialResult) as context:
                xpress_huffman_decompress(KADATH1_XPRESS_HUFFMAN_CHUNK[:-20] + bytes(count), None)
            partials.add(bytes(context.exception.partial))
        self.assertEqual(len(partials), 1)

    def test_stream_followed_by_text_keeps_its_output_as_a_partial_result(self):
        text = (KADATH1 + KADATH2).encode('utf8')
        with self.assertRaises(RefineryPartialResult) as context:
            xpress_huffman_decompress(TWINKLE_RUNS_BY_RTL_COMPRESS_BUFFER + text, None)
        self.assertTrue(bytes(context.exception.partial).startswith(TWINKLE_RUNS))

    def test_end_marker_right_after_a_full_block(self):
        plaintext = inspect.cleandoc("""
            Twinkle, twinkle, little star,
            How I wonder what you are!
            Up above the world so high,
            Like a diamond in the sky.
            Twinkle, twinkle, little star,
            How I wonder what you are!
        """).encode() * 400
        compressed_by_wimlib = bytes.fromhex(
            '0000000000050000000000000000000073000000000005070000000000000000'
            '0000000077000700000075000000000040074570455075450755645660000000'
            '0000000000000000000000000000000000000000000000000000000000000000'
            '0000000000000000000000000000000000000000000000000000000000000000'
            '0600000000000000000000000000000000000000000000000000600000000000'
            '0000000000000000060600000000000000000000000000600000000000000060'
            '0000000000000000000000000000000000000000000000000000000000000000'
            '0000000000000000000000000000000000000000000000000000000000000000'
            '1286A1B336BC88C643CD6217DDB370E18C3C622D1876309172D16305EFECC17F'
            '5C7C34CC718F915A5117FB24BB274CD208C17EA161DFC12B3D6FBA3BE31C950E'
            '26006AFF52FF0000'
        )
        result = xpress_huffman_decompress(compressed_by_wimlib, None)
        self.assertEqual(result, plaintext[:0x10000])

    def test_block_with_an_empty_code_is_rejected(self):
        stream = bytearray(KADATH1_XPRESS_HUFFMAN_CHUNK)
        stream[:256] = bytes(256)
        for size in (None, len(KADATH1)):
            with self.subTest(size=size):
                with self.assertRaises(ValueError) as context:
                    xpress_huffman_decompress(stream, size)
                self.assertNotIsInstance(context.exception, RefineryPartialResult)

    def test_output_never_exceeds_a_known_size(self):
        plaintext = KADATH1.encode('utf8')
        for size in range(len(plaintext)):
            with self.subTest(size=size):
                try:
                    result = xpress_huffman_decompress(KADATH1_XPRESS_HUFFMAN_CHUNK, size)
                except RuntimeError:
                    continue
                self.assertEqual(result, plaintext[:size])

    def test_match_of_four_gib_is_rejected_for_a_known_size(self):
        stream = bytearray(TWINKLE_RUNS_BY_RTL_COMPRESS_BUFFER)
        # The first match with a 16-bit length stores it at offset 273. When these 16 bits are
        # zero, the length is read from the 32 bits that follow.
        stream[273:275] = bytes(2) + (0xFFFFFFF0).to_bytes(4, 'little')
        with self.assertRaises(RuntimeError):
            xpress_huffman_decompress(stream, len(TWINKLE_RUNS))


@pytest.mark.cythonized
class TestXpressFast(unittest.TestCase):

    def test_output_never_exceeds_a_known_size(self):
        plaintext = KADATH1.encode('utf8')
        for size in range(len(plaintext)):
            with self.subTest(size=size):
                try:
                    result = xpress_decompress(KADATH1_XPRESS_CHUNK, size)
                except RuntimeError:
                    continue
                self.assertEqual(result, plaintext[:size])
