import inspect
import pytest
import unittest

from refinery.lib.exceptions import RefineryPartialResult
from refinery.lib.fast.aplib import aplib_decompress
from refinery.lib.fast.lzjb import lzjb_compress, lzjb_decompress
from refinery.lib.fast.blz import blz_decompress_chunk
from refinery.lib.fast.lzfse import lzfse_decompress
from refinery.lib.fast.xpress import xpress_decompress, xpress_huffman_decompress

from test import TestBase
from test.units.compression import KADATH1, KADATH1_XPRESS_CHUNK, KADATH1_XPRESS_HUFFMAN_CHUNK, KADATH2

KEVIN = B'Kevin\'s got the magic - and the magic\'s got Kevin.'
KEVIN_APLIB = bytes.fromhex('4B006576696E277320673A6F74727D68E86D7A613B6963392D77296E64104820682C982E00')

V2_LITERAL_WORD = 8
V2_LMD_WORD = 16
V2_STATE_WORD = 24


def with_v2_field(stream: bytearray, word: int, shift: int, width: int, value: int) -> bytearray:
    """
    Store `value` in the field of an LZFSE V2 block header that is `width` bits wide and starts at
    bit `shift` of the 64-bit little-endian word at offset `word` of the block.
    """
    fields = int.from_bytes(stream[word:word + 8], 'little')
    mask = ((1 << width) - 1) << shift
    stream[word:word + 8] = ((fields & ~mask) | (value << shift)).to_bytes(8, 'little')
    return stream


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


@pytest.mark.cythonized
class TestLzfseFast(TestBase):

    def _disk_image(self):
        return self.download_sample('06a764a6895f72f34fcddbb5002f63ed94241c67f2c3c6dd732583bc31bb83d3')

    def _first_lzfse_stream(self) -> bytearray:
        dmg = self._disk_image()
        start = dmg.find(B'bvx2')
        end = dmg.find(B'bvx$', start) + 4
        return bytearray(dmg[start:end])

    def _first_lzvn_stream(self) -> bytearray:
        dmg = self._disk_image()
        self.assertEqual(dmg[:4], B'bvxn')
        return bytearray(dmg[:dmg.find(B'bvx$') + 4])

    def test_block_decodes_to_the_size_in_its_header(self):
        stream = self._first_lzfse_stream()
        # The first stream of this disk image holds a single block, and the four bytes after the
        # block magic are the size of its output.
        size_in_header = int.from_bytes(stream[4:8], 'little')
        self.assertEqual(len(lzfse_decompress(stream)), size_in_header)

    def test_block_with_a_state_outside_of_its_table_is_rejected(self):
        for shift, states in ((32, 64), (42, 64), (52, 256)):
            with self.subTest(shift=shift):
                stream = with_v2_field(self._first_lzfse_stream(), V2_STATE_WORD, shift, 10, states)
                with self.assertRaises(ValueError):
                    lzfse_decompress(stream)

    def test_block_whose_payload_extends_past_the_input_is_rejected(self):
        stream = with_v2_field(self._first_lzfse_stream(), V2_LMD_WORD, 40, 20, 0xFFFFF)
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_block_whose_header_leaves_no_room_for_a_frequency_table_is_rejected(self):
        for header_size in (0, 32):
            with self.subTest(header_size=header_size):
                stream = with_v2_field(self._first_lzfse_stream(), V2_STATE_WORD, 0, 32, header_size)
                with self.assertRaises(ValueError):
                    lzfse_decompress(stream)

    def test_block_whose_frequencies_are_all_zero_is_rejected(self):
        stream = self._first_lzfse_stream()
        header_size = int.from_bytes(stream[24:28], 'little')
        # A zero frequency has the two-bit code 00, so 90 zero bytes hold exactly 360 of them.
        stream[32:header_size] = bytes(90)
        stream = with_v2_field(stream, V2_STATE_WORD, 0, 32, 32 + 90)
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_block_whose_frequency_table_leaves_a_header_byte_unread_is_rejected(self):
        stream = self._first_lzfse_stream()
        header_size = int.from_bytes(stream[24:28], 'little')
        stream[header_size:header_size] = bytes(1)
        stream = with_v2_field(stream, V2_STATE_WORD, 0, 32, header_size + 1)
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_block_whose_literal_count_is_not_a_multiple_of_four_is_rejected(self):
        stream = self._first_lzfse_stream()
        fields = int.from_bytes(stream[V2_LITERAL_WORD:V2_LITERAL_WORD + 8], 'little')
        # One literal more than the block holds leaves every decoded literal and match as it was, so
        # only the rule that the literal count is a multiple of four can reject the block.
        stream = with_v2_field(stream, V2_LITERAL_WORD, 0, 20, (fields & 0xFFFFF) + 1)
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_block_whose_literal_stream_ends_before_its_last_literal_is_rejected(self):
        stream = self._first_lzfse_stream()
        fields = int.from_bytes(stream[V2_LITERAL_WORD:V2_LITERAL_WORD + 8], 'little')
        stream = with_v2_field(stream, V2_LITERAL_WORD, 0, 20, (fields & 0xFFFFF) + 32)
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_block_whose_bit_stream_has_set_bits_among_its_unused_bits_is_rejected(self):
        stream = self._first_lzfse_stream()
        fields = int.from_bytes(stream[V2_LITERAL_WORD:V2_LITERAL_WORD + 8], 'little')
        # The literal stream of this block leaves its top five bits unused. A bit count field of 1
        # declares six unused bits, and the sixth bit from the top is set.
        self.assertEqual(fields >> 60, 2)
        stream = with_v2_field(stream, V2_LITERAL_WORD, 60, 3, 1)
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_block_whose_matches_use_more_literals_than_it_holds_is_rejected(self):
        stream = self._first_lzfse_stream()
        fields = int.from_bytes(stream[V2_LITERAL_WORD:V2_LITERAL_WORD + 8], 'little')
        stream = with_v2_field(stream, V2_LITERAL_WORD, 0, 20, (fields & 0xFFFFF) - 4)
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_block_that_decodes_to_more_than_the_size_in_its_header_is_rejected(self):
        stream = self._first_lzfse_stream()
        size_in_header = int.from_bytes(stream[4:8], 'little')
        stream[4:8] = (size_in_header - 1).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_block_that_decodes_to_less_than_the_size_in_its_header_is_rejected(self):
        stream = self._first_lzfse_stream()
        size_in_header = int.from_bytes(stream[4:8], 'little')
        stream[4:8] = (size_in_header + 1).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_block_that_claims_more_output_than_it_can_produce_is_rejected(self):
        stream = self._first_lzfse_stream()
        stream[4:8] = (0xFFFFFFFF).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_block_whose_literal_stream_has_a_byte_that_it_does_not_use_is_rejected(self):
        stream = self._first_lzfse_stream()
        header_size = int.from_bytes(stream[24:28], 'little')
        fields = int.from_bytes(stream[V2_LITERAL_WORD:V2_LITERAL_WORD + 8], 'little')
        # The literal stream is read from its end, so a byte in front of it changes no literal.
        stream[header_size:header_size] = bytes(1)
        stream = with_v2_field(stream, V2_LITERAL_WORD, 20, 20, ((fields >> 20) & 0xFFFFF) + 1)
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_block_whose_match_stream_has_more_than_eight_bytes_of_zero_padding_is_rejected(self):
        stream = self._first_lzfse_stream()
        header_size = int.from_bytes(stream[24:28], 'little')
        literal_fields = int.from_bytes(stream[V2_LITERAL_WORD:V2_LITERAL_WORD + 8], 'little')
        lmd_fields = int.from_bytes(stream[V2_LMD_WORD:V2_LMD_WORD + 8], 'little')
        lmd_payload = header_size + ((literal_fields >> 20) & 0xFFFFF)
        self.assertEqual(stream[lmd_payload:lmd_payload + 8], bytes(8))
        # The match stream is read from its end, so a byte in front of it changes no match.
        stream[lmd_payload:lmd_payload] = bytes(1)
        stream = with_v2_field(stream, V2_LMD_WORD, 40, 20, ((lmd_fields >> 40) & 0xFFFFF) + 1)
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_block_whose_match_stream_padding_is_not_zero_is_rejected(self):
        stream = self._first_lzfse_stream()
        header_size = int.from_bytes(stream[24:28], 'little')
        literal_fields = int.from_bytes(stream[V2_LITERAL_WORD:V2_LITERAL_WORD + 8], 'little')
        lmd_payload = header_size + ((literal_fields >> 20) & 0xFFFFF)
        self.assertEqual(stream[lmd_payload:lmd_payload + 8], bytes(8))
        stream[lmd_payload] = 1
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_block_whose_match_starts_before_the_output_is_rejected(self):
        stream = self._first_lzfse_stream()
        # Starting the distance decoder in state 0 instead of the final state of the encoder makes a
        # match distance point before the start of the output.
        stream = with_v2_field(stream, V2_STATE_WORD, 52, 10, 0)
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_stream_cut_inside_its_block_is_rejected(self):
        stream = self._first_lzfse_stream()
        self.assertEqual(stream[-4:], B'bvx$')
        for size in range(4, len(stream) - 4):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    lzfse_decompress(stream[:size])

    def test_stream_without_its_end_of_stream_block_is_a_partial_result_with_the_whole_output(self):
        stream = self._first_lzfse_stream()
        output = lzfse_decompress(stream)
        for size in range(len(stream) - 4, len(stream)):
            with self.subTest(size=size):
                with self.assertRaises(RefineryPartialResult) as context:
                    lzfse_decompress(stream[:size])
                self.assertEqual(context.exception.partial, output)

    def test_stream_cut_inside_its_second_block_is_a_partial_result_with_the_first_block(self):
        first = self._first_lzfse_stream()
        second = self._first_lzvn_stream()
        with self.assertRaises(RefineryPartialResult) as context:
            lzfse_decompress(first[:-4] + second[:20])
        self.assertEqual(context.exception.partial, lzfse_decompress(first))

    def test_lzvn_block_decodes_to_the_size_in_its_header(self):
        stream = self._first_lzvn_stream()
        size_in_header = int.from_bytes(stream[4:8], 'little')
        self.assertEqual(len(lzfse_decompress(stream)), size_in_header)

    def test_lzvn_match_that_starts_before_the_output_is_rejected(self):
        stream = self._first_lzvn_stream()
        # The first instruction copies one literal and then eight bytes from the distance stored in
        # the byte after the opcode. A distance of 2 points before the start of the output.
        self.assertEqual(stream[12:14], bytes.fromhex('6801'))
        stream[13] = 2
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_lzvn_block_that_claims_more_output_than_it_can_produce_is_rejected(self):
        stream = self._first_lzvn_stream()
        stream[4:8] = (0xFFFFFFFF).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_lzvn_match_beyond_the_output_cut_short_by_the_block_size_is_rejected(self):
        stream = self._first_lzvn_stream()
        # The instruction at offset 29 writes three literals at output offset 458 and then copies
        # four bytes from distance 1. Opcode C9 with the distance byte CC keeps both lengths and
        # sets the distance to 460. A block size of 459 leaves room for one of the literals, so the
        # match would start one byte before the start of the output.
        self.assertEqual(stream[29:31], bytes.fromhex('C801'))
        stream[29:31] = bytes.fromhex('C9CC')
        stream[4:8] = (459).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_lzvn_block_that_decodes_to_less_than_the_size_in_its_header_is_rejected(self):
        stream = self._first_lzvn_stream()
        size_in_header = int.from_bytes(stream[4:8], 'little')
        stream[4:8] = (size_in_header + 1).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_lzvn_block_without_its_end_of_stream_instruction_is_rejected(self):
        stream = self._first_lzvn_stream()
        payload_size = int.from_bytes(stream[8:12], 'little')
        # The payload ends with the end-of-stream opcode 06 and seven zero bytes.
        self.assertEqual(stream[-12:-4], bytes.fromhex('0600000000000000'))
        del stream[-12:-4]
        stream[8:12] = (payload_size - 8).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_lzvn_block_with_an_undefined_instruction_is_rejected(self):
        stream = self._first_lzvn_stream()
        self.assertEqual(stream[12], 0x68)
        stream[12] = 0x70
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_lzvn_match_at_distance_zero_is_rejected(self):
        stream = self._first_lzvn_stream()
        self.assertEqual(stream[12:14], bytes.fromhex('6801'))
        stream[13] = 0
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)

    def test_lzvn_block_whose_payload_ends_inside_a_run_of_literals_is_rejected(self):
        stream = self._first_lzvn_stream()
        payload_size = int.from_bytes(stream[8:12], 'little')
        # The last instruction before the end-of-stream opcode is E3, which is followed by its three
        # literals. Cutting the payload after the first of them leaves two literals missing.
        self.assertEqual(stream[-16:-12], bytes.fromhex('E30055AA'))
        stream[-14:-4] = B''
        stream[8:12] = (payload_size - 10).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            lzfse_decompress(stream)


@pytest.mark.cythonized
class TestAplibFast(unittest.TestCase):

    def test_stream_cut_short_is_a_partial_result_that_the_plaintext_starts_with(self):
        for size in range(1, len(KEVIN_APLIB)):
            with self.subTest(size=size):
                with self.assertRaises(RefineryPartialResult) as context:
                    aplib_decompress(KEVIN_APLIB[:size])
                self.assertTrue(KEVIN.startswith(context.exception.partial))

    def test_stream_without_its_end_marker_byte_is_a_partial_result_with_the_whole_plaintext(self):
        with self.assertRaises(RefineryPartialResult) as context:
            aplib_decompress(KEVIN_APLIB[:-1])
        self.assertEqual(context.exception.partial, KEVIN)

    def test_stream_whose_end_marker_is_corrupt_is_a_partial_result_with_the_whole_plaintext(self):
        stream = bytearray(KEVIN_APLIB)
        # The end marker is a short match whose offset byte is zero. The offset byte 66 makes it a
        # match with offset 51, one byte before the start of the output.
        self.assertEqual(stream[-1], 0)
        stream[-1] = 0x66
        with self.assertRaises(RefineryPartialResult) as context:
            aplib_decompress(stream)
        self.assertEqual(context.exception.partial, KEVIN)

    def test_match_that_repeats_the_offset_of_a_previous_match_before_any_match_ends_the_output(self):
        stream = bytearray(KEVIN_APLIB)
        # The second byte holds the tag bits of the next instructions. The tag bits 1, 0 begin a
        # match, and the offset code 0, 0 after them repeats the offset of the previous match.
        stream[1] = 0x80
        with self.assertRaises(RefineryPartialResult) as context:
            aplib_decompress(stream)
        self.assertEqual(context.exception.partial, KEVIN[:1])

    def test_match_whose_offset_does_not_fit_in_32_bits_ends_the_output(self):
        # After the literals A and B, a match has the offset gamma 2**24 + 3 and the low offset byte
        # 01, which makes its offset 2**32 + 1.
        with self.assertRaises(RefineryPartialResult) as context:
            aplib_decompress(bytes.fromhex('414A42AAAAAAAAABC60100'))
        self.assertEqual(context.exception.partial, B'AB')
