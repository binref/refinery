from refinery.lib.exceptions import RefineryCriticalException

from .. import TestUnitBase
from . import KADATH1


# canonical code length table for the symbols 0..3, with codes
# 0 = 0, 1 = 10, 2 = 110, and 3 = 111:
_FOUR_LENGTHS = B'\x01\x02\x03\x03'


class TestHuffman(TestUnitBase):

    def test_decode_known_stream(self):
        # the codes 0 10 110 111 and 3, 3, 3, 3, 3, 3, 3, 3 pack into the bytes 0x5B 0x80
        # and 0xFF, 0xFF, 0xFF respectively
        test = B'\x5B\x80' | self.load(_FOUR_LENGTHS, count=4) | bytes
        self.assertEqual(test, B'\x00\x01\x02\x03')
        test = B'\xFF\xFF\xFF' | self.load(_FOUR_LENGTHS) | bytes
        self.assertEqual(test, B'\x03' * 8)

    def test_decode_stops_at_a_prefix_that_matches_no_code(self):
        # the symbols 0, 1, and 2 receive the codes 00, 01, and 10, so the bits 1111... of
        # the stream match no code and decoding stops without emitting anything
        test = B'\xFF\xFF\xFF\xFF' | self.load(B'\x02\x02\x02') | bytes
        self.assertEqual(test, B'')

    def test_decode_pairs_layout(self):
        # the symbols 0x41 and 0x42 both have code length 2, so their codes are 00 and
        # 01, and the string ABAB packs into 00 01 00 01 = 0x11
        test = B'\x11' | self.load(B'\x41\x02\x42\x02', pairs=True) | bytes
        self.assertEqual(test, B'ABAB')

    def test_decode_lsb_bitorder(self):
        # in LSB-first mode, the code bits 0 10 110 111 of the symbols 0..3 are packed
        # into bit positions 0..7 and 8 of the stream, i.e. the bytes 0xDA and 0x01
        test = B'\xDA\x01' | self.load(_FOUR_LENGTHS, count=4, lsb=True) | bytes
        self.assertEqual(test, B'\x00\x01\x02\x03')

    def test_decode_oversubscribed_table(self):
        unit = self.load(B'\x01\x01\x01')
        with self.assertRaises(RefineryCriticalException):
            unit.process(bytearray(B'\x00'))

    def test_roundtrip_with_optimal_table(self):
        data = KADATH1.encode('utf8')
        chunk = next(data | self.load(reverse=True))
        self.assertLess(len(chunk), len(data))
        # the code length table and the symbol count were attached as meta variables
        # and the decoder picks both up from there without any explicit arguments:
        test = chunk | self.load() | bytes
        self.assertEqual(test, data)

    def test_roundtrip_single_symbol_alphabet(self):
        # every code of a single-symbol alphabet is one bit long, so the padded end of
        # the compressed stream would decode as additional symbols without the count
        # meta variable limiting the number of symbols to decode
        chunk = next(B'AAAA' | self.load(reverse=True))
        test = chunk | self.load() | bytes
        self.assertEqual(test, B'AAAA')

    def test_roundtrip_with_explicit_table(self):
        data = B'ABAB' * 64
        chunk = next(data | self.load(B'\x41\x02\x42\x02', pairs=True, reverse=True))
        test = chunk | self.load(B'\x41\x02\x42\x02', pairs=True) | bytes
        self.assertEqual(test, data)

    def test_roundtrip_lsb_bitorder(self):
        data = KADATH1.encode('utf8')
        chunk = next(data | self.load(reverse=True, lsb=True))
        test = chunk | self.load(lsb=True) | bytes
        self.assertEqual(test, data)

    def test_encode_unknown_symbol(self):
        unit = self.load(B'\x01\x01', pairs=True, reverse=True)
        with self.assertRaises(RefineryCriticalException):
            unit.reverse(bytearray(B'\x00'))

    def test_empty_input(self):
        chunk = next(B'' | self.load(reverse=True))
        self.assertEqual(len(chunk), 0)
        self.assertEqual(chunk.meta['count'], 0)
