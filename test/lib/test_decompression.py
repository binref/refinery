import lzma

from test import TestBase
from refinery.lib.decompression import (
    MAKE_DECODE_TABLE_ENTRY,
    DECODE_TABLE_SYMBOL_SHIFT,
    DECODE_TABLE_LENGTH_MASK,
    s32shift,
    BitBufferedReader,
    parse_lzma_properties,
    make_huffman_decode_table,
)


class TestDecompression(TestBase):

    def test_make_decode_table_entry(self):
        entry = MAKE_DECODE_TABLE_ENTRY(5, 3)
        self.assertEqual(entry >> DECODE_TABLE_SYMBOL_SHIFT, 5)
        self.assertEqual(entry & DECODE_TABLE_LENGTH_MASK, 3)

    def test_make_decode_table_entry_fits_u16(self):
        entry = MAKE_DECODE_TABLE_ENTRY(100, 10)
        self.assertEqual(entry & 0xFFFF, entry)

    def test_s32shift_positive(self):
        self.assertEqual(s32shift(1, 4), 16)

    def test_s32shift_overflow(self):
        result = s32shift(1, 31)
        self.assertLess(result, 0)
        self.assertEqual(result, -(1 << 31))

    def test_s32shift_zero_shift(self):
        self.assertEqual(s32shift(42, 0), 42)

    def test_s32shift_zero(self):
        self.assertEqual(s32shift(0, 10), 0)

    def test_s32shift_wrapping(self):
        self.assertEqual(s32shift(42, 32), s32shift(42, 0))

    def test_s32shift_large_value(self):
        result = s32shift(0xFF, 24)
        self.assertIsInstance(result, int)

    def test_bit_buffered_reader_basic(self):
        reader = BitBufferedReader(bytearray(b'\xFF\x00'), 8)
        first = reader.read(4)
        self.assertEqual(first, 0xF)
        second = reader.read(4)
        self.assertEqual(second, 0xF)

    def test_bit_buffered_reader_single_bit(self):
        reader = BitBufferedReader(bytearray(b'\x80'), 8)
        first_bit = reader.read(1)
        self.assertEqual(first_bit, 1)
        for _ in range(7):
            bit = reader.read(1)
            self.assertEqual(bit, 0)

    def test_bit_buffered_reader_len(self):
        reader = BitBufferedReader(bytearray(b'\xFF\x00'), 8)
        reader.collect()
        self.assertEqual(len(reader), 8)

    def test_bit_buffered_reader_align(self):
        reader = BitBufferedReader(bytearray(b'\xFF\x00\xAA'), 8)
        reader.read(4)
        reader.align()
        self.assertEqual(len(reader), 0)

    def test_parse_lzma1_properties(self):
        props_byte = 0x5D
        dict_size = (1 << 20).to_bytes(4, 'little')
        data = bytes([props_byte]) + dict_size
        result = parse_lzma_properties(data, version=1)
        self.assertEqual(result['id'], lzma.FILTER_LZMA1)
        self.assertEqual(result['lc'], 3)
        self.assertEqual(result['lp'], 0)
        self.assertEqual(result['pb'], 2)
        self.assertEqual(result['dict_size'], 1 << 20)

    def test_parse_lzma2_properties(self):
        data = bytes([20])
        result = parse_lzma_properties(data, version=2)
        self.assertEqual(result['id'], lzma.FILTER_LZMA2)
        self.assertEqual(result['dict_size'], 4194304)

    def test_parse_lzma_invalid_version(self):
        data = bytes([0x5D, 0, 0, 0, 0])
        with self.assertRaises(ValueError):
            parse_lzma_properties(data, version=3)

    def test_huffman_empty_table(self):
        table_data = bytearray([0] * 16)
        table_bits = 4
        max_codeword_len = 8
        result = make_huffman_decode_table(table_data, table_bits, max_codeword_len)
        self.assertEqual(len(result), 1 << table_bits)
        self.assertTrue(all(v == 0 for v in result))
