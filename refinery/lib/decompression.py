from __future__ import annotations
from typing import List, Optional, Union

from collections import Counter
from itertools import repeat

from refinery.lib.structures import StructReader


DECODE_TABLE_SYMBOL_SHIFT = 4
DECODE_TABLE_MAX_SYMBOL = ((1 << (16 - DECODE_TABLE_SYMBOL_SHIFT)) - 1)
DECODE_TABLE_MAX_LENGTH = ((1 << DECODE_TABLE_SYMBOL_SHIFT) - 1)
DECODE_TABLE_LENGTH_MASK = DECODE_TABLE_MAX_LENGTH


def MAKE_DECODE_TABLE_ENTRY(symbol, length):
    v = ((symbol << DECODE_TABLE_SYMBOL_SHIFT) | length)
    assert v & 0xFFFF == v
    return v


def s32shift(k: int, shift: int):
    """
    This helper function implements a signed left shift for 32bit integers.
    """
    M = 1 << 32
    shift %= 32
    k = k * (1 << shift) % (1 << 32)
    return k - M if k >> 31 else k


def make_huffman_decode_table(
    table_data: bytearray,
    table_bits: int,
    max_codeword_len: int,
) -> List[int]:
    remainder = 1
    codeword_length = 1
    entry_pos = 0
    decode_table: List[int] = [0] * (1 << table_bits)
    sym_count = len(table_data)
    len_counts = Counter(table_data)

    for sym in range(1, max_codeword_len + 1):
        remainder = (remainder << 1) - len_counts[sym]
        if remainder < 0:
            raise OverflowError('Lengths have overflowed the code space.')
    if remainder:
        if remainder != 1 << max_codeword_len:
            raise RuntimeError('Incomplete & nonempty code encountered.')
        return decode_table

    offsets = [0]
    for sym in range(max_codeword_len):
        offsets.append(offsets[sym] + len_counts[sym])

    sorted_syms = {}
    for i, sym in enumerate(table_data):
        offset = offsets[sym]
        offsets[sym] += 1
        sorted_syms[offset] = i

    sym_index = offsets[0]
    stores_per_loop = 1 << (table_bits - codeword_length)
    while stores_per_loop:
        end_sym_idx = sym_index + len_counts[codeword_length]
        for k in range(sym_index, end_sym_idx):
            entry_end = entry_pos + stores_per_loop
            decode_table[entry_pos:entry_end] = repeat(
                MAKE_DECODE_TABLE_ENTRY(sorted_syms[k], codeword_length),
                stores_per_loop)
            entry_pos = entry_end
        codeword_length += 1
        sym_index = end_sym_idx
        stores_per_loop >>= 1

    assert sym_index <= sym_count

    if sym_index == sym_count:
        return decode_table

    codeword = entry_pos * 2
    subtable_pos = 1 << table_bits
    subtable_bits = table_bits
    subtable_prefix = -1

    while sym_index < sym_count:
        while len_counts[codeword_length] == 0:
            if codeword_length > sym_count:
                raise IndexError('Error computing codeword')
            codeword_length += 1
            codeword <<= 1

        prefix = codeword >> (codeword_length - table_bits)

        if prefix != subtable_prefix:
            subtable_prefix = prefix
            subtable_bits = codeword_length - table_bits
            remainder = s32shift(1, subtable_bits)
            while True:
                remainder -= len_counts[table_bits + subtable_bits]
                if remainder <= 0:
                    break
                subtable_bits += 1
                remainder <<= 1
            decode_table[subtable_prefix] = MAKE_DECODE_TABLE_ENTRY(subtable_pos, subtable_bits)

        entry = MAKE_DECODE_TABLE_ENTRY(sorted_syms[sym_index], codeword_length - table_bits)
        count = 1 << (table_bits + subtable_bits - codeword_length)
        end = subtable_pos + count
        decode_table[subtable_pos:end] = repeat(entry, count)
        subtable_pos = end
        len_counts[codeword_length] -= 1
        codeword += 1
        sym_index += 1

    return decode_table


class BitBufferedReader:
    """
    A helper class to read bitwise from the compressed input stream.
    """

    def __init__(self, buffer: Union[bytearray, StructReader], bits_per_read: int = 32):
        if not isinstance(buffer, StructReader):
            buffer = StructReader(memoryview(buffer), bigendian=False)
        self._reader: StructReader[memoryview] = buffer
        self._bit_buffer_data: int = 0
        self._bit_buffer_size: int = 0
        self._bits_per_read = bits_per_read

    def variable_length_integer(self) -> int:
        value = 1
        while True:
            chunk = self.read(2)
            value = (value << 1) + (chunk >> 1)
            if not chunk & 1:
                return value

    @property
    def overshoot(self) -> int:
        return self._bit_buffer_size // 8

    def __getattr__(self, k):
        return getattr(self._reader, k)

    def __next__(self) -> int:
        return self.read(1)

    def next(self):
        return self.read(1)

    def peek(self, count: int):
        return self._bit_buffer_data >> self.collect(count)

    def __len__(self):
        return self._bit_buffer_size

    def __getitem__(self, k: int):
        if k not in range(self._bit_buffer_size):
            raise IndexError(k)
        offset = self._bit_buffer_size - k
        return (self._bit_buffer_data >> offset) & 1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, count: int) -> int:
        offset = self.collect(count)
        bits = self._bit_buffer_data >> offset
        self._bit_buffer_data ^= bits << offset
        self._bit_buffer_size -= count
        assert self._bit_buffer_data.bit_length() <= self._bit_buffer_size
        assert bits.bit_length() <= count
        return bits

    def collect(self, count: Optional[int] = None) -> int:
        if count is None:
            count = self._bits_per_read
        offset = self._bit_buffer_size - count
        if offset < 0:
            more = count - self._bit_buffer_size
            reads, _r = divmod(more, self._bits_per_read)
            reads += int(bool(_r))
            reads *= self._bits_per_read
            self._bit_buffer_data <<= reads
            self._bit_buffer_data |= self._reader.read_integer(reads)
            self._bit_buffer_size += reads
            offset += reads
            assert offset >= 0
        return offset

    def align(self):
        self._bit_buffer_size = 0
        self._bit_buffer_data = 0


def read_huffman_symbol(reader: BitBufferedReader, decode_table: List[int], table_bits: int, max_codeword_len: int):
    reader.collect(max_codeword_len)
    entry = decode_table[reader.peek(table_bits)]
    symbol = entry >> DECODE_TABLE_SYMBOL_SHIFT
    length = entry & DECODE_TABLE_LENGTH_MASK
    if max_codeword_len > table_bits and entry >= (1 << (table_bits + DECODE_TABLE_SYMBOL_SHIFT)):
        reader.read(table_bits)
        entry = decode_table[symbol + reader.peek(length)]
        symbol = entry >> DECODE_TABLE_SYMBOL_SHIFT
        length = entry & DECODE_TABLE_LENGTH_MASK
    reader.read(length)
    return symbol
