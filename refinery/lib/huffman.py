"""
Huffman decoder classes ported from 7zip.
"""
from __future__ import annotations

import abc

from refinery.lib.array import uint32array

_NUM_PAIR_LEN_BITS = 4
_PAIR_LEN_MASK = (1 << _NUM_PAIR_LEN_BITS) - 1


class OutOfBounds(RuntimeError):
    def __init__(self, where: str, what: str, value: int, limit: int):
        super().__init__(
            F'While {where}: '
            F'The {what} {value} exceeded the maximum value {limit}.')


class HuffmanStartOutOfBounds(OutOfBounds):
    def __init__(self, value, limit):
        super().__init__('building Huffman table', 'start position', value, limit)


class BitDecoderBase(abc.ABC):
    __slots__ = ()

    @abc.abstractmethod
    def get_value(self, num_bits: int) -> int:
        ...

    @abc.abstractmethod
    def move_position(self, num_bits: int):
        ...


class HuffmanDecoder:
    def __init__(self, num_bits_max: int, num_symbols: int, num_table_bits: int = 9):
        self.num_bits_max = num_bits_max
        self.num_symbols = num_symbols
        self.num_table_bits = num_table_bits

        self._limits = uint32array(num_bits_max + 2)
        self._poses = uint32array(num_bits_max + 1)
        self._lens = uint32array(1 << num_table_bits)
        self._symbols = uint32array(num_symbols)

    def build(self, lens: memoryview | bytearray):
        num_bits_max = self.num_bits_max
        num_symbols = self.num_symbols
        num_table_bits = self.num_table_bits
        max_value = 1 << num_bits_max

        counts = uint32array(num_bits_max + 1)

        for sym in range(num_symbols):
            counts[lens[sym]] += 1

        self._limits[0] = 0
        start_pos = 0
        count_sum = 0

        for i in range(1, num_bits_max + 1):
            count = counts[i]
            start_pos += count << (num_bits_max - i)
            if start_pos > max_value:
                raise HuffmanStartOutOfBounds(start_pos, max_value)
            self._limits[i] = start_pos
            counts[i] = count_sum
            self._poses[i] = count_sum
            count_sum += count
            count_sum &= 0xFFFFFFFF

        counts[0] = count_sum
        self._poses[0] = count_sum
        self._limits[num_bits_max + 1] = max_value

        for sym in range(num_symbols):
            len = lens[sym]
            if not len:
                continue
            offset = counts[len]
            counts[len] += 1
            self._symbols[offset] = sym
            if len <= num_table_bits:
                offset -= self._poses[len]
                num = 1 << (num_table_bits - len)
                val = len | (sym << _NUM_PAIR_LEN_BITS)
                pos = (self._limits[len - 1] >> (num_bits_max - num_table_bits)) + (offset << (num_table_bits - len))
                for k in range(num):
                    self._lens[pos + k] = val

        return True

    def decode(self, bits: BitDecoderBase) -> int:
        lim = self._limits
        num_bits_max = self.num_bits_max
        num_table_bits = self.num_table_bits
        val = bits.get_value(num_bits_max)
        if val < lim[num_table_bits]:
            pair = self._lens[val >> (num_bits_max - num_table_bits)]
            bits.move_position(pair & _PAIR_LEN_MASK)
            return pair >> _NUM_PAIR_LEN_BITS
        num_bits = num_table_bits + 1
        while val >= lim[num_bits]:
            num_bits += 1
        if num_bits > num_bits_max:
            return 0xFFFFFFFF
        bits.move_position(num_bits)
        index = self._poses[num_bits] + ((val - lim[num_bits - 1]) >> (num_bits_max - num_bits))
        return self._symbols[index]


class HuffmanDecoder7b:
    def __init__(self, num_symbols: int):
        self.num_symbols = num_symbols
        self._lens = bytearray(1 << 7)

    def build(self, lens: memoryview | bytearray):
        num_symbols = self.num_symbols
        num_bits_max = 7
        num_pair_len_bits = 3

        counts = uint32array(num_bits_max + 1)
        _poses = uint32array(num_bits_max + 1)
        limits = uint32array(num_bits_max + 1)

        for sym in range(num_symbols):
            counts[lens[sym]] += 1

        max_value = 1 << num_bits_max
        limits[0] = 0
        start_pos = 0
        count_sum = 0

        for i in range(1, num_bits_max + 1):
            count = counts[i]
            start_pos += count << (num_bits_max - i)
            if start_pos > max_value:
                raise HuffmanStartOutOfBounds(start_pos, max_value)
            limits[i] = start_pos
            counts[i] = count_sum
            _poses[i] = count_sum
            count_sum += count
            count_sum &= 0xFFFFFFFF

        counts[0] = count_sum
        _poses[0] = count_sum

        for sym in range(num_symbols):
            len = lens[sym]
            if not len:
                continue
            offset = counts[len]
            counts[len] += 1
            offset -= _poses[len]
            num = 1 << (num_bits_max - len)
            val = len | (sym << num_pair_len_bits)
            pos = limits[len - 1] + (offset << (num_bits_max - len))
            for k in range(num):
                self._lens[pos + k] = val

        limit = limits[num_bits_max]
        num = (1 << num_bits_max) - limit
        for k in range(num):
            self._lens[limit + k] = 0xF8
        return True

    def decode(self, bits: BitDecoderBase):
        val = bits.get_value(7)
        pair = self._lens[val]
        bits.move_position(pair & 0x7)
        return pair >> 3
