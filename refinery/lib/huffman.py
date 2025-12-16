"""
Huffman decoder classes ported from 7zip.
"""
from __future__ import annotations

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


class BitsReaderEOF(EOFError):
    def __init__(self, when: str = ''):
        if when:
            when = F' while {when}'
        super().__init__(F'The bits reader went out of bounds{when}.')


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

    def decode(self, bits: BitDecoder) -> int:
        num_bits_max = self.num_bits_max
        num_table_bits = self.num_table_bits
        val = bits.get_value(num_bits_max)
        if val < self._limits[num_table_bits]:
            pair = self._lens[val >> (num_bits_max - num_table_bits)]
            bits.move_position(pair & _PAIR_LEN_MASK)
            return pair >> _NUM_PAIR_LEN_BITS
        num_bits = num_table_bits + 1
        while val >= self._limits[num_bits]:
            num_bits += 1
        if num_bits > num_bits_max:
            return 0xFFFFFFFF
        bits.move_position(num_bits)
        index = self._poses[num_bits] + ((val - self._limits[num_bits - 1]) >> (num_bits_max - num_bits))
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

    def decode(self, bits: BitDecoder):
        val = bits.get_value(7)
        pair = self._lens[val]
        bits.move_position(pair & 0x7)
        return pair >> 3


class BitDecoder:

    __slots__ = '_bitpos', '_value', '_buf', '_pos', 'overflow'

    def __init__(self):
        self._value = 0

    def initialize(self, data: memoryview):
        self._buf = data
        self._pos = 0
        self._bitpos = 0
        self.overflow = 0

    def get_remaining_bytes(self):
        return len(self._buf) - self._pos

    def was_finished_ok(self):
        if self._pos != len(self._buf):
            return False
        if (self._bitpos >> 4) * 2 != self.overflow:
            return False
        num_bits = self._bitpos & 15
        return not ((self._value >> (self._bitpos - num_bits)) & ((1 << num_bits) - 1))

    def normalize_small(self):
        if self._bitpos > 16:
            return
        pos = self._pos
        buf = self._buf
        if pos >= len(buf) - 1:
            val = 0xFFFF
            self.overflow += 2
        else:
            val = int.from_bytes(buf[pos:pos + 2], 'little')
            self._pos += 2
        self._value = ((self._value & 0xFFFF) << 16) | val
        self._bitpos += 16

    def normalize_big(self):
        self.normalize_small()
        self.normalize_small()

    def get_value(self, num_bits: int):
        return (self._value >> (self._bitpos - num_bits)) & ((1 << num_bits) - 1)

    def move_position(self, num_bits: int):
        self._bitpos -= num_bits
        self.normalize_small()

    def read_bits_small(self, num_bits: int):
        self._bitpos -= num_bits
        val = (self._value >> self._bitpos) & ((1 << num_bits) - 1)
        self.normalize_small()
        return val

    def read_bits_big(self, num_bits: int):
        self._bitpos -= num_bits
        val = (self._value >> self._bitpos) & ((1 << num_bits) - 1)
        self.normalize_big()
        return val

    def prepare_uncompressed(self) -> bool:
        if self.overflow > 0:
            raise BitsReaderEOF
        num_bits = self._bitpos - 16
        if ((self._value >> 16) & ((1 << num_bits) - 1)):
            return False
        self._pos -= 2
        self._bitpos = 0
        return True

    def read_int32(self):
        pos = self._pos
        end = pos + 4
        self._pos = end
        return int.from_bytes(self._buf[pos:end], 'little')

    def copy_to(self, dest: memoryview, size: int):
        pos = self._pos
        end = pos + size
        self._pos = end
        dest[:size] = self._buf[pos:end]

    def is_one_direct_byte_left(self) -> bool:
        return self._pos == len(self._buf) - 1 and self.overflow == 0

    def direct_read_byte(self):
        pos = self._pos
        buf = self._buf
        if pos >= len(buf):
            self.overflow += 1
            return 0xFF
        else:
            value = buf[pos]
            self._pos += 1
            return value
