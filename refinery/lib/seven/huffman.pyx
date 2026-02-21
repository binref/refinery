# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
"""
Huffman decoder classes ported from 7zip, Cython-optimized version.
"""
cimport cython

from libc.stdint cimport uint8_t, uint32_t
from libc.string cimport memset


cdef int _NUM_PAIR_LEN_BITS = 4
cdef uint32_t _PAIR_LEN_MASK = (1 << _NUM_PAIR_LEN_BITS) - 1


class OutOfBounds(RuntimeError):
    def __init__(self, where: str, what: str, value: int, limit: int):
        super().__init__(
            F'While {where}: '
            F'The {what} {value} exceeded the maximum value {limit}.')


class HuffmanStartOutOfBounds(OutOfBounds):
    def __init__(self, value, limit):
        super().__init__('building Huffman table', 'start position', value, limit)


class BitDecoderBase:
    def get_value(self, int num_bits):
        raise NotImplementedError

    def move_position(self, int num_bits):
        raise NotImplementedError


cdef class HuffmanDecoder:
    cdef:
        int num_bits_max
        int num_symbols
        int num_table_bits
        uint32_t[::1] _limits
        uint32_t[::1] _poses
        uint32_t[::1] _lens
        uint32_t[::1] _symbols

    def __init__(self, int num_bits_max, int num_symbols, int num_table_bits=9):
        self.num_bits_max = num_bits_max
        self.num_symbols = num_symbols
        self.num_table_bits = num_table_bits

        cdef int limits_size = num_bits_max + 2
        cdef int poses_size = num_bits_max + 1
        cdef int lens_size = 1 << num_table_bits
        cdef int symbols_size = num_symbols

        import array
        self._limits = array.array('I', bytes(limits_size * 4))
        self._poses = array.array('I', bytes(poses_size * 4))
        self._lens = array.array('I', bytes(lens_size * 4))
        self._symbols = array.array('I', bytes(symbols_size * 4))

    def build(self, lens):
        cdef int num_bits_max = self.num_bits_max
        cdef int num_symbols = self.num_symbols
        cdef int num_table_bits = self.num_table_bits
        cdef uint32_t max_value = 1 << num_bits_max

        import array
        cdef int counts_size = num_bits_max + 1
        counts = array.array('I', bytes(counts_size * 4))
        cdef uint32_t[::1] counts_view = counts

        cdef uint32_t[::1] limits = self._limits
        cdef uint32_t[::1] poses = self._poses
        cdef uint32_t[::1] lens_table = self._lens
        cdef uint32_t[::1] symbols = self._symbols

        cdef int sym, i, k
        cdef uint32_t start_pos, count_sum, count, offset, num, val, pos
        cdef uint32_t length

        for sym in range(num_symbols):
            counts_view[lens[sym]] += 1

        limits[0] = 0
        start_pos = 0
        count_sum = 0

        for i in range(1, num_bits_max + 1):
            count = counts_view[i]
            start_pos += count << (num_bits_max - i)
            if start_pos > max_value:
                raise HuffmanStartOutOfBounds(start_pos, max_value)
            limits[i] = start_pos
            counts_view[i] = count_sum
            poses[i] = count_sum
            count_sum += count
            count_sum &= 0xFFFFFFFF

        counts_view[0] = count_sum
        poses[0] = count_sum
        limits[num_bits_max + 1] = max_value

        for sym in range(num_symbols):
            length = lens[sym]
            if not length:
                continue
            offset = counts_view[length]
            counts_view[length] += 1
            symbols[offset] = sym
            if <int>length <= num_table_bits:
                offset -= poses[length]
                num = 1 << (num_table_bits - length)
                val = length | (sym << _NUM_PAIR_LEN_BITS)
                pos = (limits[length - 1] >> (num_bits_max - num_table_bits)) + (offset << (num_table_bits - length))
                for k in range(<int>num):
                    lens_table[pos + k] = val

        return True

    def decode(self, bits) -> int:
        cdef uint32_t[::1] lim = self._limits
        cdef int num_bits_max = self.num_bits_max
        cdef int num_table_bits = self.num_table_bits
        cdef uint32_t val = bits.get_value(num_bits_max)
        cdef uint32_t pair
        cdef int num_bits
        cdef uint32_t index

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


cdef class HuffmanDecoder7b:
    cdef:
        int num_symbols
        uint8_t[128] _lens

    def __init__(self, int num_symbols):
        self.num_symbols = num_symbols
        memset(self._lens, 0, 128)

    def build(self, lens):
        cdef int num_symbols = self.num_symbols
        cdef int num_bits_max = 7
        cdef int num_pair_len_bits = 3

        import array
        cdef int arr_size = num_bits_max + 1
        counts_arr = array.array('I', bytes(arr_size * 4))
        poses_arr = array.array('I', bytes(arr_size * 4))
        limits_arr = array.array('I', bytes(arr_size * 4))
        cdef uint32_t[::1] counts = counts_arr
        cdef uint32_t[::1] _poses = poses_arr
        cdef uint32_t[::1] limits = limits_arr

        cdef int sym, i, k
        cdef uint32_t max_value, start_pos, count_sum, count, offset, num, val, pos, limit
        cdef uint32_t length

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
            length = lens[sym]
            if not length:
                continue
            offset = counts[length]
            counts[length] += 1
            offset -= _poses[length]
            num = 1 << (num_bits_max - length)
            val = length | (sym << num_pair_len_bits)
            pos = limits[length - 1] + (offset << (num_bits_max - length))
            for k in range(<int>num):
                self._lens[pos + k] = <uint8_t>val

        limit = limits[num_bits_max]
        num = (1 << num_bits_max) - limit
        for k in range(<int>num):
            self._lens[limit + k] = 0xF8
        return True

    def decode(self, bits):
        cdef uint32_t val = bits.get_value(7)
        cdef uint8_t pair = self._lens[val]
        bits.move_position(pair & 0x7)
        return pair >> 3
