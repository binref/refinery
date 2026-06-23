# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
"""
This is a port of the LZX implementation in 7Zip to Python, Cython-optimized version. The decode
loop, bit reader, match copy, and Huffman decoding all operate on C-level state so that this matches
the throughput of a native decoder. The pure Python module `lzx.py` is the readable fallback.
"""
cimport cython

from libc.stdint cimport int32_t, uint8_t, uint32_t
from libc.string cimport memcpy

import array as _array_mod

from refinery.lib.seven.huffman import OutOfBounds, HuffmanStartOutOfBounds


cdef int _BLOCK_TYPE_NUM_BITS = 3
cdef int _BLOCK_TYPE_VERBATIM = 1
cdef int _BLOCK_TYPE_ALIGNED = 2
cdef int _BLOCK_TYPE_UNCOMPRESSED = 3
cdef int _NUM_HUFFMAN_BITS = 16
cdef int _NUM_REPS = 3
cdef int _NUM_LEN_SLOTS = 8
cdef int _MATCH_MIN_LEN = 2
cdef int _NUM_LEN_SYMBOLS = 249
cdef int _NUM_ALIGN_LEVEL_BITS = 3
cdef int _NUM_ALIGN_BITS = 3
cdef int _ALIGN_TABLE_SIZE = 1 << 3
cdef int _NUM_POS_SLOTS = 50
cdef int _NUM_POS_LEN_SLOTS = 50 * 8
cdef int _LZX_TABLE_SIZE = 256 + 50 * 8
cdef int _LVL_TABLE_SIZE = 20
cdef int _NUM_LEVEL_BITS = 4
cdef int _LEVEL_SYM_ZERO = 17
cdef int _LEVEL_SYM_SAME = 19
cdef int _LEVEL_SYM_ZERO_START = 4
cdef int _LEVEL_SYM_ZERO_NUM_BITS = 4
cdef int _LEVEL_SYM_SAME_NUM_BITS = 1
cdef int _LEVEL_SYM_SAME_START = 4
cdef int _NUM_DICT_BITS_MIN = 15
cdef int _NUM_DICT_BITS_MAX = 21
cdef int _NUM_LINEAR_POS_SLOT_BITS = 17
cdef int _NUM_POWER_POS_SLOTS = 38

cdef int _NUM_PAIR_LEN_BITS = 4
cdef uint32_t _PAIR_LEN_MASK = (1 << 4) - 1


class NonZeroSkippedByte(RuntimeError):
    def __init__(self):
        super().__init__('A skipped byte was nonzero.')


class BitsReaderEOF(EOFError):
    def __init__(self, str when=''):
        if when:
            when = F' while {when}'
        super().__init__(F'The bits reader went out of bounds{when}.')


cdef _u32(int n):
    return _array_mod.array('I', bytes(n * 4))


cpdef void _memzap(data):
    cdef int n = len(data)
    if n == 0:
        return
    data[:] = bytes(n)


cpdef void _x86_filter(data, int size, int processed_size, int translate_size):
    cdef uint8_t[::1] buf = data
    cdef uint8_t save
    cdef int i = 0
    cdef int32_t v
    cdef int pos
    cdef uint32_t uv
    size -= 10
    if size <= 0:
        return
    save = buf[size + 4]
    buf[size + 4] = 0xE8
    while True:
        while buf[i] != 0xE8:
            i += 1
        if i >= size:
            break
        i = i + 1
        uv = buf[i] | (<uint32_t>buf[i + 1] << 8) | (<uint32_t>buf[i + 2] << 16) | (<uint32_t>buf[i + 3] << 24)
        v = <int32_t>uv
        pos = 1 - (processed_size + i)
        if v >= pos and v < translate_size:
            if v >= 0:
                v += pos
            else:
                v += translate_size
            uv = <uint32_t>v
            buf[i] = <uint8_t>(uv & 0xFF)
            buf[i + 1] = <uint8_t>((uv >> 8) & 0xFF)
            buf[i + 2] = <uint8_t>((uv >> 16) & 0xFF)
            buf[i + 3] = <uint8_t>((uv >> 24) & 0xFF)
        i += 4
    buf[size + 4] = save


@cython.final
cdef class BitDecoder:
    cdef:
        int _bitpos
        uint32_t _value
        object _buf
        const uint8_t* _ptr
        Py_ssize_t _len
        int _pos
        public int overflow

    def __init__(self):
        self._value = 0
        self._buf = None
        self._ptr = NULL
        self._len = 0

    def initialize(self, data):
        cdef const uint8_t[::1] mv = data
        self._buf = data
        self._len = mv.shape[0]
        if self._len > 0:
            self._ptr = &mv[0]
        else:
            self._ptr = NULL
        self._pos = 0
        self._bitpos = 0
        self.overflow = 0

    cdef inline int get_remaining_bytes(self):
        return <int>self._len - self._pos

    cdef inline bint was_finished_ok(self):
        if self._pos != <int>self._len:
            return False
        if (self._bitpos >> 4) * 2 != self.overflow:
            return False
        cdef int num_bits = self._bitpos & 15
        return not ((self._value >> (self._bitpos - num_bits)) & ((1 << num_bits) - 1))

    cdef inline void normalize_small(self):
        if self._bitpos > 16:
            return
        cdef int pos = self._pos
        cdef uint32_t val
        if pos >= <int>self._len - 1:
            val = 0xFFFF
            self.overflow += 2
        else:
            val = self._ptr[pos] | (<uint32_t>self._ptr[pos + 1] << 8)
            self._pos += 2
        self._value = ((self._value & 0xFFFF) << 16) | val
        self._bitpos += 16

    cdef inline void normalize_big(self):
        self.normalize_small()
        self.normalize_small()

    cdef inline uint32_t get_value(self, int num_bits):
        return (self._value >> (self._bitpos - num_bits)) & ((1 << num_bits) - 1)

    cdef inline void move_position(self, int num_bits):
        self._bitpos -= num_bits
        self.normalize_small()

    cdef inline uint32_t read_bits_small(self, int num_bits):
        self._bitpos -= num_bits
        cdef uint32_t val = (self._value >> self._bitpos) & ((1 << num_bits) - 1)
        self.normalize_small()
        return val

    cdef inline uint32_t read_bits_big(self, int num_bits):
        self._bitpos -= num_bits
        cdef uint32_t val = (self._value >> self._bitpos) & ((1 << num_bits) - 1)
        self.normalize_big()
        return val

    cdef inline bint prepare_uncompressed(self) except -1:
        if self.overflow > 0:
            raise BitsReaderEOF
        cdef int num_bits = self._bitpos - 16
        if ((self._value >> 16) & ((1 << num_bits) - 1)):
            return False
        self._pos -= 2
        self._bitpos = 0
        return True

    cdef inline uint32_t read_int32(self):
        cdef int pos = self._pos
        self._pos = pos + 4
        return (
            self._ptr[pos]
            | (<uint32_t>self._ptr[pos + 1] << 8)
            | (<uint32_t>self._ptr[pos + 2] << 16)
            | (<uint32_t>self._ptr[pos + 3] << 24)
        )

    cdef inline void copy_to_ptr(self, uint8_t* dest, int size):
        memcpy(dest, self._ptr + self._pos, size)
        self._pos += size

    cdef inline bint is_one_direct_byte_left(self):
        return self._pos == <int>self._len - 1 and self.overflow == 0

    cdef inline uint32_t direct_read_byte(self):
        cdef int pos = self._pos
        if pos >= <int>self._len:
            self.overflow += 1
            return 0xFF
        self._pos = pos + 1
        return self._ptr[pos]


@cython.final
cdef class _Huff:
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
        self._limits = _u32(num_bits_max + 2)
        self._poses = _u32(num_bits_max + 1)
        self._lens = _u32(1 << num_table_bits)
        self._symbols = _u32(num_symbols)

    cpdef bint build(self, const uint8_t[::1] lens):
        cdef int num_bits_max = self.num_bits_max
        cdef int num_symbols = self.num_symbols
        cdef int num_table_bits = self.num_table_bits
        cdef uint32_t max_value = 1 << num_bits_max

        cdef uint32_t[::1] counts = _u32(num_bits_max + 1)
        cdef uint32_t[::1] limits = self._limits
        cdef uint32_t[::1] poses = self._poses
        cdef uint32_t[::1] lens_table = self._lens
        cdef uint32_t[::1] symbols = self._symbols

        cdef int sym, i, k
        cdef uint32_t start_pos, count_sum, count, offset, num, val, pos, length

        for sym in range(num_symbols):
            counts[lens[sym]] += 1

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
            poses[i] = count_sum
            count_sum += count
            count_sum &= 0xFFFFFFFF

        counts[0] = count_sum
        poses[0] = count_sum
        limits[num_bits_max + 1] = max_value

        for sym in range(num_symbols):
            length = lens[sym]
            if not length:
                continue
            offset = counts[length]
            counts[length] += 1
            symbols[offset] = sym
            if <int>length <= num_table_bits:
                offset -= poses[length]
                num = 1 << (num_table_bits - length)
                val = length | (sym << _NUM_PAIR_LEN_BITS)
                pos = (limits[length - 1] >> (num_bits_max - num_table_bits)) + (offset << (num_table_bits - length))
                for k in range(<int>num):
                    lens_table[pos + k] = val

        return True

    cdef uint32_t decode(self, BitDecoder bits):
        cdef uint32_t* lim = &self._limits[0]
        cdef uint32_t* lens_t = &self._lens[0]
        cdef int num_bits_max = self.num_bits_max
        cdef int num_table_bits = self.num_table_bits
        cdef uint32_t val = bits.get_value(num_bits_max)
        cdef uint32_t pair
        cdef int num_bits
        cdef uint32_t index

        if val < lim[num_table_bits]:
            pair = lens_t[val >> (num_bits_max - num_table_bits)]
            bits.move_position(pair & _PAIR_LEN_MASK)
            return pair >> _NUM_PAIR_LEN_BITS
        num_bits = num_table_bits + 1
        while val >= lim[num_bits]:
            num_bits += 1
        if num_bits > num_bits_max:
            return <uint32_t>0xFFFFFFFF
        bits.move_position(num_bits)
        index = self._poses[num_bits] + ((val - lim[num_bits - 1]) >> (num_bits_max - num_bits))
        return self._symbols[index]


@cython.final
cdef class _Huff7b:
    cdef:
        int num_symbols
        uint8_t _lens[128]

    def __init__(self, int num_symbols):
        cdef int i
        self.num_symbols = num_symbols
        for i in range(128):
            self._lens[i] = 0

    cpdef bint build(self, const uint8_t[::1] lens):
        cdef int num_symbols = self.num_symbols
        cdef int num_bits_max = 7
        cdef int num_pair_len_bits = 3

        cdef uint32_t[::1] counts = _u32(num_bits_max + 1)
        cdef uint32_t[::1] _poses = _u32(num_bits_max + 1)
        cdef uint32_t[::1] limits = _u32(num_bits_max + 1)

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

    cdef uint32_t decode(self, BitDecoder bits):
        cdef uint32_t val = bits.get_value(7)
        cdef uint8_t pair = self._lens[val]
        bits.move_position(pair & 0x7)
        return pair >> 3


@cython.final
cdef class LzxDecoder:
    cdef:
        object _win
        uint8_t* _win_ptr
        uint32_t _win_size
        int _pos
        int _write_pos
        public bint keep_history
        public bint keep_history_for_next
        bint _wim_mode
        int _num_dict_bits
        uint32_t _unpack_block_size
        bint _over_dict
        bint _is_uncompressed_block
        bint _skip_byte
        int _num_align_bits
        uint32_t _reps[3]
        uint32_t _num_pos_len_slots
        uint32_t _x86_translate_size
        uint32_t _x86_processed_size
        object _x86_buf
        object _unpacked_data
        BitDecoder _bits
        _Huff _lzx_decoder
        _Huff _len_decoder
        _Huff7b _align_decoder
        _Huff _level_decoder
        object _lzx_levels
        object _len_levels

    def __init__(self, bint wim_mode=False):
        self._win = None
        self._win_ptr = NULL
        self._skip_byte = False
        self._wim_mode = wim_mode
        self._num_dict_bits = 15
        self._unpack_block_size = 0
        self._x86_buf = None
        self._x86_translate_size = 0
        self._x86_processed_size = 0
        self._unpacked_data = None

        self.keep_history = False
        self.keep_history_for_next = True

        self._bits = BitDecoder()
        self._pos = 0
        self._win_size = 0
        self._over_dict = False
        self._is_uncompressed_block = False
        self._num_align_bits = 0
        self._reps[0] = 0
        self._reps[1] = 0
        self._reps[2] = 0
        self._num_pos_len_slots = 0
        self._write_pos = 0

        self._lzx_decoder = _Huff(_NUM_HUFFMAN_BITS, _LZX_TABLE_SIZE)
        self._len_decoder = _Huff(_NUM_HUFFMAN_BITS, _NUM_LEN_SYMBOLS)
        self._align_decoder = _Huff7b(_ALIGN_TABLE_SIZE)
        self._level_decoder = _Huff(_NUM_HUFFMAN_BITS, _LVL_TABLE_SIZE, 7)

        self._lzx_levels = bytearray(_LZX_TABLE_SIZE)
        self._len_levels = bytearray(_NUM_LEN_SYMBOLS)

    cdef void _refresh_win_ptr(self):
        cdef uint8_t[::1] mv
        if self._win is not None and len(self._win) > 0:
            mv = self._win
            self._win_ptr = &mv[0]
        else:
            self._win_ptr = NULL

    @property
    def window(self):
        if self._win is not None and len(self._win) > 0:
            return memoryview(self._win)
        raise AttributeError

    def set_external_window(self, win, int num_dict_bits):
        self._win = win
        self._win_size = 1 << num_dict_bits
        self._refresh_win_ptr()
        return self.set_params(num_dict_bits)

    def _flush(self):
        win = self.window
        if self._x86_translate_size != 0:
            dst = win[self._write_pos:]
            cur_size = self._pos - self._write_pos
            if self.keep_history_for_next:
                if not self._x86_buf:
                    chunk_size = 1 << 15
                    if cur_size > chunk_size:
                        raise OutOfBounds('flushing input', 'remaining size', cur_size, chunk_size)
                    self._x86_buf = bytearray(chunk_size)
                x86 = memoryview(self._x86_buf)
                x86[:cur_size] = win[self._write_pos:self._pos]
                self._unpacked_data = x86
                dst = x86
            _x86_filter(dst, cur_size, self._x86_processed_size, self._x86_translate_size)
            self._x86_processed_size += cur_size
            if self._x86_processed_size >= (1 << 30):
                self._x86_translate_size = 0

    def read_table(self, levels, int num_symbols):
        lvls = bytearray(_LVL_TABLE_SIZE)
        cdef BitDecoder bits = self._bits
        for i in range(_LVL_TABLE_SIZE):
            lvls[i] = bits.read_bits_small(_NUM_LEVEL_BITS)
        self._level_decoder.build(lvls)
        i = 0
        while i < num_symbols:
            sym = self._level_decoder.decode(bits)
            num = 0
            if sym <= _NUM_HUFFMAN_BITS:
                delta = levels[i] - sym
                if delta < 0:
                    delta += _NUM_HUFFMAN_BITS + 1
                levels[i] = delta
                i += 1
                continue
            if sym < _LEVEL_SYM_SAME:
                sym -= _LEVEL_SYM_ZERO
                num += bits.read_bits_small(_LEVEL_SYM_ZERO_NUM_BITS + sym)
                num += _LEVEL_SYM_ZERO_START
                num += (sym << _LEVEL_SYM_ZERO_NUM_BITS)
                symbol = 0
            elif sym == _LEVEL_SYM_SAME:
                num += _LEVEL_SYM_SAME_START
                num += bits.read_bits_small(_LEVEL_SYM_SAME_NUM_BITS)
                sym = self._level_decoder.decode(bits)
                if sym > _NUM_HUFFMAN_BITS:
                    raise OutOfBounds('reading table', 'bit count', sym, _NUM_HUFFMAN_BITS)
                delta = levels[i] - sym
                if delta < 0:
                    delta += _NUM_HUFFMAN_BITS + 1
                symbol = delta
            else:
                raise OutOfBounds('reading table', 'symbol', sym, _LEVEL_SYM_SAME)
            idx = i + num
            if idx > num_symbols:
                raise OutOfBounds('reading table', 'table index', idx, num_symbols)
            while True:
                levels[i] = symbol
                i += 1
                if i >= idx:
                    break

    def read_tables(self):
        cdef BitDecoder bits = self._bits
        if self._skip_byte:
            if bits.direct_read_byte() != 0:
                raise NonZeroSkippedByte
        bits.normalize_big()
        block_type = bits.read_bits_small(_BLOCK_TYPE_NUM_BITS)
        if block_type > _BLOCK_TYPE_UNCOMPRESSED:
            raise RuntimeError(F'Unknown block type {block_type}.')
        self._unpack_block_size = 1 << 15
        if not self._wim_mode or bits.read_bits_small(1) == 0:
            self._unpack_block_size = bits.read_bits_small(16)
            if not self._wim_mode or self._num_dict_bits >= 16:
                self._unpack_block_size <<= 8
                self._unpack_block_size |= bits.read_bits_small(8)
                self._unpack_block_size &= 0xFFFFFFFF
        self._is_uncompressed_block = block_type == _BLOCK_TYPE_UNCOMPRESSED
        self._skip_byte = False
        if self._is_uncompressed_block:
            self._skip_byte = bool(self._unpack_block_size & 1)
            if not bits.prepare_uncompressed():
                raise RuntimeError('Invalid data before uncompressed block.')
            if bits.get_remaining_bytes() < _NUM_REPS * 4:
                raise EOFError('Not enough space left in buffer to read table reps.')
            for i in range(_NUM_REPS):
                rep = bits.read_int32()
                if rep > self._win_size:
                    raise OutOfBounds('reading table reps', 'rep value', rep, self._win_size)
                self._reps[i] = rep
            return True
        elif block_type == _BLOCK_TYPE_ALIGNED:
            levels = bytearray(_ALIGN_TABLE_SIZE)
            self._num_align_bits = _NUM_ALIGN_BITS
            for i in range(_ALIGN_TABLE_SIZE):
                levels[i] = bits.read_bits_small(_NUM_ALIGN_LEVEL_BITS)
            self._align_decoder.build(levels)
        else:
            self._num_align_bits = 64

        lvl = memoryview(self._lzx_levels)
        end = 0
        for t in (256, self._num_pos_len_slots):
            self.read_table(lvl[end:], t)
            end += t
        _memzap(lvl[end:_LZX_TABLE_SIZE])
        self._lzx_decoder.build(self._lzx_levels)
        self.read_table(self._len_levels, _NUM_LEN_SYMBOLS)
        self._len_decoder.build(self._len_levels)

    cdef int _decompress(self, long long expected) except *:
        cdef BitDecoder bits = self._bits
        cdef uint8_t* win = self._win_ptr
        cdef uint32_t win_size = self._win_size
        cdef uint32_t mask = win_size - 1
        cdef _Huff lzx_decoder = self._lzx_decoder
        cdef _Huff len_decoder = self._len_decoder
        cdef _Huff7b align_decoder = self._align_decoder
        cdef int num_pos_len_slots = <int>self._num_pos_len_slots

        cdef long long cur_size, next_val, rem
        cdef bint eof_halt
        cdef uint32_t sym, len_temp, pos_slot, len_slot, length, dist, align_temp, v
        cdef int num_direct_bits, pos, dst_pos, src_pos, num_align_bits, i
        cdef uint32_t reps[3]

        if not self.keep_history or not self._is_uncompressed_block:
            bits.normalize_big()
        if not self.keep_history:
            self._skip_byte = False
            self._unpack_block_size = 0
            _memzap(self._lzx_levels)
            _memzap(self._len_levels)
            if self._wim_mode:
                self._x86_translate_size = 12000000
            else:
                self._x86_translate_size = 0
                if bits.read_bits_small(1):
                    v = bits.read_bits_small(16) << 16
                    v |= bits.read_bits_small(16)
                    self._x86_translate_size = v
            self._x86_processed_size = 0
            self._reps[0] = 1
            self._reps[1] = 1
            self._reps[2] = 1

        if expected == 0:
            cur_size = 0x7FFFFFFFFFFFFFFF
            eof_halt = True
        else:
            cur_size = expected
            eof_halt = False

        pos = self._pos

        while cur_size > 0:
            if bits.overflow > 4:
                raise BitsReaderEOF
            if self._unpack_block_size == 0:
                self._pos = pos
                self.read_tables()
                continue
            next_val = self._unpack_block_size
            if next_val > cur_size:
                next_val = cur_size
            if self._is_uncompressed_block:
                rem = bits.get_remaining_bytes()
                if rem == 0:
                    if eof_halt:
                        self._pos = pos
                        return 0
                    raise BitsReaderEOF('reading an uncompressed block')
                if next_val > rem:
                    next_val = rem
                bits.copy_to_ptr(win + pos, <int>next_val)
                pos += <int>next_val
                cur_size -= next_val
                self._unpack_block_size -= <uint32_t>next_val
                if self._skip_byte and self._unpack_block_size == 0 and cur_size == 0 and bits.is_one_direct_byte_left():
                    self._skip_byte = False
                    if bits.direct_read_byte() != 0:
                        raise NonZeroSkippedByte
                continue
            cur_size -= next_val
            self._unpack_block_size -= <uint32_t>next_val

            reps[0] = self._reps[0]
            reps[1] = self._reps[1]
            reps[2] = self._reps[2]
            num_align_bits = self._num_align_bits

            while next_val > 0:
                if bits.overflow > 4:
                    raise BitsReaderEOF
                sym = lzx_decoder.decode(bits)
                if eof_halt and bits.overflow > 2:
                    self._pos = pos
                    self._reps[0] = reps[0]
                    self._reps[1] = reps[1]
                    self._reps[2] = reps[2]
                    return 0
                if sym < 256:
                    win[pos] = <uint8_t>sym
                    next_val -= 1
                    pos += 1
                    continue
                sym -= 256
                if sym >= <uint32_t>num_pos_len_slots:
                    raise OutOfBounds('reading compressed block', 'huffman length slot', sym, num_pos_len_slots)
                pos_slot = sym // <uint32_t>_NUM_LEN_SLOTS
                len_slot = sym % <uint32_t>_NUM_LEN_SLOTS
                length = _MATCH_MIN_LEN + len_slot
                if len_slot == <uint32_t>(_NUM_LEN_SLOTS - 1):
                    len_temp = len_decoder.decode(bits)
                    if len_temp >= <uint32_t>_NUM_LEN_SYMBOLS:
                        raise OutOfBounds('reading compressed block', 'huffman length symbol', len_temp, _NUM_LEN_SYMBOLS)
                    length = _MATCH_MIN_LEN + _NUM_LEN_SLOTS - 1 + len_temp
                if pos_slot < <uint32_t>_NUM_REPS:
                    dist = reps[pos_slot]
                    reps[pos_slot] = reps[0]
                    reps[0] = dist
                else:
                    if pos_slot < <uint32_t>_NUM_POWER_POS_SLOTS:
                        num_direct_bits = <int>(pos_slot >> 1) - 1
                        dist = (2 | (pos_slot & 1)) << num_direct_bits
                    else:
                        num_direct_bits = _NUM_LINEAR_POS_SLOT_BITS
                        dist = (pos_slot - 0x22) << _NUM_LINEAR_POS_SLOT_BITS
                    dist &= 0xFFFFFFFF
                    if num_direct_bits >= num_align_bits:
                        dist += bits.read_bits_small(num_direct_bits - _NUM_ALIGN_BITS) << _NUM_ALIGN_BITS
                        align_temp = align_decoder.decode(bits)
                        if align_temp >= <uint32_t>_ALIGN_TABLE_SIZE:
                            raise OutOfBounds('reading compressed block', 'align symbol', align_temp, _ALIGN_TABLE_SIZE)
                        dist += align_temp
                    else:
                        dist += bits.read_bits_big(num_direct_bits)
                    dist -= _NUM_REPS - 1
                    reps[2] = reps[1]
                    reps[1] = reps[0]
                    reps[0] = dist
                if length > next_val:
                    raise OutOfBounds('reading compressed block', 'replay data length', length, next_val)
                if dist > <uint32_t>pos and not self._over_dict:
                    raise OutOfBounds('reading compressed block', 'replay data distance', dist, pos)
                next_val -= length
                dst_pos = pos
                src_pos = <int>((<uint32_t>pos - dist) & mask)
                pos += <int>length
                if length > win_size - <uint32_t>src_pos:
                    for i in range(<int>length):
                        win[dst_pos] = win[src_pos]
                        dst_pos += 1
                        src_pos += 1
                        if <uint32_t>src_pos == win_size:
                            src_pos = 0
                else:
                    for i in range(<int>length):
                        win[dst_pos + i] = win[src_pos + i]

            self._reps[0] = reps[0]
            self._reps[1] = reps[1]
            self._reps[2] = reps[2]

        self._pos = pos
        return bits.was_finished_ok()

    def get_output_data(self):
        data = self._unpacked_data
        if data is None:
            raise RuntimeError
        view = memoryview(data)
        return view[:self._pos - self._write_pos]

    def decompress(self, data, int expected_output_size=0):
        if not self.keep_history:
            self._pos = 0
            self._over_dict = False
        elif self._pos == <int>self._win_size:
            self._pos = 0
            self._over_dict = True
        win = self.window
        self._write_pos = self._pos
        self._unpacked_data = win[self._pos:]
        if expected_output_size > <int>(self._win_size - self._pos):
            raise OutOfBounds(
                'preparing to decompress',
                'expected output size',
                expected_output_size,
                self._win_size - self._pos
            )
        self._bits.initialize(data)
        self._decompress(expected_output_size)
        self._flush()
        return self.get_output_data()

    def set_params(self, int num_dict_bits):
        if num_dict_bits < _NUM_DICT_BITS_MIN or num_dict_bits > _NUM_DICT_BITS_MAX:
            raise ValueError(
                F'Invalid window size {num_dict_bits}, must be in range '
                F'[{_NUM_DICT_BITS_MIN};{_NUM_DICT_BITS_MAX}].')
        self._num_dict_bits = num_dict_bits
        if num_dict_bits < 20:
            num_pos_slots = num_dict_bits * 2
        else:
            num_pos_slots = 34 + (1 << (num_dict_bits - 17))
        self._num_pos_len_slots = num_pos_slots * _NUM_LEN_SLOTS

    def set_params_and_alloc(self, int num_dict_bits):
        self.set_params(num_dict_bits)
        new_win_size = 1 << num_dict_bits
        if not self._win or new_win_size != self._win_size:
            self._win = bytearray(new_win_size)
        self._win_size = new_win_size
        self._refresh_win_ptr()
