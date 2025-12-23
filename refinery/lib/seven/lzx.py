"""
This is a port of the LZX implementation in 7Zip to Python. A focus was on preserving the exact
logic and few Python-specific optimizations have been implemented.
"""
from __future__ import annotations

from refinery.lib.array import uint32array
from refinery.lib.seven.huffman import BitDecoderBase, HuffmanDecoder, HuffmanDecoder7b, OutOfBounds
from refinery.lib.types import INF

_BLOCK_TYPE_NUM_BITS = 3
_BLOCK_TYPE_VERBATIM = 1 # noqa
_BLOCK_TYPE_ALIGNED = 2
_BLOCK_TYPE_UNCOMPRESSED = 3
_NUM_HUFFMAN_BITS = 16
_NUM_REPS = 3
_NUM_LEN_SLOTS = 8
_MATCH_MIN_LEN = 2
_NUM_LEN_SYMBOLS = 249
_NUM_ALIGN_LEVEL_BITS = 3
_NUM_ALIGN_BITS = 3
_ALIGN_TABLE_SIZE = 1 << _NUM_ALIGN_BITS
_NUM_POS_SLOTS = 50
_NUM_POS_LEN_SLOTS = _NUM_POS_SLOTS * _NUM_LEN_SLOTS
_LZX_TABLE_SIZE = 256 + _NUM_POS_LEN_SLOTS
_LVL_TABLE_SIZE = 20
_NUM_LEVEL_BITS = 4
_LEVEL_SYM_ZERO = 17
_LEVEL_SYM_SAME = 19
_LEVEL_SYM_ZERO_START = 4
_LEVEL_SYM_ZERO_NUM_BITS = 4
_LEVEL_SYM_SAME_NUM_BITS = 1
_LEVEL_SYM_SAME_START = 4
_NUM_DICT_BITS_MIN = 15
_NUM_DICT_BITS_MAX = 21
_NUM_LINEAR_POS_SLOT_BITS = 17
_NUM_POWER_POS_SLOTS = 38


class NonZeroSkippedByte(RuntimeError):
    def __init__(self):
        super().__init__('A skipped byte was nonzero.')


def _memzap(data: memoryview | bytearray):
    n = len(data)
    if n == 0:
        return
    data[:] = bytes(n)


def _x86_filter(data: memoryview, size: int, processed_size: int, translate_size: int):
    size -= 10
    if size <= 0:
        return
    save = data[size + 4]
    data[size + 4] = 0xE8
    i = 0
    while True:
        while data[i] != 0xE8:
            i += 1
        if i >= size:
            break
        i = i + 1
        v = int.from_bytes(data[i:i + 4], 'little', signed=True)
        pos = 1 - (processed_size + i)
        if v >= pos and v < translate_size:
            v += pos if v >= 0 else translate_size
            v &= 0xFFFFFFFF
            data[i:i + 4] = v.to_bytes(4, 'little')
        i += 4
    data[size + 4] = save


class BitsReaderEOF(EOFError):
    def __init__(self, when: str = ''):
        if when:
            when = F' while {when}'
        super().__init__(F'The bits reader went out of bounds{when}.')


class BitDecoder(BitDecoderBase):

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


class LzxDecoder:
    def __init__(self, wim_mode: bool = False):
        self._win = None
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
        self._reps = uint32array(_NUM_REPS)
        self._num_pos_len_slots = 0
        self._unpack_block_size = 0
        self._write_pos = 0

        self._lzx_decoder = HuffmanDecoder(_NUM_HUFFMAN_BITS, _LZX_TABLE_SIZE)
        self._len_decoder = HuffmanDecoder(_NUM_HUFFMAN_BITS, _NUM_LEN_SYMBOLS)
        self._align_decoder = HuffmanDecoder7b(_ALIGN_TABLE_SIZE)
        self._level_decoder = HuffmanDecoder(_NUM_HUFFMAN_BITS, _LVL_TABLE_SIZE, 7)

        self._lzx_levels = bytearray(_LZX_TABLE_SIZE)
        self._len_levels = bytearray(_NUM_LEN_SYMBOLS)

    @property
    def window(self):
        if _win := self._win:
            return memoryview(_win)
        raise AttributeError

    def set_external_window(self, win: bytearray, num_dict_bits: int):
        self._win = win
        self._win_size = 1 << num_dict_bits
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

    def read_table(self, levels: memoryview | bytearray, num_symbols: int):
        lvls = bytearray(_LVL_TABLE_SIZE)
        bits = self._bits
        log_phase = 'reading table'
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
                    raise OutOfBounds(log_phase, 'bit count', sym, _NUM_HUFFMAN_BITS)
                delta = levels[i] - sym
                if delta < 0:
                    delta += _NUM_HUFFMAN_BITS + 1
                symbol = delta
            else:
                raise OutOfBounds(log_phase, 'symbol', sym, _LEVEL_SYM_SAME)
            idx = i + num
            if idx > num_symbols:
                raise OutOfBounds(log_phase, 'table index', idx, num_symbols)
            while True:
                levels[i] = symbol
                i += 1
                if i >= idx:
                    break

    def read_tables(self):
        bits = self._bits
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

    def _decompress(self, cur_size: int | INF):
        win = self.window
        bits = self._bits
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

        if cur_size == 0:
            cur_size = INF
            eof_halt = True
        else:
            eof_halt = False

        while cur_size > 0:
            if bits.overflow > 4:
                raise BitsReaderEOF
            if self._unpack_block_size == 0:
                self.read_tables()
                continue
            next = min(self._unpack_block_size, cur_size)
            if self._is_uncompressed_block:
                rem = bits.get_remaining_bytes()
                if rem == 0:
                    if eof_halt:
                        return
                    raise BitsReaderEOF('reading an uncompressed block')
                if next > rem:
                    next = rem
                bits.copy_to(win[self._pos:], next)
                self._pos += next
                cur_size -= next
                self._unpack_block_size -= next
                if self._skip_byte and self._unpack_block_size == 0 and cur_size == 0 and bits.is_one_direct_byte_left():
                    self._skip_byte = False
                    if bits.direct_read_byte() != 0:
                        raise NonZeroSkippedByte
                continue
            log_phase = 'reading compressed block'
            cur_size -= next
            self._unpack_block_size -= next
            while next > 0:
                if bits.overflow > 4:
                    raise BitsReaderEOF
                sym = self._lzx_decoder.decode(bits)
                if eof_halt and bits.overflow > 2:
                    return
                if sym < 256:
                    win[self._pos] = sym
                    next -= 1
                    self._pos += 1
                    continue
                sym -= 256
                if sym >= self._num_pos_len_slots:
                    raise OutOfBounds(log_phase, 'huffman length slot', sym, self._num_pos_len_slots)
                pos_slot, len_slot = divmod(sym, _NUM_LEN_SLOTS)
                len = _MATCH_MIN_LEN + len_slot
                if len_slot == _NUM_LEN_SLOTS - 1:
                    len_temp = self._len_decoder.decode(bits)
                    if len_temp >= _NUM_LEN_SYMBOLS:
                        raise OutOfBounds(log_phase, 'huffman length symbol', len_temp, _NUM_LEN_SYMBOLS)
                    len = _MATCH_MIN_LEN + _NUM_LEN_SLOTS - 1 + len_temp
                if pos_slot < _NUM_REPS:
                    dist = self._reps[pos_slot]
                    self._reps[pos_slot] = self._reps[0]
                    self._reps[0] = dist
                else:
                    if pos_slot < _NUM_POWER_POS_SLOTS:
                        num_direct_bits = (pos_slot >> 1) - 1
                        dist = ((2 | (pos_slot & 1)) << num_direct_bits)
                    else:
                        num_direct_bits = _NUM_LINEAR_POS_SLOT_BITS
                        dist = ((pos_slot - 0x22) << _NUM_LINEAR_POS_SLOT_BITS)
                    dist &= 0xFFFFFFFF
                    if num_direct_bits >= self._num_align_bits:
                        dist += bits.read_bits_small(num_direct_bits - _NUM_ALIGN_BITS) << _NUM_ALIGN_BITS
                        align_temp = self._align_decoder.decode(bits)
                        if align_temp >= _ALIGN_TABLE_SIZE:
                            raise OutOfBounds(log_phase, 'align symbol', align_temp, _ALIGN_TABLE_SIZE)
                        dist += align_temp
                    else:
                        dist += bits.read_bits_big(num_direct_bits)
                    dist -= _NUM_REPS - 1
                    self._reps[2] = self._reps[1]
                    self._reps[1] = self._reps[0]
                    self._reps[0] = dist
                if len > next:
                    raise OutOfBounds(log_phase, 'replay data length', len, next)
                if dist > self._pos and not self._over_dict:
                    raise OutOfBounds(log_phase, 'replay data distance', dist, self._pos)
                mask = self._win_size
                next -= len
                dst_pos = self._pos
                src_pos = (self._pos - dist) % mask
                for _ in range(len):
                    win[dst_pos] = win[src_pos]
                    dst_pos += 1
                    src_pos += 1
                    src_pos %= mask
                self._pos += len
        return bits.was_finished_ok()

    def get_output_data(self):
        data = self._unpacked_data
        if data is None:
            raise RuntimeError
        view = memoryview(data)
        return view[:self._pos - self._write_pos]

    def decompress(self, data: memoryview, expected_output_size: int = 0):
        if not self.keep_history:
            self._pos = 0
            self._over_dict = False
        elif self._pos == self._win_size:
            self._pos = 0
            self._over_dict = True
        win = self.window
        self._write_pos = self._pos
        self._unpacked_data = win[self._pos:]
        if expected_output_size > self._win_size - self._pos:
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

    def set_params(self, num_dict_bits: int):
        if num_dict_bits < _NUM_DICT_BITS_MIN or num_dict_bits > _NUM_DICT_BITS_MAX:
            raise ValueError(
                F'Invalid window size {num_dict_bits}, must be in range '
                F'[{_NUM_DICT_BITS_MIN};{_NUM_DICT_BITS_MAX}].')
        self._num_dict_bits = num_dict_bits
        num_pos_slots = num_dict_bits * 2 if num_dict_bits < 20 else 34 + (1 << (num_dict_bits - 17))
        self._num_pos_len_slots = num_pos_slots * _NUM_LEN_SLOTS

    def set_params_and_alloc(self, num_dict_bits: int):
        self.set_params(num_dict_bits)
        new_win_size = 1 << num_dict_bits
        if not self._win or new_win_size != self._win_size:
            self._win = bytearray(new_win_size)
        self._win_size = new_win_size
