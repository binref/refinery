"""
Structures for unpacking ZIP archives. This can cover a lot more than the built-in zipfile module,
but it is incapable of creating ZIP archives.
"""
from __future__ import annotations

import enum

from typing import Callable

from refinery.lib.array import make_array
from refinery.lib.seven.huffman import BitDecoderBase, HuffmanDecoder, HuffmanDecoder7b
from refinery.lib.structures import StructReader

kNumHuffmanBits = 15
kHistorySize32 = (1 << 15)
kHistorySize64 = (1 << 16)
kDistTableSize32 = 30
kDistTableSize64 = 32
kNumLenSymbols32 = 256
kNumLenSymbols64 = 255
kNumLenSymbolsMax = kNumLenSymbols32

kNumLenSlots = 29

kFixedDistTableSize = 32
kFixedLenTableSize = 31

kSymbolEndOfBlock = 0x100
kSymbolMatch = kSymbolEndOfBlock + 1

kMainTableSize = kSymbolMatch + kNumLenSlots
kFixedMainTableSize = kSymbolMatch + kFixedLenTableSize

kLevelTableSize = 19

kTableDirectLevels = 16
kTableLevelRepNumber = kTableDirectLevels
kTableLevel0Number = kTableLevelRepNumber + 1
kTableLevel0Number2 = kTableLevel0Number + 1

kLevelMask = 0xF

kLenStartXX = (
    B'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0c\x0e\x10\x14\x18\x1c'
    B'\x20\x28\x30\x38\x40\x50\x60\x70\x80\xa0\xc0\xe0'
)
kLenStart32 = kLenStartXX + B'\xff\x00\x00'
kLenStart64 = kLenStartXX + B'\x00\x00\x00'

kLenDirectBitsXX = (
    B'\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x02\x02\x02\x02'
    B'\x03\x03\x03\x03\x04\x04\x04\x04\x05\x05\x05\x05'
)
kLenDirectBits32 = kLenDirectBitsXX + B'\x00\x00\x00'
kLenDirectBits64 = kLenDirectBitsXX + B'\x10\x00\x00'

kDistStart = make_array(4, init=[
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0006, 0x0008, 0x000C,
    0x0010, 0x0018, 0x0020, 0x0030, 0x0040, 0x0060, 0x0080, 0x00C0,
    0x0100, 0x0180, 0x0200, 0x0300, 0x0400, 0x0600, 0x0800, 0x0C00,
    0x1000, 0x1800, 0x2000, 0x3000, 0x4000, 0x6000, 0x8000, 0xC000,
])
kDistDirectBits = (
    B'\x00\x00\x00\x00\x01\x01\x02\x02\x03\x03\x04\x04\x05\x05\x06\x06'
    B'\x07\x07\x08\x08\x09\x09\x0a\x0a\x0b\x0b\x0c\x0c\x0d\x0d\x0e\x0e'
)

kLevelDirectBits = B'\02\03\07'
kCodeLengthAlphabetOrder = B'\x10\x11\x12\x00\x08\x07\x09\x06\x0a\x05\x0b\x04\x0c\x03\x0d\x02\x0e\x01\x0f'

kMatchMinLen = 3
kMatchMaxLen32 = kNumLenSymbols32 + kMatchMinLen - 1 // 256 + 2
kMatchMaxLen64 = kNumLenSymbols64 + kMatchMinLen - 1 // 255 + 2
kMatchMaxLen = kMatchMaxLen32

kFinalBlockFieldSize = 1

kBlockTypeFieldSize = 2

kNumLenCodesFieldSize = 5
kNumDistCodesFieldSize = 5
kNumLevelCodesFieldSize = 4

kNumLitLenCodesMin = 257
kNumDistCodesMin = 1
kNumLevelCodesMin = 4

kLevelFieldSize = 3

kStoredBlockLengthFieldSize = 16


class FinalBlockField(enum.IntEnum):
    NotFinalBlock = 0
    FinalBlock = 1


class BlockType(enum.IntEnum):
    Stored = 0
    FixedHuffman = 1
    DynamicHuffman = 2


class DecoderLevels:
    main_levels: bytearray
    dist_levels: bytearray

    def __init__(self) -> None:
        self.main_levels = bytearray(kFixedMainTableSize)
        self.dist_levels = bytearray(kFixedDistTableSize)

    def sub_clear(self):
        for i in range(kNumLitLenCodesMin, kFixedMainTableSize):
            self.main_levels[i] = 0
        for i in range(kFixedDistTableSize):
            self.dist_levels[i] = 0

    def set_fixed_levels(self):
        i = 0
        for i in range(144):
            self.main_levels[i] = 8
        for i in range(144, 256):
            self.main_levels[i] = 9
        for i in range(256, 280):
            self.main_levels[i] = 7
        for i in range(280, 288):
            self.main_levels[i] = 8
        for i in range(kFixedDistTableSize):
            self.dist_levels[i] = 5


kLenIdFinished = -1
kLenIdNeedInit = -2


kNumBigValueBits = 8 * 4
kNumValueBytes = 3
kNumValueBits = 8 * kNumValueBytes
kMask = (1 << kNumValueBits) - 1
kInvertTable = bytes(
    ((v * 0x202020202) & 0x10884422010) % 1023 for v in range(0x100))


class BitLDecoderBase:
    __slots__ = (
        '_bit_pos',
        '_value',
        '_stream',
        '_num_extra_bytes',
        'read_direct_byte',
    )

    read_direct_byte: Callable[[], int]

    def __init__(self, reader: StructReader):
        def _rdb():
            try:
                return u8fast()
            except Exception:
                self._num_extra_bytes += 1
                return 0xFF
        self._bit_pos = kNumBigValueBits
        self._value = 0
        self._stream = reader
        self._num_extra_bytes = 0
        u8fast = reader.u8fast
        self.read_direct_byte = _rdb

    def get_stream_size(self):
        if self.extra_bits_were_read():
            return len(self._stream)
        else:
            return self.tell()

    def tell(self):
        return self._stream.tell() - ((kNumBigValueBits - self._bit_pos) >> 3)

    def there_are_data_in_bit_buffer(self):
        return self._bit_pos != kNumBigValueBits

    def normalize(self):
        while self._bit_pos >= 8:
            self._value = (self.read_direct_byte() << (kNumBigValueBits - self._bit_pos)) | self._value
            self._bit_pos -= 8

    def read_bits(self, numBits: int):
        self.normalize()
        res = self._value & ((1 << numBits) - 1)
        self._bit_pos += numBits
        self._value >>= numBits
        return res

    def extra_bits_were_read(self):
        return (self._num_extra_bytes > 4 or kNumBigValueBits - self._bit_pos < (self._num_extra_bytes << 3))

    def extra_bits_were_read_fast(self):
        return self._num_extra_bytes > 4


class BitLDecoder(BitDecoderBase, BitLDecoderBase):

    __slots__ = '_normal_value',

    def __init__(self, reader: StructReader):
        super().__init__(reader)
        self._normal_value = 0

    def normalize(self):
        p = self._bit_pos
        if p < 8:
            return
        v = self._value
        n = self._normal_value
        while p >= 8:
            b = self.read_direct_byte()
            n |= b << (kNumBigValueBits - p)
            p -= 8
            v = ((v & 0xFFFFFF) << 8) | kInvertTable[b]
        self._bit_pos = p
        self._value = v
        self._normal_value = n

    def get_value(self, num_bits: int):
        self.normalize()
        return ((self._value >> (8 - self._bit_pos)) & kMask) >> (kNumValueBits - num_bits)

    def move_position(self, num_bits: int):
        self._bit_pos += num_bits
        self._normal_value >>= num_bits

    def read_bits(self, numBits: int):
        self.normalize()
        res = self._normal_value & ((1 << numBits) - 1)
        self.move_position(numBits)
        return res

    def align_to_byte(self):
        self.move_position((32 - self._bit_pos) & 7)

    def read_aligned_byte(self):
        if self._bit_pos == kNumBigValueBits:
            return self.read_direct_byte()
        b = self._normal_value & 0xFF
        self.move_position(8)
        return b

    def read_aligned_byte_from_buffer(self):
        if self._num_extra_bytes != 0:
            if self.extra_bits_were_read():
                return None
        return self.read_aligned_byte()


def replay(buffer: bytearray, offset: int, length: int):
    cursor = len(buffer)
    rep, r = divmod(length, offset)
    offset = cursor - offset
    replay = buffer[offset:offset + r]
    if rep > 0:
        prefix = buffer[offset:cursor]
        for _ in range(rep):
            buffer.extend(prefix)
    buffer.extend(replay)


class Deflate:
    def __init__(
        self,
        dst: bytearray,
        src: StructReader,
        df64: bool = False,
        nsis: bool = False,
        zlib: bool = False,
    ):
        self.dst = dst
        self.src = src
        self.bits = BitLDecoder(src)
        self.main_decoder = HuffmanDecoder(kNumHuffmanBits, kFixedMainTableSize)
        self.dist_decoder = HuffmanDecoder(kNumHuffmanBits, kFixedDistTableSize)
        self.level_decoder = HuffmanDecoder7b(kLevelTableSize)
        self.stored_block_size = 0
        self.is_final_block = False
        self.stored_mode = False
        self.zlib_tail = bytearray(4)
        self.zlib_mode = zlib
        self.nsis_mode = nsis
        self.deflate64 = df64
        self.keep_history = False
        self._num_dist_levels = 0
        self._need_to_finish_input = False
        self._need_to_read_table = True
        self._leftover_replay_size = 0
        self._leftover_replay_dist = 0
        self._out_size = 0
        self._out_start_pos = 0

    @property
    def _out_size_defined(self):
        return self._out_size > 0

    def decode_levels(self, levels: memoryview, numSymbols: int):
        bits = self.bits
        i = 0
        while i < numSymbols:
            sym = self.level_decoder.decode(self.bits)
            if sym < kTableDirectLevels:
                levels[i] = sym
                i += 1
                continue
            if sym >= kLevelTableSize:
                return False
            if sym == kTableLevelRepNumber:
                if i == 0:
                    return False
                numBits = 2
                num = 0
                symbol = levels[i - 1]
            else:
                sym -= kTableLevel0Number
                sym <<= 2
                numBits = 3 + sym
                num = sym << 1
                symbol = 0
            num += i + 3 + bits.read_bits(numBits)
            if num > numSymbols:
                return False
            while True:
                levels[i] = symbol
                i += 1
                if i >= num:
                    break
        return True

    def read_tables(self):
        bits = self.bits
        self.is_final_block = (bits.read_bits(kFinalBlockFieldSize) == FinalBlockField.FinalBlock)
        if self.bits.extra_bits_were_read():
            return False
        blockType = bits.read_bits(kBlockTypeFieldSize)
        if blockType > BlockType.DynamicHuffman:
            return False
        if self.bits.extra_bits_were_read():
            return False
        if blockType == BlockType.Stored:
            self.stored_mode = True
            self.bits.align_to_byte()
            self.stored_block_size = self.read_aligned_u16()
            if self.nsis_mode:
                return True
            return (self.stored_block_size == ~self.read_aligned_u16() & 0xFFFF)
        else:
            self.stored_mode = False

        levels = DecoderLevels()

        if blockType == BlockType.FixedHuffman:
            levels.set_fixed_levels()
            self._num_dist_levels = kDistTableSize64 if self.deflate64 else kDistTableSize32
        else:
            numLitLenLevels = bits.read_bits(kNumLenCodesFieldSize) + kNumLitLenCodesMin
            self._num_dist_levels = bits.read_bits(kNumDistCodesFieldSize) + kNumDistCodesMin
            numLevelCodes = bits.read_bits(kNumLevelCodesFieldSize) + kNumLevelCodesMin
            if not self.deflate64:
                if self._num_dist_levels > kDistTableSize32:
                    return False
            levelLevels = bytearray(kLevelTableSize)
            for i in range(kLevelTableSize):
                position = kCodeLengthAlphabetOrder[i]
                if i < numLevelCodes:
                    levelLevels[position] = bits.read_bits(kLevelFieldSize)
                else:
                    levelLevels[position] = 0

            if self.bits.extra_bits_were_read():
                return False

            if not self.level_decoder.build(levelLevels):
                return False

            b_tmpLevels = bytearray(kFixedMainTableSize + kFixedDistTableSize)
            tmpLevels = memoryview(b_tmpLevels)
            if not self.decode_levels(tmpLevels, numLitLenLevels + self._num_dist_levels):
                return False
            if self.bits.extra_bits_were_read():
                return False
            levels.sub_clear()
            levels.main_levels[:numLitLenLevels] = tmpLevels[:numLitLenLevels]
            levels.dist_levels[:self._num_dist_levels] = tmpLevels[numLitLenLevels:][:self._num_dist_levels]
        if not self.main_decoder.build(levels.main_levels):
            return False
        return self.dist_decoder.build(levels.dist_levels)

    def decode_block(self, size: int, finish_input_stream: bool):
        bits = self.bits
        dst = self.dst
        main_decoder = self.main_decoder
        dist_decoder = self.dist_decoder
        write_byte = dst.append

        if self._leftover_replay_size == kLenIdFinished:
            return True
        if self._leftover_replay_size == kLenIdNeedInit:
            if not self.keep_history:
                dst.clear()
            self.is_final_block = False
            self._leftover_replay_size = 0
            self._need_to_read_table = True
        if carry := min(self._leftover_replay_size, size):
            size -= carry
            replay(dst, self._leftover_replay_dist + 1, carry)
            self._leftover_replay_size -= carry
        while size > 0 or finish_input_stream:
            if bits.extra_bits_were_read():
                return False
            if self._need_to_read_table:
                if self.is_final_block:
                    self._leftover_replay_size = kLenIdFinished
                    break
                if not self.read_tables():
                    return False
                if bits.extra_bits_were_read():
                    return False
                self._need_to_read_table = False
            if self.stored_mode:
                if finish_input_stream and size == 0 and self.stored_block_size != 0:
                    return False
                # NSIS version contains some bits in bitl bits buffer.
                # So we must read some first bytes via ReadAlignedByte
                while self.stored_block_size > 0 and size > 0 and bits.there_are_data_in_bit_buffer():
                    write_byte(bits.read_aligned_byte())
                    self.stored_block_size -= 1
                    size -= 1
                while self.stored_block_size > 0 and size > 0:
                    write_byte(bits.read_direct_byte())
                    self.stored_block_size -= 1
                    size -= 1
                self._need_to_read_table = self.stored_block_size == 0
                continue
            while size > 0:
                if bits.extra_bits_were_read_fast():
                    return False
                if (sym := main_decoder.decode(bits)) < 0x100:
                    write_byte(sym)
                    size -= 1
                    continue
                elif sym == kSymbolEndOfBlock:
                    self._need_to_read_table = True
                    break
                elif sym >= kMainTableSize:
                    return False
                else:
                    sym -= kSymbolMatch
                    if self.deflate64:
                        length = kLenStart64[sym]
                        n_bits = kLenDirectBits64[sym]
                    else:
                        length = kLenStart32[sym]
                        n_bits = kLenDirectBits32[sym]
                    length += kMatchMinLen + bits.read_bits(n_bits)
                    loc = min(length, size)
                    sym = dist_decoder.decode(bits)
                    if sym >= self._num_dist_levels:
                        return False
                    sym = kDistStart[sym] + bits.read_bits(kDistDirectBits[sym])
                    replay(dst, sym + 1, loc)
                    size -= loc
                    length -= loc
                    if length != 0:
                        self._leftover_replay_size = length
                        self._leftover_replay_dist = sym
                        break
            if finish_input_stream and size == 0:
                if main_decoder.decode(bits) != kSymbolEndOfBlock:
                    return False
                self._need_to_read_table = True
        return not bits.extra_bits_were_read()

    def decode_real(self):
        while True:
            size = 1 << 20
            finish_input_stream = False
            if self._out_size_defined:
                rem = self._out_size - (len(self.dst) - self._out_start_pos)
                if size >= rem:
                    size = rem
                    if self.zlib_mode or self._need_to_finish_input:
                        finish_input_stream = True
            if not finish_input_stream and size == 0:
                break
            if not self.decode_block(size, finish_input_stream):
                return False
            if self._leftover_replay_size == kLenIdFinished:
                break
        if self._leftover_replay_size == kLenIdFinished and self.zlib_mode:
            self.bits.align_to_byte()
            for i in range(4):
                self.zlib_tail[i] = self.bits.read_aligned_byte()
        return True

    def initialize_out_stream_for_resume(self, out_size: int = 0):
        if not self.keep_history:
            self.dst.clear()
        self._out_size = out_size
        self._out_start_pos = len(self.dst)
        self._leftover_replay_size = kLenIdNeedInit

    def decode(self, out_size: int = 0):
        self.initialize_out_stream_for_resume(out_size)
        return self.decode_real()

    def is_finished(self):
        return self._leftover_replay_size == kLenIdFinished

    def read_aligned_u16(self):
        b = self.bits
        v = b.read_aligned_byte()
        return v | (b.read_aligned_byte() << 8)

    def had_input_eof_error(self):
        return self.bits.extra_bits_were_read()
