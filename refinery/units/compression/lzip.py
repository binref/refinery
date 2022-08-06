#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from itertools import count
from typing import ClassVar, List, Optional, overload
from zlib import crc32

from refinery.units import Unit
from refinery.lib.structures import MemoryFile, Struct, StructReader, EOF


class State:
    Count: ClassVar[int] = 12

    __slots__ = '__value',

    def __init__(self):
        self.__value = 0

    def set_char(self):
        self.__value = (0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5)[self.__value]

    def __index__(self):
        return self.__value

    @property
    def is_char(self):
        return self.__value < 7

    def set_match(self):
        self.__value = 7 if self.is_char else 10

    def set_rep(self):
        self.__value = 8 if self.is_char else 11

    def set_short_rep(self):
        self.__value = 9 if self.is_char else 11


_MIN_DICT_SIZE        = 1 << 12                      # noqa
_MAX_DICT_SIZE        = 1 << 29                      # noqa
_LITERAL_CONTEXT_BITS = 3                            # noqa
_POS_STATE_BITS       = 2                            # noqa
_POS_STATES           = 1 << _POS_STATE_BITS         # noqa
_POS_STATE_MASK       = _POS_STATES - 1              # noqa
_LEN_STATES           = 4                            # noqa
_DIS_SLOT_BITS        = 6                            # noqa
_START_DIS_MODEL      = 4                            # noqa
_END_DIS_MODEL        = 14                           # noqa
_MODELED_DISTANCES    = 1 << (_END_DIS_MODEL // 2)   # noqa
_DIS_ALIGN_BITS       = 4                            # noqa
_DIS_ALIGN_SIZE       = 1 << _DIS_ALIGN_BITS         # noqa
_LEN_L_BITS           = 3                            # noqa
_LEN_M_BITS           = 3                            # noqa
_LEN_H_BITS           = 8                            # noqa
_LEN_L_SYMB           = 1 << _LEN_L_BITS             # noqa
_LEN_M_SYMB           = 1 << _LEN_M_BITS             # noqa
_LEN_H_SYMB           = 1 << _LEN_H_BITS             # noqa
_MIN_MATCH_LEN        = 2                            # noqa
_BIT_MODEL_MOVE_BITS  = 5                            # noqa
_BIT_MODEL_TOTAL_BITS = 11                           # noqa
_BIT_MODEL_TOTAL      = 1 << _BIT_MODEL_TOTAL_BITS   # noqa


class BitModel:
    probability: int
    __slots__ = 'probability',

    def __init__(self):
        self.probability = _BIT_MODEL_TOTAL // 2

    @overload
    @classmethod
    def Array(cls, x: int) -> List[BitModel]:
        ...

    @overload
    @classmethod
    def Array(cls, x: int, y: int) -> List[List[BitModel]]:
        ...

    @classmethod
    def Array(cls, x: int, y: Optional[int] = None):
        if y is None:
            return [cls() for _ in range(x)]
        return [cls.Array(y) for _ in range(x)]


class LenModel:
    __slots__ = (
        'choice1',
        'choice2',
        'bm_low',
        'bm_mid',
        'bm_high'
    )

    def __init__(self):
        self.choice1 = BitModel()
        self.choice2 = BitModel()
        self.bm_low = BitModel.Array(_POS_STATES, _LEN_L_SYMB)
        self.bm_mid = BitModel.Array(_POS_STATES, _LEN_M_SYMB)
        self.bm_high = BitModel.Array(_LEN_H_SYMB)


class RangeDecoder(Struct):
    member_pos: int
    code: int
    range: int

    def __init__(self, reader: StructReader):
        self.member_pos = 6
        self.code = 0
        self.range = 0xFFFFFFFF
        self.reader = reader
        for _ in range(5):
            self.code = (self.code << 8) | self.get_byte()

    def get_byte(self):
        self.member_pos += 1
        return self.reader.read_byte()

    def decode(self, num_bits: int) -> int:
        symbol = 0
        for _ in range(num_bits):
            self.range >>= 1
            symbol <<= 1
            if (self.code >= self.range):
                self.code -= self.range
                symbol |= 1
            if (self.range <= 0x00FFFFFF):
                self.range <<= 8
                self.code = (self.code << 8) | self.get_byte()
        return symbol

    def decode_bit(self, bm: BitModel):
        symbol = 0
        bound = (self.range >> _BIT_MODEL_TOTAL_BITS) * bm.probability
        if (self.code < bound):
            self.range = bound
            bm.probability += (_BIT_MODEL_TOTAL - bm.probability) >> _BIT_MODEL_MOVE_BITS
            symbol = 0
        else:
            self.range -= bound
            self.code -= bound
            bm.probability -= bm.probability >> _BIT_MODEL_MOVE_BITS
            symbol = 1
        if (self.range <= 0x00FFFFFF):
            self.range <<= 8
            self.code = (self.code << 8) | self.get_byte()
        return symbol

    def decode_tree(self, bm: List[BitModel], num_bits: int, bmx: int = 0) -> int:
        symbol = 1
        for _ in range(num_bits):
            symbol = (symbol << 1) | self.decode_bit(bm[bmx + symbol])
        return symbol - (1 << num_bits)

    def decode_tree_reversed(self, bm: List[BitModel], num_bits: int, bmx: int = 0) -> int:
        symbol = self.decode_tree(bm, num_bits, bmx)
        reversed_symbol = 0
        for i in range(num_bits):
            reversed_symbol = (reversed_symbol << 1) | (symbol & 1)
            symbol >>= 1
        return reversed_symbol

    def decode_matched(self, bm: List[BitModel], match_byte: int) -> int:
        symbol = 1
        for i in range(7, -1, -1):
            match_bit = (match_byte >> i) & 1
            bit = self.decode_bit(bm[symbol + (match_bit << 8) + 0x100])
            symbol = (symbol << 1) | bit
            if match_bit != bit:
                while symbol < 0x100:
                    symbol = (symbol << 1) | self.decode_bit(bm[symbol])
                break
        return symbol & 0xFF

    def decode_len(self, lm: LenModel, pos_state: int):
        if self.decode_bit(lm.choice1) == 0:
            return self.decode_tree(lm.bm_low[pos_state], _LEN_L_BITS)
        if self.decode_bit(lm.choice2) == 0:
            return _LEN_L_SYMB + self.decode_tree(lm.bm_mid[pos_state], _LEN_M_BITS)
        return _LEN_L_SYMB + _LEN_M_SYMB + self.decode_tree(lm.bm_high, _LEN_H_BITS)


class MemberDecoder:
    partial_data_pos: int
    rdec: RangeDecoder
    dictionary_size: int
    buffer: bytearray
    pos: int
    stream_pos: int
    crc32: int
    pos_wrapped: bool

    reader: StructReader
    output: MemoryFile

    def flush_data(self):
        if self.pos > self.stream_pos:
            v = memoryview(self.buffer)
            b = v[self.stream_pos:self.pos]
            self.crc32 = crc32(b, self.crc32)
        self.output.write(b)
        if self.pos >= self.dictionary_size:
            self.partial_data_pos += self.pos
            self.pos = 0
            self.pos_wrapped = True
        self.stream_pos = self.pos

    def peek(self, distance: int):
        if self.pos > distance:
            return self.buffer[self.pos - distance - 1]
        if self.pos_wrapped:
            return self.buffer[self.dictionary_size + self.pos - distance - 1]
        return 0

    def put_byte(self, b: int):
        self.buffer[self.pos] = b
        self.pos += 1
        if self.pos >= self.dictionary_size:
            self.flush_data()

    def __init__(self, dict_size: int, reader: StructReader, output: MemoryFile):
        self.reader = reader
        self.output = output
        self.rdec = RangeDecoder(reader)
        self.partial_data_pos = 0
        self.dictionary_size = dict_size
        self.buffer = bytearray(dict_size)
        self.pos = 0
        self.stream_pos = 0
        self.crc32 = 0
        self.pos_wrapped = False

    @property
    def data_position(self):
        return self.partial_data_pos + self.pos

    @property
    def member_position(self):
        return self.rdec.member_pos

    def __call__(self) -> bool:
        bm_literal = BitModel.Array(1 << _LITERAL_CONTEXT_BITS, 0x300)
        bm_match = BitModel.Array(State.Count, _POS_STATES)
        bm_rep = BitModel.Array(State.Count)
        bm_rep0 = BitModel.Array(State.Count)
        bm_rep1 = BitModel.Array(State.Count)
        bm_rep2 = BitModel.Array(State.Count)
        bm_len = BitModel.Array(State.Count, _POS_STATES)
        bm_dis_slot = BitModel.Array(_LEN_STATES, 1 << _DIS_SLOT_BITS)
        bm_dis = BitModel.Array(_MODELED_DISTANCES - _END_DIS_MODEL + 1)
        bm_align = BitModel.Array(_DIS_ALIGN_SIZE)

        match_len_model = LenModel()
        rep_len_model = LenModel()

        rep0 = 0
        rep1 = 0
        rep2 = 0
        rep3 = 0
        state = State()

        while not self.reader.eof:
            pos_state = self.data_position & _POS_STATE_MASK
            if self.rdec.decode_bit(bm_match[state][pos_state]) == 0:
                prev_byte = self.peek(0)
                literal_state = prev_byte >> (8 - _LITERAL_CONTEXT_BITS)
                bm = bm_literal[literal_state]
                if state.is_char:
                    self.put_byte(self.rdec.decode_tree(bm, 8))
                else:
                    self.put_byte(self.rdec.decode_matched(bm, self.peek(rep0)))
                state.set_char()
                continue

            if self.rdec.decode_bit(bm_rep[state]) != 0:
                if self.rdec.decode_bit(bm_rep0[state]) == 0:
                    if self.rdec.decode_bit(bm_len[state][pos_state]) == 0:
                        state.set_short_rep()
                        self.put_byte(self.peek(rep0))
                        continue
                else:
                    if self.rdec.decode_bit(bm_rep1[state]) == 0:
                        distance = rep1
                    else:
                        if self.rdec.decode_bit(bm_rep2[state]) == 0:
                            distance = rep2
                        else:
                            distance = rep3
                            rep3 = rep2
                        rep2 = rep1
                    rep1 = rep0
                    rep0 = distance
                state.set_rep()
                lit_len = _MIN_MATCH_LEN + self.rdec.decode_len(rep_len_model, pos_state)
            else:
                rep3 = rep2
                rep2 = rep1
                rep1 = rep0
                lit_len = _MIN_MATCH_LEN + self.rdec.decode_len(match_len_model, pos_state)
                len_state = min(lit_len - _MIN_MATCH_LEN, _LEN_STATES - 1)
                rep0 = self.rdec.decode_tree(bm_dis_slot[len_state], _DIS_SLOT_BITS)
                if rep0 >= _START_DIS_MODEL:
                    dis_slot = rep0
                    direct_bits = (dis_slot >> 1) - 1
                    rep0 = (2 | (dis_slot & 1)) << direct_bits
                    if dis_slot < _END_DIS_MODEL:
                        rep0 += self.rdec.decode_tree_reversed(bm_dis, direct_bits, bmx=rep0 - dis_slot)
                    else:
                        rep0 += self.rdec.decode(direct_bits - _DIS_ALIGN_BITS) << _DIS_ALIGN_BITS
                        rep0 += self.rdec.decode_tree_reversed(bm_align, _DIS_ALIGN_BITS)
                        if rep0 == 0xFFFFFFFF:
                            self.flush_data()
                            return lit_len == _MIN_MATCH_LEN
                state.set_match()
                if rep0 >= self.dictionary_size or (rep0 >= self.pos and not self.pos_wrapped):
                    self.flush_data()
                    return False
            for i in range(lit_len):
                self.put_byte(self.peek(rep0))
        self.flush_data()
        return False


class lzip(Unit):
    """
    LZIP decompression
    """
    def process(self, data: bytearray):
        view = memoryview(data)
        with MemoryFile() as output, StructReader(view) as reader:
            for k in count(1):
                if reader.eof:
                    break
                trailing_size = len(data) - reader.tell()
                try:
                    ID, VN, DS = reader.read_struct('4sBB')
                    if ID != B'LZIP':
                        if k > 1:
                            raise EOF
                        else:
                            self.log_warn(F'ignoring invalid LZIP signature: {ID.hex()}')
                    if VN != 1:
                        self.log_warn(F'ignoring invalid LZIP version: {VN}')
                    dict_size = 1 << (DS & 0x1F)
                    dict_size -= (dict_size // 16) * ((DS >> 5) & 7)
                    if dict_size not in range(_MIN_DICT_SIZE, _MAX_DICT_SIZE + 1):
                        raise ValueError(
                            F'The dictionary size {dict_size} is out of the valid range '
                            F'[{_MIN_DICT_SIZE}, {_MAX_DICT_SIZE}]; unable to proceed.'
                        )
                    decoder = MemberDecoder(dict_size, reader, output)
                    if not decoder():
                        raise ValueError(F'Data error in stream {k}.')
                    crc32, data_size, member_size = reader.read_struct('<LQQ')
                    if crc32 != decoder.crc32:
                        self.log_warn(F'checksum in stream {k} was {decoder.crc:08X}, should have been {crc32:08X}.')
                    if member_size - 20 != decoder.member_position:
                        self.log_warn(F'member size in stream {k} was {decoder.member_position}, should have been {member_size}.')
                    if data_size != decoder.data_position:
                        self.log_warn(F'data size in stream {k} was {decoder.data_position}, should have been {data_size}.')
                except EOF:
                    if k <= 1:
                        raise
                    self.log_info(F'silently ignoring {trailing_size} bytes of trailing data')
                    break

            return output.getvalue()

    @classmethod
    def handles(self, data: bytearray):
        return data[:4] == B'LZIP'
