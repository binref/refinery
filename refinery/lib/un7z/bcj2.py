"""
BCJ2 decoder for 7z archives.

BCJ2 is a complex x86 branch filter with 4 input streams and 1 output stream.
It uses a range coder to predict whether the relative address of an x86 CALL, JMP, or conditional
jump instruction was converted to an absolute one.

Stream layout:
  - Stream 0 (MAIN): Non-branch bytes and branch instruction opcodes
  - Stream 1 (CALL): 4-byte big-endian CALL target addresses
  - Stream 2 (JUMP): 4-byte big-endian JMP and conditional jump target addresses
  - Stream 3 (RC):   Range coder data for branch prediction
"""
from __future__ import annotations

import re

from typing import TYPE_CHECKING

from refinery.lib.un7z.headers import SzCorruptArchive

if TYPE_CHECKING:
    from refinery.lib.types import buf

_TOP_VALUE = 1 << 24
_NUM_MODEL_BITS = 11
_BIT_MODEL_TOTAL = 1 << _NUM_MODEL_BITS
_NUM_MOVE_BITS = 5
_NUM_PROBS = 2 + 256

_MASK32 = 0xFFFFFFFF

_BRANCH_OPCODE = re.compile(B'[\xE8\xE9]|\x0F[\x80-\x8F]')


def decode_bcj2(
    main_data: buf,
    call_data: buf,
    jump_data: buf,
    rc_data: buf,
    output_size: int,
) -> bytearray:
    """
    Decode the four BCJ2 streams. The output is shorter than `output_size` when the main stream
    ends early.
    """
    main = memoryview(main_data)
    call = memoryview(call_data)
    jump = memoryview(jump_data)
    rc = memoryview(rc_data)

    if len(rc) < 5:
        raise SzCorruptArchive('BCJ2: range coder stream too short.')
    if rc[0] != 0:
        raise SzCorruptArchive('BCJ2: range coder stream must start with 0x00.')

    code = int.from_bytes(rc[1:5], 'big')
    if code == _MASK32:
        raise SzCorruptArchive('BCJ2: range coder stream starts with an invalid code.')
    range_ = _MASK32
    rc_pos = 5
    call_pos = 0
    jump_pos = 0
    main_pos = 0
    prev_byte = 0
    probs = [_BIT_MODEL_TOTAL >> 1] * _NUM_PROBS
    output = bytearray()
    find_opcode = _BRANCH_OPCODE.search

    while True:
        if range_ < _TOP_VALUE:
            if rc_pos >= len(rc):
                raise SzCorruptArchive('BCJ2: unexpected end of range coder stream.')
            range_ = (range_ << 8) & _MASK32
            code = ((code << 8) | rc[rc_pos]) & _MASK32
            rc_pos += 1

        end = min(len(main), main_pos + output_size - len(output))
        if prev_byte == 0x0F and main_pos < end and main[main_pos] & 0xF0 == 0x80:
            opcode_pos = main_pos
        elif match := find_opcode(main, main_pos, end):
            opcode_pos = match.end() - 1
        else:
            output.extend(main[main_pos:end])
            break

        opcode = main[opcode_pos]
        if opcode_pos > main_pos:
            prev_byte = main[opcode_pos - 1]
        output.extend(main[main_pos:opcode_pos + 1])
        main_pos = opcode_pos + 1

        if opcode == 0xE8:
            prob_index = 2 + prev_byte
        elif opcode == 0xE9:
            prob_index = 1
        else:
            prob_index = 0

        ttt = probs[prob_index]
        bound = (range_ >> _NUM_MODEL_BITS) * ttt

        if code < bound:
            range_ = bound
            probs[prob_index] = ttt + ((_BIT_MODEL_TOTAL - ttt) >> _NUM_MOVE_BITS)
            prev_byte = opcode
            continue

        range_ -= bound
        code -= bound
        probs[prob_index] = ttt - (ttt >> _NUM_MOVE_BITS)

        if opcode == 0xE8:
            if call_pos + 4 > len(call):
                raise SzCorruptArchive('BCJ2: unexpected end of CALL stream.')
            val = int.from_bytes(call[call_pos:call_pos + 4], 'big')
            call_pos += 4
        else:
            if jump_pos + 4 > len(jump):
                raise SzCorruptArchive('BCJ2: unexpected end of JUMP stream.')
            val = int.from_bytes(jump[jump_pos:jump_pos + 4], 'big')
            jump_pos += 4

        val = (val - len(output) - 4) & _MASK32
        output.extend(val.to_bytes(4, 'little'))
        prev_byte = val >> 24

    del output[output_size:]
    return output
