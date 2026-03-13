"""
BCJ2 decoder for 7z archives.

Ported from 7-Zip's Bcj2.c (Igor Pavlov, public domain).

BCJ2 is a complex x86 branch filter with 4 input streams and 1 output stream.
It uses a range coder to predict whether x86 CALL/JMP instructions should
have their relative addresses converted to absolute.

Stream layout:
  - Stream 0 (MAIN): Non-branch bytes and branch instruction opcodes
  - Stream 1 (CALL): 4-byte big-endian CALL target addresses
  - Stream 2 (JUMP): 4-byte big-endian JMP target addresses
  - Stream 3 (RC):   Range coder data for branch prediction
"""
from __future__ import annotations

from refinery.lib.un7z.headers import SzCorruptArchive

_TOP_VALUE = 1 << 24
_NUM_MODEL_BITS = 11
_BIT_MODEL_TOTAL = 1 << _NUM_MODEL_BITS
_NUM_MOVE_BITS = 5
_NUM_PROBS = 2 + 256

_MASK32 = 0xFFFFFFFF


def decode_bcj2(
    main_data: bytes | bytearray | memoryview,
    call_data: bytes | bytearray | memoryview,
    jump_data: bytes | bytearray | memoryview,
    rc_data: bytes | bytearray | memoryview,
    output_size: int,
) -> bytearray:
    main = memoryview(main_data)
    call = memoryview(call_data)
    jump = memoryview(jump_data)
    rc = memoryview(rc_data)

    main_pos = 0
    call_pos = 0
    jump_pos = 0
    rc_pos = 0

    probs = [_BIT_MODEL_TOTAL >> 1] * _NUM_PROBS

    if len(rc) < 5:
        raise SzCorruptArchive('BCJ2: range coder stream too short.')
    if rc[0] != 0:
        raise SzCorruptArchive('BCJ2: range coder stream must start with 0x00.')
    code = 0
    for i in range(1, 5):
        code = (code << 8) | rc[i]
    rc_pos = 5
    range_ = _MASK32

    output = bytearray(output_size)
    out_pos = 0
    ip = 0
    prev_byte = 0

    while out_pos < output_size:
        if range_ < _TOP_VALUE:
            if rc_pos >= len(rc):
                raise SzCorruptArchive('BCJ2: unexpected end of range coder stream.')
            range_ = (range_ << 8) & _MASK32
            code = ((code << 8) | rc[rc_pos]) & _MASK32
            rc_pos += 1

        found_branch = False

        while main_pos < len(main):
            b = main[main_pos]
            main_pos += 1
            if b == 0x0F and main_pos < len(main) and (main[main_pos] & 0xF0) == 0x80:
                output[out_pos] = b
                out_pos += 1
                b = main[main_pos]
                main_pos += 1
                output[out_pos] = b
                out_pos += 1
                ip += 2
                prev_byte = b
                continue
            if (b & 0xFE) == 0xE8:
                found_branch = True
                output[out_pos] = b
                out_pos += 1
                ip += 1
                break
            output[out_pos] = b
            out_pos += 1
            ip += 1
            prev_byte = b

        if not found_branch:
            break

        b = output[out_pos - 1]
        if b == 0xE8:
            prob_idx = 2 + prev_byte
        elif b == 0xE9:
            prob_idx = 1
        else:
            prob_idx = 0

        ttt = probs[prob_idx]
        bound = (range_ >> _NUM_MODEL_BITS) * ttt

        if (code & _MASK32) < bound:
            range_ = bound
            probs[prob_idx] = ttt + ((_BIT_MODEL_TOTAL - ttt) >> _NUM_MOVE_BITS)
            prev_byte = b
            continue

        range_ = (range_ - bound) & _MASK32
        code = (code - bound) & _MASK32
        probs[prob_idx] = ttt - (ttt >> _NUM_MOVE_BITS)

        if b == 0xE8:
            if call_pos + 4 > len(call):
                raise SzCorruptArchive('BCJ2: unexpected end of CALL stream.')
            val = int.from_bytes(call[call_pos:call_pos + 4], 'big')
            call_pos += 4
        else:
            if jump_pos + 4 > len(jump):
                raise SzCorruptArchive('BCJ2: unexpected end of JUMP stream.')
            val = int.from_bytes(jump[jump_pos:jump_pos + 4], 'big')
            jump_pos += 4

        ip += 4
        val = (val - ip) & _MASK32

        output[out_pos:out_pos + 4] = val.to_bytes(4, 'little')
        out_pos += 4
        prev_byte = (val >> 24) & 0xFF

    return output
