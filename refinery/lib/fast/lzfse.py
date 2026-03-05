"""
Pure-Python implementation of the LZFSE and LZVN decompression algorithms used by Apple. The
implementation is designed for readability and Cython compatibility: all hot-path functions
are module-level with simple typed parameters, lookup tables are plain lists, and no Python
objects are allocated in inner loops.

Reference: https://github.com/lzfse/lzfse
"""
from __future__ import annotations

import struct

_LZFSE_V1_MAGIC: int = 0x31787662
_LZFSE_V2_MAGIC: int = 0x32787662
_LZVN_MAGIC: int = 0x6E787662
_UNCOMPRESSED_MAGIC: int = 0x2D787662
_ENDOFSTREAM_MAGIC: int = 0x24787662

_ENCODE_L_SYMBOLS: int = 20
_ENCODE_M_SYMBOLS: int = 20
_ENCODE_D_SYMBOLS: int = 64
_ENCODE_LITERAL_SYMBOLS: int = 256
_ENCODE_L_STATES: int = 64
_ENCODE_M_STATES: int = 64
_ENCODE_D_STATES: int = 256
_ENCODE_LITERAL_STATES: int = 1024

_L_EXTRA_BITS: list[int] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8]
_L_BASE_VALUE: list[int] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60]

_M_EXTRA_BITS: list[int] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11]
_M_BASE_VALUE: list[int] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312]

_D_EXTRA_BITS: list[int] = [
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
    8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11,
    12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
]
_D_BASE_VALUE: list[int] = [
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52,
    60, 76, 92, 108, 124, 156, 188, 220, 252, 316, 380, 444, 508, 636, 764, 892,
    1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092, 5116, 6140, 7164,
    8188, 10236, 12284, 14332, 16380, 20476, 24572, 28668, 32764, 40956,
    49148, 57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
]

_LZVN_EOS = 0
_LZVN_NOP = 1
_LZVN_UDEF = 2
_LZVN_SML_D = 3
_LZVN_MED_D = 4
_LZVN_LRG_D = 5
_LZVN_PRE_D = 6
_LZVN_SML_L = 7
_LZVN_LRG_L = 8
_LZVN_SML_M = 9
_LZVN_LRG_M = 10

_LZVN_OPC_TABLE: list[int] = [
    3, 3, 3, 3, 3, 3, 0, 5, 3, 3, 3, 3, 3, 3, 1, 5,
    3, 3, 3, 3, 3, 3, 1, 5, 3, 3, 3, 3, 3, 3, 2, 5,
    3, 3, 3, 3, 3, 3, 2, 5, 3, 3, 3, 3, 3, 3, 2, 5,
    3, 3, 3, 3, 3, 3, 2, 5, 3, 3, 3, 3, 3, 3, 2, 5,
    3, 3, 3, 3, 3, 3, 6, 5, 3, 3, 3, 3, 3, 3, 6, 5,
    3, 3, 3, 3, 3, 3, 6, 5, 3, 3, 3, 3, 3, 3, 6, 5,
    3, 3, 3, 3, 3, 3, 6, 5, 3, 3, 3, 3, 3, 3, 6, 5,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 6, 5, 3, 3, 3, 3, 3, 3, 6, 5,
    3, 3, 3, 3, 3, 3, 6, 5, 3, 3, 3, 3, 3, 3, 6, 5,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    3, 3, 3, 3, 3, 3, 6, 5, 3, 3, 3, 3, 3, 3, 6, 5,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    10, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
]
_FREQ_NBITS_TABLE: list[int] = [
    2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
    2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
]
_FREQ_VALUE_TABLE: list[int] = [
    0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
    0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1,
]


def _clz32(x: int) -> int:
    """
    Count leading zeros of a 32-bit integer.
    """
    if x == 0:
        return 32
    return 32 - x.bit_length()


def _read_le_u64_safe(buf: bytes | bytearray | memoryview, pos: int) -> int:
    """
    Read up to 8 bytes as LE uint64, zero-padding if near buffer boundary.
    """
    end = pos + 8
    if end <= len(buf):
        return struct.unpack_from('<Q', buf, pos)[0]
    result = 0
    for i in range(min(len(buf) - pos, 8)):
        result |= buf[pos + i] << (8 * i)
    return result


def _fse_in_init(buf: bytes | bytearray | memoryview, offset: int, nbytes: int, nbits: int) -> list:
    """
    Initialise a backward bit-stream reader for the 64-bit FSE decoding path.
    """
    buf_pos = offset + nbytes
    if nbits:
        buf_pos -= 8
        accum = _read_le_u64_safe(buf, buf_pos)
        accum_nbits = nbits + 64
    else:
        buf_pos -= 7
        accum = _read_le_u64_safe(buf, buf_pos) & 0xFFFFFFFFFFFFFF
        accum_nbits = 56
    return [buf, buf_pos, accum, accum_nbits]


def _fse_in_flush(state: list) -> None:
    """
    Refill the accumulator (64-bit path).

    Matches fse_in_checked_flush64 from the C reference: left-shift the
    existing accumulator, then OR in new bits at the bottom.
    """
    accum_nbits = state[3]
    nbits = (63 - accum_nbits) & ~7
    if nbits <= 0:
        return
    nbytes = nbits >> 3
    buf_pos = state[1] - nbytes
    if buf_pos < 0:
        return
    state[1] = buf_pos
    incoming = _read_le_u64_safe(state[0], buf_pos)
    state[2] = (state[2] << nbits) | (incoming & ((1 << nbits) - 1))
    state[3] = accum_nbits + nbits


def _fse_in_pull(state: list, n: int) -> int:
    """
    Pull n bits from the top of the accumulator.
    """
    state[3] -= n
    result = state[2] >> state[3]
    state[2] &= (1 << state[3]) - 1
    return result


def _fse_init_decoder_table(
    nstates: int,
    nsymbols: int,
    freq: list[int],
) -> list[int]:
    """
    Build a literal FSE decoder table.

    Each entry is packed as: (k << 0) | (symbol << 8) | (delta << 16)
    where k is the number of bits to consume and delta is the signed state
    increment (stored as a 16-bit signed integer in the upper 16 bits).

    Returns a list of nstates packed int32 entries.
    """
    n_clz = _clz32(nstates)
    table: list[int] = [0] * nstates
    idx = 0
    for symbol in range(nsymbols):
        f = freq[symbol]
        if f == 0:
            continue
        k = _clz32(f) - n_clz
        j0 = ((2 * nstates) >> k) - f
        for j in range(f):
            if j < j0:
                bits = k
                delta = ((f + j) << k) - nstates
            else:
                bits = k - 1
                delta = (j - j0) << (k - 1)
            table[idx] = bits | (symbol << 8) | (delta << 16)
            idx += 1
    return table


def _fse_init_value_decoder_table(
    nstates: int,
    nsymbols: int,
    freq: list[int],
    symbol_vbits: list[int],
    symbol_vbase: list[int],
) -> list[list[int]]:
    """
    Build a value FSE decoder table (for L, M, or D).

    Each entry is [total_bits, value_bits, delta, vbase].

    Returns a list of nstates entries.
    """
    n_clz = _clz32(nstates)
    table: list[list[int]] = []
    for symbol in range(nsymbols):
        f = freq[symbol]
        if f == 0:
            continue
        k = _clz32(f) - n_clz
        j0 = ((2 * nstates) >> k) - f
        vbits = symbol_vbits[symbol]
        vbase = symbol_vbase[symbol]
        for j in range(f):
            if j < j0:
                total = k + vbits
                delta = ((f + j) << k) - nstates
            else:
                total = (k - 1) + vbits
                delta = (j - j0) << (k - 1)
            table.append([total, vbits, delta, vbase])
    return table


def _decode_v2_freq_table(buf: bytes | bytearray | memoryview, offset: int, header_size: int) -> list[int]:
    """
    Decode the variable-length compressed frequency table from a V2 header.

    The frequency payload starts at offset (after the fixed fields) and extends
    to header_size bytes from the block start.

    Returns a list of 360 frequency values (L:20 + M:20 + D:64 + literal:256).
    """
    total_freq_count = _ENCODE_L_SYMBOLS + _ENCODE_M_SYMBOLS + _ENCODE_D_SYMBOLS + _ENCODE_LITERAL_SYMBOLS

    accum = 0
    accum_nbits = 0
    src_pos = offset

    freqs: list[int] = []

    while len(freqs) < total_freq_count:
        while accum_nbits < 14:
            if src_pos < len(buf):
                accum |= buf[src_pos] << accum_nbits
                src_pos += 1
                accum_nbits += 8
            else:
                break

        lookup = accum & 0x1F
        nbits = _FREQ_NBITS_TABLE[lookup]
        value = _FREQ_VALUE_TABLE[lookup]

        if nbits <= 5:
            accum >>= nbits
            accum_nbits -= nbits
            freqs.append(value)
        elif nbits == 8:
            accum >>= 4
            accum_nbits -= 4
            value = 8 + (accum & 0xF)
            accum >>= 4
            accum_nbits -= 4
            freqs.append(value)
        elif nbits == 14:
            accum >>= 4
            accum_nbits -= 4
            value = 24 + (accum & 0x3FF)
            accum >>= 10
            accum_nbits -= 10
            freqs.append(value)
        else:
            raise ValueError(F'unexpected nbits={nbits} in V2 frequency table')

    return freqs


def _decode_lzfse_block(
    buf: bytes | bytearray | memoryview,
    pos: int,
    output: bytearray,
) -> int:
    """
    Decode a single LZFSE compressed block (V1 or V2) starting at pos.

    Returns the new position in buf after consuming the block.
    Appends decompressed data to output.
    """
    magic = struct.unpack_from('<I', buf, pos)[0]

    if magic == _LZFSE_V2_MAGIC:
        return _decode_lzfse_v2_block(buf, pos, output)
    elif magic == _LZFSE_V1_MAGIC:
        return _decode_lzfse_v1_block(buf, pos, output)
    else:
        raise ValueError(F'expected LZFSE block magic, got 0x{magic:08X}')


def _decode_lzfse_v2_block(
    buf: bytes | bytearray | memoryview,
    pos: int,
    output: bytearray,
) -> int:
    """
    Decode a V2 LZFSE block. Returns new position.
    """
    block_start = pos
    pos += 4

    n_raw_bytes = struct.unpack_from('<I', buf, pos)[0]
    pos += 4

    pf0, pf1, pf2 = struct.unpack_from('<QQQ', buf, pos)
    pos += 24

    n_literals = pf0 & 0xFFFFF
    n_literal_payload_bytes = (pf0 >> 20) & 0xFFFFF
    n_matches = (pf0 >> 40) & 0xFFFFF
    literal_bits = ((pf0 >> 60) & 0x7) - 7

    literal_state0 = pf1 & 0x3FF
    literal_state1 = (pf1 >> 10) & 0x3FF
    literal_state2 = (pf1 >> 20) & 0x3FF
    literal_state3 = (pf1 >> 30) & 0x3FF
    n_lmd_payload_bytes = (pf1 >> 40) & 0xFFFFF
    lmd_bits = ((pf1 >> 60) & 0x7) - 7

    header_size = pf2 & 0xFFFFFFFF
    l_state = (pf2 >> 32) & 0x3FF
    m_state = (pf2 >> 42) & 0x3FF
    d_state = (pf2 >> 52) & 0x3FF

    n_payload_bytes = n_literal_payload_bytes + n_lmd_payload_bytes

    freq_start = pos
    freqs = _decode_v2_freq_table(buf, freq_start, header_size)

    i = 0
    l_freq = freqs[i:(i := i + _ENCODE_L_SYMBOLS)]
    m_freq = freqs[i:(i := i + _ENCODE_M_SYMBOLS)]
    d_freq = freqs[i:(i := i + _ENCODE_D_SYMBOLS)]
    literal_freq = freqs[i:i + _ENCODE_LITERAL_SYMBOLS]

    payload_offset = block_start + header_size

    _decode_lzfse_payload(
        buf,
        payload_offset,
        n_raw_bytes,
        n_literals,
        n_matches,
        n_literal_payload_bytes,
        n_lmd_payload_bytes,
        literal_bits,
        literal_state0,
        literal_state1,
        literal_state2,
        literal_state3,
        lmd_bits,
        l_state,
        m_state,
        d_state,
        l_freq,
        m_freq,
        d_freq,
        literal_freq,
        output,
    )

    return payload_offset + n_payload_bytes


def _decode_lzfse_v1_block(
    buf: bytes | bytearray | memoryview,
    pos: int,
    output: bytearray,
) -> int:
    """
    Decode a V1 LZFSE block. Returns new position.
    """
    pos += 4

    (n_raw_bytes, n_payload_bytes, n_literals, n_matches,
     n_literal_payload_bytes, n_lmd_payload_bytes,
     literal_bits) = struct.unpack_from('<IIIIIIi', buf, pos)
    pos += 28

    literal_state0, literal_state1, literal_state2, literal_state3 = struct.unpack_from('<HHHH', buf, pos)
    pos += 8

    lmd_bits = struct.unpack_from('<i', buf, pos)[0]
    pos += 4

    l_state, m_state, d_state = struct.unpack_from('<HHH', buf, pos)
    pos += 6

    l_freq = list(struct.unpack_from(F'<{_ENCODE_L_SYMBOLS}H', buf, pos))
    pos += _ENCODE_L_SYMBOLS * 2
    m_freq = list(struct.unpack_from(F'<{_ENCODE_M_SYMBOLS}H', buf, pos))
    pos += _ENCODE_M_SYMBOLS * 2
    d_freq = list(struct.unpack_from(F'<{_ENCODE_D_SYMBOLS}H', buf, pos))
    pos += _ENCODE_D_SYMBOLS * 2
    literal_freq = list(struct.unpack_from(F'<{_ENCODE_LITERAL_SYMBOLS}H', buf, pos))
    pos += _ENCODE_LITERAL_SYMBOLS * 2

    payload_offset = pos

    _decode_lzfse_payload(
        buf, payload_offset,
        n_raw_bytes, n_literals, n_matches,
        n_literal_payload_bytes, n_lmd_payload_bytes,
        literal_bits, literal_state0, literal_state1, literal_state2, literal_state3,
        lmd_bits, l_state, m_state, d_state,
        l_freq, m_freq, d_freq, literal_freq,
        output,
    )

    return payload_offset + n_payload_bytes


def _decode_lzfse_payload(
    buf: bytes | bytearray | memoryview,
    payload_offset: int,
    n_raw_bytes: int,
    n_literals: int,
    n_matches: int,
    n_literal_payload_bytes: int,
    n_lmd_payload_bytes: int,
    literal_bits: int,
    literal_state0: int,
    literal_state1: int,
    literal_state2: int,
    literal_state3: int,
    lmd_bits: int,
    l_state: int,
    m_state: int,
    d_state: int,
    l_freq: list[int],
    m_freq: list[int],
    d_freq: list[int],
    literal_freq: list[int],
    output: bytearray,
) -> None:
    """
    Decode the FSE-encoded literal and LMD payloads, apply LZ77, append to output.
    """

    lit_table = _fse_init_decoder_table(_ENCODE_LITERAL_STATES, _ENCODE_LITERAL_SYMBOLS, literal_freq)
    l_table = _fse_init_value_decoder_table(_ENCODE_L_STATES, _ENCODE_L_SYMBOLS, l_freq, _L_EXTRA_BITS, _L_BASE_VALUE)
    m_table = _fse_init_value_decoder_table(_ENCODE_M_STATES, _ENCODE_M_SYMBOLS, m_freq, _M_EXTRA_BITS, _M_BASE_VALUE)
    d_table = _fse_init_value_decoder_table(_ENCODE_D_STATES, _ENCODE_D_SYMBOLS, d_freq, _D_EXTRA_BITS, _D_BASE_VALUE)

    lit_stream = _fse_in_init(buf, payload_offset, n_literal_payload_bytes, literal_bits)

    literals = bytearray(n_literals)
    s0 = literal_state0
    s1 = literal_state1
    s2 = literal_state2
    s3 = literal_state3

    i = 0
    while i + 3 < n_literals:
        _fse_in_flush(lit_stream)

        entry = lit_table[s0]
        k = entry & 0xFF
        sym = (entry >> 8) & 0xFF
        delta = entry >> 16
        literals[i] = sym
        s0 = delta + _fse_in_pull(lit_stream, k)

        entry = lit_table[s1]
        k = entry & 0xFF
        sym = (entry >> 8) & 0xFF
        delta = entry >> 16
        literals[i + 1] = sym
        s1 = delta + _fse_in_pull(lit_stream, k)

        entry = lit_table[s2]
        k = entry & 0xFF
        sym = (entry >> 8) & 0xFF
        delta = entry >> 16
        literals[i + 2] = sym
        s2 = delta + _fse_in_pull(lit_stream, k)

        entry = lit_table[s3]
        k = entry & 0xFF
        sym = (entry >> 8) & 0xFF
        delta = entry >> 16
        literals[i + 3] = sym
        s3 = delta + _fse_in_pull(lit_stream, k)

        i += 4

    lmd_offset = payload_offset + n_literal_payload_bytes
    lmd_stream = _fse_in_init(buf, lmd_offset, n_lmd_payload_bytes, lmd_bits)

    lit_pos = 0
    prev_d = -1

    for _ in range(n_matches):
        _fse_in_flush(lmd_stream)

        le = l_table[l_state]
        total_bits = le[0]
        value_bits = le[1]
        l_delta = le[2]
        l_vbase = le[3]
        bits = _fse_in_pull(lmd_stream, total_bits)
        l_state = l_delta + (bits >> value_bits)
        l_value = l_vbase + (bits & ((1 << value_bits) - 1)) if value_bits else l_vbase

        me = m_table[m_state]
        total_bits = me[0]
        value_bits = me[1]
        m_delta = me[2]
        m_vbase = me[3]
        bits = _fse_in_pull(lmd_stream, total_bits)
        m_state = m_delta + (bits >> value_bits)
        m_value = m_vbase + (bits & ((1 << value_bits) - 1)) if value_bits else m_vbase

        de = d_table[d_state]
        total_bits = de[0]
        value_bits = de[1]
        d_delta = de[2]
        d_vbase = de[3]
        bits = _fse_in_pull(lmd_stream, total_bits)
        d_state = d_delta + (bits >> value_bits)
        d_value = d_vbase + (bits & ((1 << value_bits) - 1)) if value_bits else d_vbase

        if d_value == 0:
            d_value = prev_d
        else:
            prev_d = d_value

        if l_value > 0:
            output.extend(literals[lit_pos:lit_pos + l_value])
            lit_pos += l_value

        if m_value > 0:
            out_len = len(output)
            match_start = out_len - d_value
            if d_value >= m_value:
                output.extend(output[match_start:match_start + m_value])
            else:
                for j in range(m_value):
                    output.append(output[match_start + j])

    if lit_pos < n_literals:
        output.extend(literals[lit_pos:n_literals])


def _decode_lzvn_block(
    buf: bytes | bytearray | memoryview,
    pos: int,
    output: bytearray,
) -> int:
    """
    Decode an LZVN compressed block starting at pos.

    Returns the new position in buf after consuming the block.
    Appends decompressed data to output.
    """
    pos += 4
    n_raw_bytes = struct.unpack_from('<I', buf, pos)[0]
    pos += 4
    n_payload_bytes = struct.unpack_from('<I', buf, pos)[0]
    pos += 4

    payload_start = pos
    payload_end = pos + n_payload_bytes
    _lzvn_decode(buf, payload_start, payload_end, n_raw_bytes, output)

    return payload_end


def _lzvn_decode(
    src: bytes | bytearray | memoryview,
    src_pos: int,
    src_end: int,
    n_raw_bytes: int,
    output: bytearray,
) -> None:
    """
    Decode an LZVN byte stream. Appends up to n_raw_bytes to output.

    Uses a 256-entry lookup table for opcode classification, matching the
    C reference implementation exactly.
    """
    dst_start = len(output)
    d_prev = 0

    while src_pos < src_end and (len(output) - dst_start) < n_raw_bytes:
        opc = src[src_pos]
        kind = _LZVN_OPC_TABLE[opc]

        if kind == _LZVN_EOS:
            break
        elif kind == _LZVN_NOP:
            src_pos += 1
            continue
        elif kind == _LZVN_UDEF:
            break
        elif kind == _LZVN_SML_L:
            L = opc & 0x0F
            src_pos += 1
            if src_pos + L > src_end:
                L = src_end - src_pos
            output.extend(src[src_pos:src_pos + L])
            src_pos += L
            continue
        elif kind == _LZVN_LRG_L:
            if src_pos + 1 >= src_end:
                break
            L = src[src_pos + 1] + 16
            src_pos += 2
            if src_pos + L > src_end:
                L = src_end - src_pos
            output.extend(src[src_pos:src_pos + L])
            src_pos += L
            continue
        elif kind == _LZVN_SML_M:
            M = opc & 0x0F
            src_pos += 1
            D = d_prev
            if D == 0:
                break
            _lzvn_copy_match(output, D, M)
        elif kind == _LZVN_LRG_M:
            if src_pos + 1 >= src_end:
                break
            M = src[src_pos + 1] + 16
            src_pos += 2
            D = d_prev
            if D == 0:
                break
            _lzvn_copy_match(output, D, M)
        elif kind == _LZVN_PRE_D:
            L = (opc >> 6) & 0x03
            M = ((opc >> 3) & 0x07) + 3
            src_pos += 1
            D = d_prev
            if D == 0:
                break
            if L > 0:
                if src_pos + L > src_end:
                    break
                output.extend(src[src_pos:src_pos + L])
                src_pos += L
            _lzvn_copy_match(output, D, M)
        elif kind == _LZVN_LRG_D:
            if src_pos + 2 >= src_end:
                break
            L = (opc >> 6) & 0x03
            M = ((opc >> 3) & 0x07) + 3
            D = struct.unpack_from('<H', src, src_pos + 1)[0]
            src_pos += 3
            if D == 0:
                break
            d_prev = D
            if L > 0:
                if src_pos + L > src_end:
                    break
                output.extend(src[src_pos:src_pos + L])
                src_pos += L
            _lzvn_copy_match(output, D, M)
        elif kind == _LZVN_MED_D:
            if src_pos + 2 >= src_end:
                break
            L = (opc >> 3) & 0x03
            opc23 = struct.unpack_from('<H', src, src_pos + 1)[0]
            M = ((opc & 0x07) << 2 | (opc23 & 0x03)) + 3
            D = opc23 >> 2
            src_pos += 3
            if D == 0:
                break
            d_prev = D
            if L > 0:
                if src_pos + L > src_end:
                    break
                output.extend(src[src_pos:src_pos + L])
                src_pos += L
            _lzvn_copy_match(output, D, M)
        elif kind == _LZVN_SML_D:
            if src_pos + 1 >= src_end:
                break
            L = (opc >> 6) & 0x03
            M = ((opc >> 3) & 0x07) + 3
            D = ((opc & 0x07) << 8) | src[src_pos + 1]
            src_pos += 2
            if D == 0:
                break
            d_prev = D
            if L > 0:
                if src_pos + L > src_end:
                    break
                output.extend(src[src_pos:src_pos + L])
                src_pos += L
            _lzvn_copy_match(output, D, M)


def _lzvn_copy_match(output: bytearray, D: int, M: int) -> None:
    """
    Copy M bytes from output[-D] to end of output.
    """
    out_len = len(output)
    start = out_len - D
    if start < 0:
        raise ValueError(F'LZVN match distance {D} exceeds output size {out_len}')
    if D >= M:
        output.extend(output[start:start + M])
    else:
        for _ in range(M):
            output.append(output[start])
            start += 1


def lzfse_decompress(src: bytes | bytearray | memoryview) -> bytearray:
    """
    Decompress an LZFSE compressed stream.

    The stream consists of a sequence of typed blocks (LZFSE, LZVN, raw, or
    end-of-stream). Returns the concatenated decompressed output as bytes.
    """
    pos = 0
    end = len(src)
    output = bytearray()

    while pos + 4 <= end:
        magic = struct.unpack_from('<I', src, pos)[0]

        if magic == _ENDOFSTREAM_MAGIC:
            pos += 4
            break
        elif magic == _UNCOMPRESSED_MAGIC:
            pos += 4
            n_raw_bytes = struct.unpack_from('<I', src, pos)[0]
            pos += 4
            output.extend(src[pos:pos + n_raw_bytes])
            pos += n_raw_bytes
        elif magic == _LZFSE_V1_MAGIC or magic == _LZFSE_V2_MAGIC:
            pos = _decode_lzfse_block(src, pos, output)
        elif magic == _LZVN_MAGIC:
            pos = _decode_lzvn_block(src, pos, output)
        else:
            raise ValueError(F'unknown LZFSE block magic: 0x{magic:08X}')

    return output
