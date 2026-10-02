"""
Pure-Python implementation of the LZFSE and LZVN decompression algorithms used by Apple. The
implementation is designed for readability and Cython compatibility: all hot-path functions
are module-level with simple typed parameters, lookup tables are plain lists, and no Python
objects are allocated in inner loops.

Reference: https://github.com/lzfse/lzfse
"""
from __future__ import annotations

from refinery.lib.exceptions import RefineryPartialResult
from refinery.lib.fast.lzfse_header import BlockHeader, BlockKind, read_block_header

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
_LZVN_INSTRUCTION_SIZE: list[int] = [1, 1, 1, 2, 3, 3, 1, 1, 2, 1, 2]

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


def _fse_in_load(state: list, pos: int) -> int:
    """
    Read 8 bytes at `pos` as LE uint64; bytes outside the payload of the stream read as zero.
    """
    lo = max(pos, state[4])
    hi = min(pos + 8, state[5])
    if lo >= hi:
        return 0
    return int.from_bytes(state[0][lo:hi], 'little') << (8 * (lo - pos))


def _fse_in_init(buf: memoryview, start: int, end: int, nbits: int) -> list:
    """
    Initialise a backward bit-stream reader for the 64-bit FSE decoding path over the payload from
    `start` to `end`.
    """
    state = [buf, 0, 0, 0, start, end]
    if nbits:
        state[1] = end - 8
        state[2] = _fse_in_load(state, end - 8)
        state[3] = nbits + 64
    else:
        state[1] = end - 7
        state[2] = _fse_in_load(state, end - 7) & 0xFFFFFFFFFFFFFF
        state[3] = 56
    if state[2] >> state[3]:
        raise ValueError('the unused bits of an LZFSE bit stream are not zero')
    return state


def _fse_in_remaining(state: list) -> int:
    """
    The number of payload bits that were not consumed yet; it is negative when bits from before the
    start of the payload were consumed.
    """
    return state[3] + 8 * (state[1] - state[4])


def _fse_in_flush(state: list) -> None:
    """
    Refill the accumulator (64-bit path).

    Matches fse_in_checked_flush64 from the C reference: left-shift the
    existing accumulator, then OR in new bits at the bottom.
    """
    if _fse_in_remaining(state) < 0:
        raise ValueError('an LZFSE bit stream ends before its last symbol')
    accum_nbits = state[3]
    nbits = (63 - accum_nbits) & ~7
    if nbits <= 0:
        return
    buf_pos = state[1] - (nbits >> 3)
    state[1] = buf_pos
    incoming = _fse_in_load(state, buf_pos)
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


def _decode_v2_freq_table(buf: memoryview, pos: int, end: int) -> list[int]:
    """
    Decode the variable-length compressed frequency table from a V2 header, which must consume the
    bytes from `pos` to `end`.

    Returns a list of 360 frequency values (L:20 + M:20 + D:64 + literal:256).
    """
    total_freq_count = _ENCODE_L_SYMBOLS + _ENCODE_M_SYMBOLS + _ENCODE_D_SYMBOLS + _ENCODE_LITERAL_SYMBOLS

    accum = 0
    accum_nbits = 0

    freqs: list[int] = []

    while len(freqs) < total_freq_count:
        while accum_nbits < 14 and pos < end:
            accum |= buf[pos] << accum_nbits
            pos += 1
            accum_nbits += 8

        lookup = accum & 0x1F
        nbits = _FREQ_NBITS_TABLE[lookup]
        if nbits > accum_nbits:
            raise ValueError('an LZFSE frequency table ends before its last value')
        if nbits == 8:
            freqs.append(8 + ((accum >> 4) & 0xF))
        elif nbits == 14:
            freqs.append(24 + ((accum >> 4) & 0x3FF))
        else:
            freqs.append(_FREQ_VALUE_TABLE[lookup])
        accum >>= nbits
        accum_nbits -= nbits

    if pos < end or accum_nbits >= 8:
        raise ValueError('an LZFSE frequency table does not fill its header')

    return freqs


def _decode_lzfse_block(buf: memoryview, header: BlockHeader, output: bytearray) -> None:
    """
    Decode an LZFSE V1 or V2 block and append the decompressed data to output.
    """
    if header.kind is BlockKind.LZFSE_V2:
        freqs = _decode_v2_freq_table(buf, header.freq_table, header.payload)
    else:
        freqs = list(header.freqs)

    i = 0
    l_freq = freqs[i:(i := i + _ENCODE_L_SYMBOLS)]
    m_freq = freqs[i:(i := i + _ENCODE_M_SYMBOLS)]
    d_freq = freqs[i:(i := i + _ENCODE_D_SYMBOLS)]
    literal_freq = freqs[i:i + _ENCODE_LITERAL_SYMBOLS]

    if (
        sum(l_freq) != _ENCODE_L_STATES
        or sum(m_freq) != _ENCODE_M_STATES
        or sum(d_freq) != _ENCODE_D_STATES
        or sum(literal_freq) != _ENCODE_LITERAL_STATES
    ):
        raise ValueError('an LZFSE frequency table does not sum to its number of states')

    literal_state0, literal_state1, literal_state2, literal_state3 = header.literal_states

    _decode_lzfse_payload(
        buf,
        header.payload,
        header.literal_payload_size,
        header.lmd_payload_size,
        header.raw_size,
        header.n_literals,
        header.n_matches,
        header.literal_bits,
        literal_state0,
        literal_state1,
        literal_state2,
        literal_state3,
        header.lmd_bits,
        header.l_state,
        header.m_state,
        header.d_state,
        l_freq,
        m_freq,
        d_freq,
        literal_freq,
        output,
    )


def _decode_lzfse_payload(
    buf: memoryview,
    payload: int,
    literal_payload_size: int,
    lmd_payload_size: int,
    raw_size: int,
    n_literals: int,
    n_matches: int,
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

    lmd_payload = payload + literal_payload_size
    lit_stream = _fse_in_init(buf, payload, lmd_payload, literal_bits)

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

    if _fse_in_remaining(lit_stream) != 0:
        raise ValueError('an LZFSE literal stream does not end with its last literal')

    lmd_stream = _fse_in_init(buf, lmd_payload, lmd_payload + lmd_payload_size, lmd_bits)

    lit_pos = 0
    prev_d = -1
    block_start = len(output)

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

        if lit_pos + l_value > n_literals:
            raise ValueError('an LZFSE match uses more literals than its block has')
        if len(output) - block_start + l_value + m_value > raw_size:
            raise ValueError('an LZFSE block decodes to more than the size in its header')
        if m_value > 0 and not 0 < d_value <= len(output) + l_value:
            raise ValueError('an LZFSE match starts before the start of the output')

        if l_value > 0:
            output.extend(literals[lit_pos:lit_pos + l_value])
            lit_pos += l_value

        if m_value > 0:
            _copy_match(output, d_value, m_value)

    if _fse_in_remaining(lmd_stream) != 64 or any(buf[lmd_payload:lmd_payload + 8]):
        raise ValueError('an LZFSE match stream does not end with its eight bytes of zero padding')
    if len(output) - block_start != raw_size:
        raise ValueError('an LZFSE block decodes to less than the size in its header')


def _copy_match(output: bytearray, distance: int, length: int) -> None:
    """
    Append `length` bytes that repeat the output from `distance` bytes before its end.
    """
    start = len(output) - distance
    if distance >= length:
        output.extend(output[start:start + length])
    else:
        for k in range(start, start + length):
            output.append(output[k])


def _lzvn_decode(
    src: memoryview,
    src_pos: int,
    src_end: int,
    n_raw_bytes: int,
    output: bytearray,
) -> None:
    """
    Decode the LZVN payload of a block up to its end-of-stream instruction, which must append
    exactly `n_raw_bytes` bytes to the output.
    """
    dst_end = len(output) + n_raw_bytes
    D = 0

    while True:
        if src_pos >= src_end:
            raise ValueError('an LZVN block ends before its end-of-stream instruction')
        opc = src[src_pos]
        kind = _LZVN_OPC_TABLE[opc]
        if kind == _LZVN_EOS:
            break
        if kind == _LZVN_NOP:
            src_pos += 1
            continue
        if kind == _LZVN_UDEF:
            raise ValueError(F'an LZVN block contains the undefined instruction 0x{opc:02X}')
        size = _LZVN_INSTRUCTION_SIZE[kind]
        if src_pos + size > src_end:
            raise ValueError('an LZVN block ends inside an instruction')
        L = opc >> 6
        M = ((opc >> 3) & 7) + 3
        if kind == _LZVN_SML_D:
            D = ((opc & 7) << 8) | src[src_pos + 1]
        elif kind == _LZVN_MED_D:
            L = (opc >> 3) & 3
            M = (((opc & 7) << 2) | (src[src_pos + 1] & 3)) + 3
            D = (src[src_pos + 1] >> 2) | (src[src_pos + 2] << 6)
        elif kind == _LZVN_LRG_D:
            D = src[src_pos + 1] | (src[src_pos + 2] << 8)
        elif kind == _LZVN_SML_L:
            L, M = opc & 0x0F, 0
        elif kind == _LZVN_LRG_L:
            L, M = src[src_pos + 1] + 16, 0
        elif kind == _LZVN_SML_M:
            L, M = 0, opc & 0x0F
        elif kind == _LZVN_LRG_M:
            L, M = 0, src[src_pos + 1] + 16
        src_pos += size

        if len(output) + L + M > dst_end:
            raise ValueError('an LZVN block decodes to more than the size in its header')
        if L:
            if src_pos + L > src_end:
                raise ValueError('an LZVN block ends inside a run of literals')
            output.extend(src[src_pos:src_pos + L])
            src_pos += L
        if M:
            if not 0 < D <= len(output):
                raise ValueError(F'an LZVN match distance of {D} is outside the output of size {len(output)}')
            _copy_match(output, D, M)

    if len(output) != dst_end:
        raise ValueError('an LZVN block decodes to less than the size in its header')


def lzfse_decompress(src: bytes | bytearray | memoryview) -> bytearray:
    """
    Decompress an LZFSE stream, which ends with an end-of-stream block. Input that ends before that
    block, or that cannot be decoded after some output, raises a `RefineryPartialResult` with the
    output of the blocks decoded so far.
    """
    view = memoryview(src)
    output = bytearray()
    decoded = 0
    pos = 0

    try:
        while (header := read_block_header(view, pos)).kind is not BlockKind.END:
            if header.kind is BlockKind.RAW:
                output.extend(view[header.payload:header.end])
            elif header.kind is BlockKind.LZVN:
                _lzvn_decode(view, header.payload, header.end, header.raw_size, output)
            else:
                _decode_lzfse_block(view, header, output)
            decoded = len(output)
            pos = header.end
    except ValueError as error:
        if not decoded:
            raise
        raise RefineryPartialResult(F'Decoding failed after {decoded} bytes: {error!s}', output[:decoded]) from error

    return output
