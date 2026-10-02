# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
cimport cython

from libc.stdint cimport int8_t, int32_t, uint8_t, uint16_t, uint32_t, uint64_t
from libc.stdlib cimport free, malloc
from libc.string cimport memcpy

from refinery.lib.fast._buffer cimport reserve

from refinery.lib.exceptions import RefineryPartialResult
from refinery.lib.fast.lzfse_header import LITERALS_PER_BLOCK, BlockKind, read_block_header

DEF ENCODE_L_SYMBOLS = 20
DEF ENCODE_M_SYMBOLS = 20
DEF ENCODE_D_SYMBOLS = 64
DEF ENCODE_LITERAL_SYMBOLS = 256
DEF ENCODE_L_STATES = 64
DEF ENCODE_M_STATES = 64
DEF ENCODE_D_STATES = 256
DEF ENCODE_LITERAL_STATES = 1024
DEF TOTAL_FREQ_COUNT = 360
DEF VALUE_STRIDE = 4

DEF LZVN_EOS   = 0
DEF LZVN_NOP   = 1
DEF LZVN_UDEF  = 2
DEF LZVN_SML_D = 3
DEF LZVN_MED_D = 4
DEF LZVN_LRG_D = 5
DEF LZVN_PRE_D = 6
DEF LZVN_SML_L = 7
DEF LZVN_LRG_L = 8
DEF LZVN_SML_M = 9
DEF LZVN_LRG_M = 10

# ---------------------------------------------------------------------------
# Lookup tables – module-level cdef arrays
# ---------------------------------------------------------------------------

cdef uint8_t _L_EXTRA_BITS[20]
_L_EXTRA_BITS[:] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8]

cdef uint32_t _L_BASE_VALUE[20]
_L_BASE_VALUE[:] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60]

cdef uint8_t _M_EXTRA_BITS[20]
_M_EXTRA_BITS[:] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11]

cdef uint32_t _M_BASE_VALUE[20]
_M_BASE_VALUE[:] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312]

cdef uint8_t _D_EXTRA_BITS[64]
_D_EXTRA_BITS[:] = [
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
    8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11,
    12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
]

cdef uint32_t _D_BASE_VALUE[64]
_D_BASE_VALUE[:] = [
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52,
    60, 76, 92, 108, 124, 156, 188, 220, 252, 316, 380, 444, 508, 636, 764, 892,
    1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092, 5116, 6140, 7164,
    8188, 10236, 12284, 14332, 16380, 20476, 24572, 28668, 32764, 40956,
    49148, 57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
]

cdef uint8_t _LZVN_OPC_TABLE[256]
_LZVN_OPC_TABLE[:] = [
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

cdef uint8_t _LZVN_INSTRUCTION_SIZE[11]
_LZVN_INSTRUCTION_SIZE[:] = [1, 1, 1, 2, 3, 3, 1, 1, 2, 1, 2]

cdef uint8_t _FREQ_NBITS_TABLE[32]
_FREQ_NBITS_TABLE[:] = [
    2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
    2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
]

# Stored as signed values because it contains -1.
# We use int (not int8_t) to avoid type issues and keep values usable in arithmetic.
cdef int _FREQ_VALUE_TABLE[32]
_FREQ_VALUE_TABLE[:] = [
    0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
    0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1,
]

# ---------------------------------------------------------------------------
# FSE state struct
# ---------------------------------------------------------------------------

ctypedef struct FseInState:
    const uint8_t *buf
    Py_ssize_t start
    Py_ssize_t end
    Py_ssize_t pos
    uint64_t accum
    int accum_nbits

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

cdef inline int _clz32(uint32_t x) noexcept nogil:
    cdef int n
    if x == 0:
        return 32
    n = 0
    if x <= 0x0000FFFF:
        n += 16
        x <<= 16
    if x <= 0x00FFFFFF:
        n += 8
        x <<= 8
    if x <= 0x0FFFFFFF:
        n += 4
        x <<= 4
    if x <= 0x3FFFFFFF:
        n += 2
        x <<= 2
    if x <= 0x7FFFFFFF:
        n += 1
    return n


cdef inline uint64_t _read_le_u64(const uint8_t *buf, Py_ssize_t pos) noexcept nogil:
    cdef uint64_t result
    memcpy(&result, &buf[pos], 8)
    return result


cdef inline void _copy_match(uint8_t *dst, Py_ssize_t distance, Py_ssize_t length) noexcept nogil:
    """
    Write `length` bytes to `dst` that repeat the output from `distance` bytes before `dst`.
    """
    cdef Py_ssize_t k
    if distance >= length:
        memcpy(dst, dst - distance, length)
    else:
        for k in range(length):
            dst[k] = dst[k - distance]

# ---------------------------------------------------------------------------
# FSE bit-stream operations
# ---------------------------------------------------------------------------

cdef inline uint64_t _fse_in_load(FseInState *st) noexcept nogil:
    """
    Read 8 bytes at the stream position; bytes outside the payload of the stream read as zero.
    """
    cdef uint64_t result = 0
    cdef Py_ssize_t i
    if st.pos >= st.start and st.pos + 8 <= st.end:
        memcpy(&result, &st.buf[st.pos], 8)
        return result
    for i in range(max(st.pos, st.start), min(st.pos + 8, st.end)):
        result |= (<uint64_t>st.buf[i]) << (8 * (i - st.pos))
    return result


cdef inline int _fse_in_init(
    FseInState *st,
    const uint8_t *buf,
    Py_ssize_t start,
    Py_ssize_t end,
    int nbits,
) noexcept nogil:
    st.buf = buf
    st.start = start
    st.end = end
    if nbits:
        st.pos = end - 8
        st.accum = _fse_in_load(st)
        st.accum_nbits = nbits + 64
    else:
        st.pos = end - 7
        st.accum = _fse_in_load(st) & <uint64_t>0xFFFFFFFFFFFFFF
        st.accum_nbits = 56
    if st.accum >> st.accum_nbits:
        return -1
    return 0


cdef inline Py_ssize_t _fse_in_remaining(FseInState *st) noexcept nogil:
    """
    The number of payload bits that were not consumed yet; it is negative when bits from before the
    start of the payload were consumed.
    """
    return st.accum_nbits + 8 * (st.pos - st.start)


cdef inline int _fse_in_flush(FseInState *st) noexcept nogil:
    cdef int nbits = (63 - st.accum_nbits) & ~7
    if _fse_in_remaining(st) < 0:
        return -1
    if nbits:
        st.pos -= nbits >> 3
        st.accum = (st.accum << nbits) | (_fse_in_load(st) & ((<uint64_t>1 << nbits) - 1))
        st.accum_nbits += nbits
    return 0


cdef inline uint32_t _fse_in_pull(FseInState *st, int n) noexcept nogil:
    cdef uint32_t result
    st.accum_nbits -= n
    result = <uint32_t>(st.accum >> st.accum_nbits)
    st.accum &= (<uint64_t>1 << st.accum_nbits) - 1
    return result

# ---------------------------------------------------------------------------
# FSE table construction
# ---------------------------------------------------------------------------

cdef void _fse_init_decoder_table(
    int nstates,
    int nsymbols,
    const uint16_t *freq,
    uint32_t *table,
) noexcept nogil:
    """
    Build a literal FSE decoder table. Each entry is packed as:
    (bits) | (symbol << 8) | (delta << 16)
    """
    cdef int n_clz = _clz32(<uint32_t>nstates)
    cdef int idx = 0
    cdef int symbol, f, k, j0, j, bits
    cdef int32_t delta
    for symbol in range(nsymbols):
        f = freq[symbol]
        if f == 0:
            continue
        k = _clz32(<uint32_t>f) - n_clz
        j0 = ((2 * nstates) >> k) - f
        for j in range(f):
            if j < j0:
                bits = k
                delta = ((f + j) << k) - nstates
            else:
                bits = k - 1
                delta = (j - j0) << (k - 1)
            table[idx] = <uint32_t>bits | (<uint32_t>symbol << 8) | (<uint32_t>delta << 16)
            idx += 1


cdef void _fse_init_value_decoder_table(
    int nstates,
    int nsymbols,
    const uint16_t *freq,
    const uint8_t *symbol_vbits,
    const uint32_t *symbol_vbase,
    uint32_t *table,
) noexcept nogil:
    """
    Build a value FSE decoder table (for L, M, or D).
    Flat layout with stride 4: [total_bits, value_bits, delta, vbase].
    """
    cdef int n_clz = _clz32(<uint32_t>nstates)
    cdef int idx = 0
    cdef int symbol, f, k, j0, j, total, vbits
    cdef uint32_t vbase
    cdef int32_t delta
    for symbol in range(nsymbols):
        f = freq[symbol]
        if f == 0:
            continue
        k = _clz32(<uint32_t>f) - n_clz
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
            table[idx]     = <uint32_t>total
            table[idx + 1] = <uint32_t>vbits
            table[idx + 2] = <uint32_t>delta
            table[idx + 3] = vbase
            idx += VALUE_STRIDE

# ---------------------------------------------------------------------------
# V2 frequency table decoder
# ---------------------------------------------------------------------------

cdef int _decode_v2_freq_table(
    const uint8_t *buf,
    Py_ssize_t pos,
    Py_ssize_t end,
    uint16_t *freqs,
) noexcept nogil:
    """
    Decode the variable-length compressed frequency table of a V2 header, which must consume the
    bytes from pos to end. Writes TOTAL_FREQ_COUNT values to freqs. Returns 0 on success, -1 on
    error.
    """
    cdef uint32_t accum = 0
    cdef int accum_nbits = 0
    cdef int count, nbits
    cdef uint32_t lookup

    for count in range(TOTAL_FREQ_COUNT):
        while accum_nbits < 14 and pos < end:
            accum |= (<uint32_t>buf[pos]) << accum_nbits
            pos += 1
            accum_nbits += 8

        lookup = accum & 0x1F
        nbits = _FREQ_NBITS_TABLE[lookup]
        if nbits > accum_nbits:
            return -1
        if nbits == 8:
            freqs[count] = <uint16_t>(8 + ((accum >> 4) & 0xF))
        elif nbits == 14:
            freqs[count] = <uint16_t>(24 + ((accum >> 4) & 0x3FF))
        else:
            freqs[count] = <uint16_t>_FREQ_VALUE_TABLE[lookup]
        accum >>= nbits
        accum_nbits -= nbits

    if pos < end or accum_nbits >= 8:
        return -1
    return 0


cdef inline int _sum_freqs(const uint16_t *freqs, int count) noexcept nogil:
    cdef int total = 0
    cdef int i
    for i in range(count):
        total += freqs[i]
    return total

# ---------------------------------------------------------------------------
# LZFSE payload decoder (core FSE + LZ77 loop)
# ---------------------------------------------------------------------------

cdef Py_ssize_t _decode_lzfse_payload(
    const uint8_t *buf,
    Py_ssize_t payload,
    Py_ssize_t literal_payload_size,
    Py_ssize_t lmd_payload_size,
    Py_ssize_t raw_size,
    Py_ssize_t n_literals,
    Py_ssize_t n_matches,
    int literal_bits,
    int literal_state0,
    int literal_state1,
    int literal_state2,
    int literal_state3,
    int lmd_bits,
    int l_state,
    int m_state,
    int d_state,
    const uint16_t *freqs,
    uint8_t *literals,
    uint8_t *output,
    Py_ssize_t out_pos,
) noexcept nogil:
    """
    Decode the FSE-encoded literal and LMD payloads, apply LZ77.
    Returns the number of bytes written, or -1 on error.
    """
    cdef uint32_t lit_table[ENCODE_LITERAL_STATES]
    cdef uint32_t l_table[ENCODE_L_STATES * VALUE_STRIDE]
    cdef uint32_t m_table[ENCODE_M_STATES * VALUE_STRIDE]
    cdef uint32_t d_table[ENCODE_D_STATES * VALUE_STRIDE]
    cdef const uint16_t *l_freq = freqs
    cdef const uint16_t *m_freq = l_freq + ENCODE_L_SYMBOLS
    cdef const uint16_t *d_freq = m_freq + ENCODE_M_SYMBOLS
    cdef const uint16_t *literal_freq = d_freq + ENCODE_D_SYMBOLS

    if (
        _sum_freqs(l_freq, ENCODE_L_SYMBOLS) != ENCODE_L_STATES
        or _sum_freqs(m_freq, ENCODE_M_SYMBOLS) != ENCODE_M_STATES
        or _sum_freqs(d_freq, ENCODE_D_SYMBOLS) != ENCODE_D_STATES
        or _sum_freqs(literal_freq, ENCODE_LITERAL_SYMBOLS) != ENCODE_LITERAL_STATES
    ):
        return -1

    _fse_init_decoder_table(ENCODE_LITERAL_STATES, ENCODE_LITERAL_SYMBOLS, literal_freq, lit_table)
    _fse_init_value_decoder_table(ENCODE_L_STATES, ENCODE_L_SYMBOLS, l_freq, _L_EXTRA_BITS, _L_BASE_VALUE, l_table)
    _fse_init_value_decoder_table(ENCODE_M_STATES, ENCODE_M_SYMBOLS, m_freq, _M_EXTRA_BITS, _M_BASE_VALUE, m_table)
    _fse_init_value_decoder_table(ENCODE_D_STATES, ENCODE_D_SYMBOLS, d_freq, _D_EXTRA_BITS, _D_BASE_VALUE, d_table)

    # Decode literals
    cdef Py_ssize_t lmd_payload = payload + literal_payload_size
    cdef FseInState lit_stream
    if _fse_in_init(&lit_stream, buf, payload, lmd_payload, literal_bits) < 0:
        return -1

    cdef int s0 = literal_state0
    cdef int s1 = literal_state1
    cdef int s2 = literal_state2
    cdef int s3 = literal_state3
    cdef uint32_t entry
    cdef int k, sym
    cdef int32_t lit_delta
    cdef Py_ssize_t i = 0

    while i + 3 < n_literals:
        if _fse_in_flush(&lit_stream) < 0:
            return -1

        entry = lit_table[s0]
        k = entry & 0xFF
        sym = (entry >> 8) & 0xFF
        lit_delta = entry >> 16
        literals[i] = <uint8_t>sym
        s0 = lit_delta + <int>_fse_in_pull(&lit_stream, k)

        entry = lit_table[s1]
        k = entry & 0xFF
        sym = (entry >> 8) & 0xFF
        lit_delta = entry >> 16
        literals[i + 1] = <uint8_t>sym
        s1 = lit_delta + <int>_fse_in_pull(&lit_stream, k)

        entry = lit_table[s2]
        k = entry & 0xFF
        sym = (entry >> 8) & 0xFF
        lit_delta = entry >> 16
        literals[i + 2] = <uint8_t>sym
        s2 = lit_delta + <int>_fse_in_pull(&lit_stream, k)

        entry = lit_table[s3]
        k = entry & 0xFF
        sym = (entry >> 8) & 0xFF
        lit_delta = entry >> 16
        literals[i + 3] = <uint8_t>sym
        s3 = lit_delta + <int>_fse_in_pull(&lit_stream, k)

        i += 4

    if _fse_in_remaining(&lit_stream) != 0:
        return -1

    # LMD decode
    cdef FseInState lmd_stream
    if _fse_in_init(&lmd_stream, buf, lmd_payload, lmd_payload + lmd_payload_size, lmd_bits) < 0:
        return -1

    cdef int lit_pos = 0
    cdef int prev_d = -1
    cdef int l_value, m_value, d_value
    cdef int total_bits, value_bits
    cdef int32_t lmd_delta
    cdef uint32_t vbase, bits
    cdef Py_ssize_t written = 0
    cdef int vidx

    for i in range(n_matches):
        if _fse_in_flush(&lmd_stream) < 0:
            return -1

        # L
        vidx = l_state * VALUE_STRIDE
        total_bits = <int>l_table[vidx]
        value_bits = <int>l_table[vidx + 1]
        lmd_delta  = <int32_t>l_table[vidx + 2]
        vbase      = l_table[vidx + 3]
        bits = _fse_in_pull(&lmd_stream, total_bits)
        l_state = <int>lmd_delta + <int>(bits >> value_bits)
        if value_bits:
            l_value = <int>(vbase + (bits & ((<uint32_t>1 << value_bits) - 1)))
        else:
            l_value = <int>vbase

        # M
        vidx = m_state * VALUE_STRIDE
        total_bits = <int>m_table[vidx]
        value_bits = <int>m_table[vidx + 1]
        lmd_delta  = <int32_t>m_table[vidx + 2]
        vbase      = m_table[vidx + 3]
        bits = _fse_in_pull(&lmd_stream, total_bits)
        m_state = <int>lmd_delta + <int>(bits >> value_bits)
        if value_bits:
            m_value = <int>(vbase + (bits & ((<uint32_t>1 << value_bits) - 1)))
        else:
            m_value = <int>vbase

        # D
        vidx = d_state * VALUE_STRIDE
        total_bits = <int>d_table[vidx]
        value_bits = <int>d_table[vidx + 1]
        lmd_delta  = <int32_t>d_table[vidx + 2]
        vbase      = d_table[vidx + 3]
        bits = _fse_in_pull(&lmd_stream, total_bits)
        d_state = <int>lmd_delta + <int>(bits >> value_bits)
        if value_bits:
            d_value = <int>(vbase + (bits & ((<uint32_t>1 << value_bits) - 1)))
        else:
            d_value = <int>vbase

        if d_value == 0:
            d_value = prev_d
        else:
            prev_d = d_value

        if (
            l_value < 0
            or m_value < 0
            or lit_pos + l_value > n_literals
            or written + l_value + m_value > raw_size
        ):
            return -1
        if m_value > 0 and (d_value <= 0 or out_pos + written + l_value - d_value < 0):
            return -1

        # Copy literals
        if l_value > 0:
            memcpy(&output[out_pos + written], &literals[lit_pos], l_value)
            lit_pos += l_value
            written += l_value

        # Copy match
        if m_value > 0:
            _copy_match(&output[out_pos + written], d_value, m_value)
            written += m_value

    if (
        _fse_in_remaining(&lmd_stream) != 64
        or _read_le_u64(buf, lmd_payload) != 0
        or written != raw_size
    ):
        return -1
    return written


cdef Py_ssize_t _decode_lzfse_block(
    const uint8_t *buf,
    object header,
    uint8_t *literals,
    uint8_t *output,
    Py_ssize_t out_pos,
):
    """
    Decode an LZFSE V1 or V2 block. Returns the number of bytes written, or -1 on error.
    """
    cdef uint16_t freqs[TOTAL_FREQ_COUNT]
    cdef int i
    if header.kind is BlockKind.LZFSE_V2:
        if _decode_v2_freq_table(buf, header.freq_table, header.payload, freqs) < 0:
            return -1
    else:
        for i in range(TOTAL_FREQ_COUNT):
            freqs[i] = header.freqs[i]
    s0, s1, s2, s3 = header.literal_states
    return _decode_lzfse_payload(
        buf,
        header.payload,
        header.literal_payload_size,
        header.lmd_payload_size,
        header.raw_size,
        header.n_literals,
        header.n_matches,
        header.literal_bits,
        s0,
        s1,
        s2,
        s3,
        header.lmd_bits,
        header.l_state,
        header.m_state,
        header.d_state,
        freqs,
        literals,
        output,
        out_pos,
    )

# ---------------------------------------------------------------------------
# LZVN decoder
# ---------------------------------------------------------------------------

cdef Py_ssize_t _lzvn_decode(
    const uint8_t *src,
    Py_ssize_t src_pos,
    Py_ssize_t src_end,
    Py_ssize_t n_raw_bytes,
    uint8_t *output,
    Py_ssize_t out_pos,
) noexcept nogil:
    """
    Decode the LZVN payload of a block up to its end-of-stream instruction. Returns the number of
    bytes written, which is `n_raw_bytes`, or -1 if the payload is corrupt.
    """
    cdef Py_ssize_t written = 0
    cdef Py_ssize_t L, M, D = 0
    cdef uint8_t opc
    cdef int kind

    while True:
        if src_pos >= src_end:
            return -1
        opc = src[src_pos]
        kind = _LZVN_OPC_TABLE[opc]
        if kind == LZVN_EOS:
            break
        if kind == LZVN_NOP:
            src_pos += 1
            continue
        if kind == LZVN_UDEF or src_pos + _LZVN_INSTRUCTION_SIZE[kind] > src_end:
            return -1
        L = opc >> 6
        M = ((opc >> 3) & 7) + 3
        if kind == LZVN_SML_D:
            D = ((opc & 7) << 8) | src[src_pos + 1]
        elif kind == LZVN_MED_D:
            L = (opc >> 3) & 3
            M = (((opc & 7) << 2) | (src[src_pos + 1] & 3)) + 3
            D = (src[src_pos + 1] >> 2) | (src[src_pos + 2] << 6)
        elif kind == LZVN_LRG_D:
            D = src[src_pos + 1] | (src[src_pos + 2] << 8)
        elif kind == LZVN_SML_L:
            L = opc & 0x0F
            M = 0
        elif kind == LZVN_LRG_L:
            L = src[src_pos + 1] + 16
            M = 0
        elif kind == LZVN_SML_M:
            L = 0
            M = opc & 0x0F
        elif kind == LZVN_LRG_M:
            L = 0
            M = src[src_pos + 1] + 16
        src_pos += _LZVN_INSTRUCTION_SIZE[kind]

        if written + L + M > n_raw_bytes:
            return -1
        if L:
            if src_pos + L > src_end:
                return -1
            memcpy(&output[out_pos + written], &src[src_pos], L)
            src_pos += L
            written += L
        if M:
            if not 0 < D <= out_pos + written:
                return -1
            _copy_match(&output[out_pos + written], D, M)
            written += M

    if written != n_raw_bytes:
        return -1
    return written

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def lzfse_decompress(data) -> bytearray:
    """
    Decompress an LZFSE stream, which ends with an end-of-stream block. Input that ends before that
    block, or that cannot be decoded after some output, raises a `RefineryPartialResult` with the
    output of the blocks decoded so far.
    """
    view = memoryview(data)
    cdef:
        const uint8_t[::1] src = view
        Py_ssize_t end = len(src)
        Py_ssize_t pos = 0
        Py_ssize_t payload, raw_size, written
        Py_ssize_t out_pos = 0
        Py_ssize_t out_cap = end * 4 if end > 64 else 256
        uint8_t *out_buf = <uint8_t *>malloc(out_cap)
        uint8_t *literals = <uint8_t *>malloc(LITERALS_PER_BLOCK)
        const uint8_t *buf_ptr = &src[0]

    try:
        if out_buf == NULL or literals == NULL:
            raise MemoryError
        while (header := read_block_header(view, pos)).kind is not BlockKind.END:
            kind = header.kind
            payload = header.payload
            raw_size = header.raw_size
            reserve(&out_buf, &out_cap, out_pos, raw_size)
            if kind is BlockKind.RAW:
                memcpy(&out_buf[out_pos], &buf_ptr[payload], raw_size)
                written = raw_size
            elif kind is BlockKind.LZVN:
                written = _lzvn_decode(buf_ptr, payload, header.end, raw_size, out_buf, out_pos)
            else:
                written = _decode_lzfse_block(buf_ptr, header, literals, out_buf, out_pos)
            if written < 0:
                raise ValueError(F'the LZFSE block at offset {pos} is corrupt')
            out_pos += written
            pos = header.end
        return bytearray(out_buf[:out_pos])
    except ValueError as error:
        if not out_pos:
            raise
        raise RefineryPartialResult(
            F'Decoding failed after {out_pos} bytes: {error!s}', bytearray(out_buf[:out_pos])) from error
    finally:
        free(out_buf)
        free(literals)
