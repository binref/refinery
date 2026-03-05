# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
cimport cython

from libc.stdint cimport int8_t, int32_t, uint8_t, uint16_t, uint32_t, uint64_t
from libc.stdlib cimport free, malloc, realloc
from libc.string cimport memcpy

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

cdef uint32_t _LZFSE_V1_MAGIC = 0x31787662
cdef uint32_t _LZFSE_V2_MAGIC = 0x32787662
cdef uint32_t _LZVN_MAGIC     = 0x6E787662
cdef uint32_t _UNCOMPRESSED_MAGIC = 0x2D787662
cdef uint32_t _ENDOFSTREAM_MAGIC  = 0x24787662

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
    int buf_start       # lower bound (offset) for the buffer pointer
    int buf_pos
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


cdef inline uint64_t _read_le_u64_safe(const uint8_t *buf, int pos, int buf_len) noexcept nogil:
    cdef uint64_t result = 0
    cdef int avail, i
    if pos + 8 <= buf_len:
        memcpy(&result, &buf[pos], 8)
        return result
    avail = buf_len - pos
    if avail <= 0:
        return 0
    for i in range(avail):
        result |= (<uint64_t>buf[pos + i]) << (8 * i)
    return result


cdef inline uint32_t _read_le_u32(const uint8_t *buf, int pos) noexcept nogil:
    cdef uint32_t result
    memcpy(&result, &buf[pos], 4)
    return result


cdef inline uint16_t _read_le_u16(const uint8_t *buf, int pos) noexcept nogil:
    cdef uint16_t result
    memcpy(&result, &buf[pos], 2)
    return result


cdef inline uint64_t _read_le_u64(const uint8_t *buf, int pos) noexcept nogil:
    cdef uint64_t result
    memcpy(&result, &buf[pos], 8)
    return result

# ---------------------------------------------------------------------------
# FSE bit-stream operations
# ---------------------------------------------------------------------------

cdef inline FseInState _fse_in_init(const uint8_t *buf, int offset, int nbytes, int nbits, int buf_len) noexcept nogil:
    cdef FseInState st
    st.buf = buf
    st.buf_start = offset
    st.buf_pos = offset + nbytes
    if nbits:
        st.buf_pos -= 8
        st.accum = _read_le_u64_safe(buf, st.buf_pos, buf_len)
        st.accum_nbits = nbits + 64
    else:
        st.buf_pos -= 7
        st.accum = _read_le_u64_safe(buf, st.buf_pos, buf_len) & <uint64_t>0xFFFFFFFFFFFFFF
        st.accum_nbits = 56
    return st


cdef inline void _fse_in_flush(FseInState *st, int buf_len) noexcept nogil:
    cdef int nbits, nbytes
    cdef uint64_t incoming
    nbits = (63 - st.accum_nbits) & ~7
    if nbits <= 0:
        return
    nbytes = nbits >> 3
    if st.buf_pos - nbytes < st.buf_start:
        return
    st.buf_pos -= nbytes
    incoming = _read_le_u64_safe(st.buf, st.buf_pos, buf_len)
    st.accum = (st.accum << nbits) | (incoming & ((<uint64_t>1 << nbits) - 1))
    st.accum_nbits += nbits


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
    int buf_len,
    int offset,
    int header_size,
    uint16_t *freqs,
) noexcept nogil:
    """
    Decode the variable-length compressed frequency table from a V2 header.
    Writes TOTAL_FREQ_COUNT values to freqs. Returns 0 on success, -1 on error.
    """
    cdef uint32_t accum = 0
    cdef int accum_nbits = 0
    cdef int src_pos = offset
    cdef int count = 0
    cdef uint32_t lookup
    cdef int nbits, value

    while count < TOTAL_FREQ_COUNT:
        while accum_nbits < 14:
            if src_pos < buf_len:
                accum |= (<uint32_t>buf[src_pos]) << accum_nbits
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
            freqs[count] = <uint16_t>value
            count += 1
        elif nbits == 8:
            accum >>= 4
            accum_nbits -= 4
            value = 8 + (accum & 0xF)
            accum >>= 4
            accum_nbits -= 4
            freqs[count] = <uint16_t>value
            count += 1
        elif nbits == 14:
            accum >>= 4
            accum_nbits -= 4
            value = 24 + (accum & 0x3FF)
            accum >>= 10
            accum_nbits -= 10
            freqs[count] = <uint16_t>value
            count += 1
        else:
            return -1

    return 0

# ---------------------------------------------------------------------------
# LZFSE payload decoder (core FSE + LZ77 loop)
# ---------------------------------------------------------------------------

cdef int _decode_lzfse_payload(
    const uint8_t *buf,
    int buf_len,
    int payload_offset,
    int n_raw_bytes,
    int n_literals,
    int n_matches,
    int n_literal_payload_bytes,
    int n_lmd_payload_bytes,
    int literal_bits,
    int literal_state0,
    int literal_state1,
    int literal_state2,
    int literal_state3,
    int lmd_bits,
    int l_state,
    int m_state,
    int d_state,
    const uint16_t *l_freq,
    const uint16_t *m_freq,
    const uint16_t *d_freq,
    const uint16_t *literal_freq,
    uint8_t *output,
    int out_pos,
    int out_cap,
) noexcept nogil:
    """
    Decode the FSE-encoded literal and LMD payloads, apply LZ77.
    Returns the number of bytes written, or -1 on error.
    """
    cdef uint32_t lit_table[ENCODE_LITERAL_STATES]
    cdef uint32_t l_table[ENCODE_L_STATES * VALUE_STRIDE]
    cdef uint32_t m_table[ENCODE_M_STATES * VALUE_STRIDE]
    cdef uint32_t d_table[ENCODE_D_STATES * VALUE_STRIDE]

    _fse_init_decoder_table(ENCODE_LITERAL_STATES, ENCODE_LITERAL_SYMBOLS, literal_freq, lit_table)
    _fse_init_value_decoder_table(ENCODE_L_STATES, ENCODE_L_SYMBOLS, l_freq, _L_EXTRA_BITS, _L_BASE_VALUE, l_table)
    _fse_init_value_decoder_table(ENCODE_M_STATES, ENCODE_M_SYMBOLS, m_freq, _M_EXTRA_BITS, _M_BASE_VALUE, m_table)
    _fse_init_value_decoder_table(ENCODE_D_STATES, ENCODE_D_SYMBOLS, d_freq, _D_EXTRA_BITS, _D_BASE_VALUE, d_table)

    # Decode literals
    cdef FseInState lit_stream = _fse_in_init(buf, payload_offset, n_literal_payload_bytes, literal_bits, buf_len)
    cdef uint8_t *literals = <uint8_t *>malloc(n_literals + 4)
    if literals == NULL:
        return -1

    cdef int s0 = literal_state0
    cdef int s1 = literal_state1
    cdef int s2 = literal_state2
    cdef int s3 = literal_state3
    cdef uint32_t entry
    cdef int k, sym
    cdef int32_t lit_delta
    cdef int i = 0

    while i + 3 < n_literals:
        _fse_in_flush(&lit_stream, buf_len)

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

    # LMD decode
    cdef int lmd_offset = payload_offset + n_literal_payload_bytes
    cdef FseInState lmd_stream = _fse_in_init(buf, lmd_offset, n_lmd_payload_bytes, lmd_bits, buf_len)

    cdef int lit_pos = 0
    cdef int prev_d = -1
    cdef int l_value, m_value, d_value
    cdef int total_bits, value_bits
    cdef int32_t lmd_delta
    cdef uint32_t vbase, bits
    cdef int match_start, j, written = 0
    cdef int vidx

    for i in range(n_matches):
        _fse_in_flush(&lmd_stream, buf_len)

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

        # Copy literals
        if l_value > 0:
            memcpy(&output[out_pos + written], &literals[lit_pos], l_value)
            lit_pos += l_value
            written += l_value

        # Copy match
        if m_value > 0:
            match_start = out_pos + written - d_value
            if d_value >= m_value:
                memcpy(&output[out_pos + written], &output[match_start], m_value)
            else:
                for j in range(m_value):
                    output[out_pos + written + j] = output[match_start + j]
            written += m_value

    # Remaining literals
    if lit_pos < n_literals:
        memcpy(&output[out_pos + written], &literals[lit_pos], n_literals - lit_pos)
        written += n_literals - lit_pos

    free(literals)
    return written

# ---------------------------------------------------------------------------
# LZFSE V2 block decoder
# ---------------------------------------------------------------------------

cdef int _decode_lzfse_v2_block(
    const uint8_t *buf,
    int buf_len,
    int pos,
    uint8_t *output,
    int out_pos,
    int out_cap,
    int *new_pos,
) noexcept nogil:
    """
    Decode a V2 LZFSE block. Returns bytes written, or -1 on error.
    Sets *new_pos to the next position in buf.
    """
    cdef int block_start = pos
    pos += 4  # skip magic

    cdef uint32_t n_raw_bytes = _read_le_u32(buf, pos)
    pos += 4

    cdef uint64_t pf0 = _read_le_u64(buf, pos)
    cdef uint64_t pf1 = _read_le_u64(buf, pos + 8)
    cdef uint64_t pf2 = _read_le_u64(buf, pos + 16)
    pos += 24

    cdef int n_literals                = <int>(pf0 & <uint64_t>0xFFFFF)
    cdef int n_literal_payload_bytes   = <int>((pf0 >> 20) & <uint64_t>0xFFFFF)
    cdef int n_matches                 = <int>((pf0 >> 40) & <uint64_t>0xFFFFF)
    cdef int literal_bits              = <int>(((pf0 >> 60) & <uint64_t>0x7)) - 7

    cdef int literal_state0            = <int>(pf1 & <uint64_t>0x3FF)
    cdef int literal_state1            = <int>((pf1 >> 10) & <uint64_t>0x3FF)
    cdef int literal_state2            = <int>((pf1 >> 20) & <uint64_t>0x3FF)
    cdef int literal_state3            = <int>((pf1 >> 30) & <uint64_t>0x3FF)
    cdef int n_lmd_payload_bytes       = <int>((pf1 >> 40) & <uint64_t>0xFFFFF)
    cdef int lmd_bits                  = <int>(((pf1 >> 60) & <uint64_t>0x7)) - 7

    cdef uint32_t header_size          = <uint32_t>(pf2 & <uint64_t>0xFFFFFFFF)
    cdef int l_state                   = <int>((pf2 >> 32) & <uint64_t>0x3FF)
    cdef int m_state                   = <int>((pf2 >> 42) & <uint64_t>0x3FF)
    cdef int d_state                   = <int>((pf2 >> 52) & <uint64_t>0x3FF)

    cdef int n_payload_bytes = n_literal_payload_bytes + n_lmd_payload_bytes

    # Decode frequency table
    cdef uint16_t freqs[TOTAL_FREQ_COUNT]
    if _decode_v2_freq_table(buf, buf_len, pos, header_size, freqs) < 0:
        return -1

    cdef int payload_offset = block_start + <int>header_size
    cdef int written

    written = _decode_lzfse_payload(
        buf, buf_len, payload_offset,
        <int>n_raw_bytes, n_literals, n_matches,
        n_literal_payload_bytes, n_lmd_payload_bytes,
        literal_bits,
        literal_state0, literal_state1, literal_state2, literal_state3,
        lmd_bits, l_state, m_state, d_state,
        &freqs[0],
        &freqs[ENCODE_L_SYMBOLS],
        &freqs[ENCODE_L_SYMBOLS + ENCODE_M_SYMBOLS],
        &freqs[ENCODE_L_SYMBOLS + ENCODE_M_SYMBOLS + ENCODE_D_SYMBOLS],
        output, out_pos, out_cap,
    )

    new_pos[0] = payload_offset + n_payload_bytes
    return written

# ---------------------------------------------------------------------------
# LZFSE V1 block decoder
# ---------------------------------------------------------------------------

cdef int _decode_lzfse_v1_block(
    const uint8_t *buf,
    int buf_len,
    int pos,
    uint8_t *output,
    int out_pos,
    int out_cap,
    int *new_pos,
) noexcept nogil:
    """
    Decode a V1 LZFSE block. Returns bytes written, or -1 on error.
    Sets *new_pos to the next position in buf.
    """
    pos += 4  # skip magic

    cdef uint32_t n_raw_bytes            = _read_le_u32(buf, pos)
    cdef uint32_t n_payload_bytes        = _read_le_u32(buf, pos + 4)
    cdef uint32_t n_literals_u           = _read_le_u32(buf, pos + 8)
    cdef uint32_t n_matches_u            = _read_le_u32(buf, pos + 12)
    cdef uint32_t n_literal_payload_u    = _read_le_u32(buf, pos + 16)
    cdef uint32_t n_lmd_payload_u        = _read_le_u32(buf, pos + 20)
    cdef int32_t literal_bits_s
    memcpy(&literal_bits_s, &buf[pos + 24], 4)
    pos += 28

    cdef int literal_state0 = <int>_read_le_u16(buf, pos)
    cdef int literal_state1 = <int>_read_le_u16(buf, pos + 2)
    cdef int literal_state2 = <int>_read_le_u16(buf, pos + 4)
    cdef int literal_state3 = <int>_read_le_u16(buf, pos + 6)
    pos += 8

    cdef int32_t lmd_bits_s
    memcpy(&lmd_bits_s, &buf[pos], 4)
    pos += 4

    cdef int l_state = <int>_read_le_u16(buf, pos)
    cdef int m_state = <int>_read_le_u16(buf, pos + 2)
    cdef int d_state = <int>_read_le_u16(buf, pos + 4)
    pos += 6

    # Read frequency tables (inline, each is an array of uint16)
    cdef uint16_t l_freq[ENCODE_L_SYMBOLS]
    cdef uint16_t m_freq[ENCODE_M_SYMBOLS]
    cdef uint16_t d_freq[ENCODE_D_SYMBOLS]
    cdef uint16_t literal_freq[ENCODE_LITERAL_SYMBOLS]

    memcpy(l_freq, &buf[pos], ENCODE_L_SYMBOLS * 2)
    pos += ENCODE_L_SYMBOLS * 2
    memcpy(m_freq, &buf[pos], ENCODE_M_SYMBOLS * 2)
    pos += ENCODE_M_SYMBOLS * 2
    memcpy(d_freq, &buf[pos], ENCODE_D_SYMBOLS * 2)
    pos += ENCODE_D_SYMBOLS * 2
    memcpy(literal_freq, &buf[pos], ENCODE_LITERAL_SYMBOLS * 2)
    pos += ENCODE_LITERAL_SYMBOLS * 2

    cdef int payload_offset = pos
    cdef int written

    written = _decode_lzfse_payload(
        buf, buf_len, payload_offset,
        <int>n_raw_bytes, <int>n_literals_u, <int>n_matches_u,
        <int>n_literal_payload_u, <int>n_lmd_payload_u,
        <int>literal_bits_s,
        literal_state0, literal_state1, literal_state2, literal_state3,
        <int>lmd_bits_s, l_state, m_state, d_state,
        l_freq, m_freq, d_freq, literal_freq,
        output, out_pos, out_cap,
    )

    new_pos[0] = payload_offset + <int>n_payload_bytes
    return written

# ---------------------------------------------------------------------------
# LZVN decoder
# ---------------------------------------------------------------------------

cdef inline void _lzvn_copy_match(
    uint8_t *output, int out_pos, int D, int M,
) noexcept nogil:
    cdef int start = out_pos - D
    cdef int j
    if D >= M:
        memcpy(&output[out_pos], &output[start], M)
    else:
        for j in range(M):
            output[out_pos + j] = output[start + j]


cdef int _lzvn_decode(
    const uint8_t *src,
    int src_pos,
    int src_end,
    int n_raw_bytes,
    uint8_t *output,
    int out_pos,
) noexcept nogil:
    """
    Decode an LZVN byte stream. Returns number of bytes written.
    """
    cdef int written = 0
    cdef int d_prev = 0
    cdef uint8_t opc
    cdef int kind, L, M, D
    cdef uint16_t opc23

    while src_pos < src_end and written < n_raw_bytes:
        opc = src[src_pos]
        kind = _LZVN_OPC_TABLE[opc]

        if kind == LZVN_EOS:
            break
        elif kind == LZVN_NOP:
            src_pos += 1
            continue
        elif kind == LZVN_UDEF:
            break
        elif kind == LZVN_SML_L:
            L = opc & 0x0F
            src_pos += 1
            if src_pos + L > src_end:
                L = src_end - src_pos
            if written + L > n_raw_bytes:
                L = n_raw_bytes - written
            memcpy(&output[out_pos + written], &src[src_pos], L)
            written += L
            src_pos += L
            continue
        elif kind == LZVN_LRG_L:
            if src_pos + 1 >= src_end:
                break
            L = src[src_pos + 1] + 16
            src_pos += 2
            if src_pos + L > src_end:
                L = src_end - src_pos
            if written + L > n_raw_bytes:
                L = n_raw_bytes - written
            memcpy(&output[out_pos + written], &src[src_pos], L)
            written += L
            src_pos += L
            continue
        elif kind == LZVN_SML_M:
            M = opc & 0x0F
            src_pos += 1
            D = d_prev
            if D == 0:
                break
            if written + M > n_raw_bytes:
                M = n_raw_bytes - written
            _lzvn_copy_match(output, out_pos + written, D, M)
            written += M
        elif kind == LZVN_LRG_M:
            if src_pos + 1 >= src_end:
                break
            M = src[src_pos + 1] + 16
            src_pos += 2
            D = d_prev
            if D == 0:
                break
            if written + M > n_raw_bytes:
                M = n_raw_bytes - written
            _lzvn_copy_match(output, out_pos + written, D, M)
            written += M
        elif kind == LZVN_PRE_D:
            L = (opc >> 6) & 0x03
            M = ((opc >> 3) & 0x07) + 3
            src_pos += 1
            D = d_prev
            if D == 0:
                break
            if L > 0:
                if src_pos + L > src_end:
                    break
                if written + L > n_raw_bytes:
                    L = n_raw_bytes - written
                memcpy(&output[out_pos + written], &src[src_pos], L)
                written += L
                src_pos += L
            if written + M > n_raw_bytes:
                M = n_raw_bytes - written
            _lzvn_copy_match(output, out_pos + written, D, M)
            written += M
        elif kind == LZVN_LRG_D:
            if src_pos + 2 >= src_end:
                break
            L = (opc >> 6) & 0x03
            M = ((opc >> 3) & 0x07) + 3
            D = <int>_read_le_u16(src, src_pos + 1)
            src_pos += 3
            if D == 0:
                break
            d_prev = D
            if L > 0:
                if src_pos + L > src_end:
                    break
                if written + L > n_raw_bytes:
                    L = n_raw_bytes - written
                memcpy(&output[out_pos + written], &src[src_pos], L)
                written += L
                src_pos += L
            if written + M > n_raw_bytes:
                M = n_raw_bytes - written
            _lzvn_copy_match(output, out_pos + written, D, M)
            written += M
        elif kind == LZVN_MED_D:
            if src_pos + 2 >= src_end:
                break
            L = (opc >> 3) & 0x03
            opc23 = _read_le_u16(src, src_pos + 1)
            M = ((opc & 0x07) << 2 | (opc23 & 0x03)) + 3
            D = opc23 >> 2
            src_pos += 3
            if D == 0:
                break
            d_prev = D
            if L > 0:
                if src_pos + L > src_end:
                    break
                if written + L > n_raw_bytes:
                    L = n_raw_bytes - written
                memcpy(&output[out_pos + written], &src[src_pos], L)
                written += L
                src_pos += L
            if written + M > n_raw_bytes:
                M = n_raw_bytes - written
            _lzvn_copy_match(output, out_pos + written, D, M)
            written += M
        elif kind == LZVN_SML_D:
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
                if written + L > n_raw_bytes:
                    L = n_raw_bytes - written
                memcpy(&output[out_pos + written], &src[src_pos], L)
                written += L
                src_pos += L
            if written + M > n_raw_bytes:
                M = n_raw_bytes - written
            _lzvn_copy_match(output, out_pos + written, D, M)
            written += M

    return written


cdef int _decode_lzvn_block(
    const uint8_t *buf,
    int buf_len,
    int pos,
    uint8_t *output,
    int out_pos,
    int out_cap,
    int *new_pos,
) noexcept nogil:
    """
    Decode an LZVN compressed block. Returns bytes written.
    """
    pos += 4  # skip magic
    cdef uint32_t n_raw_bytes = _read_le_u32(buf, pos)
    pos += 4
    cdef uint32_t n_payload_bytes = _read_le_u32(buf, pos)
    pos += 4

    cdef int payload_start = pos
    cdef int payload_end = pos + <int>n_payload_bytes
    cdef int written = _lzvn_decode(buf, payload_start, payload_end, <int>n_raw_bytes, output, out_pos)

    new_pos[0] = payload_end
    return written

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def lzfse_decompress(data) -> bytes:
    """
    Decompress an LZFSE compressed stream. Returns the decompressed data as bytes.
    """
    cdef:
        const uint8_t[::1] src = memoryview(data)
        int end = len(data)
        int pos = 0
        uint32_t magic
        uint32_t n_raw_bytes
        int out_pos = 0
        int out_cap = end * 4 if end > 64 else 256
        uint8_t *out_buf
        int new_pos, written
        const uint8_t *buf_ptr = &src[0]

    if out_cap < 256:
        out_cap = 256

    out_buf = <uint8_t *>malloc(out_cap)
    if out_buf == NULL:
        raise MemoryError

    try:
        while pos + 4 <= end:
            magic = _read_le_u32(buf_ptr, pos)

            if magic == _ENDOFSTREAM_MAGIC:
                pos += 4
                break
            elif magic == _UNCOMPRESSED_MAGIC:
                pos += 4
                n_raw_bytes = _read_le_u32(buf_ptr, pos)
                pos += 4
                # Ensure capacity
                while out_pos + <int>n_raw_bytes > out_cap:
                    out_cap = out_cap * 2
                    out_buf = <uint8_t *>realloc(out_buf, out_cap)
                    if out_buf == NULL:
                        raise MemoryError
                memcpy(&out_buf[out_pos], &buf_ptr[pos], n_raw_bytes)
                out_pos += <int>n_raw_bytes
                pos += <int>n_raw_bytes
            elif magic == _LZFSE_V1_MAGIC or magic == _LZFSE_V2_MAGIC:
                # Read n_raw_bytes from byte 4 of the block header
                n_raw_bytes = _read_le_u32(buf_ptr, pos + 4)
                # Ensure capacity
                while out_pos + <int>n_raw_bytes > out_cap:
                    out_cap = out_cap * 2
                    out_buf = <uint8_t *>realloc(out_buf, out_cap)
                    if out_buf == NULL:
                        raise MemoryError
                if magic == _LZFSE_V2_MAGIC:
                    written = _decode_lzfse_v2_block(
                        buf_ptr, end, pos, out_buf, out_pos, out_cap, &new_pos)
                else:
                    written = _decode_lzfse_v1_block(
                        buf_ptr, end, pos, out_buf, out_pos, out_cap, &new_pos)
                if written < 0:
                    raise ValueError('LZFSE block decoding failed')
                out_pos += written
                pos = new_pos
            elif magic == _LZVN_MAGIC:
                # Read n_raw_bytes from byte 4 of the block header
                n_raw_bytes = _read_le_u32(buf_ptr, pos + 4)
                # Ensure capacity
                while out_pos + <int>n_raw_bytes > out_cap:
                    out_cap = out_cap * 2
                    out_buf = <uint8_t *>realloc(out_buf, out_cap)
                    if out_buf == NULL:
                        raise MemoryError
                written = _decode_lzvn_block(
                    buf_ptr, end, pos, out_buf, out_pos, out_cap, &new_pos)
                out_pos += written
                pos = new_pos
            else:
                raise ValueError(f'unknown LZFSE block magic: 0x{magic:08X}')

        return bytes(out_buf[:out_pos])
    finally:
        free(out_buf)
