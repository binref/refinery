# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True

from libc.stdint cimport uint8_t, uint32_t, uint64_t
from libc.string cimport memcpy, memset


cdef uint32_t _SHA256_K[64]
_SHA256_K[:] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


cdef inline uint32_t _rotr(uint32_t x, int n):
    return (x >> n) | (x << (32 - n))


cdef void _sha256_compress(const uint8_t* data, int length, uint8_t* out):
    cdef uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a
    cdef uint32_t h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19
    cdef uint32_t w[64]
    cdef uint8_t block[64]
    cdef int i, blk, remaining, blocks
    cdef uint64_t bitlen = <uint64_t>length * 8
    cdef uint32_t a, b, c, d, e, f, g, hh, t1, t2
    cdef const uint8_t* p

    blocks = length / 64
    for blk in range(blocks):
        p = data + blk * 64
        for i in range(16):
            w[i] = ((<uint32_t>p[i*4]) << 24) | ((<uint32_t>p[i*4+1]) << 16) | ((<uint32_t>p[i*4+2]) << 8) | <uint32_t>p[i*4+3]
        for i in range(16, 64):
            w[i] = (_rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ (w[i-2] >> 10)) + w[i-7] + (_rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ (w[i-15] >> 3)) + w[i-16]
        a = h0; b = h1; c = h2; d = h3
        e = h4; f = h5; g = h6; hh = h7
        for i in range(64):
            t1 = hh + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) + ((e & f) ^ (~e & g)) + _SHA256_K[i] + w[i]
            t2 = (_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))
            hh = g; g = f; f = e; e = d + t1
            d = c; c = b; b = a; a = t1 + t2
        h0 += a; h1 += b; h2 += c; h3 += d
        h4 += e; h5 += f; h6 += g; h7 += hh

    remaining = length - blocks * 64
    memset(block, 0, 64)
    if remaining > 0:
        memcpy(block, data + blocks * 64, remaining)
    block[remaining] = 0x80

    if remaining >= 56:
        for i in range(16):
            w[i] = ((<uint32_t>block[i*4]) << 24) | ((<uint32_t>block[i*4+1]) << 16) | ((<uint32_t>block[i*4+2]) << 8) | <uint32_t>block[i*4+3]
        for i in range(16, 64):
            w[i] = (_rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ (w[i-2] >> 10)) + w[i-7] + (_rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ (w[i-15] >> 3)) + w[i-16]
        a = h0; b = h1; c = h2; d = h3
        e = h4; f = h5; g = h6; hh = h7
        for i in range(64):
            t1 = hh + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) + ((e & f) ^ (~e & g)) + _SHA256_K[i] + w[i]
            t2 = (_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))
            hh = g; g = f; f = e; e = d + t1
            d = c; c = b; b = a; a = t1 + t2
        h0 += a; h1 += b; h2 += c; h3 += d
        h4 += e; h5 += f; h6 += g; h7 += hh
        memset(block, 0, 64)

    block[56] = <uint8_t>(bitlen >> 56)
    block[57] = <uint8_t>(bitlen >> 48)
    block[58] = <uint8_t>(bitlen >> 40)
    block[59] = <uint8_t>(bitlen >> 32)
    block[60] = <uint8_t>(bitlen >> 24)
    block[61] = <uint8_t>(bitlen >> 16)
    block[62] = <uint8_t>(bitlen >> 8)
    block[63] = <uint8_t>(bitlen)

    for i in range(16):
        w[i] = ((<uint32_t>block[i*4]) << 24) | ((<uint32_t>block[i*4+1]) << 16) | ((<uint32_t>block[i*4+2]) << 8) | <uint32_t>block[i*4+3]
    for i in range(16, 64):
        w[i] = (_rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ (w[i-2] >> 10)) + w[i-7] + (_rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ (w[i-15] >> 3)) + w[i-16]
    a = h0; b = h1; c = h2; d = h3
    e = h4; f = h5; g = h6; hh = h7
    for i in range(64):
        t1 = hh + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) + ((e & f) ^ (~e & g)) + _SHA256_K[i] + w[i]
        t2 = (_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))
        hh = g; g = f; f = e; e = d + t1
        d = c; c = b; b = a; a = t1 + t2
    h0 += a; h1 += b; h2 += c; h3 += d
    h4 += e; h5 += f; h6 += g; h7 += hh

    out[0] = <uint8_t>(h0 >> 24); out[1] = <uint8_t>(h0 >> 16); out[2] = <uint8_t>(h0 >> 8); out[3] = <uint8_t>h0
    out[4] = <uint8_t>(h1 >> 24); out[5] = <uint8_t>(h1 >> 16); out[6] = <uint8_t>(h1 >> 8); out[7] = <uint8_t>h1
    out[8] = <uint8_t>(h2 >> 24); out[9] = <uint8_t>(h2 >> 16); out[10] = <uint8_t>(h2 >> 8); out[11] = <uint8_t>h2
    out[12] = <uint8_t>(h3 >> 24); out[13] = <uint8_t>(h3 >> 16); out[14] = <uint8_t>(h3 >> 8); out[15] = <uint8_t>h3
    out[16] = <uint8_t>(h4 >> 24); out[17] = <uint8_t>(h4 >> 16); out[18] = <uint8_t>(h4 >> 8); out[19] = <uint8_t>h4
    out[20] = <uint8_t>(h5 >> 24); out[21] = <uint8_t>(h5 >> 16); out[22] = <uint8_t>(h5 >> 8); out[23] = <uint8_t>h5
    out[24] = <uint8_t>(h6 >> 24); out[25] = <uint8_t>(h6 >> 16); out[26] = <uint8_t>(h6 >> 8); out[27] = <uint8_t>h6
    out[28] = <uint8_t>(h7 >> 24); out[29] = <uint8_t>(h7 >> 16); out[30] = <uint8_t>(h7 >> 8); out[31] = <uint8_t>h7


cdef struct PRNGState:
    uint8_t seeded[32]
    uint64_t counter
    uint8_t buf[32]
    int offset


cdef void prng_init(PRNGState* state, const uint8_t* key):
    memcpy(state.seeded, key, 32)
    state.counter = 0
    state.offset = 32


cdef void prng_refill(PRNGState* state):
    cdef uint8_t msg[40]
    cdef uint64_t c = state.counter
    memcpy(msg, state.seeded, 32)
    msg[32] = <uint8_t>((c >> 56) & 0xFF)
    msg[33] = <uint8_t>((c >> 48) & 0xFF)
    msg[34] = <uint8_t>((c >> 40) & 0xFF)
    msg[35] = <uint8_t>((c >> 32) & 0xFF)
    msg[36] = <uint8_t>((c >> 24) & 0xFF)
    msg[37] = <uint8_t>((c >> 16) & 0xFF)
    msg[38] = <uint8_t>((c >> 8) & 0xFF)
    msg[39] = <uint8_t>(c & 0xFF)
    _sha256_compress(msg, 40, state.buf)
    state.counter += 1
    state.offset = 0


cdef uint32_t prng_next_u32(PRNGState* state):
    cdef int offset = state.offset
    cdef uint32_t result
    if offset + 4 > 32:
        if state.offset >= 32:
            prng_refill(state)
        result = (<uint32_t>state.buf[state.offset]) << 24
        state.offset += 1
        if state.offset >= 32:
            prng_refill(state)
        result |= (<uint32_t>state.buf[state.offset]) << 16
        state.offset += 1
        if state.offset >= 32:
            prng_refill(state)
        result |= (<uint32_t>state.buf[state.offset]) << 8
        state.offset += 1
        if state.offset >= 32:
            prng_refill(state)
        result |= <uint32_t>state.buf[state.offset]
        state.offset += 1
        return result
    state.offset = offset + 4
    return ((<uint32_t>state.buf[offset]) << 24
            | (<uint32_t>state.buf[offset + 1]) << 16
            | (<uint32_t>state.buf[offset + 2]) << 8
            | <uint32_t>state.buf[offset + 3])


cdef void _generate_inverse_permutation(PRNGState* prng, uint8_t* inv):
    cdef uint8_t table[256]
    cdef int n, j
    cdef uint32_t rand, threshold
    cdef uint8_t tmp

    for n in range(256):
        table[n] = <uint8_t>n

    for n in range(255, 0, -1):
        threshold = 0xFFFFFFFF - (0xFFFFFFFF % (<uint32_t>(n + 1)))
        while True:
            rand = prng_next_u32(prng)
            if rand <= threshold:
                break
        j = <int>(rand % (<uint32_t>(n + 1)))
        tmp = table[n]
        table[n] = table[j]
        table[j] = tmp

    for n in range(256):
        inv[table[n]] = <uint8_t>n


cdef int _int_to_str(int value, char* buf):
    cdef int len_val = 0
    cdef char tmp[12]
    cdef int i

    if value == 0:
        buf[0] = <char>48
        return 1

    while value > 0:
        tmp[len_val] = <char>(48 + (value % 10))
        value = value // 10
        len_val += 1

    for i in range(len_val):
        buf[i] = tmp[len_val - 1 - i]

    return len_val


cdef void _compute_byte_seed(
    const uint8_t* key, int key_len, int round_idx, int byte_index, uint8_t* out_seed
):
    cdef uint8_t msg[128]
    cdef char idx_str[12]
    cdef int idx_len
    cdef int total_len

    memcpy(msg, key, key_len)
    msg[key_len] = <uint8_t>round_idx
    idx_len = _int_to_str(byte_index, idx_str)
    memcpy(&msg[key_len + 1], idx_str, idx_len)
    total_len = key_len + 1 + idx_len
    _sha256_compress(msg, total_len, out_seed)


def decrypt_round(data, key, int round_idx):
    cdef int data_len = len(data)
    cdef const uint8_t[::1] data_view = bytes(data)
    cdef bytearray result = bytearray(data_len)
    cdef uint8_t[::1] result_view = result
    cdef uint8_t inv[256]
    cdef uint8_t prev = 0
    cdef uint8_t current
    cdef int i
    cdef PRNGState prng
    cdef uint8_t byte_seed[32]

    cdef bytes key_bytes = bytes(key)
    cdef const uint8_t[::1] key_view = key_bytes
    cdef int key_len = len(key_bytes)

    if round_idx < 0 or round_idx > 0xFF:
        raise OverflowError('%c arg not in range(256)')

    for i in range(data_len):
        _compute_byte_seed(&key_view[0], key_len, round_idx, i, byte_seed)
        prng_init(&prng, byte_seed)
        _generate_inverse_permutation(&prng, inv)
        current = data_view[i]
        result_view[i] = inv[current] ^ prev
        prev = current

    return bytes(result)
