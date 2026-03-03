# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
cimport cython

from libc.stdint cimport uint8_t, uint32_t, uint64_t
from libc.stdlib cimport free, malloc
from libc.string cimport memcpy, memset

import hashlib
import struct

ARGON2D = 0
ARGON2I = 1
ARGON2ID = 2

DEF QWORDS_PER_BLOCK = 128
DEF BLOCK_BYTES = 1024
DEF SYNC_POINTS = 4


def _blake2b_long(data, int digest_size):
    """
    Variable-length hash H' as defined in RFC 9106 Section 3.1. Uses hashlib.blake2b (stdlib) and
    chains 64-byte digests for outputs longer than 64 bytes.
    """
    if digest_size <= 64:
        return hashlib.blake2b(
            struct.pack('<I', digest_size) + bytes(data),
            digest_size=digest_size,
        ).digest()

    result = bytearray()
    vi = hashlib.blake2b(
        struct.pack('<I', digest_size) + bytes(data),
        digest_size=64,
    ).digest()
    result.extend(vi[:32])

    todo = digest_size - 32
    while todo > 64:
        vi = hashlib.blake2b(vi, digest_size=64).digest()
        result.extend(vi[:32])
        todo -= 32

    vi = hashlib.blake2b(vi, digest_size=todo).digest()
    result.extend(vi)

    return bytes(result[:digest_size])


def _initial_hash(
    int parallelism,
    int tag_length,
    int memory_cost,
    int time_cost,
    int version,
    int variant,
    password,
    salt,
    secret,
    associated_data,
):
    """
    Compute 64-byte initial hash H0 from all input parameters as described in RFC 9106 Section 3.2.
    """
    pack = struct.pack
    h = hashlib.blake2b(digest_size=64)
    h.update(pack('<I', parallelism))
    h.update(pack('<I', tag_length))
    h.update(pack('<I', memory_cost))
    h.update(pack('<I', time_cost))
    h.update(pack('<I', version))
    h.update(pack('<I', variant))
    h.update(pack('<I', len(password)))
    h.update(bytes(password))
    h.update(pack('<I', len(salt)))
    h.update(bytes(salt))
    h.update(pack('<I', len(secret)))
    h.update(bytes(secret))
    h.update(pack('<I', len(associated_data)))
    h.update(bytes(associated_data))
    return h.digest()


cdef inline void _gb(uint64_t *v, int a, int b, int c, int d) noexcept nogil:
    cdef uint64_t va, vb, vc, vd, lo_a, lo_b
    va = v[a]
    vb = v[b]
    vc = v[c]
    vd = v[d]

    lo_a = <uint32_t>va
    lo_b = <uint32_t>vb
    va = va + vb + (lo_a * lo_b << 1)
    vd = vd ^ va
    vd = (vd >> 32) | (vd << 32)
    lo_a = <uint32_t>vc
    lo_b = <uint32_t>vd
    vc = vc + vd + (lo_a * lo_b << 1)
    vb = vb ^ vc
    vb = (vb >> 24) | (vb << 40)

    lo_a = <uint32_t>va
    lo_b = <uint32_t>vb
    va = va + vb + (lo_a * lo_b << 1)
    vd = vd ^ va
    vd = (vd >> 16) | (vd << 48)
    lo_a = <uint32_t>vc
    lo_b = <uint32_t>vd
    vc = vc + vd + (lo_a * lo_b << 1)
    vb = vb ^ vc
    vb = (vb >> 63) | (vb << 1)

    v[a] = va
    v[b] = vb
    v[c] = vc
    v[d] = vd


cdef inline void _P(
    uint64_t *v,
    int i0, int i1, int i2, int i3,
    int i4, int i5, int i6, int i7,
    int i8, int i9, int iA, int iB,
    int iC, int iD, int iE, int iF,
) noexcept nogil:
    _gb(v, i0, i4, i8, iC)
    _gb(v, i1, i5, i9, iD)
    _gb(v, i2, i6, iA, iE)
    _gb(v, i3, i7, iB, iF)
    _gb(v, i0, i5, iA, iF)
    _gb(v, i1, i6, iB, iC)
    _gb(v, i2, i7, i8, iD)
    _gb(v, i3, i4, i9, iE)


cdef void _xor_blocks(uint64_t *dst, uint64_t *a, uint64_t *b) noexcept nogil:
    cdef int i
    for i in range(QWORDS_PER_BLOCK):
        dst[i] = a[i] ^ b[i]


cdef void _compress(uint64_t *out, uint64_t *x, uint64_t *y) noexcept nogil:
    cdef:
        uint64_t r[QWORDS_PER_BLOCK]
        uint64_t q[QWORDS_PER_BLOCK]
        uint64_t z[QWORDS_PER_BLOCK]
        int i, base, col

    _xor_blocks(r, x, y)
    memcpy(q, r, BLOCK_BYTES)

    for i in range(8):
        base = i * 16
        _P(q,
            base + 0, base + 1, base + 2, base + 3,
            base + 4, base + 5, base + 6, base + 7,
            base + 8, base + 9, base + 10, base + 11,
            base + 12, base + 13, base + 14, base + 15,
        )

    memcpy(z, q, BLOCK_BYTES)

    for col in range(8):
        base = col * 2
        _P(z,
            base + 0, base + 1, base + 16, base + 17,
            base + 32, base + 33, base + 48, base + 49,
            base + 64, base + 65, base + 80, base + 81,
            base + 96, base + 97, base + 112, base + 113,
        )

    _xor_blocks(out, r, z)


cdef void _generate_addresses_i(
    uint64_t *pseudo_rands,
    int pass_number,
    int lane,
    int slice_number,
    int m_prime,
    int total_passes,
    int variant,
    int segment_length,
) noexcept nogil:
    """
    Pre-generate (J1, J2) pairs for Argon2i-style independent indexing. Each uint64 in pseudo_rands
    stores J1 in the low 32 bits and J2 in the high 32 bits. Buffer must have room for at least
    segment_length entries.
    """
    cdef:
        uint64_t zero_block[QWORDS_PER_BLOCK]
        uint64_t input_block[QWORDS_PER_BLOCK]
        uint64_t tmp_block[QWORDS_PER_BLOCK]
        uint64_t addr_block[QWORDS_PER_BLOCK]
        int counter = 0
        int count = 0
        int k

    memset(zero_block, 0, BLOCK_BYTES)

    while count < segment_length:
        counter += 1
        memset(input_block, 0, BLOCK_BYTES)
        input_block[0] = <uint64_t>pass_number
        input_block[1] = <uint64_t>lane
        input_block[2] = <uint64_t>slice_number
        input_block[3] = <uint64_t>m_prime
        input_block[4] = <uint64_t>total_passes
        input_block[5] = <uint64_t>variant
        input_block[6] = <uint64_t>counter

        _compress(tmp_block, zero_block, input_block)
        _compress(addr_block, zero_block, tmp_block)

        for k in range(QWORDS_PER_BLOCK):
            pseudo_rands[count] = addr_block[k]
            count += 1
            if count >= segment_length:
                break


cdef void _fill_segment(
    uint64_t *memory,
    int pass_number,
    int lane,
    int slice_number,
    int lanes,
    int segment_length,
    int lane_length,
    int total_passes,
    int m_prime,
    int variant,
    int version,
) noexcept nogil:
    cdef:
        int first_pass = (pass_number == 0)
        int data_independent
        uint64_t *pseudo_rands
        int index, j, prev_j, lane_base
        uint64_t qw
        uint32_t j1, j2
        int ref_lane, same_lane, ref_area_size, ref_index, start_pos
        uint64_t x
        uint64_t new_block[QWORDS_PER_BLOCK]
        uint64_t *prev_block
        uint64_t *ref_block
        uint64_t *old_block
        int i

    data_independent = (
            variant == 1  # ARGON2I
        or (variant == 2  # ARGON2ID
            and pass_number == 0
            and slice_number <= 1)
    )

    pseudo_rands = NULL
    if data_independent:
        pseudo_rands = <uint64_t *>malloc(segment_length * sizeof(uint64_t))
        if pseudo_rands == NULL:
            return
        _generate_addresses_i(
            pseudo_rands, pass_number, lane, slice_number, m_prime,
            total_passes, variant, segment_length,
        )

    for index in range(segment_length):
        j = slice_number * segment_length + index

        if first_pass and j < 2:
            continue

        prev_j = ((j - 1) % lane_length + lane_length) % lane_length
        lane_base = lane * lane_length

        if data_independent:
            qw = pseudo_rands[index]
            j1 = <uint32_t>qw
            j2 = <uint32_t>(qw >> 32)
        else:
            prev_block = &memory[(lane_base + prev_j) * QWORDS_PER_BLOCK]
            j1 = <uint32_t>prev_block[0]
            j2 = <uint32_t>(prev_block[0] >> 32)

        ref_lane = j2 % lanes
        if first_pass and slice_number == 0:
            ref_lane = lane

        same_lane = (ref_lane == lane)
        if first_pass:
            if slice_number == 0 or same_lane:
                ref_area_size = j - 1
            elif index == 0:
                ref_area_size = slice_number * segment_length - 1
            else:
                ref_area_size = slice_number * segment_length
        else:
            if same_lane:
                ref_area_size = lane_length - segment_length + index - 1
            elif index == 0:
                ref_area_size = lane_length - segment_length - 1
            else:
                ref_area_size = lane_length - segment_length

        x = (<uint64_t>j1 * <uint64_t>j1) >> 32
        ref_index = ref_area_size - 1 - <int>((<uint64_t>ref_area_size * x) >> 32)

        if first_pass or slice_number == 3:
            start_pos = 0
        else:
            start_pos = (slice_number + 1) * segment_length

        ref_index = (start_pos + ref_index) % lane_length

        prev_block = &memory[(lane_base + prev_j) * QWORDS_PER_BLOCK]
        ref_block = &memory[(ref_lane * lane_length + ref_index) * QWORDS_PER_BLOCK]
        _compress(new_block, prev_block, ref_block)

        if pass_number > 0 and version == 0x13:
            old_block = &memory[(lane_base + j) * QWORDS_PER_BLOCK]
            for i in range(QWORDS_PER_BLOCK):
                new_block[i] = new_block[i] ^ old_block[i]

        memcpy(&memory[(lane_base + j) * QWORDS_PER_BLOCK], new_block, BLOCK_BYTES)

    if pseudo_rands != NULL:
        free(pseudo_rands)


def argon2hash(
    password,
    salt,
    int time_cost,
    int memory_cost,
    int parallelism,
    int tag_length,
    int variant=ARGON2ID,
    int version=0x13,
    secret=b'',
    associated_data=b'',
):
    """
    Compute an Argon2 hash tag.

    Args:
        password:        Input password bytes
        salt:            Salt bytes
        time_cost:       Number of passes (iterations)
        memory_cost:     Memory size in KiB
        parallelism:     Degree of parallelism (number of lanes)
        tag_length:      Desired output tag length in bytes
        variant:         ARGON2D (0), ARGON2I (1), or ARGON2ID (2)
        version:         Protocol version (0x13 for v1.3)
        secret:          Optional secret/key bytes
        associated_data: Optional associated data bytes
    """
    cdef:
        int m_prime, lane_length, segment_length, total_blocks
        uint64_t *memory = NULL
        int pass_number, slice_number, lane_idx
        int i
        uint64_t *final_block_c
        uint64_t *last_block

    if variant not in (ARGON2D, ARGON2I, ARGON2ID):
        raise ValueError(F'invalid Argon2 variant: {variant}')
    if time_cost < 1:
        raise ValueError(F'time_cost must be at least 1, got {time_cost}')
    if parallelism < 1:
        raise ValueError(F'parallelism must be at least 1, got {parallelism}')
    if tag_length < 4:
        raise ValueError(F'tag_length must be at least 4, got {tag_length}')

    m_prime = (memory_cost // (4 * parallelism)) * (4 * parallelism)
    lane_length = m_prime // parallelism
    segment_length = lane_length // 4

    if segment_length < 1:
        segment_length = 1
        lane_length = 4
        m_prime = lane_length * parallelism

    h0 = _initial_hash(
        parallelism, tag_length, memory_cost, time_cost,
        version, variant, password, salt, secret, associated_data,
    )

    total_blocks = lane_length * parallelism
    memory = <uint64_t *>malloc(<size_t>total_blocks * BLOCK_BYTES)
    if memory == NULL:
        raise MemoryError

    try:
        memset(memory, 0, <size_t>total_blocks * BLOCK_BYTES)

        for lane_idx in range(parallelism):
            h_input_0 = h0 + struct.pack('<II', 0, lane_idx)
            block_bytes_0 = _blake2b_long(h_input_0, BLOCK_BYTES)
            memcpy(
                &memory[(lane_idx * lane_length + 0) * QWORDS_PER_BLOCK],
                <const uint8_t *>(<bytes>block_bytes_0),
                BLOCK_BYTES,
            )

            h_input_1 = h0 + struct.pack('<II', 1, lane_idx)
            block_bytes_1 = _blake2b_long(h_input_1, BLOCK_BYTES)
            memcpy(
                &memory[(lane_idx * lane_length + 1) * QWORDS_PER_BLOCK],
                <const uint8_t *>(<bytes>block_bytes_1),
                BLOCK_BYTES,
            )

        with nogil:
            for pass_number in range(time_cost):
                for slice_number in range(SYNC_POINTS):
                    for lane_idx in range(parallelism):
                        _fill_segment(
                            memory, pass_number, lane_idx, slice_number,
                            parallelism, segment_length, lane_length,
                            time_cost, m_prime, variant, version,
                        )

        final_block_c = <uint64_t *>malloc(BLOCK_BYTES)
        if final_block_c == NULL:
            raise MemoryError

        try:
            memcpy(
                final_block_c,
                &memory[(0 * lane_length + lane_length - 1) * QWORDS_PER_BLOCK],
                BLOCK_BYTES,
            )
            for lane_idx in range(1, parallelism):
                last_block = &memory[(lane_idx * lane_length + lane_length - 1) * QWORDS_PER_BLOCK]
                for i in range(QWORDS_PER_BLOCK):
                    final_block_c[i] = final_block_c[i] ^ last_block[i]

            final_bytes = (<uint8_t *>final_block_c)[:BLOCK_BYTES]
        finally:
            free(final_block_c)
    finally:
        free(memory)

    return _blake2b_long(final_bytes, tag_length)
