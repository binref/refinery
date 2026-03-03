"""
Pure-Python implementation of the Argon2 password hashing function as specified
in RFC 9106. Supports all three variants: Argon2d, Argon2i, and Argon2id.

The implementation is designed for readability and Cython compatibility: all hot
path functions are module-level with simple typed parameters, blocks are
represented as list[int] (128 x uint64) which maps directly to uint64_t[128] in
Cython, and no Python objects are allocated in the inner loops.
"""
from __future__ import annotations

import hashlib
import struct

ARGON2D: int = 0
ARGON2I: int = 1
ARGON2ID: int = 2

_BLOCK_SIZE: int = 1024
_QWORDS_PER_BLOCK: int = 128
_SYNC_POINTS: int = 4
_MASK64: int = 0xFFFFFFFFFFFFFFFF
_MASK32: int = 0xFFFFFFFF


def _blake2b_long(data: bytes | bytearray | memoryview, digest_size: int) -> bytes:
    """
    Variable-length hash H' as defined in RFC 9106 Section 3.1.
    Uses hashlib.blake2b (stdlib) and chains 64-byte digests for outputs
    longer than 64 bytes.
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
    parallelism: int,
    tag_length: int,
    memory_cost: int,
    time_cost: int,
    version: int,
    variant: int,
    password: bytes | bytearray | memoryview,
    salt: bytes | bytearray | memoryview,
    secret: bytes | bytearray | memoryview,
    associated_data: bytes | bytearray | memoryview,
) -> bytes:
    """
    Compute the 64-byte initial hash H0 from all input parameters as described
    in RFC 9106 Section 3.2.
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


def _bytes_to_block(data: bytes | bytearray | memoryview) -> list[int]:
    return list(struct.unpack_from('<128Q', data))


def _block_to_bytes(block: list[int]) -> bytes:
    return struct.pack('<128Q', *block)


def _xor_blocks(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


def _gb(v: list[int], a: int, b: int, c: int, d: int) -> None:
    """
    In-place Blake2b-based quarter-round (RFC 9106 Section 3.5). Uses the fBlaMka multiplication:
        2 * trunc(a) * trunc(b)
    where trunc takes the lower 32 bits.
    """
    va = v[a]
    vb = v[b]
    vc = v[c]
    vd = v[d]

    va = (va + vb + 2 * (va & _MASK32) * (vb & _MASK32)) & _MASK64
    vd = vd ^ va
    vd = (vd >> 32) | ((vd & _MASK32) << 32)
    vc = (vc + vd + 2 * (vc & _MASK32) * (vd & _MASK32)) & _MASK64
    vb = vb ^ vc
    vb = (vb >> 24) | ((vb & 0xFFFFFF) << 40)

    va = (va + vb + 2 * (va & _MASK32) * (vb & _MASK32)) & _MASK64
    vd = vd ^ va
    vd = (vd >> 16) | ((vd & 0xFFFF) << 48)
    vc = (vc + vd + 2 * (vc & _MASK32) * (vd & _MASK32)) & _MASK64
    vb = vb ^ vc
    vb = (vb >> 63) | ((vb << 1) & _MASK64)

    v[a] = va
    v[b] = vb
    v[c] = vc
    v[d] = vd


def _P(v: list[int],
    i0: int, i1: int, i2: int, i3: int,
    i4: int, i5: int, i6: int, i7: int,
    i8: int, i9: int, iA: int, iB: int,
    iC: int, iD: int, iE: int, iF: int,
) -> None:
    _gb(v, i0, i4, i8, iC)
    _gb(v, i1, i5, i9, iD)
    _gb(v, i2, i6, iA, iE)
    _gb(v, i3, i7, iB, iF)
    _gb(v, i0, i5, iA, iF)
    _gb(v, i1, i6, iB, iC)
    _gb(v, i2, i7, i8, iD)
    _gb(v, i3, i4, i9, iE)


def _compress(x: list[int], y: list[int]) -> list[int]:
    """
    Compression function G(X, Y) per RFC 9106 Section 3.4.

    The 128 uint64 values are treated as an 8x8 matrix of 128-bit cells (each cell = 2 consecutive
    uint64 values). P is applied row-wise producing Q, then column-wise on Q producing Z, and the
    result is R ^ Z.
    """
    r = _xor_blocks(x, y)
    q = list(r)
    for row in range(8):
        base = row * 16
        _P(
            q,
            base + 0x0, base + 0x1, base + 0x2, base + 0x3,
            base + 0x4, base + 0x5, base + 0x6, base + 0x7,
            base + 0x8, base + 0x9, base + 0xA, base + 0xB,
            base + 0xC, base + 0xD, base + 0xE, base + 0xF,
        )
    z = list(q)
    for col in range(8):
        base = col * 2
        _P(
            z,
            base + 0x00, base + 0x01, base + 0x10, base + 0x11,
            base + 0x20, base + 0x21, base + 0x30, base + 0x31,
            base + 0x40, base + 0x41, base + 0x50, base + 0x51,
            base + 0x60, base + 0x61, base + 0x70, base + 0x71,
        )

    return _xor_blocks(r, z)


def _generate_addresses_i(
    pass_number: int,
    lane: int,
    slice_number: int,
    m_prime: int,
    total_passes: int,
    variant: int,
    segment_length: int,
) -> list[tuple[int, int]]:
    """
    Pre-generate (J1, J2) pairs for Argon2i-style independent indexing. Generates pairs via
        G(G(zero, input_block))
    as per RFC 9106 Section 3.3. Returns a list of (J1, J2) tuples, one per block in the segment.
    """
    zero_block = [0] * _QWORDS_PER_BLOCK
    pseudo_rands: list[tuple[int, int]] = []
    counter = 0
    while len(pseudo_rands) < segment_length:
        counter += 1
        input_block = [0] * _QWORDS_PER_BLOCK
        input_block[0] = pass_number
        input_block[1] = lane
        input_block[2] = slice_number
        input_block[3] = m_prime
        input_block[4] = total_passes
        input_block[5] = variant
        input_block[6] = counter
        addr_block = _compress(zero_block, _compress(zero_block, input_block))
        for qw in addr_block:
            pseudo_rands.append((qw & _MASK32, (qw >> 32) & _MASK32))
            if len(pseudo_rands) >= segment_length:
                break
    return pseudo_rands


def _fill_segment(
    memory: list[list[int]],
    pass_number: int,
    lane: int,
    slice_number: int,
    lanes: int,
    segment_length: int,
    lane_length: int,
    total_passes: int,
    m_prime: int,
    variant: int,
    version: int,
) -> None:
    """
    Fill one segment of memory for a given (pass, lane, slice). Contains the single branching point
    for variant selection.
    """
    first_pass = (pass_number == 0)

    data_independent = (
        variant == ARGON2I
        or (variant == ARGON2ID and pass_number == 0 and slice_number <= 1)
    )

    pseudo_rands: list[tuple[int, int]] = []
    if data_independent:
        pseudo_rands = _generate_addresses_i(
            pass_number, lane, slice_number, m_prime,
            total_passes, variant, segment_length,
        )

    for index in range(segment_length):
        j = slice_number * segment_length + index

        if first_pass and j < 2:
            # First two blocks per lane are initialized separately
            continue

        # Previous block index (wraps around within the lane)
        prev_j = (j - 1) % lane_length
        lane_base = lane * lane_length

        # Determine J1, J2
        if data_independent:
            j1, j2 = pseudo_rands[index]
        else:
            # Argon2d: derive from first 8 bytes of the previous block
            prev_block = memory[lane_base + prev_j]
            j1 = prev_block[0] & _MASK32
            j2 = (prev_block[0] >> 32) & _MASK32

        # Determine reference lane
        ref_lane = j2 % lanes
        if first_pass and slice_number == 0:
            ref_lane = lane

        # Determine reference area size
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

        # Map J1 to reference index using biased distribution
        x = (j1 * j1) >> 32
        ref_index = ref_area_size - 1 - ((ref_area_size * x) >> 32)

        # Compute start position for the reference set
        if first_pass or slice_number == 3:
            start_pos = 0
        else:
            start_pos = (slice_number + 1) * segment_length

        ref_index = (start_pos + ref_index) % lane_length

        # Compress previous block with reference block
        prev_block = memory[lane_base + prev_j]
        ref_block = memory[ref_lane * lane_length + ref_index]
        new_block = _compress(prev_block, ref_block)

        if pass_number > 0 and version == 0x13:
            old_block = memory[lane_base + j]
            new_block = _xor_blocks(new_block, old_block)

        memory[lane_base + j] = new_block


def argon2hash(
    password: bytes | bytearray | memoryview,
    salt: bytes | bytearray | memoryview,
    time_cost: int,
    memory_cost: int,
    parallelism: int,
    tag_length: int,
    variant: int = ARGON2ID,
    version: int = 0x13,
    secret: bytes | bytearray | memoryview = b'',
    associated_data: bytes | bytearray | memoryview = b'',
) -> bytes:
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
    if variant not in (ARGON2D, ARGON2I, ARGON2ID):
        raise ValueError(F'invalid Argon2 variant: {variant}')
    if time_cost < 1:
        raise ValueError(F'time_cost must be at least 1, got {time_cost}')
    if parallelism < 1:
        raise ValueError(F'parallelism must be at least 1, got {parallelism}')
    if tag_length < 4:
        raise ValueError(F'tag_length must be at least 4, got {tag_length}')

    # Compute memory layout: m' must be a multiple of 4*parallelism
    m_prime = (memory_cost // (4 * parallelism)) * (4 * parallelism)
    lane_length = m_prime // parallelism
    segment_length = lane_length // 4

    if segment_length < 1:
        segment_length = 1
        lane_length = 4
        m_prime = lane_length * parallelism

    # Step 1: Compute H0
    h0 = _initial_hash(
        parallelism, tag_length, memory_cost, time_cost,
        version, variant, password, salt, secret, associated_data,
    )

    # Step 2: Initialize memory - flat list of blocks
    total_blocks = lane_length * parallelism
    memory: list[list[int]] = [[0] * _QWORDS_PER_BLOCK for _ in range(total_blocks)]

    # Step 3: Compute first two blocks for each lane
    for lane_idx in range(parallelism):
        h_input_0 = h0 + struct.pack('<II', 0, lane_idx)
        block_bytes = _blake2b_long(h_input_0, _BLOCK_SIZE)
        memory[lane_idx * lane_length + 0] = _bytes_to_block(block_bytes)

        h_input_1 = h0 + struct.pack('<II', 1, lane_idx)
        block_bytes = _blake2b_long(h_input_1, _BLOCK_SIZE)
        memory[lane_idx * lane_length + 1] = _bytes_to_block(block_bytes)

    # Step 4: Fill memory passes
    for pass_number in range(time_cost):
        for slice_number in range(_SYNC_POINTS):
            for lane_idx in range(parallelism):
                _fill_segment(
                    memory, pass_number, lane_idx, slice_number,
                    parallelism, segment_length, lane_length,
                    time_cost, m_prime, variant, version,
                )

    # Step 5: Finalize - XOR last column of all lanes
    final_block = list(memory[0 * lane_length + lane_length - 1])
    for lane_idx in range(1, parallelism):
        last_block = memory[lane_idx * lane_length + lane_length - 1]
        final_block = _xor_blocks(final_block, last_block)

    # Step 6: Produce tag
    return _blake2b_long(_block_to_bytes(final_block), tag_length)
