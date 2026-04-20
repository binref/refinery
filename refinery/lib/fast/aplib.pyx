# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
cimport cython

from libc.stdint cimport uint8_t, uint32_t
from libc.stdlib cimport free, malloc, realloc
from libc.string cimport memcpy


cdef inline uint32_t _lengthdelta(uint32_t offset) noexcept nogil:
    if offset < 0x80 or offset >= 0x7D00:
        return 2
    elif offset >= 0x500:
        return 1
    return 0


cdef void _ensure_capacity(
    uint8_t **buf, uint32_t *cap, uint32_t needed
) except * nogil:
    cdef uint32_t new_cap
    cdef uint8_t *tmp
    if needed <= cap[0]:
        return
    new_cap = cap[0]
    while new_cap < needed:
        new_cap = new_cap * 2
    tmp = <uint8_t *>realloc(buf[0], new_cap)
    if tmp == NULL:
        with gil:
            raise MemoryError
    buf[0] = tmp
    cap[0] = new_cap


def aplib_decompress(data) -> bytearray:
    cdef:
        const uint8_t[::1] src = memoryview(data)
        int end = len(data)
        int pos = 0
        uint32_t tag = 0
        uint32_t bitcount = 0
        uint32_t bit
        uint32_t offs, length, R0, LWM
        uint32_t cursor = 0
        uint32_t out_cap
        uint8_t *out_buf
        uint8_t b
        int i, done

    if end == 0:
        return bytearray()

    out_cap = <uint32_t>(end * 4) if end < 0x10000000 else <uint32_t>end
    if out_cap < 256:
        out_cap = 256
    out_buf = <uint8_t *>malloc(out_cap)
    if out_buf == NULL:
        raise MemoryError

    try:
        R0 = 0
        LWM = 0
        done = 0

        # first byte verbatim
        out_buf[cursor] = src[pos]
        cursor += 1
        pos += 1

        while not done:
            # read bit
            if bitcount == 0:
                if pos >= end:
                    break
                tag = src[pos]
                pos += 1
                bitcount = 8
            bitcount -= 1
            bit = (tag >> 7) & 1
            tag = (tag << 1) & 0xFF

            if bit:
                # read second bit
                if bitcount == 0:
                    if pos >= end:
                        break
                    tag = src[pos]
                    pos += 1
                    bitcount = 8
                bitcount -= 1
                bit = (tag >> 7) & 1
                tag = (tag << 1) & 0xFF

                if bit:
                    # read third bit
                    if bitcount == 0:
                        if pos >= end:
                            break
                        tag = src[pos]
                        pos += 1
                        bitcount = 8
                    bitcount -= 1
                    bit = (tag >> 7) & 1
                    tag = (tag << 1) & 0xFF

                    if bit:
                        # single byte: read 4-bit offset
                        offs = 0
                        for i in range(4):
                            if bitcount == 0:
                                if pos >= end:
                                    break
                                tag = src[pos]
                                pos += 1
                                bitcount = 8
                            bitcount -= 1
                            offs = (offs << 1) | ((tag >> 7) & 1)
                            tag = (tag << 1) & 0xFF

                        _ensure_capacity(&out_buf, &out_cap, cursor + 1)
                        if offs:
                            if offs > cursor:
                                raise IndexError
                            out_buf[cursor] = out_buf[cursor - offs]
                        else:
                            out_buf[cursor] = 0
                        cursor += 1
                        LWM = 0
                    else:
                        # short block
                        if pos >= end:
                            break
                        b = src[pos]
                        pos += 1

                        if b <= 1:
                            done = 1
                        else:
                            length = 2 + (b & 1)
                            offs = b >> 1
                            if offs > cursor:
                                raise IndexError
                            _ensure_capacity(&out_buf, &out_cap, cursor + length)
                            for i in range(<int>length):
                                out_buf[cursor] = out_buf[cursor - offs]
                                cursor += 1
                            R0 = offs
                            LWM = 1
                else:
                    # block: read gamma-encoded offset
                    offs = 1
                    # read gamma
                    if bitcount == 0:
                        if pos >= end:
                            break
                        tag = src[pos]
                        pos += 1
                        bitcount = 8
                    bitcount -= 1
                    offs = (offs << 1) | ((tag >> 7) & 1)
                    tag = (tag << 1) & 0xFF

                    while True:
                        if bitcount == 0:
                            if pos >= end:
                                break
                            tag = src[pos]
                            pos += 1
                            bitcount = 8
                        bitcount -= 1
                        bit = (tag >> 7) & 1
                        tag = (tag << 1) & 0xFF
                        if not bit:
                            break
                        if bitcount == 0:
                            if pos >= end:
                                break
                            tag = src[pos]
                            pos += 1
                            bitcount = 8
                        bitcount -= 1
                        offs = (offs << 1) | ((tag >> 7) & 1)
                        tag = (tag << 1) & 0xFF

                    if LWM == 0 and offs == 2:
                        offs = R0
                        # read gamma for length
                        length = 1
                        if bitcount == 0:
                            if pos >= end:
                                break
                            tag = src[pos]
                            pos += 1
                            bitcount = 8
                        bitcount -= 1
                        length = (length << 1) | ((tag >> 7) & 1)
                        tag = (tag << 1) & 0xFF

                        while True:
                            if bitcount == 0:
                                if pos >= end:
                                    break
                                tag = src[pos]
                                pos += 1
                                bitcount = 8
                            bitcount -= 1
                            bit = (tag >> 7) & 1
                            tag = (tag << 1) & 0xFF
                            if not bit:
                                break
                            if bitcount == 0:
                                if pos >= end:
                                    break
                                tag = src[pos]
                                pos += 1
                                bitcount = 8
                            bitcount -= 1
                            length = (length << 1) | ((tag >> 7) & 1)
                            tag = (tag << 1) & 0xFF

                        if offs > cursor:
                            raise IndexError
                        _ensure_capacity(&out_buf, &out_cap, cursor + length)
                        for i in range(<int>length):
                            out_buf[cursor] = out_buf[cursor - offs]
                            cursor += 1
                    else:
                        if LWM == 0:
                            offs -= 3
                        else:
                            offs -= 2

                        if pos >= end:
                            break
                        offs = (offs << 8) | src[pos]
                        pos += 1

                        # read gamma for length
                        length = 1
                        if bitcount == 0:
                            if pos >= end:
                                break
                            tag = src[pos]
                            pos += 1
                            bitcount = 8
                        bitcount -= 1
                        length = (length << 1) | ((tag >> 7) & 1)
                        tag = (tag << 1) & 0xFF

                        while True:
                            if bitcount == 0:
                                if pos >= end:
                                    break
                                tag = src[pos]
                                pos += 1
                                bitcount = 8
                            bitcount -= 1
                            bit = (tag >> 7) & 1
                            tag = (tag << 1) & 0xFF
                            if not bit:
                                break
                            if bitcount == 0:
                                if pos >= end:
                                    break
                                tag = src[pos]
                                pos += 1
                                bitcount = 8
                            bitcount -= 1
                            length = (length << 1) | ((tag >> 7) & 1)
                            tag = (tag << 1) & 0xFF

                        length += _lengthdelta(offs)

                        if offs > cursor:
                            raise IndexError
                        _ensure_capacity(&out_buf, &out_cap, cursor + length)
                        for i in range(<int>length):
                            out_buf[cursor] = out_buf[cursor - offs]
                            cursor += 1
                        R0 = offs

                    LWM = 1
            else:
                # literal
                if pos >= end:
                    break
                _ensure_capacity(&out_buf, &out_cap, cursor + 1)
                out_buf[cursor] = src[pos]
                cursor += 1
                pos += 1
                LWM = 0

        return bytearray(out_buf[:cursor])
    finally:
        free(out_buf)


cdef struct CompressorState:
    const uint8_t *src
    uint32_t length
    uint8_t *out_buf
    uint32_t out_cap
    uint32_t cursor
    uint8_t bitbuffer
    uint32_t bitcount
    uint32_t tagoffset
    int is_tagged
    uint32_t offset
    uint32_t lastoffset
    int pair


cdef inline void _flush_tag(CompressorState *st) noexcept nogil:
    st.out_buf[st.tagoffset] = st.bitbuffer


cdef void _write_bit(CompressorState *st, int value) except * nogil:
    if st.bitcount != 0:
        st.bitcount -= 1
    else:
        if not st.is_tagged:
            st.is_tagged = 1
        else:
            _flush_tag(st)
        _ensure_capacity(&st.out_buf, &st.out_cap, st.cursor + 1)
        st.tagoffset = st.cursor
        st.out_buf[st.cursor] = 0
        st.cursor += 1
        st.bitcount = 7
        st.bitbuffer = 0
    if value:
        st.bitbuffer |= (1 << st.bitcount)


cdef inline void _write_byte(CompressorState *st, uint8_t b) except * nogil:
    _ensure_capacity(&st.out_buf, &st.out_cap, st.cursor + 1)
    st.out_buf[st.cursor] = b
    st.cursor += 1


cdef void _write_fixednumber(CompressorState *st, uint32_t value, int nbbit) except * nogil:
    cdef int i
    for i in range(nbbit - 1, -1, -1):
        _write_bit(st, (value >> i) & 1)


cdef void _write_gamma(CompressorState *st, uint32_t value) except * nogil:
    cdef int length, i
    if value < 2:
        return
    length = 0
    cdef uint32_t tmp = value >> 2
    while tmp:
        length += 1
        tmp >>= 1
    _write_bit(st, (value >> length) & 1)
    for i in range(length - 1, -1, -1):
        _write_bit(st, 1)
        _write_bit(st, (value >> i) & 1)
    _write_bit(st, 0)


cdef (uint32_t, uint32_t) _find_longest_match(
    bytes data, uint32_t offset
):
    cdef:
        uint32_t pivot = 0
        uint32_t total = <uint32_t>len(data)
        uint32_t limit = total - offset
        uint32_t size = limit
        uint32_t rewind = 0
        int pos

    while size > 0:
        pos = data.rfind(data[offset:offset + pivot + size], 0, offset)
        if pos == -1:
            size = size // 2
            continue
        rewind = offset - <uint32_t>pos
        if pivot + size >= limit:
            return (rewind, limit)
        pivot += size
    if pivot == 0:
        return (0, 0)
    return (rewind, pivot)


def aplib_compress(data) -> bytearray:
    cdef:
        bytes src_bytes = bytes(data)
        const uint8_t[::1] src_view = src_bytes
        uint32_t length = <uint32_t>len(data)
        CompressorState st
        uint32_t match_offset, match_length
        uint8_t c
        uint32_t high

    if length == 0:
        return bytearray()

    st.src = &src_view[0]
    st.length = length
    st.out_cap = length if length > 256 else 256
    st.out_buf = <uint8_t *>malloc(st.out_cap)
    if st.out_buf == NULL:
        raise MemoryError
    st.cursor = 0
    st.bitbuffer = 0
    st.bitcount = 0
    st.tagoffset = 0
    st.is_tagged = 0
    st.offset = 0
    st.lastoffset = 0
    st.pair = 1

    try:
        # first byte verbatim
        _write_byte(&st, st.src[st.offset])
        st.offset += 1

        while st.offset < st.length:
            match_offset, match_length = _find_longest_match(
                src_bytes, st.offset
            )

            if match_length == 0:
                c = st.src[st.offset]
                if c == 0:
                    # singlebyte(0)
                    _write_bit(&st, 1)
                    _write_bit(&st, 1)
                    _write_bit(&st, 1)
                    _write_fixednumber(&st, 0, 4)
                    st.offset += 1
                    st.pair = 1
                else:
                    # literal
                    _write_bit(&st, 0)
                    _write_byte(&st, st.src[st.offset])
                    st.offset += 1
                    st.pair = 1
            elif match_length == 1 and match_offset < 16:
                # singlebyte
                _write_bit(&st, 1)
                _write_bit(&st, 1)
                _write_bit(&st, 1)
                _write_fixednumber(&st, match_offset, 4)
                st.offset += 1
                st.pair = 1
            elif 2 <= match_length <= 3 and 0 < match_offset <= 127:
                # shortblock
                _write_bit(&st, 1)
                _write_bit(&st, 1)
                _write_bit(&st, 0)
                _write_byte(&st, <uint8_t>((match_offset << 1) + (match_length - 2)))
                st.offset += match_length
                st.lastoffset = match_offset
                st.pair = 0
            elif match_length > 3 and match_offset >= 2:
                # block
                _write_bit(&st, 1)
                _write_bit(&st, 0)
                if st.pair and st.lastoffset == match_offset:
                    _write_gamma(&st, 2)
                    _write_gamma(&st, match_length)
                else:
                    high = (match_offset >> 8) + 2
                    if st.pair:
                        high += 1
                    _write_gamma(&st, high)
                    _write_byte(&st, <uint8_t>(match_offset & 0xFF))
                    _write_gamma(&st, match_length - _lengthdelta(match_offset))
                st.offset += match_length
                st.lastoffset = match_offset
                st.pair = 0
            else:
                # literal fallback
                _write_bit(&st, 0)
                _write_byte(&st, st.src[st.offset])
                st.offset += 1
                st.pair = 1

        # end marker
        _write_bit(&st, 1)
        _write_bit(&st, 1)
        _write_bit(&st, 0)
        _write_byte(&st, 0)

        _flush_tag(&st)
        return bytearray(st.out_buf[:st.cursor])
    finally:
        free(st.out_buf)
