from __future__ import annotations


def blz_decompress_chunk(
    data: bytes | bytearray | memoryview,
    src_offset: int,
    verbatim_offset: int,
    size: int,
    prefix: bytes | bytearray | memoryview | None = None,
) -> tuple[bytearray, int]:
    """
    Decompress a single BriefLZ chunk.
    """
    src = memoryview(data)
    end = len(src)
    pos = src_offset
    bitcount = 0
    bitstore = 0
    prefix_len = len(prefix) if prefix else 0

    def readbit():
        nonlocal bitcount, bitstore, pos
        if not bitcount:
            if pos + 1 >= end:
                raise EOFError('unexpected end of input during bit read')
            bitstore = src[pos] | (src[pos + 1] << 8)
            pos += 2
            bitcount = 0xF
        else:
            bitcount -= 1
        return (bitstore >> bitcount) & 1

    def readint():
        result = 2 + readbit()
        while readbit():
            result = (result << 1) | readbit()
        return result

    out = bytearray()
    out.append(src[verbatim_offset])
    decompressed = 1

    try:
        while decompressed < size:
            if readbit():
                length = readint() + 2
                sector = readint() - 2
                if pos >= end:
                    raise EOFError('unexpected end of input reading offset byte')
                offset = src[pos] + 1
                pos += 1
                delta = offset + 0x100 * sector
                available = prefix_len + len(out)
                if delta > available:
                    raise ValueError(
                        F'Requested rewind by 0x{delta:08X} bytes '
                        F'with only 0x{available:08X} bytes in output buffer.'
                    )
                global_pos = available - delta
                remaining = length
                while remaining > 0:
                    if global_pos < prefix_len:
                        chunk_len = min(prefix_len - global_pos, remaining)
                        out.extend(prefix[global_pos:global_pos + chunk_len])
                        global_pos += chunk_len
                        remaining -= chunk_len
                    else:
                        ref_start = global_pos - prefix_len
                        chunk_len = min(len(out) - ref_start, remaining)
                        if chunk_len <= 0:
                            raise ValueError('zero-length copy in replay')
                        out.extend(out[ref_start:ref_start + chunk_len])
                        global_pos += chunk_len
                        remaining -= chunk_len
                decompressed += length
            else:
                if pos >= end:
                    raise EOFError('unexpected end of input reading literal')
                out.append(src[pos])
                pos += 1
                decompressed += 1
    except EOFError:
        raise

    return (out, pos)
