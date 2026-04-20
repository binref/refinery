from __future__ import annotations

from refinery.lib.exceptions import RefineryPartialResult

_INIT_BITS = 9
_BITS = 0x10
_CLEAR = 0x100
_FIRST = 0x101
_WSIZE = 0x8000


def lzw_decompress(
    ibuf: bytes | bytearray | memoryview,
    maxbits: int,
    block_mode: bool,
) -> bytearray:
    """
    LZW decompression of raw stream data. The caller is responsible for parsing and stripping the
    3-byte header (\\x1F\\x9D + flags) before invoking this function.
    """
    if maxbits > _BITS:
        raise ValueError(F'Compressed with {maxbits} bits; cannot handle file.')

    ibuf = memoryview(ibuf)
    maxmaxcode = 1 << maxbits

    tab_suffix = bytearray(_WSIZE * 2)
    tab_prefix = [0] * (1 << _BITS)

    n_bits = _INIT_BITS
    maxcode = (1 << n_bits) - 1
    bitmask = (1 << n_bits) - 1
    oldcode = ~0
    finchar = 0
    posbits = 0

    free_entry = _FIRST if block_mode else 0x100
    tab_suffix[:0x100] = range(0x100)
    resetbuf = True
    out = bytearray()

    while resetbuf:
        resetbuf = False

        ibuf = ibuf[posbits >> 3:]
        insize = len(ibuf)
        posbits = 0
        inbits = (insize << 3) - (n_bits - 1)

        while inbits > posbits:
            if free_entry > maxcode:
                n = n_bits << 3
                p = posbits - 1
                posbits = p + (n - (p + n) % n)
                n_bits += 1
                if n_bits == maxbits:
                    maxcode = maxmaxcode
                else:
                    maxcode = (1 << n_bits) - 1
                bitmask = (1 << n_bits) - 1
                resetbuf = True
                break

            p = ibuf[posbits >> 3:]
            code = int.from_bytes(p[:3], 'little') >> (posbits & 7) & bitmask
            posbits += n_bits

            if oldcode == -1:
                if code >= 256:
                    raise ValueError('corrupt input.')
                oldcode = code
                finchar = oldcode
                out.append(finchar)
                continue

            if code == _CLEAR and block_mode:
                tab_prefix[:0x100] = [0] * 0x100
                free_entry = _FIRST - 1
                n = n_bits << 3
                p = posbits - 1
                posbits = p + (n - (p + n) % n)
                n_bits = _INIT_BITS
                maxcode = (1 << n_bits) - 1
                bitmask = (1 << n_bits) - 1
                resetbuf = True
                break

            incode = code
            stack = bytearray()

            if code >= free_entry:
                if code > free_entry:
                    raise RefineryPartialResult('corrupt input.', bytes(out))
                stack.append(finchar)
                code = oldcode
            while code >= 256:
                stack.append(tab_suffix[code])
                code = tab_prefix[code]

            finchar = tab_suffix[code]
            stack.append(finchar)
            stack.reverse()
            out.extend(stack)
            code = free_entry

            if code < maxmaxcode:
                tab_prefix[code] = oldcode & 0xFFFF
                tab_suffix[code] = finchar & 0x00FF
                free_entry = code + 1

            oldcode = incode

    return out
