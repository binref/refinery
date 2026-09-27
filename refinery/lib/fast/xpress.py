from __future__ import annotations

from refinery.lib.decompression import (
    DECODE_TABLE_LENGTH_MASK,
    DECODE_TABLE_SYMBOL_SHIFT,
    make_huffman_decode_table,
)
from refinery.lib.exceptions import RefineryPartialResult

XPRESS_NUM_CHARS = 256
XPRESS_NUM_SYMBOLS = 512
XPRESS_MAX_CODEWORD_LEN = 15
XPRESS_MIN_MATCH_LEN = 3
XPRESS_TABLEBITS = 11
XPRESS_END_OF_DATA = 256


def xpress_decompress(src: bytes | bytearray | memoryview, target: int | None) -> bytearray:
    """
    XPRESS (plain) decompression. The format interleaves 32-bit flag words with data bytes: each
    flag word provides 32 single-bit flags, and between flag words the data bytes (literals, match
    descriptors, extended lengths) are read sequentially. The `target` is the exact output size; a
    match that runs past it raises a `RuntimeError`. When it is `None`, decompression continues
    until the input ends.
    """
    src = memoryview(src)
    out = bytearray()
    pos = 0
    end = len(src)
    flags = 0
    flag_cnt = 0
    nibble_cache = None

    while pos < end or flag_cnt > 0:
        if len(out) == target:
            break

        if flag_cnt == 0:
            if pos + 3 >= end:
                break
            flags = src[pos] | (src[pos + 1] << 8) | (src[pos + 2] << 16) | (src[pos + 3] << 24)
            pos += 4
            flag_cnt = 32

        if not (flags >> 31):
            flags = (flags << 1) & 0xFFFFFFFF
            flag_cnt -= 1
            if pos >= end:
                break
            out.append(src[pos])
            pos += 1
            continue

        flags = (flags << 1) & 0xFFFFFFFF
        flag_cnt -= 1
        if pos + 1 >= end:
            break
        val = src[pos] | (src[pos + 1] << 8)
        pos += 2
        offset = (val >> 3) + 1
        length = val & 7

        if length == 7:
            if nibble_cache is not None:
                length = nibble_cache
                nibble_cache = None
            else:
                if pos >= end:
                    break
                length_pair = src[pos]
                pos += 1
                nibble_cache = length_pair >> 4
                length = length_pair & 0xF
            if length == 15:
                if pos >= end:
                    break
                length = src[pos]
                pos += 1
                if length == 0xFF:
                    if pos + 1 >= end:
                        break
                    length = src[pos] | (src[pos + 1] << 8)
                    pos += 2
                    if length == 0:
                        if pos + 3 >= end:
                            break
                        length = (
                            src[pos]
                            | (src[pos + 1] << 8)
                            | (src[pos + 2] << 16)
                            | (src[pos + 3] << 24)
                        )
                        pos += 4
                    length -= 22
                    if length < 0:
                        raise RuntimeError(
                            F'Invalid match length of {length} for long delta sequence')
                length += 15
            length += 7
        length += 3

        if target is not None and length > target - len(out):
            raise RuntimeError(F'A match of length {length} runs past the output size {target}.')
        start = len(out) - offset
        if start < 0:
            raise ValueError(F'Offset {offset} exceeds output size {len(out)}')
        while length > 0:
            chunk = out[start:start + length]
            out.extend(chunk)
            start += len(chunk)
            length -= len(chunk)

    return out


def _fill_bits(src, pos, end, bit_buf, bit_cnt, need):
    """
    Fill the MSB-first bit buffer with enough 16-bit LE words to have at least `need` bits.
    Consumed bits are discarded before each word is appended. Returns (bit_buf, bit_cnt, pos).
    """
    while bit_cnt < need and pos + 1 < end:
        bit_buf = ((bit_buf & ((1 << bit_cnt) - 1)) << 16) | src[pos] | (src[pos + 1] << 8)
        bit_cnt += 16
        pos += 2
    return bit_buf, bit_cnt, pos


def xpress_huffman_decompress(
    src: bytes | bytearray | memoryview,
    target: int | None,
    max_chunk_size: int = 0x10000,
) -> bytearray:
    """
    XPRESS with Huffman decompression. Uses MSB-first bit ordering matching BitBufferedReader
    semantics: new 16-bit words are appended at the low end (bit_buf = (bit_buf << 16) | word),
    and bits are consumed from the top (bit_buf >> (bit_cnt - N)). Each Huffman block decodes
    64 KiB of output, counted from the position where the previous block ended; that position can
    lie beyond a multiple of 64 KiB because a match may cross the block boundary. A block whose
    code has no codewords raises a `ValueError`.

    The `target` is the exact output size; a match that runs past it raises a `RuntimeError`. When
    it is `None`, the stream ends with the end-of-data symbol 256, after which the input holds only
    zero bits. A block that reaches 64 KiB when no further block fits into the input continues
    until that symbol. Input that ends before it raises a `RefineryPartialResult`.
    """
    src = memoryview(src)
    out = bytearray()
    pos = 0
    end = len(src)
    data_end = end
    limit = 0

    if target is None:
        while data_end > 0 and not src[data_end - 1]:
            data_end -= 1

    while pos < end:
        if XPRESS_NUM_SYMBOLS // 2 > end - pos:
            if target is None:
                break
            raise IndexError(
                F'There are only {end - pos} bytes remaining in the input buffer,'
                F' but at least {XPRESS_NUM_SYMBOLS // 2} are required to read a Huffman table.')

        table_data = bytearray(
            src[pos + i // 2] >> (4 * (i & 1)) & 0xF
            for i in range(XPRESS_NUM_SYMBOLS)
        )
        if not any(table_data):
            raise ValueError('The Huffman code of a block has no codewords.')
        pos += XPRESS_NUM_SYMBOLS // 2
        decode_table = make_huffman_decode_table(table_data, XPRESS_TABLEBITS, XPRESS_MAX_CODEWORD_LEN)

        limit = len(out) + max_chunk_size
        last_block = False
        bit_buf = 0
        bit_cnt = 0

        while True:
            out_pos = len(out)
            if out_pos == target:
                return out
            if out_pos >= limit and not last_block:
                next_block = pos + 2 if bit_cnt < 16 and pos + 1 < end else pos
                if (
                    target is None
                    and (next_block >= data_end or end - next_block < XPRESS_NUM_SYMBOLS // 2)
                ):
                    last_block = True
                else:
                    pos = next_block
                    break

            bit_buf, bit_cnt, pos = _fill_bits(
                src, pos, end, bit_buf, bit_cnt, XPRESS_MAX_CODEWORD_LEN)
            if bit_cnt < XPRESS_TABLEBITS:
                break

            top_bits = bit_buf >> (bit_cnt - XPRESS_TABLEBITS)
            entry = decode_table[top_bits & ((1 << XPRESS_TABLEBITS) - 1)]
            sym = entry >> DECODE_TABLE_SYMBOL_SHIFT
            length = entry & DECODE_TABLE_LENGTH_MASK

            if entry >= (1 << (XPRESS_TABLEBITS + DECODE_TABLE_SYMBOL_SHIFT)):
                bit_cnt -= XPRESS_TABLEBITS
                bit_buf, bit_cnt, pos = _fill_bits(
                    src, pos, end, bit_buf, bit_cnt, XPRESS_MAX_CODEWORD_LEN)
                if bit_cnt < length:
                    break
                top_bits = bit_buf >> (bit_cnt - length)
                entry = decode_table[sym + (top_bits & ((1 << length) - 1))]
                sym = entry >> DECODE_TABLE_SYMBOL_SHIFT
                length = entry & DECODE_TABLE_LENGTH_MASK

            bit_cnt -= length

            if sym < XPRESS_NUM_CHARS:
                out.append(sym)
                continue

            if (
                sym == XPRESS_END_OF_DATA
                and target is None
                and pos >= data_end
                and not bit_buf & ((1 << bit_cnt) - 1)
            ):
                return out

            match_length = sym & 0xF
            offsetlog = (sym >> 4) & 0xF

            bit_buf, bit_cnt, pos = _fill_bits(
                src, pos, end, bit_buf, bit_cnt, 16)
            if bit_cnt < offsetlog:
                break

            if offsetlog > 0:
                top_bits = bit_buf >> (bit_cnt - offsetlog)
                offset = (1 << offsetlog) | (top_bits & ((1 << offsetlog) - 1))
                bit_cnt -= offsetlog
            else:
                offset = 1

            if match_length == 0xF:
                if pos >= end:
                    break
                nudge = src[pos]
                pos += 1
                if nudge < 0xFF:
                    match_length += nudge
                else:
                    if pos + 1 >= end:
                        break
                    match_length = src[pos] | (src[pos + 1] << 8)
                    pos += 2
                    if match_length == 0:
                        if pos + 3 >= end:
                            break
                        match_length = (
                            src[pos]
                            | (src[pos + 1] << 8)
                            | (src[pos + 2] << 16)
                            | (src[pos + 3] << 24)
                        )
                        pos += 4
            match_length += XPRESS_MIN_MATCH_LEN

            if target is not None and match_length > target - len(out):
                raise RuntimeError(F'A match of length {match_length} runs past the output size {target}.')
            start = len(out) - offset
            if start < 0:
                raise ValueError(F'Offset {offset} exceeds output size {len(out)}')
            while match_length > 0:
                chunk = out[start:start + match_length]
                out.extend(chunk)
                start += len(chunk)
                match_length -= len(chunk)

    if target is None:
        raise RefineryPartialResult('The input ended before the end-of-data symbol.', out)
    return out
