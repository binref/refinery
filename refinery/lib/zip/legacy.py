"""
Decompression of the ZIP compression methods Shrink, Reduce, and Implode, which PKZIP used before
Deflate replaced them. None of these streams has an end marker, so each decoder requires the size
of the uncompressed data from the ZIP header.
"""
from __future__ import annotations

from typing import Iterator

from refinery.lib.seven.deflate import BitLDecoder, replay
from refinery.lib.seven.huffman import BitDecoderBase, HuffmanDecoder
from refinery.lib.structures import StructReader
from refinery.lib.types import buf

_SHRINK_CODES = 0x2000
_SHRINK_CONTROL = 0x100
_SHRINK_FIRST_CODE = 0x101
_SHRINK_MIN_WIDTH = 9
_SHRINK_MAX_WIDTH = 13
_SHRINK_UNUSED = -1

_REDUCE_ESCAPE = 0x90

_IMPLODE_CODE_BITS = 16


def _truncated(method: str, output: bytearray, size: int) -> EOFError:
    return EOFError(F'The {method} stream ended after {len(output)} of {size} bytes.')


def _copy(output: bytearray, distance: int, length: int):
    if (zeros := min(distance - len(output), length)) > 0:
        output.extend(bytes(zeros))
        length -= zeros
    if length > 0:
        replay(output, distance, length)


def _free_leaves(parents: list[int]):
    prefixes = set(parents)
    for code in range(_SHRINK_FIRST_CODE, _SHRINK_CODES):
        if code not in prefixes:
            parents[code] = _SHRINK_UNUSED


def unshrink(data: buf, size: int) -> bytearray:
    """
    Decompress `size` bytes from a stream that uses the Shrink method, a variant of LZW with code
    widths from 9 to 13 bits. The code 256 is followed by 1 to widen the codes by one bit, or by 2
    to free every code that is not the prefix of another code. Each new code takes the lowest free
    code value.
    """
    bits = BitLDecoder(StructReader(memoryview(data)))
    parents = [_SHRINK_UNUSED] * _SHRINK_CODES
    suffixes = bytearray(_SHRINK_CODES)
    output = bytearray()
    width = _SHRINK_MIN_WIDTH
    free = _SHRINK_FIRST_CODE
    last_code = None
    last_head = 0
    while len(output) < size:
        code = bits.read_bits(width)
        if code == _SHRINK_CONTROL:
            control = bits.read_bits(width)
            if bits.extra_bits_were_read():
                raise _truncated('Shrink', output, size)
            if control == 1 and width < _SHRINK_MAX_WIDTH:
                width += 1
            elif control == 2:
                _free_leaves(parents)
                free = _SHRINK_FIRST_CODE
            else:
                raise ValueError(F'Invalid Shrink control code {control} at code width {width}.')
            continue
        if bits.extra_bits_were_read():
            raise _truncated('Shrink', output, size)
        new_code = None
        if last_code is not None:
            while free < _SHRINK_CODES and parents[free] != _SHRINK_UNUSED:
                free += 1
            if free < _SHRINK_CODES:
                new_code = free
                parents[new_code] = last_code
                suffixes[new_code] = last_head
                free += 1
        string = bytearray()
        node = code
        while node >= _SHRINK_FIRST_CODE:
            string.append(suffixes[node])
            node = parents[node]
            if node == _SHRINK_UNUSED or len(string) >= _SHRINK_CODES:
                raise ValueError(F'The Shrink code {code} does not belong to any string.')
        string.append(node)
        if new_code is not None:
            suffixes[new_code] = node
        string.reverse()
        output.extend(string)
        last_code = code
        last_head = node
    del output[size:]
    return output


def _reduce_symbols(bits: BitLDecoder, output: bytearray, size: int) -> Iterator[int]:
    followers: list[bytes] = [B''] * 0x100
    for byte in reversed(range(0x100)):
        count = bits.read_bits(6)
        followers[byte] = bytes(bits.read_bits(8) for _ in range(count))
    widths = [max(1, (len(follower) - 1).bit_length()) for follower in followers]
    last = 0
    while True:
        if not (follower := followers[last]) or bits.read_bits(1):
            last = bits.read_bits(8)
        elif (index := bits.read_bits(widths[last])) < len(follower):
            last = follower[index]
        else:
            raise ValueError(F'The Reduce stream references follower {index} of {len(follower)}.')
        if bits.extra_bits_were_read():
            raise _truncated('Reduce', output, size)
        yield last


def unreduce(data: buf, size: int, factor: int) -> bytearray:
    """
    Decompress `size` bytes from a stream that uses the Reduce method with the given compression
    factor from 1 to 4, which corresponds to the ZIP compression methods 2 to 5. The stream starts
    with a follower set for each byte value, which lists the bytes that are likely to follow it.
    The bytes that these sets decode contain back-references, which start with the byte 0x90.
    Back-references to data before the start of the output read zeros.
    """
    if factor not in range(1, 5):
        raise ValueError(F'Invalid Reduce compression factor {factor}.')
    bits = BitLDecoder(StructReader(memoryview(data)))
    output = bytearray()
    symbols = _reduce_symbols(bits, output, size)
    length_mask = 0xFF >> factor
    while len(output) < size:
        if (byte := next(symbols)) != _REDUCE_ESCAPE:
            output.append(byte)
            continue
        if not (reference := next(symbols)):
            output.append(_REDUCE_ESCAPE)
            continue
        if (length := reference & length_mask) == length_mask:
            length += next(symbols)
        distance = ((reference >> (8 - factor)) << 8) + next(symbols) + 1
        _copy(output, distance, length + 3)
    del output[size:]
    return output


class _ComplementedBits(BitDecoderBase):
    __slots__ = '_bits',

    def __init__(self, bits: BitLDecoder):
        self._bits = bits

    def get_value(self, num_bits: int) -> int:
        return self._bits.get_value(num_bits) ^ ((1 << num_bits) - 1)

    def move_position(self, num_bits: int):
        self._bits.move_position(num_bits)


def _shannon_fano_tree(bits: BitLDecoder, count: int) -> HuffmanDecoder:
    lengths = bytearray()
    for _ in range(bits.read_aligned_byte() + 1):
        record = bits.read_aligned_byte()
        lengths.extend([(record & 0xF) + 1] * ((record >> 4) + 1))
    if len(lengths) != count:
        raise ValueError(F'The Implode stream has a tree with {len(lengths)} instead of {count} codes.')
    if sum(1 << (_IMPLODE_CODE_BITS - length) for length in lengths) != 1 << _IMPLODE_CODE_BITS:
        raise ValueError('The Implode stream has an incomplete or oversubscribed tree.')
    tree = HuffmanDecoder(_IMPLODE_CODE_BITS, count)
    tree.build(lengths)
    return tree


def explode(
    data: buf,
    size: int,
    large_window: bool,
    literal_tree: bool,
    pkzip101: bool = False,
) -> bytearray:
    """
    Decompress `size` bytes from a stream that uses the Implode method. The window is 8K large if
    `large_window` is set and 4K large otherwise; `literal_tree` indicates that literals are coded
    by a tree rather than stored as plain bytes. The minimum length of a back-reference is 3 when
    there is a literal tree and 2 otherwise. PKZIP 1.01 and 1.02 derived it from the window size
    instead, which `pkzip101` selects. Back-references to data before the start of the output read
    zeros. The stream stores its Shannon-Fano codes as the bitwise complement of canonical Huffman
    codes, so `refinery.lib.seven.huffman.HuffmanDecoder` decodes them from a complemented view of
    the bit stream.
    """
    bits = BitLDecoder(StructReader(memoryview(data)))
    codes = _ComplementedBits(bits)
    output = bytearray()
    literals = _shannon_fano_tree(bits, 0x100) if literal_tree else None
    lengths = _shannon_fano_tree(bits, 0x40)
    distances = _shannon_fano_tree(bits, 0x40)
    if bits.extra_bits_were_read():
        raise _truncated('Implode', output, size)
    low_distance_bits = 7 if large_window else 6
    min_length = 3 if (large_window if pkzip101 else literal_tree) else 2
    while len(output) < size:
        if bits.read_bits(1):
            output.append(literals.decode(codes) if literals else bits.read_bits(8))
        else:
            distance = bits.read_bits(low_distance_bits)
            distance |= distances.decode(codes) << low_distance_bits
            if (length := lengths.decode(codes)) == 0x3F:
                length += bits.read_bits(8)
            _copy(output, distance + 1, length + min_length)
        if bits.extra_bits_were_read():
            raise _truncated('Implode', output, size)
    del output[size:]
    return output
