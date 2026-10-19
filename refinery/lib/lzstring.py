"""
Decompression for the format of [lz-string][LZ], the LZ-based string compression library for
JavaScript. The format reads a stream of bits out of a sequence of numbers, each of which carries a
fixed count of them; `decompress_from_utf16` reads the variant that stores 15 bits in each UTF-16
code unit of a string, offset by 32.

This code is derived from the JavaScript implementation in the lz-string package.

The original work is copyright (c) 2013 pieroxy.

The source code has been modified to fit the code requirements of this project.

The original implementation is covered by an MIT license. Regardless of the
license used for the binary refinery, this code file is also subject to the
terms and conditions of the MIT license, which is included here:

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

[LZ]: https://github.com/pieroxy/lz-string
"""
from __future__ import annotations

from typing import Callable


def decompress_from_utf16(text: str, limit: int | None = None) -> str | None:
    """
    What the library's `decompressFromUTF16` returns for *text*, a string given as its UTF-16 code
    units, one to a character, and returned the same way: `None` where the library returns `null`,
    which it does for the empty string and for a stream naming an entry its dictionary does not
    hold yet. A stream whose first code the library has no case for raises `ValueError`: the
    library goes on with an entry that is `undefined`, which no output of its compressor holds.
    The output of a stream can grow with the square of its length, and a stream whose output
    would exceed *limit* characters raises `ValueError` once it does.
    """
    if not text:
        return None
    length = len(text)
    return _decompress(length, 16384, lambda index: ord(text[index]) - 32 if index < length else 0, limit)


def _decompress(
    length: int,
    reset: int,
    value_at: Callable[[int], int],
    limit: int | None = None,
) -> str | None:
    """
    The library's `_decompress`. A number past the end of the input reads as zero bits, as the
    `NaN` the library reads there does under its bitwise `and`. Every entry of the dictionary but
    the first is one already written to the output and one more character, so bounding the output
    by *limit* bounds the dictionary as well.
    """
    dictionary: dict[int, str] = {}
    enlarge_in = 4
    size = 4
    width = 3
    result: list[str] = []
    value = value_at(0)
    position = reset
    index = 1

    def read(count: int) -> int:
        nonlocal value, position, index
        bits = 0
        for power in range(count):
            bit = value & position
            position >>= 1
            if position == 0:
                position = reset
                value = value_at(index)
                index += 1
            if bit > 0:
                bits |= 1 << power
        return bits

    kind = read(2)
    if kind == 0:
        entry = chr(read(8))
    elif kind == 1:
        entry = chr(read(16))
    elif kind == 2:
        return ''
    else:
        raise ValueError('the stream starts with a code the library reads no first entry for')
    dictionary[3] = entry
    previous = entry
    result.append(entry)
    total = len(entry)
    while True:
        if index > length:
            return ''
        code = read(width)
        if code == 0 or code == 1:
            dictionary[size] = chr(read(8 if code == 0 else 16))
            size += 1
            code = size - 1
            enlarge_in -= 1
        elif code == 2:
            return ''.join(result)
        if enlarge_in == 0:
            enlarge_in = 1 << width
            width += 1
        if code in dictionary:
            entry = dictionary[code]
        elif code == size:
            entry = previous + previous[0]
        else:
            return None
        result.append(entry)
        total += len(entry)
        if limit is not None and total > limit:
            raise ValueError(F'the decompressed text exceeds {limit} characters')
        dictionary[size] = previous + entry[0]
        size += 1
        enlarge_in -= 1
        previous = entry
        if enlarge_in == 0:
            enlarge_in = 1 << width
            width += 1
