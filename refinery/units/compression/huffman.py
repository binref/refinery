#!/usr/bin/env python3
# -*- coding:utf-8 -*-
from __future__ import annotations

import heapq

from refinery.lib.meta import MV, metavars
from refinery.lib.types import Param, asbuffer, buf
from refinery.units import Arg, RefineryCriticalException, Unit

_LENS_VAR = 'lens'


class huffman(Unit):
    """
    Compress and decompress data with a canonical Huffman code.

    The codes are assigned canonically, following the algorithm from RFC 1951; in ascending order
    of code length and, within the same length, in ascending order of the symbol value. This
    convention is used by DEFLATE, JPEG, and many bespoke implementations.

    By default, the table is expected in "lengths" layout: one byte per symbol, where the byte at
    offset `i` is the code length of the symbol `i`, and a length of zero means that the symbol is
    not in the alphabet. In "pairs" layout, the table is a sequence of two-byte pairs of symbol and
    code length, which allows the alphabet to be sparse.

    In reverse mode, the code length table is computed from the byte frequencies of the input when
    none is provided, and attached to the output chunk as the `{}` meta variable, along with the
    `count` of encoded symbols. In decoding mode, both meta variables on the input chunk are used
    when the corresponding arguments are not given.
    """

    _REVERSED_BITS = bytes(int('{:08b}'.format(k)[::-1], 2) for k in range(256))

    def __init__(
        self,
        lens: Param[buf, Arg.Binary(help=(
            'The code length table data.'))] = b'',
        pairs: Param[bool, Arg.Switch('-p', help=(
            'Specify when the code length data uses pairs layout; the default is lengths-based.'
        ))] = False,
        lsb: Param[bool, Arg.Switch('-l', help=(
            'Use least significant bit (LSB) packing order; default is MSB. Most formats pack'
            ' codes MSB-first, but e.g. DEFLATE and LZX pack them LSB-first.'
        ))] = False,
        count: Param[int, Arg.Number('-c', help=(
            'Number of symbols to decode; by default, this number is taken from the count meta '
            'variable when present, and the unit otherwise decodes until the stream is exhausted, '
            'i.e. until fewer bits remain than the shortest code is long. Since padding bits at '
            'the end of the stream can accidentally form a valid code, it is safer to provide '
            'this count when it is known.'
        ))] = 0,
    ):
        super().__init__(lens=lens, pairs=pairs, lsb=lsb, count=count)

    def _parse_lengths(self, table: buf) -> list[tuple[int, int]]:
        """
        Returns the (symbol, code length) pairs from the table in the requested layout.
        """
        if not self.args.pairs:
            return [(s, l) for s, l in enumerate(table) if l > 0]
        if len(table) % 2:
            raise RefineryCriticalException('a table in pairs layout must have an even number of bytes')
        return [(table[k], table[k + 1]) for k in range(0, len(table), 2) if table[k + 1] > 0]

    def _canonical_codes(self, lengths: list[tuple[int, int]]) -> dict[int, tuple[int, int]]:
        """
        Given a list of (symbol, code length) pairs, returns a dictionary mapping each
        symbol to a (code length, code) tuple, using canonical code assignment (RFC 1951).
        """
        if not lengths:
            return {}
        max_len = max(l for _, l in lengths)
        if max_len > 64:
            raise RefineryCriticalException('a code length of more than 64 bits is not supported')
        count = [0] * (max_len + 1)
        for _, length in lengths:
            count[length] += 1
        if sum(count[k] << (max_len - k) for k in range(1, max_len + 1)) > (1 << max_len):
            raise RefineryCriticalException('the code length table is over-subscribed')
        code = -1
        prev = 0
        codes: dict[int, tuple[int, int]] = {}
        for symbol, length in sorted(lengths, key=lambda p: (p[1], p[0])):
            code = (code + 1) << (length - prev)
            codes[symbol] = (length, code)
            prev = length
        return codes

    def _optimal_lengths(self, data: buf) -> dict[int, tuple[int, int]]:
        """
        Computes an optimal code length for each byte value occurring in the input and
        returns the canonical codes, i.e. the same dictionary as `_canonical_codes`.
        """
        frequency: dict[int, int] = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        if not frequency:
            return {}
        if len(frequency) == 1:
            return {next(iter(frequency)): (1, 0)}
        # build the Huffman tree with a priority queue over (weight, tie breaker,
        # symbols); the depth of each symbol in that tree is its code length
        forest: list[tuple[int, int, list[int]]] = [
            (weight, k, [symbol]) for k, (symbol, weight) in enumerate(frequency.items())]
        heapq.heapify(forest)
        depth = dict.fromkeys(frequency, 0)
        while len(forest) > 1:
            weight_a, _, a = heapq.heappop(forest)
            weight_b, _, b = heapq.heappop(forest)
            for symbol in a + b:
                depth[symbol] += 1
            forest.append((weight_a + weight_b, -1, a + b))
        return self._canonical_codes([(symbol, length) for symbol, length in depth.items()])

    def _decode(self, data: buf, codes: dict[int, tuple[int, int]], count: int) -> tuple[bytes, int]:
        """
        Decode a bit-packed Huffman stream using the given canonical codes; returns the
        decoded data and the number of decoded symbols.
        """
        if not codes:
            return b'', 0
        max_len = max(length for length, _ in codes.values())
        min_len = min(length for length, _ in codes.values())
        if self.args.lsb:
            # after reversing the bits of every byte, the first bit of the stream is the
            # most significant bit of the first byte, and the same extraction code as for
            # MSB-first streams applies
            data = bytes(self._REVERSED_BITS[b] for b in data)
        total = len(data) * 8
        size = len(data)
        fast: list[int] | None = None
        if max_len <= 16:
            fast = [-1] * (1 << max_len)
            for symbol, (length, code) in codes.items():
                shift = max_len - length
                for index in range(code << shift, (code + 1) << shift):
                    fast[index] = symbol
        lookup = {(length, code): symbol for symbol, (length, code) in codes.items()}
        out = bytearray()
        pos = 0
        decoded = 0
        while True:
            if count and decoded >= count:
                break
            if pos + min_len > total:
                break
            symbol = None
            if fast is not None and pos + max_len <= total and (pos >> 3) + 3 <= size:
                # read max_len bits starting at the current position; the first bit of
                # the code is the most significant bit of the extracted value
                offset = pos >> 3
                window = data[offset] << 16 | data[offset + 1] << 8 | data[offset + 2]
                index = (window >> (24 - (pos & 7) - max_len)) & ((1 << max_len) - 1)
                symbol = fast[index]
                if symbol < 0:
                    symbol = None
                else:
                    pos += codes[symbol][0]
            else:
                code = 0
                length = 0
                while length < max_len and pos < total:
                    bit = data[pos >> 3] >> (7 - (pos & 7)) & 1
                    code = code << 1 | bit
                    pos += 1
                    length += 1
                    symbol = lookup.get((length, code))
                    if symbol is not None:
                        break
            if symbol is None:
                # either the padding at the end of the stream or a code that is not in
                # the table; without an explicit count, this is treated as the end
                break
            decoded += 1
            out.append(symbol)
        if count and decoded < count:
            self.log_warn(F'decoded only {decoded} of {count} requested symbols')
        return bytes(out), decoded

    def _encode(self, data: buf, codes: dict[int, tuple[int, int]]) -> buf:
        out = bytearray()
        accumulator = 0
        bits = 0
        lsb = self.args.lsb
        for symbol in data:
            try:
                length, code = codes[symbol]
            except KeyError:
                raise RefineryCriticalException(F'the symbol {symbol:#04x} is not in the alphabet')
            accumulator = accumulator << length | code
            bits += length
            while bits >= 8:
                bits -= 8
                byte = accumulator >> bits & 0xFF
                out.append(self._REVERSED_BITS[byte] if lsb else byte)
            accumulator &= (1 << bits) - 1
        if bits:
            byte = accumulator << 8 - bits & 0xFF
            out.append(self._REVERSED_BITS[byte] if lsb else byte)
        return bytes(out)

    def process(self, data):
        meta = metavars(data)
        lens = self.args.lens
        if not lens:
            lens = meta.get(_LENS_VAR)
        if not (_lens := asbuffer(lens)):
            raise RefineryCriticalException(
                'no code length table was provided, neither as an argument nor as a meta variable')
        codes = self._canonical_codes(self._parse_lengths(_lens))
        count = self.args.count or meta.get(MV.COUNT, 0)
        if not isinstance(count, int):
            raise RefineryCriticalException(
                F'the specified code count was not an integer but an instance of type {type(count).__name__}')
        out, decoded = self._decode(bytes(data), codes, count)
        return self.labelled(out, **{MV.COUNT: decoded})

    def reverse(self, data):
        if self.args.lens:
            codes = self._canonical_codes(self._parse_lengths(bytes(self.args.lens)))
        else:
            codes = self._optimal_lengths(data)
        lens = bytes(codes.get(s, (0, 0))[0] for s in range(256))
        chunk = self._encode(data, codes)
        return self.labelled(chunk, **{MV.COUNT: len(data), _LENS_VAR: lens})


if __d := huffman.__doc__:
    huffman.__doc__ = __d.format(_LENS_VAR)
