#!/usr/bin/env python
# ============================ MOTIFICATION NOTE ============================
# The content of this file has been modified for use in binary refinery; it
# has been ported from Python2 to Python3 and the BZip2 implementation was
# rewritten to support NSIS-specific BZip stream and block headers, which are
# different from the official standard values. The original code was taken
# from the following location:
#  https://github.com/pfalcon/pyflate/blob/master/pyflate.py

# ============================ ORIGINAL LICENSING ============================
# Copyright 2006--2007-01-21 Paul Sladen
#  http://www.paul.sladen.org/projects/compression/
#
# You may use and distribute this code under any DFSG-compatible license (eg.
# BSD, GNU GPLv2).
#
# Stand-alone pure-Python DEFLATE (gzip) and bzip2 decoder/decompressor. This
# is probably most useful for research purposes/index building; there is
# certainly some room for improvement in the Huffman bit-matcher.
#
# With the as-written implementation, there was a known bug in BWT decoding
# to do with repeated strings. This has been worked around; see bwt_reverse().
# Correct output is produced in all test cases but ideally the problem would
# be found...
# ============================================================================
from __future__ import annotations
from typing import List, Tuple, Iterable, Optional, BinaryIO

import itertools
import abc


class BitfieldBase(abc.ABC):

    def __init__(self, x):
        if isinstance(x, BitfieldBase):
            self.f = x.f
            self.bits = x.bits
            self.bitfield = x.bitfield
            self.count = x.bitfield
        else:
            self.f = x
            self.bits = 0
            self.bitfield = 0x0
            self.count = 0

    def _read(self, n):
        s = self.f.read(n)
        if not s:
            raise RuntimeError('length error')
        self.count += len(s)
        return s

    def needbits(self, n):
        while self.bits < n:
            self._more()

    def _mask(self, n):
        return (1 << n) - 1

    def toskip(self):
        return self.bits & 0x7

    def align(self):
        self.readbits(self.toskip())

    def dropbits(self, n=8):
        while n >= self.bits and n > 7:
            n -= self.bits
            self.bits = 0
            n -= len(self.f._read(n >> 3)) << 3
        if n:
            self.readbits(n)

    def dropbytes(self, n=1):
        self.dropbits(n << 3)

    def tell(self):
        return self.count - ((self.bits + 7) >> 3), 7 - ((self.bits - 1) & 0x7)

    def tellbits(self):
        bytes, bits = self.tell()
        return (bytes << 3) + bits

    @abc.abstractmethod
    def _more(self):
        pass

    @abc.abstractmethod
    def snoopbits(self, n=8):
        pass

    @abc.abstractmethod
    def readbits(self, n=8):
        pass


class LBitfield(BitfieldBase):

    def _more(self):
        c = self._read(1)
        self.bitfield += c[0] << self.bits
        self.bits += 8

    def snoopbits(self, n=8):
        if n > self.bits:
            self.needbits(n)
        return self.bitfield & self._mask(n)

    def readbits(self, n=8):
        if n > self.bits:
            self.needbits(n)
        r = self.bitfield & self._mask(n)
        self.bits -= n
        self.bitfield >>= n
        return r


class RBitfield(BitfieldBase):

    def _more(self):
        c = self._read(1)
        self.bitfield <<= 8
        self.bitfield += c[0]
        self.bits += 8

    def snoopbits(self, n=8):
        if n > self.bits:
            self.needbits(n)
        return (self.bitfield >> (self.bits - n)) & self._mask(n)

    def readbits(self, n=8):
        if n > self.bits:
            self.needbits(n)
        r = (self.bitfield >> (self.bits - n)) & self._mask(n)
        self.bits -= n
        self.bitfield &= ~(self._mask(n) << self.bits)
        return r


class HuffmanLength:
    code: int
    bits: int
    symbol: Optional[int]
    reverse_symbol: Optional[int]

    def __init__(self, code, bits=0):
        self.code = code
        self.bits = bits
        self.symbol = None
        self.reverse_symbol = None

    def __lt__(self, other):
        return self.__cmp(other) < 0

    def __gt__(self, other):
        return self.__cmp(other) > 0

    def __eq__(self, other):
        return self.__cmp(other) == 0

    def __le__(self, other):
        return self.__cmp(other) <= 0

    def __ge__(self, other):
        return self.__cmp(other) >= 0

    def __ne__(self, other):
        return self.__cmp(other) != 0

    def __cmp(self, other):
        a, b = self.bits, other.bits
        if a == b:
            a, b = self.code, other.code
        return (a > b) - (a < b)


def reverse_bits(v: int, n: int):
    a = 1 << 0
    b = 1 << (n - 1)
    z = 0
    for i in range(n - 1, -1, -2):
        z |= (v >> i) & a
        z |= (v << i) & b
        a <<= 1
        b >>= 1
    return z


def reverse_bytes(v, n):
    a = 0xff << 0
    b = 0xff << (n - 8)
    z = 0
    for i in range(n - 8, -8, -16):
        z |= (v >> i) & a
        z |= (v << i) & b
        a <<= 8
        b >>= 8
    return z


class HuffmanTable:
    table: List[HuffmanLength]

    def __init__(self, bootstrap):
        table = []
        start, bits = bootstrap[0]
        for finish, endbits in bootstrap[1:]:
            if bits:
                for code in range(start, finish):
                    table.append(HuffmanLength(code, bits))
            start, bits = finish, endbits
            if endbits == -1:
                break
        table.sort()
        self.table = table

    def populate_huffman_symbols(self):
        bits, symbol = -1, -1
        for x in self.table:
            symbol += 1
            if x.bits != bits:
                symbol <<= (x.bits - bits)
                bits = x.bits
            x.symbol = symbol
            x.reverse_symbol = reverse_bits(symbol, bits)

    def min_max_bits(self):
        self.min_bits, self.max_bits = 16, -1
        for x in self.table:
            if x.bits < self.min_bits: self.min_bits = x.bits
            if x.bits > self.max_bits: self.max_bits = x.bits

    def _find_symbol(self, bits: int, symbol: int, table: Iterable[HuffmanLength]) -> int:
        for h in table:
            if h.bits == bits and h.reverse_symbol == symbol:
                return h.code
        return -1

    def find_next_symbol(self, field: LBitfield, reversed=True):
        cached_length = -1
        cached = None
        for x in self.table:
            if cached_length != x.bits:
                cached = field.snoopbits(x.bits)
                cached_length = x.bits
            if (reversed and x.reverse_symbol == cached) or (not reversed and x.symbol == cached):
                field.readbits(x.bits)
                return x.code
        raise RuntimeError(F'symbol not found even after end of table at {field.tell()}')


class OrderedHuffmanTable(HuffmanTable):
    def __init__(self, lengths):
        _ordered_lengths = list(enumerate(lengths))
        _ordered_lengths.append((len(lengths), -1))
        super().__init__(_ordered_lengths)


CODE_LENGTH_ORDERS = (
    0x10, 0x11, 0x12, 0x00, 0x08, 0x07, 0x09, 0x06, 0x0A, 0x05,
    0x0B, 0x04, 0x0C, 0x03, 0x0D, 0x02, 0x0E, 0x01, 0x0F)

DISTANCE_BASE = (
    0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0007, 0x0009, 0x000D, 0x0011, 0x0019,
    0x0021, 0x0031, 0x0041, 0x0061, 0x0081, 0x00C1, 0x0101, 0x0181, 0x0201, 0x0301,
    0x0401, 0x0601, 0x0801, 0x0C01, 0x1001, 0x1801, 0x2001, 0x3001, 0x4001, 0x6001)

LENGTH_BASE = (
    0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x000B, 0x000D,
    0x000F, 0x0011, 0x0013, 0x0017, 0x001B, 0x001F, 0x0023, 0x002B, 0x0033, 0x003B,
    0x0043, 0x0053, 0x0063, 0x0073, 0x0083, 0x00A3, 0x00C3, 0x00E3, 0x0102)


def extra_distance_bits(n):
    if 0 <= n <= 1:
        return 0
    elif 2 <= n <= 29:
        return (n >> 1) - 1
    else:
        raise RuntimeError('illegal distance code')


def extra_length_bits(n):
    if 257 <= n <= 260 or n == 285:
        return 0
    elif 261 <= n <= 284:
        return ((n - 257) >> 2) - 1
    else:
        raise RuntimeError('illegal length code')


def move_to_front(array: list, index):
    array[:] = itertools.chain(
        itertools.islice(array, index, index + 1),
        itertools.islice(array, 0, index),
        itertools.islice(array, index + 1, None)
    )


def bwt_transform(data):
    tmp = bytearray(sorted(data))
    base = list(map(tmp.find, range(256)))
    pointers = [-1] * len(data)
    for i, symbol in enumerate(data):
        pointers[base[symbol]] = i
        base[symbol] += 1
    return pointers


def bwt_reverse(data, end):
    out = bytearray(len(data))
    transform = bwt_transform(data)

    # STRAGENESS WARNING: There was a bug somewhere here in that
    # if the output of the BWT resolves to a perfect copy of N
    # identical strings (think exact multiples of 255 'X' here),
    # then a loop is formed.  When decoded, the output string would
    # be cut off after the first loop, typically '\0\0\0\0\xfb'.
    # The previous loop construct was:
    #
    #  next = T[end]
    #  while next != end:
    #      out += L[next]
    #      next = T[next]
    #  out += L[next]
    #
    # For the moment, I've instead replaced it with a check to see
    # if there has been enough output generated.  I didn't figured
    # out where the off-by-one-ism is yet---that actually produced
    # the cyclic loop.

    for i in range(len(data)):
        end = transform[end]
        out[i] = data[end]

    return out


class _DecompressionFile(abc.ABC):

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def writable(self) -> bool:
        return False

    def write(self, __b):
        raise NotImplementedError

    data: BinaryIO
    bits: BitfieldBase
    nsis: bool
    done: bool
    current_block: bytearray

    def __init__(self, data: BinaryIO, nsis: bool = True):
        self.data = data
        self.nsis = nsis
        self.done = False
        self.current_block = bytearray()

    def readall(self) -> bytes:
        return self.read()

    def readinto(self, __buffer):
        data = self.read(len(__buffer))
        size = len(data)
        __buffer[:size] = data
        return size

    def read(self, size=-1):
        while size not in range(len(self.current_block)):
            if not self._readblock():
                break
        block = self.current_block
        if size < 0 or size >= len(block):
            self.current_block = bytearray()
            return block
        else:
            out = block[:size]
            del block[:size]
            return out

    @abc.abstractmethod
    def _readblock(self) -> bool:
        pass


class BZip2File(_DecompressionFile):

    blocksize: int
    block_header_size: int
    block_header_type: Tuple[int, int]
    current_block: bytearray

    def __init__(self, data: BinaryIO, nsis: bool = True):
        super().__init__(data, nsis)
        self.bits = RBitfield(data)

        if nsis:
            self.blocksize = 9
            self.block_header_size = 8
            self.block_header_type = (0x31, 0x17)
        else:
            if data.read(2) != b'BZ':
                raise RuntimeError('BZip2 header magic is missing')
            if self.bits.readbits(8) != ord('h'):
                raise RuntimeError('BZip2 header contains unknown compression method')
            blocksize = self.bits.readbits(8)
            if 0x31 <= blocksize <= 0x39:
                blocksize = blocksize - 0x30
            else:
                raise RuntimeError('BZip2 header specifies invalid block size')
            self.blocksize = blocksize
            self.block_header_size = 48
            self.block_header_type = (0x314159265359, 0x177245385090)

        self.blocksize *= 100_000

    def _readblock(self):
        out = self.current_block
        if self.done:
            return False
        br = self.bits
        blocktype = br.readbits(self.block_header_size)
        if not self.nsis:
            _ = br.readbits(32) # crc
        if blocktype == self.block_header_type[0]:
            if not self.nsis and br.readbits(1):
                raise RuntimeError('BZip2 randomised support not implemented')
            pointer = br.readbits(24)
            huffman_used_map = br.readbits(16)
            map_mask = 1 << 15
            used = []
            while map_mask > 0:
                if huffman_used_map & map_mask:
                    huffman_used_bitmap = br.readbits(16)
                    bit_mask = 1 << 15
                    while bit_mask > 0:
                        if huffman_used_bitmap & bit_mask:
                            pass
                        used += [bool(huffman_used_bitmap & bit_mask)]
                        bit_mask >>= 1
                else:
                    used += [False] * 16
                map_mask >>= 1
            huffman_groups = br.readbits(3)
            if not 2 <= huffman_groups <= 6:
                raise RuntimeError('BZip2 number of Huffman groups not in range 2..6')
            selectors_used = br.readbits(15)
            mtf = list(range(huffman_groups))
            selectors_list = []
            for i in range(selectors_used):
                c = 0
                while br.readbits(1):
                    c += 1
                    if c >= huffman_groups:
                        raise RuntimeError('BZip2 chosen selector greater than number of groups (max 6)')
                if c >= 0:
                    move_to_front(mtf, c)
                selectors_list += mtf[0:1]
            groups_lengths = []
            symbols_in_use = sum(used) + 2  # remember RUN[AB] RLE symbols
            for _ in range(huffman_groups):
                length = br.readbits(5)
                lengths = []
                for i in range(symbols_in_use):
                    if not 0 <= length <= 20:
                        raise RuntimeError('BZip2 Huffman length code outside range 0..20')
                    while br.readbits(1):
                        length -= (br.readbits(1) * 2) - 1
                    lengths += [length]
                groups_lengths += [lengths]

            tables = []
            for g in groups_lengths:
                codes = OrderedHuffmanTable(g)
                codes.populate_huffman_symbols()
                codes.min_max_bits()
                tables.append(codes)

            favourites = [y for y, x in enumerate(used) if x]
            selector_pointer = 0
            decoded = 0
            repeat = repeat_power = 0
            buffer = bytearray()
            t = None
            while True:
                decoded -= 1
                if decoded <= 0:
                    decoded = 50
                    if selector_pointer <= len(selectors_list):
                        t = tables[selectors_list[selector_pointer]]
                        selector_pointer += 1
                r = t.find_next_symbol(br, False)
                if 0 <= r <= 1:
                    if repeat == 0:
                        repeat_power = 1
                    repeat += repeat_power << r
                    repeat_power <<= 1
                    continue
                elif repeat > 0:
                    buffer.extend(itertools.repeat(favourites[0], repeat))
                    repeat = 0
                if r == symbols_in_use - 1:
                    break
                else:
                    o = favourites[r - 1]
                    move_to_front(favourites, r - 1)
                    buffer.append(o)
            # RLE step
            nt = bwt_reverse(buffer, pointer)
            done = bytearray()
            n = len(nt)
            i = 0
            while i < n:
                if i < n - 4 and nt[i] == nt[i + 1] == nt[i + 2] == nt[i + 3]:
                    done.extend(itertools.repeat(nt[i], nt[i + 4] + 4))
                    i += 5
                else:
                    done.append(nt[i])
                    i += 1
            out.extend(done)
            return True
        elif blocktype == self.block_header_type[1]:
            br.align()
            self.done = True
            return False
        else:
            raise RuntimeError(
                F'unknown BZip2 block value 0x{blocktype:0{self.block_header_size // 4}X}')


class GZipFile(_DecompressionFile):

    def __init__(self, data: BinaryIO, nsis: bool = True):
        super().__init__(data, nsis)
        br = self.bits = LBitfield(data)
        if self.data.read(2) != b'\x1F\x8B':
            raise RuntimeError('Unknown (not 1F8B) header')
        if br.readbits(8) != 8:
            raise RuntimeError('Unknown (not type 8 DEFLATE) compression method')
        self.flags = br.readbits(8)
        self.mtime = br.readbits(32)
        self.extra_flags = br.readbits(8)
        self.os_type = br.readbits(8)
        self.file_name = ''
        self.comment = ''

        if self.flags & 0x04:
            # structured GZ_FEXTRA miscellaneous data
            xlen = br.readbits(16)
            br.dropbytes(xlen)
        while self.flags & 0x08:
            # original GZ_FNAME filename
            cc = br.readbits(8)
            if not cc:
                break
            self.file_name += chr(cc)
        while self.flags & 0x10:
            # human readable GZ_FCOMMENT
            cc = br.readbits(8)
            if not cc:
                break
            self.comment += chr(cc)
        if self.flags & 0x02:
            # header-only GZ_FHCRC checksum
            br.readbits(16)

    def _readblock(self) -> bool:
        if self.done:
            return False
        br = self.bits
        out = self.current_block
        lastbit = br.readbits(1)
        blocktype = br.readbits(2)

        def _error_unused(msg):
            return RuntimeError(F'illegal unused {msg} in use at {br.tell()}')

        if blocktype == 0:
            br.align()
            length = br.readbits(16)
            if length & br.readbits(16):
                raise RuntimeError('stored block lengths do not match each other')
            if not br.bits:
                it = self.data.read(length)
            else:
                it = (br.readbits(8) for _ in range(length))
            out.extend(it)

        elif blocktype == 1 or blocktype == 2:
            main_literals, main_distances = None, None

            if blocktype == 1: # Static Huffman
                static_huffman_bootstrap = [(0, 8), (144, 9), (256, 7), (280, 8), (288, -1)]
                static_huffman_lengths_bootstrap = [(0, 5), (32, -1)]
                main_literals = HuffmanTable(static_huffman_bootstrap)
                main_distances = HuffmanTable(static_huffman_lengths_bootstrap)

            elif blocktype == 2: # Dynamic Huffman
                len_codes = br.readbits(5)
                literals = len_codes + 257
                distances = br.readbits(5) + 1
                code_lengths_length = br.readbits(4) + 4
                table = [0] * 19
                for i in range(code_lengths_length):
                    table[CODE_LENGTH_ORDERS[i]] = br.readbits(3)
                dynamic_codes = OrderedHuffmanTable(table)
                dynamic_codes.populate_huffman_symbols()
                dynamic_codes.min_max_bits()

                # Decode the code_lengths for both tables at once,
                # then split the list later

                code_lengths = []
                n = 0
                while n < (literals + distances):
                    r = dynamic_codes.find_next_symbol(br)
                    if 0 <= r <= 15: # literal bitlength for this code
                        count = 1
                        what = r
                    elif r == 16: # repeat last code
                        count = 3 + br.readbits(2)
                        # Is this supposed to default to '0' if in the zeroth position?
                        what = code_lengths[-1]
                    elif r == 17: # repeat zero
                        count = 3 + br.readbits(3)
                        what = 0
                    elif r == 18: # repeat zero lots
                        count = 11 + br.readbits(7)
                        what = 0
                    else:
                        raise RuntimeError('next code length is outside of the range 0 <= r <= 18')
                    code_lengths += [what] * count
                    n += count

                main_literals = OrderedHuffmanTable(code_lengths[:literals])
                main_distances = OrderedHuffmanTable(code_lengths[literals:])

            main_literals.populate_huffman_symbols()
            main_distances.populate_huffman_symbols()
            main_literals.min_max_bits()
            main_distances.min_max_bits()
            literal_count = 0

            while True:
                r = main_literals.find_next_symbol(br)
                if 0 <= r <= 255:
                    literal_count += 1
                    out.append(r)
                elif r == 256:
                    if literal_count > 0:
                        literal_count = 0
                    break
                elif 257 <= r <= 285: # dictionary lookup
                    if literal_count > 0:
                        literal_count = 0
                    length_extra = br.readbits(extra_length_bits(r))
                    length = LENGTH_BASE[r - 257] + length_extra

                    r1 = main_distances.find_next_symbol(br)
                    if 0 <= r1 <= 29:
                        distance = DISTANCE_BASE[r1] + br.readbits(extra_distance_bits(r1))
                        while length > distance:
                            out += out[-distance:]
                            length -= distance
                        if length == distance:
                            out += out[-distance:]
                        else:
                            out += out[-distance:length - distance]
                    elif 30 <= r1 <= 31:
                        raise _error_unused('distance symbol')
                elif 286 <= r <= 287:
                    raise _error_unused('literal/length symbol')
        elif blocktype == 3:
            raise _error_unused('blocktype')

        if lastbit:
            self.done = True
            br.align()
            _ = br.readbits(32) # crc
            _ = br.readbits(32) # length
            return False
        else:
            return True
