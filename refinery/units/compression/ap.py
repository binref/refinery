#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from io import BytesIO, SEEK_END

from .. import Unit

__all__ = ['aplib']


class _bits_compress(BytesIO):
    def __init__(self, tagsize):
        super().__init__()
        self.__tagsize = tagsize
        self.__bitbuffer = 0
        self.__tagoffset = 0
        self.__maxbit = (self.__tagsize * 8) - 1
        self.__bitcount = 0
        self.__is_tagged = False

    def getvalue(self):
        self.update_tag()
        return super().getvalue()

    def update_tag(self):
        self.seek(self.__tagoffset)
        self.write_byte(self.__bitbuffer)
        self.seek(0, SEEK_END)

    def write_bit(self, value):
        if self.__bitcount != 0:
            self.__bitcount -= 1
        else:
            if not self.__is_tagged:
                self.__is_tagged = True
            else:
                self.update_tag()
            self.__tagoffset = self.tell()
            self.write(bytes(self.__tagsize))
            self.__bitcount = self.__maxbit
            self.__bitbuffer = 0
        if value:
            self.__bitbuffer |= (1 << self.__bitcount)

    def write_bit_sequence(self, *bits):
        for bit in bits:
            self.write_bit(bit)

    def write_byte(self, b):
        self.write(bytes((b,)))

    def write_fixednumber(self, value, nbbit):
        for i in range(nbbit - 1, -1, -1):
            self.write_bit((value >> i) & 1)

    def write_variablenumber(self, value):
        assert value >= 2
        length = value.bit_length() - 2
        self.write_bit(value & (1 << length))
        for i in range(length - 1, -1, -1):
            self.write_bit(1)
            self.write_bit(value & (1 << i))
        self.write_bit(0)
        return


class _bits_decompress(BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.__bitcount = 0
        self.__bitbuffer = 0
        self.decompressed = bytearray()

    def read_bit(self):
        return self.read_bits(1)

    def read_byte(self):
        buffer = self.read(1)
        if len(buffer) != 1:
            raise BufferError('received zero bytes from read')
        return buffer[0]

    def read_bits(self, nbits):
        while self.__bitcount < nbits:
            self.__bitbuffer = (self.__bitbuffer << 8) | self.read_byte()
            self.__bitcount += 8
        self.__bitcount -= nbits
        value, self.__bitbuffer = divmod(self.__bitbuffer, (1 << self.__bitcount))
        return value

    def read_variablenumber(self):
        result = 1
        result = (result << 1) + self.read_bit()
        while self.read_bit():
            result = (result << 1) + self.read_bit()
        return result

    def read_setbits(self, max_, set_=1):
        result = 0
        while result < max_ and self.read_bit() == set_:
            result += 1
        return result

    def back_copy(self, offset, length=1):
        for _ in range(length):
            self.decompressed.append(self.decompressed[-offset])
        return

    def read_literal(self, value=None):
        if value is None:
            self.decompressed.append(self.read_byte())
        else:
            self.decompressed.append(value)
        return False


def lengthdelta(offset):
    if offset < 0x80 or 0x7D00 <= offset:
        return 2
    elif 0x500 <= offset:
        return 1
    return 0


class compressor(_bits_compress):
    def __init__(self, data, length=None):
        _bits_compress.__init__(self, 1)
        self.__in = data
        self.__length = length or len(data)
        self.__offset = 0
        self.__lastoffset = 0
        self.__pair = True

    @staticmethod
    def find_longest_match(data, offset):
        pivot = 0
        limit = size = len(data) - offset
        rewind = 0
        while size > 0:
            pos = data.rfind(data[offset : offset + pivot + size], 0, offset)
            if pos == -1:
                size //= 2
                continue
            rewind = offset - pos
            if pivot + size >= limit:
                return rewind, limit
            else:
                pivot += size
        if not pivot:
            return (0, 0)
        return (rewind, pivot)

    def __literal(self, marker=True):
        if marker:
            self.write_bit(0)
        self.write_byte(self.__in[self.__offset])
        self.__offset += 1
        self.__pair = True

    def __block(self, offset, length):
        assert offset >= 2
        self.write_bit_sequence(1, 0)
        if self.__pair and self.__lastoffset == offset:
            self.write_variablenumber(2)
            self.write_variablenumber(length)
        else:
            high = (offset >> 8) + 2
            if self.__pair:
                high += 1
            self.write_variablenumber(high)
            self.write_byte(offset & 0xFF)
            self.write_variablenumber(length - lengthdelta(offset))
        self.__offset += length
        self.__lastoffset = offset
        self.__pair = False

    def __shortblock(self, offset, length):
        assert 2 <= length <= 3
        assert 0 < offset <= 127
        self.write_bit_sequence(1, 1, 0)
        b = (offset << 1) + (length - 2)
        self.write_byte(b)
        self.__offset += length
        self.__lastoffset = offset
        self.__pair = False

    def __singlebyte(self, offset):
        assert 0 <= offset < 16
        self.write_bit_sequence(1, 1, 1)
        self.write_fixednumber(offset, 4)
        self.__offset += 1
        self.__pair = True

    def __end(self):
        self.write_bit_sequence(1, 1, 0)
        self.write_byte(0)

    def compress(self):
        self.__literal(False)
        while self.__offset < self.__length:
            offset, length = self.find_longest_match(self.__in, self.__offset)
            if length == 0:
                c = self.__in[self.__offset]
                if c == 0:
                    self.__singlebyte(0)
                else:
                    self.__literal()
            elif length == 1 and 0 <= offset < 16:
                self.__singlebyte(offset)
            elif 2 <= length <= 3 and 0 < offset <= 127:
                self.__shortblock(offset, length)
            elif 3 < length and 2 <= offset:
                self.__block(offset, length)
            else:
                self.__literal()
        self.__end()
        return self.getvalue()


class decompressor(_bits_decompress):
    def __init__(self, data):
        super().__init__(data)
        self.__pair = True
        self.__lastoffset = 0
        self.__functions = [
            self.__literal,
            self.__block,
            self.__shortblock,
            self.__singlebyte
        ]

    def __literal(self):
        self.read_literal()
        self.__pair = True
        return False

    def __block(self):
        b = self.read_variablenumber()
        if b == 2 and self.__pair:
            offset = self.__lastoffset
            length = self.read_variablenumber()
        else:
            high = b - 2
            if self.__pair:
                high -= 1
            offset = (high << 8) + self.read_byte()
            length = self.read_variablenumber()
            length += lengthdelta(offset)
        self.__lastoffset = offset
        self.back_copy(offset, length)
        self.__pair = False
        return False

    def __shortblock(self):
        b = self.read_byte()
        if b <= 1:  # likely 0
            return True
        length = 2 + (b & 0x01)  # 2-3
        offset = b >> 1  # 1-127
        self.back_copy(offset, length)
        self.__lastoffset = offset
        self.__pair = False
        return False

    def __singlebyte(self):
        offset = self.read_bits(4)  # 0-15
        if offset:
            self.back_copy(offset)
        else:
            self.read_literal(0)
        self.__pair = True
        return False

    def decompress(self):
        self.seek(0)
        self.read_literal()
        while not self.__functions[self.read_setbits(3)]():
            continue
        return self.decompressed


class aplib(Unit):
    """
    APLib compression and decompression.
    """

    def reverse(self, buf):
        return compressor(buf).compress()

    def process(self, buf):
        return decompressor(buf).decompress()
