from __future__ import annotations

from io import SEEK_END, BytesIO

from refinery.units import Unit

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

    __slots__ = 'bitcount', 'bitbuffer', 'bytebuf', 'decompressed'

    def __init__(self, data):
        super().__init__(data)
        self.bitcount = 0
        self.bitbuffer = 0
        self.bytebuf = bytearray(1)
        self.decompressed = bytearray()

    def read_byte(self):
        bb = self.bytebuf
        if self.readinto(bb) != 1:
            raise EOFError
        return bb[0]

    def read_bits(self, nbits=1):
        r1 = self.bytebuf
        bc = self.bitcount
        bb = self.bitbuffer
        while bc < nbits:
            if self.readinto(r1) != 1:
                raise EOFError
            bb <<= 8
            bb |= r1[0]
            bc += 8
        bc -= nbits
        value, bb = divmod(bb, (1 << bc))
        self.bitbuffer = bb
        self.bitcount = bc
        return value

    def read_variablenumber(self):
        bit = self.read_bits
        result = 1
        result = (result << 1) + bit()
        while bit():
            result = (result << 1) + bit()
        return result

    def back_copy(self, offset, length=1):
        buffer = self.decompressed
        if offset == 0:
            end = len(buffer)
            buffer[end:end + length] = (buffer[0] for _ in range(length))
        elif 1 <= length <= 8:
            append = buffer.append
            for _ in range(length):
                append(buffer[-offset])
        else:
            write = buffer.extend
            rep, rest = divmod(length, offset)
            offset = len(buffer) - offset
            if offset < 0:
                raise IndexError
            if rep > 0:
                head = buffer[offset:]
                for _ in range(rep):
                    write(head)
            if rest > 0:
                write(buffer[offset:offset + rest])


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

    __slots__ = 'pair', 'lastoffset'

    def __init__(self, data):
        super().__init__(data)
        self.pair = True
        self.lastoffset = 0

    def literal(self):
        self.decompressed.append(self.read_byte())
        self.pair = True
        return False

    def block(self):
        b = self.read_variablenumber()
        if b == 2 and self.pair:
            offset = self.lastoffset
            length = self.read_variablenumber()
        else:
            high = b - 2
            if self.pair:
                high -= 1
            offset = (high << 8) + self.read_byte()
            length = self.read_variablenumber()
            length += lengthdelta(offset)
        self.lastoffset = offset
        self.back_copy(offset, length)
        self.pair = False
        return False

    def shortblock(self):
        b = self.read_byte()
        if b <= 1:
            return True
        length = 2 + (b & 1)
        offset = b >> 1
        self.back_copy(offset, length)
        self.lastoffset = offset
        self.pair = False
        return False

    def singlebyte(self):
        offset = self.read_bits(4)
        if offset:
            self.back_copy(offset)
        else:
            self.decompressed.append(0)
        self.pair = True
        return False

    def read_sequence(self):
        if not self.read_bits(1):
            return self.literal()
        if not self.read_bits(1):
            return self.block()
        if not self.read_bits(1):
            return self.shortblock()
        else:
            return self.singlebyte()

    def decompress(self):
        self.seek(0)
        self.decompressed.append(self.read_byte())
        while not self.read_sequence():
            continue
        return self.decompressed


class aplib(Unit):
    """
    APLib compression and decompression.
    """

    def reverse(self, buf):
        return compressor(buf).compress()

    def process(self, buf):
        view = memoryview(buf)
        size = 0
        if view[:4] == B'AP32':
            size = int.from_bytes(buf[4:8], 'little')
            if size > 0x80:
                size = 0
            else:
                self.log_info(F'detected aPLib header of size {size}')
        return decompressor(view[size:]).decompress()

    @classmethod
    def handles(cls, data):
        if len(data) < 2:
            return False
        if data[:4] == B'AP32':
            return True
        return None
