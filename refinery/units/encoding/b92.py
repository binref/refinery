from __future__ import annotations

from refinery.lib.structures import MemoryFile, StructReaderBits
from refinery.units import RefineryPartialResult, Unit

_B92_ALPHABET = (
    RB"!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_abcdefghijklmnopqrstuvwxyz{|}"
)
_B92_DECODING = {
    c: k for k, c in enumerate(_B92_ALPHABET)
}


class b92(Unit):
    """
    Base92 encoding and decoding.
    """
    def reverse(self, data):
        if not data:
            return B'~'

        reader = StructReaderBits(data, bigendian=True)
        output = MemoryFile()
        while reader.remaining_bits > 0:
            try:
                block = reader.read_integer(13)
            except EOFError:
                count = reader.remaining_bits
                block = reader.read_integer(count)
                self.log_debug(F'reading {count} remaining bits: {block:0{count}b}')
                shift = 6 - count
                if shift >= 0:
                    block <<= shift
                    self.log_debug(F'encoding block: {block:06b}')
                    output.write_byte(_B92_ALPHABET[block])
                    break
                block <<= 13 - count
            self.log_debug(F'encoding block: {block:013b}')
            hi, lo = divmod(block, 91)
            output.write_byte(_B92_ALPHABET[hi])
            output.write_byte(_B92_ALPHABET[lo])
        return output.getvalue()

    def process(self, data):
        if data == B'~':
            return B''

        output = MemoryFile()
        buffer = 0
        length = 0

        view = memoryview(data)
        q, r = divmod(len(view), 2)

        if r > 0:
            bits = 6
            tail = _B92_DECODING[data[~0]]
        else:
            bits = 13
            tail = _B92_DECODING[data[~1]] * 91 + _B92_DECODING[data[~0]]
            view = view[:(q - 1) * 2]

        it = iter(view)

        for a, b in zip(it, it):
            block = _B92_DECODING[a] * 91 + _B92_DECODING[b]
            assert length < 8
            buffer <<= 13
            buffer |= block
            length += 13
            size, length = divmod(length, 8)
            assert size > 0
            output.write((buffer >> length).to_bytes(size, 'big'))
            buffer &= (1 << length) - 1

        missing = 8 - length
        shift = bits - missing

        if shift < 8:
            bytecount = 1
        else:
            bytecount = 2
            shift -= 8
            missing += 8

        if shift < 0:
            raise RefineryPartialResult(
                F'Invalid padding, missing {-shift} bits.',
                output.getvalue())

        buffer <<= missing
        buffer |= tail >> shift
        length += missing
        output.write(buffer.to_bytes(bytecount, 'big'))

        if tail & ((1 << shift) - 1) != 0:
            raise RefineryPartialResult(
                F'Invalid padding, lower {shift} bits of {tail:0{bits}b} are not zero.',
                output.getvalue())

        return output.getvalue()

    @classmethod
    def handles(cls, data):
        from refinery.lib.patterns import formats
        return formats.b92.value.bin.fullmatch(data) is not None
