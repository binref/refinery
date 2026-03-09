import struct
import io
import math
import itertools

from refinery.lib.structures import StructReader, StructReaderBits, MemoryFile

from .. import TestBase


class TestStructures(TestBase):

    def test_memoryfile_bytes(self):
        buffers: list[bytes | memoryview] = [
            B'Binary Refinery'
        ]
        buffers.append(memoryview(buffers[0]))
        if hasattr(memoryview, 'toreadonly'):
            # Python 3.8 addition
            buffers.append(memoryview(bytearray(buffers[0])).toreadonly())
        for b in buffers:
            with MemoryFile(b) as mem:
                self.assertFalse(mem.writable())
                self.assertTrue(mem.readable())
                with self.assertRaises(Exception):
                    mem.write(B'Unicode')
                self.assertEqual(mem.read(6), B'Binary')

    def test_memoryfile_memoryview(self):
        with MemoryFile(memoryview(bytearray(B'Binary Refinery'))) as mem:
            self.assertTrue(mem.writable())
            mem.write(list(B'Uni'))
            mem.write(bytearray(B'code'))
            mem.seek(0, 2)
            with self.assertRaises(Exception):
                mem.write(B'Rocks')
            mem.seek(0)
            self.assertEqual(mem.read(), B'UnicodeRefinery')

    def test_memoryfile(self):
        buffer = bytearray()
        data = [
            B"Slumber, watcher, till the spheres"      B"\n",
            B"Six and twenty thousand years"           B"\n",
            B"Have revolv'd, and I return"             B"\n",
            B"To the spot where now I burn."           B"\n",
            B"Other stars anon shall rise"             B"\n",
            B"To the axis of the skies;"               B"\n",
            B"Stars that soothe and stars that bless"  B"\n",
            B"With a sweet forgetfulness:"             B"\n",
            B"Only when my round is o'er"              B"\n",
            B"Shall the past disturb thy door."        B"\n",
        ]
        with MemoryFile(buffer) as mem:
            self.assertTrue(mem.writable())
            self.assertTrue(mem.seekable())
            self.assertTrue(mem.readable())
            self.assertFalse(mem.isatty())
            mem.writelines(data)
            self.assertRaises(ValueError, lambda: mem.truncate(-7))
            self.assertRaises(OSError, mem.fileno)
            mem.seek(0)
            self.assertEqual(mem.tell(), 0)
            mem.seekrel(9)
            self.assertEqual(mem.tell(), 9)
            self.assertEqual(mem.read(7), B'watcher')
            self.assertTrue(mem.readline().endswith(B'spheres\n'))
            self.assertSequenceEqual(list(mem.readlines()), data[1:])
            mem.seek(0, io.SEEK_END)
            self.assertEqual(mem.tell(), len(mem.getvalue()))
            mem.seekrel(-7)
            tmp = bytearray(10)
            self.assertLessEqual(mem.readinto(tmp), 10)
            self.assertIn(B'door', tmp)
            mem.seek(7)
            self.assertEqual(10, mem.readinto(tmp))
            self.assertEqual(tmp, data[0][7:17])
            mem.seek(0)
            self.assertSequenceEqual(list(mem), data)
            self.assertTrue(mem.eof)
            mem.close()
            self.assertFalse(mem.writable())
            self.assertFalse(mem.readable())
            self.assertFalse(mem.seekable())
            self.assertTrue(mem.closed)

    def test_bitreader_be(self):
        data = 0b01010_10011101_0100100001_1111_0111101010000101010101010010010111100000101001010101100000001110010111110100111000_101
        size, remainder = divmod(data.bit_length(), 8)
        self.assertEqual(remainder, 7)
        data = memoryview(data.to_bytes(size + 1, 'big'))
        sr = StructReaderBits(data)
        with sr.be:
            self.assertEqual(sr.read_bit(), 0)
            self.assertEqual(sr.read_bit(), 1)
            self.assertEqual(sr.read_bit(), 0)
            self.assertEqual(sr.read_bit(), 1)
            self.assertEqual(sr.read_bit(), 0)
            self.assertEqual(sr.read_byte(), 0b10011101)
            self.assertEqual(sr.read_integer(10), 0b100100001)
            self.assertTrue(all(sr.read_flags(4)))
            self.assertEqual(sr.read_integer(82), 0b0111101010000101010101010010010111100000101001010101100000001110010111110100111000)
            self.assertRaises(EOFError, sr.u16)

    def test_bitreader_be_fields(self):
        data = 0b0_1110100_11101010_0100001111_101111_11111111_010101010100100101111000001010010101011000000011100101111101001101011101
        size, remainder = divmod(data.bit_length(), 8)
        self.assertEqual(remainder, 7)
        data = memoryview(data.to_bytes(size + 1, 'big'))
        sr = StructReader(data)
        with sr.be:
            self.assertEqual(tuple(sr.read_bits(8)), (0, 1, 1, 1, 0, 1, 0, 0))
            self.assertEqual(sr.read_byte(), 0b11101010)
            self.assertListEqual(sr.read_bit_field(10, 6), [0b0100001111, 0b101111])
            self.assertTrue(all(sr.read_flags(8)))
            self.assertEqual(sr.read_integer(72), 0b010101010100100101111000001010010101011000000011100101111101001101011101)
            self.assertRaises(EOFError, sr.u16)

    def test_bitreader_le(self):
        data = 0b10010100111010100100001111101_11_00000000_0101010101010010010111100000101001010101100000001110010111110100_111_000_100
        size, remainder = divmod(data.bit_length(), 8)
        self.assertEqual(remainder, 0)
        data = memoryview(data.to_bytes(size, 'little'))
        sr = StructReaderBits(data)
        self.assertEqual(sr.read_integer(3), 0b100)
        self.assertEqual(sr.read_integer(3), 0b000)
        self.assertEqual(sr.read_integer(3), 0b111)
        self.assertEqual(sr.u64(), 0b0101010101010010010111100000101001010101100000001110010111110100)
        self.assertFalse(any(sr.read_flags(8, reverse=True)))
        self.assertEqual(sr.read_bit(), 1)
        self.assertRaises(ValueError, lambda: sr.read_struct(''))
        self.assertEqual(sr.read_bit(), 1)
        self.assertEqual(sr.read_integer(29), 0b10010100111010100100001111101)
        self.assertTrue(sr.eof)

    def test_bitreader_le_fields(self):
        data = 0b1001010011101010_00000000_0100001111100000101010101010010010111100000101001010101100000001_110010_111110_100_111_000_100
        size, remainder = divmod(data.bit_length(), 8)
        self.assertEqual(remainder, 0)
        data = memoryview(data.to_bytes(size, 'little'))
        sr = StructReader(data)
        self.assertEqual(sr.read_bit_field(3, 3, 3, 3, 6, 6), [0b100, 0, 0b111, 0b100, 0b111110, 0b110010])
        self.assertEqual(sr.u64(), 0b0100001111100000101010101010010010111100000101001010101100000001)
        self.assertFalse(any(sr.read_flags(8, reverse=True)))
        self.assertEqual(sr.i16(), -27414)
        self.assertTrue(sr.eof)

    def test_bitreader_structured(self):
        items = (
             0b1100101,   # noqa
            -0x1337,      # noqa
             0xDEFACED,   # noqa
             0xC0CAC01A,  # noqa
            -0o1337,      # noqa
             2076.171875, # noqa
             math.pi      # noqa
        )
        data = struct.pack('<bhiLqfd', *items)
        sr = StructReaderBits(data)
        self.assertEqual(sr.read_nibble(), 0b101)
        self.assertRaises(sr.Unaligned, lambda: sr.read_exactly(2))
        sr.seek(0)
        self.assertEqual(sr.read_byte(), 0b1100101)
        self.assertEqual(sr.i16(), -0x1337)
        self.assertEqual(sr.i32(), 0xDEFACED)
        self.assertEqual(sr.u32(), 0xC0CAC01A)
        self.assertEqual(sr.i64(), -0o1337)
        self.assertAlmostEqual(sr.f32(), 2076.171875)
        self.assertAlmostEqual(sr.f64(), math.pi)
        self.assertTrue(sr.eof)

    def test_string_builder(self):
        builder = MemoryFile()
        self.assertTrue(builder.writable())
        builder.write(B'The binary refinery ')
        builder.write(B'refines the finer binaries.')
        builder.seekrel(-1)
        builder.write(B'!')
        self.assertEqual(builder.getvalue(), B'The binary refinery refines the finer binaries!')

    def test_write_iterables(self):
        builder = MemoryFile()
        builder.write(B'FOO BAR BAR FOO FOO')
        builder.seek(4)
        builder.write(itertools.repeat(B'X'[0], 7))
        self.assertEqual(builder.getvalue(), B'FOO XXXXXXX FOO FOO')
        builder.seekset(len(builder))
        builder.write(B' ')
        builder.write(itertools.repeat(B'X'[0], 4))
        self.assertEqual(builder.getvalue(), B'FOO XXXXXXX FOO FOO XXXX')

    def test_peeking_bits(self):
        seed = 0b_1011_0101_1100_0000_0111_1111
        data = seed.to_bytes(3, 'big')
        reader = StructReaderBits(data, bigendian=True)
        self.assertEqual(reader.peek(2), bytes((0b10110101, 0b11000000)))
        T = True
        F = False
        self.assertEqual(reader.read_integer(0x18, peek=T), seed)
        self.assertEqual(reader.read_integer(0x02, peek=T), 0b10)
        self.assertEqual(reader.read_integer(0x02, peek=T), 0b10)
        self.assertEqual(reader.peek(), data)
        self.assertEqual(reader.read_integer(0x02, peek=F), 0b10)
        self.assertEqual(reader.read_integer(0x02, peek=T), 0b11)
        self.assertEqual(reader.read_integer(0x02, peek=T), 0b11)
        self.assertEqual(reader.read_integer(0x02, peek=F), 0b11)


class TestStructuresExtended(TestBase):

    def test_memoryfile_truncate(self):
        buffer = bytearray(b'Hello World')
        with MemoryFile(buffer) as mem:
            mem.truncate(5)
            self.assertEqual(mem.getvalue(), b'Hello')

    def test_memoryfile_truncate_at_cursor(self):
        buffer = bytearray(b'Hello World')
        with MemoryFile(buffer) as mem:
            mem.seek(5)
            mem.truncate()
            self.assertEqual(mem.getvalue(), b'Hello')

    def test_memoryfile_getbuffer(self):
        buffer = bytearray(b'Hello')
        with MemoryFile(buffer) as mem:
            view = mem.getbuffer()
            self.assertEqual(bytes(view), b'Hello')

    def test_memoryfile_len(self):
        buffer = bytearray(b'Hello World')
        with MemoryFile(buffer) as mem:
            self.assertEqual(len(mem), 11)

    def test_memoryfile_bool(self):
        with MemoryFile(bytearray(b'Hi')) as mem:
            self.assertTrue(bool(mem))
        with MemoryFile(bytearray(b'')) as mem:
            self.assertFalse(bool(mem))

    def test_memoryfile_seekset(self):
        buffer = bytearray(b'Hello World')
        with MemoryFile(buffer) as mem:
            mem.seekset(5)
            self.assertEqual(mem.tell(), 5)

    def test_memoryfile_remaining_bytes(self):
        buffer = bytearray(b'Hello World')
        with MemoryFile(buffer) as mem:
            mem.seek(5)
            self.assertEqual(mem.remaining_bytes, 6)

    def test_eof_exception_bytes(self):
        from refinery.lib.structures import EOF
        e = EOF(10, b'AB')
        self.assertEqual(bytes(e), b'AB')
        self.assertEqual(e.size, 10)

    def test_stream_detour(self):
        from refinery.lib.structures import StreamDetour
        buffer = bytearray(b'ABCDEFGHIJ')
        mem = MemoryFile(buffer)
        mem.seek(3)
        with StreamDetour(mem, 7):
            self.assertEqual(mem.read(2), b'HI')
        self.assertEqual(mem.tell(), 3)

    def test_signed_function(self):
        from refinery.lib.structures import signed
        self.assertEqual(signed(0xFF, 8), -1)
        self.assertEqual(signed(0x7F, 8), 127)
        self.assertEqual(signed(0x80, 8), -128)
        self.assertEqual(signed(0, 8), 0)
        self.assertEqual(signed(0xFFFF, 16), -1)
        self.assertEqual(signed(0x7FFF, 16), 32767)

    def test_struct_reader_u8_u16_u32(self):
        data = struct.pack('<BHI', 0xAB, 0xCDEF, 0x12345678)
        sr = StructReader(data)
        self.assertEqual(sr.u8(), 0xAB)
        self.assertEqual(sr.u16(), 0xCDEF)
        self.assertEqual(sr.u32(), 0x12345678)
        self.assertTrue(sr.eof)

    def test_struct_reader_read_exactly(self):
        data = b'Hello World'
        sr = StructReader(data)
        self.assertEqual(sr.read_exactly(5), b'Hello')
        self.assertEqual(sr.read_exactly(6), b' World')

    def test_struct_reader_read_exactly_eof(self):
        from refinery.lib.structures import EOF
        data = b'Hi'
        sr = StructReader(data)
        with self.assertRaises(EOF):
            sr.read_exactly(10)

    def test_memoryfile_close(self):
        buffer = bytearray(b'test')
        mem = MemoryFile(buffer)
        data = mem.read()
        self.assertEqual(data, b'test')
        mem.close()
        self.assertTrue(mem.closed)

    def test_memoryfile_write_extends(self):
        buffer = bytearray()
        with MemoryFile(buffer) as mem:
            mem.write(b'Hello')
            mem.write(b' World')
            self.assertEqual(mem.getvalue(), b'Hello World')

    def test_memoryfile_seek_modes(self):
        buffer = bytearray(b'ABCDEFGHIJ')
        with MemoryFile(buffer) as mem:
            mem.seek(0, io.SEEK_SET)
            self.assertEqual(mem.tell(), 0)
            mem.seek(0, io.SEEK_END)
            self.assertEqual(mem.tell(), 10)
            mem.seek(-3, io.SEEK_CUR)
            self.assertEqual(mem.tell(), 7)

    def test_struct_reader_be_u16(self):
        data = struct.pack('>HI', 0xABCD, 0x12345678)
        sr = StructReader(data)
        with sr.be:
            self.assertEqual(sr.u16(), 0xABCD)
            self.assertEqual(sr.u32(), 0x12345678)

    def test_struct_reader_signed_i8(self):
        data = struct.pack('<bbb', -1, 127, -128)
        sr = StructReader(data)
        self.assertEqual(sr.i8(), -1)
        self.assertEqual(sr.i8(), 127)
        self.assertEqual(sr.i8(), -128)

    def test_struct_reader_signed_i16(self):
        data = struct.pack('<hhh', -1, 32767, -32768)
        sr = StructReader(data)
        self.assertEqual(sr.i16(), -1)
        self.assertEqual(sr.i16(), 32767)
        self.assertEqual(sr.i16(), -32768)

    def test_struct_reader_signed_i32(self):
        data = struct.pack('<ii', -1, 0x7FFFFFFF)
        sr = StructReader(data)
        self.assertEqual(sr.i32(), -1)
        self.assertEqual(sr.i32(), 0x7FFFFFFF)

    def test_struct_reader_read_struct_basic(self):
        data = struct.pack('<BHI', 0x42, 0x1234, 0xDEADBEEF)
        sr = StructReader(data)
        result = sr.read_struct('BHI')
        self.assertEqual(result, [0x42, 0x1234, 0xDEADBEEF])
        self.assertTrue(sr.eof)

    def test_struct_reader_read_struct_explicit_byteorder(self):
        data = struct.pack('>HI', 0x1234, 0xDEADBEEF)
        sr = StructReader(data)
        result = sr.read_struct('>HI')
        self.assertEqual(result, [0x1234, 0xDEADBEEF])

    def test_struct_reader_read_terminated_array(self):
        data = b'Hello\x00World\x00'
        sr = StructReader(data)
        result = sr.read_terminated_array(b'\x00')
        self.assertEqual(result, b'Hello')
        result = sr.read_terminated_array(b'\x00')
        self.assertEqual(result, b'World')

    def test_struct_reader_read_terminated_array_wide(self):
        data = b'A\x00B\x00\x00\x00C\x00\x00\x00'
        sr = StructReader(data)
        result = sr.read_terminated_array(b'\x00\x00', alignment=2)
        self.assertEqual(result, b'A\x00B\x00')

    def test_struct_reader_peek(self):
        data = b'ABCDEF'
        sr = StructReader(data)
        peeked = sr.peek(3)
        self.assertEqual(bytes(peeked), b'ABC')
        self.assertEqual(sr.tell(), 0)
        sr.read_exactly(2)
        peeked = sr.peek(2)
        self.assertEqual(bytes(peeked), b'CD')
        self.assertEqual(sr.tell(), 2)

    def test_struct_reader_peek_all(self):
        data = b'ABCDEF'
        sr = StructReader(data)
        sr.read_exactly(3)
        peeked = sr.peek()
        self.assertEqual(bytes(peeked), b'DEF')
        self.assertEqual(sr.tell(), 3)

    def test_struct_reader_seekset(self):
        data = b'ABCDEFGHIJ'
        sr = StructReader(data)
        sr.read_exactly(5)
        self.assertEqual(sr.tell(), 5)
        sr.seekset(2)
        self.assertEqual(sr.tell(), 2)
        self.assertEqual(sr.read_exactly(3), b'CDE')

    def test_struct_reader_seekset_negative(self):
        data = b'ABCDEFGHIJ'
        sr = StructReader(data)
        sr.seekset(-3)
        self.assertEqual(sr.tell(), 7)
        self.assertEqual(sr.read_exactly(3), b'HIJ')

    def test_struct_reader_seekrel(self):
        data = b'ABCDEFGHIJ'
        sr = StructReader(data)
        sr.read_exactly(3)
        self.assertEqual(sr.tell(), 3)
        sr.seekrel(4)
        self.assertEqual(sr.tell(), 7)
        self.assertEqual(sr.read_exactly(1), b'H')
        sr.seekrel(-2)
        self.assertEqual(sr.tell(), 6)
        self.assertEqual(sr.read_exactly(1), b'G')

    def test_struct_reader_bigendian(self):
        data = struct.pack('>HI', 0xBEEF, 0xCAFEBABE)
        sr = StructReader(data, bigendian=True)
        self.assertTrue(sr.bigendian)
        self.assertEqual(sr.u16(), 0xBEEF)
        self.assertEqual(sr.u32(), 0xCAFEBABE)

    def test_struct_reader_bigendian_signed(self):
        data = struct.pack('>hh', -1, -32768)
        sr = StructReader(data, bigendian=True)
        self.assertEqual(sr.i16(), -1)
        self.assertEqual(sr.i16(), -32768)

    def test_struct_reader_bigendian_context_manager(self):
        data_be = struct.pack('>H', 0xABCD)
        data_le = struct.pack('<H', 0x1234)
        sr = StructReader(data_be + data_le)
        with sr.be:
            self.assertTrue(sr.bigendian)
            self.assertEqual(sr.u16(), 0xABCD)
        self.assertFalse(sr.bigendian)
        self.assertEqual(sr.u16(), 0x1234)

    def test_struct_reader_read_exactly_raises_on_short_read(self):
        from refinery.lib.structures import EOF
        data = b'AB'
        sr = StructReader(data)
        with self.assertRaises(EOF) as ctx:
            sr.read_exactly(10)
        self.assertEqual(bytes(ctx.exception), b'AB')
        self.assertEqual(ctx.exception.size, 10)

    def test_struct_reader_read_c_string(self):
        data = b'Hello\x00World\x00'
        sr = StructReader(data)
        self.assertEqual(sr.read_c_string(), b'Hello')
        self.assertEqual(sr.read_c_string(), b'World')

    def test_struct_reader_read_c_string_with_encoding(self):
        data = b'Hello\x00'
        sr = StructReader(data)
        result = sr.read_c_string(encoding='ascii')
        self.assertEqual(result, 'Hello')

    def test_struct_reader_read_w_string(self):
        data = b'A\x00B\x00\x00\x00'
        sr = StructReader(data)
        result = sr.read_w_string()
        self.assertEqual(result, b'A\x00B\x00')

    def test_struct_reader_read_w_string_with_encoding(self):
        data = 'Hello'.encode('utf-16le') + b'\x00\x00'
        sr = StructReader(data)
        result = sr.read_w_string(encoding='utf-16le')
        self.assertEqual(result, 'Hello')

    def test_struct_reader_read_guid(self):
        import uuid as uuid_mod
        test_uuid = uuid_mod.UUID('12345678-1234-5678-1234-567812345678')
        data = test_uuid.bytes_le
        sr = StructReader(data)
        result = sr.read_guid()
        self.assertEqual(result, test_uuid)

    def test_struct_reader_read_uuid(self):
        import uuid as uuid_mod
        test_uuid = uuid_mod.UUID('12345678-1234-5678-1234-567812345678')
        data = test_uuid.bytes
        sr = StructReader(data)
        result = sr.read_uuid()
        self.assertEqual(result, test_uuid)

    def test_struct_reader_read_length_prefixed(self):
        # 32-bit LE prefix = 5, followed by 5 bytes of data
        data = struct.pack('<I', 5) + b'Hello'
        sr = StructReader(data)
        result = sr.read_length_prefixed()
        self.assertEqual(result, b'Hello')

    def test_struct_reader_read_length_prefixed_utf8(self):
        text = 'Hello'
        payload = text.encode('utf8')
        data = struct.pack('<I', len(payload)) + payload
        sr = StructReader(data)
        result = sr.read_length_prefixed_utf8()
        self.assertEqual(result, 'Hello')

    def test_struct_reader_read_length_prefixed_ascii(self):
        text = 'World'
        payload = text.encode('latin1')
        data = struct.pack('<I', len(payload)) + payload
        sr = StructReader(data)
        result = sr.read_length_prefixed_ascii()
        self.assertEqual(result, 'World')

    def test_struct_reader_read_7bit_encoded_int_simple(self):
        # Encode value 127: single byte 0x7F (no continuation bit)
        data = bytes([0x7F])
        sr = StructReader(data)
        result = sr.read_7bit_encoded_int()
        self.assertEqual(result, 127)

    def test_struct_reader_read_7bit_encoded_int_multi(self):
        # Value 300 = 0b100101100
        # LE 7-bit encoding: byte0 = 0b10101100 = 0xAC (continuation set, lower 7 bits = 0b0101100 = 44)
        # byte1 = 0b00000010 = 0x02 (no continuation, value = 2)
        # result = 44 | (2 << 7) = 44 + 256 = 300
        data = bytes([0xAC, 0x02])
        sr = StructReader(data)
        result = sr.read_7bit_encoded_int()
        self.assertEqual(result, 300)

    def test_struct_reader_read_7bit_encoded_int_bigendian(self):
        # Value 300 in big-endian 7-bit encoding:
        # byte0 = 0b10000010 = 0x82 (continuation, value = 2)
        # byte1 = 0b00101100 = 0x2C (no continuation, value = 44)
        # result = (2 << 7) | 44 = 256 + 44 = 300
        data = bytes([0x82, 0x2C])
        sr = StructReader(data, bigendian=True)
        result = sr.read_7bit_encoded_int()
        self.assertEqual(result, 300)

    def test_struct_reader_read_bool_byte(self):
        data = bytes([0x01, 0x00, 0x05])
        sr = StructReader(data)
        self.assertTrue(sr.read_bool_byte())
        self.assertFalse(sr.read_bool_byte())
        # Non-strict: any nonzero is True
        self.assertTrue(sr.read_bool_byte())

    def test_struct_reader_read_bool_byte_strict(self):
        data = bytes([0x05])
        sr = StructReader(data)
        with self.assertRaises(ValueError):
            sr.read_bool_byte(strict=True)

    def test_struct_reader_read_char(self):
        data = b'ABC'
        sr = StructReader(data)
        self.assertEqual(sr.read_char(), 'A')
        self.assertEqual(sr.read_char(), 'B')
        self.assertEqual(sr.read_char(peek=True), 'C')
        self.assertEqual(sr.read_char(), 'C')

    def test_struct_reader_byte_align(self):
        data = b'ABCDEFGHIJKLMNOP'
        sr = StructReader(data)
        sr.read_exactly(3)
        sr.byte_align(4)
        self.assertEqual(sr.tell(), 4)

    def test_struct_reader_read_regex(self):
        data = b'Hello123World'
        sr = StructReader(data)
        match = sr.read_regex(rb'Hello(\d+)')
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), b'123')
        self.assertEqual(sr.tell(), 8)

    def test_struct_reader_read_regex_no_match(self):
        data = b'Hello World'
        sr = StructReader(data)
        match = sr.read_regex(rb'\d+')
        self.assertIsNone(match)

    def test_struct_reader_custom_string_format(self):
        # Test 'a' format (C-string) in read_struct
        data = b'hello\x00' + struct.pack('<H', 0x1234)
        sr = StructReader(data)
        result = sr.read_struct('aH')
        self.assertEqual(result, [b'hello', 0x1234])

    def test_struct_reader_read_nibble(self):
        data = bytes([0b01011010])
        sr = StructReaderBits(data)
        # LE: read_nibble reads 4 bits
        result = sr.read_nibble()
        self.assertEqual(result, 0b1010)  # low nibble first in LE

    def test_memoryfile_readif(self):
        buffer = bytearray(b'Hello World')
        mem = MemoryFile(buffer)
        self.assertTrue(mem.readif(b'Hello'))
        self.assertEqual(mem.tell(), 5)
        self.assertFalse(mem.readif(b'Nope'))
        self.assertEqual(mem.tell(), 5)

    def test_memoryfile_maxlen_exceeded(self):
        from refinery.lib.structures import LimitExceeded
        mem = MemoryFile(bytearray(), maxlen=5)
        mem.write(b'Hello')
        with self.assertRaises(LimitExceeded):
            mem.write(b'!')

    def test_memoryfile_maxlen_initial_exceeds(self):
        with self.assertRaises(ValueError):
            MemoryFile(bytearray(b'Hello World'), maxlen=5)

    def test_memoryfile_write_byte(self):
        mem = MemoryFile(bytearray(b'ABC'))
        mem.write_byte(0x44)  # 'D'
        self.assertEqual(mem.getvalue(), b'DBC')

    def test_memoryfile_write_byte_append(self):
        mem = MemoryFile(bytearray())
        mem.write_byte(0x41)
        mem.write_byte(0x42)
        self.assertEqual(mem.getvalue(), b'AB')

    def test_memoryfile_write_byte_readonly(self):
        mem = MemoryFile(b'Hello')
        with self.assertRaises(TypeError):
            mem.write_byte(0x41)

    def test_memoryfile_replay(self):
        mem = MemoryFile(bytearray())
        mem.write(b'ABCD')
        mem.replay(4, 8)
        self.assertEqual(mem.getvalue(), b'ABCDABCDABCD')

    def test_memoryfile_replay_partial(self):
        mem = MemoryFile(bytearray())
        mem.write(b'ABC')
        mem.replay(3, 5)
        self.assertEqual(mem.getvalue(), b'ABCABCAB')

    def test_memoryfile_copy_constructor(self):
        mem1 = MemoryFile(bytearray(b'Hello'))
        mem1.seek(3)
        mem2 = MemoryFile(mem1)
        self.assertEqual(mem2.tell(), 3)
        self.assertEqual(mem2.getvalue(), b'Hello')

    def test_memoryfile_name(self):
        mem = MemoryFile(bytearray(b'test'), name='myfile')
        self.assertEqual(mem.name, 'myfile')

    def test_memoryfile_name_unset(self):
        mem = MemoryFile(bytearray())
        mem.name = None
        with self.assertRaises(AttributeError):
            _ = mem.name

    def test_memoryfile_fileno(self):
        mem = MemoryFile(bytearray(), fileno=42)
        self.assertEqual(mem.fileno(), 42)

    def test_memoryfile_read_as(self):
        mem = MemoryFile(bytearray(b'Hello'))
        result = mem.read_as(bytes, 5)
        self.assertIsInstance(result, bytes)
        self.assertEqual(result, b'Hello')

    def test_memoryfile_readline_with_size(self):
        mem = MemoryFile(bytearray(b'Hello\nWorld\n'))
        line = mem.readline(3)
        self.assertEqual(len(line), 3)

    def test_memoryfile_readlines_with_hint(self):
        mem = MemoryFile(bytearray(b'AB\nCD\nEF\n'))
        lines = list(mem.readlines_iter(3))
        self.assertGreaterEqual(len(lines), 1)

    def test_memoryfile_mode(self):
        mem = MemoryFile(bytearray())
        self.assertEqual(mem.mode, 'r+b')

    def test_struct_reader_order_property(self):
        from refinery.lib.structures import order
        self.assertEqual(order.big, '>')
        self.assertEqual(order.little, '<')

    def test_memoryfile_skip(self):
        mem = MemoryFile(bytearray(b'ABCDEF'))
        mem.skip(3)
        self.assertEqual(mem.tell(), 3)
        self.assertEqual(mem.read(1), b'D')

    def test_memoryfile_seekend(self):
        sr = StructReader(bytearray(b'ABCDEF'))
        sr.seekend(-2)
        self.assertEqual(sr.tell(), 4)
        self.assertEqual(sr.read_exactly(2), b'EF')
