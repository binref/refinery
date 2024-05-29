#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct
import io
import math
import itertools

from refinery.lib.structures import StructReader, MemoryFile, EOF
from .. import TestBase


class TestStructures(TestBase):

    def test_memoryfile_bytes(self):
        buffers = [
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
                with self.assertRaises(OSError):
                    mem.write(B'Unicode')
                self.assertEqual(mem.read(6), B'Binary')

    def test_memoryfile_memoryview(self):
        with MemoryFile(memoryview(bytearray(B'Binary Refinery'))) as mem:
            self.assertTrue(mem.writable())
            mem.write(B'Unicode')
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
            self.assertEqual(mem.tell(), len(mem.getbuffer()))
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
        sr = StructReader(data)
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

    def test_bitreader_le(self):
        data = 0b10010100111010100100001111101_11_00000000_0101010101010010010111100000101001010101100000001110010111110100_111_000_100
        size, remainder = divmod(data.bit_length(), 8)
        self.assertEqual(remainder, 0)
        data = memoryview(data.to_bytes(size, 'little'))
        sr = StructReader(data)
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
        sr = StructReader(data)
        self.assertEqual(sr.read_nibble(), 0b101)
        self.assertRaises(sr.Unaligned, lambda: sr.read_exactly(2))
        sr.seek(0)
        self.assertEqual(sr.read_byte(), 0b1100101)
        self.assertEqual(sr.i16(), -0x1337)
        self.assertEqual(sr.i32(), 0xDEFACED)
        self.assertEqual(sr.u32(), 0xC0CAC01A)
        self.assertEqual(sr.i64(), -0o1337)
        self.assertAlmostEqual(sr.read_struct('f', True), 2076.171875)
        self.assertAlmostEqual(sr.read_struct('d', True), math.pi)
        self.assertTrue(sr.eof)

    def test_string_builder(self):
        builder = MemoryFile()
        self.assertTrue(builder.writable())
        builder.write(B'The binary refinery ')
        builder.write(B'refines the finer binaries.')
        builder.seekrel(-1)
        builder.write(B'!')
        self.assertEqual(builder.getbuffer(), B'The binary refinery refines the finer binaries!')

    def test_write_iterables(self):
        builder = MemoryFile()
        builder.write(B'FOO BAR BAR FOO FOO')
        builder.seek(4)
        builder.write(itertools.repeat(B'X'[0], 7))
        self.assertEqual(builder.getbuffer(), B'FOO XXXXXXX FOO FOO')
        builder.seekset(len(builder))
        builder.write(B' ')
        builder.write(itertools.repeat(B'X'[0], 4))
        self.assertEqual(builder.getbuffer(), B'FOO XXXXXXX FOO FOO XXXX')

    def test_peeking_bits(self):
        seed = 0b_1011_0101_1100_0000_0111_1111
        data = seed.to_bytes(3, 'big')
        reader = StructReader(data, bigendian=True)
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
