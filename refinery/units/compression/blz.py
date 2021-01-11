#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct
import zlib

from .. import Unit, RefineryPartialResult
from ...lib.structures import EOF, StructReader, MemoryFile


class blz(Unit):
    """
    BriefLZ compression and decompression. The compression algorithm uses a pure Python suffix tree
    implementation: It requires a lot of time & memory.
    """
    def _begin(self, data):
        self._src = StructReader(memoryview(data))
        self._dst = MemoryFile(bytearray())
        return self

    def _reset(self):
        self._src.seek(0)
        self._dst.seek(0)
        self._dst.truncate()
        return self

    def _decompress(self):
        (
            signature,
            version,
            src_count,
            src_crc32,
            dst_count,
            dst_crc32,
        ) = self._src.read_struct('>6L')
        if signature != 0x626C7A1A:
            raise ValueError(F'Invalid BriefLZ signature: {signature:08X}, should be 626C7A1A.')
        if version > 10:
            raise ValueError(F'Invalid version number {version}, should be less than 10.')
        self.log_debug(F'signature: 0x{signature:08X} V{version}')
        self.log_debug(F'src count: 0x{src_count:08X}')
        self.log_debug(F'src crc32: 0x{src_crc32:08X}')
        self.log_debug(F'dst count: 0x{dst_count:08X}')
        self.log_debug(F'dst crc32: 0x{dst_crc32:08X}')
        src = self._src.getbuffer()
        src = src[24:24 + src_count]
        if len(src) < src_count:
            self.log_warn(F'Only {len(src)} bytes in buffer, but header annoucned a length of {src_count}.')
        if src_crc32:
            check = zlib.crc32(src)
            if check != src_crc32:
                self.log_warn(F'Invalid source data CRC {check:08X}, should be {src_crc32:08X}.')
        dst = self._decompress_chunk(dst_count)
        if not dst_crc32:
            return dst
        check = zlib.crc32(dst)
        if check != dst_crc32:
            self.log_warn(F'Invalid result data CRC {check:08X}, should be {dst_crc32:08X}.')
        return dst

    def _decompress_modded(self):
        self._src.seekrel(8)
        total_size = self._src.u64()
        chunk_size = self._src.u64()
        remaining = total_size
        self.log_debug(F'total size: 0x{total_size:016X}')
        self.log_debug(F'chunk size: 0x{chunk_size:016X}')
        while remaining > chunk_size:
            self._decompress_chunk(chunk_size)
            remaining -= chunk_size
        return self._decompress_chunk(remaining)

    def _decompress_chunk(self, size=None):
        bitcount = 0
        bitstore = 0
        decompressed = 1

        def readbit():
            nonlocal bitcount, bitstore
            if not bitcount:
                bitstore = int.from_bytes(self._src.read(2), 'little')
                bitcount = 0xF
            else:
                bitcount = bitcount - 1
            return (bitstore >> bitcount) & 1

        def readint():
            result = 2 + readbit()
            while readbit():
                result <<= 1
                result += readbit()
            return result

        self._dst.write(self._src.read(1))

        try:
            while not size or decompressed < size:
                if readbit():
                    length = readint() + 2
                    sector = readint() - 2
                    offset = self._src.read(1)[0] + 1
                    delta = offset + 0x100 * sector
                    available = self._dst.tell()
                    if delta not in range(available + 1):
                        raise RefineryPartialResult(
                            F'Requested rewind by 0x{delta:08X} bytes with only 0x{available:08X} bytes in output buffer.',
                            partial=self._dst.getvalue())
                    quotient, remainder = divmod(length, delta)
                    replay = memoryview(self._dst.getbuffer())
                    replay = bytes(replay[-delta:] if quotient else replay[-delta:length - delta])
                    replay = quotient * replay + replay[:remainder]
                    self._dst.write(replay)
                    decompressed += length
                else:
                    self._dst.write(self._src.read(1))
                    decompressed += 1
        except EOF as E:
            raise RefineryPartialResult(str(E), partial=self._dst.getbuffer())
        dst = self._dst.getbuffer()
        if decompressed < size:
            raise RefineryPartialResult(
                F'Attempted to decompress {size} bytes, got only {len(dst)}.', dst)
        if decompressed > size:
            raise RuntimeError('Decompressed buffer contained more bytes than expected.')
        return dst

    def _compress(self):
        from ...lib.suffixtree import SuffixTree

        try:
            self.log_info('computing suffix tree')
            tree = SuffixTree(self._src.getbuffer())
        except Exception:
            raise

        bitstore = 0  # The bit stream to be written
        bitcount = 0  # The number of bits in the bit stream
        buffer = MemoryFile(bytearray())

        # Write empty header and first byte of source
        self._dst.write(bytearray(24))
        self._dst.write(self._src.read(1))

        def writeint(n: int) -> None:
            """
            Write an integer to the bit stream.
            """
            nonlocal bitstore, bitcount
            nbits = n.bit_length()
            if nbits < 2:
                raise ValueError
            # The highest bit is implicitly assumed:
            n ^= 1 << (nbits - 1)
            remaining = nbits - 2
            while remaining:
                remaining -= 1
                bitstore <<= 2
                bitcount += 2
                bitstore |= ((n >> remaining) & 3) | 1
            bitstore <<= 2
            bitcount += 2
            bitstore |= (n & 1) << 1

        src = self._src.getbuffer()
        remaining = len(src) - 1
        self.log_info('compressing data')

        while True:
            cursor = len(src) - remaining
            rest = src[cursor:]
            if bitcount >= 0x10:
                block_count, bitcount = divmod(bitcount, 0x10)
                info_channel = bitstore >> bitcount
                bitstore = info_channel << bitcount ^ bitstore
                # The decompressor will read bits from top to bottom, and each 16 bit block has to be
                # little-endian encoded. The bit stream is encoded top to bottom bit in the bitstore
                # variable, and by encoding it as a big endian integer, the stream is in the correct
                # order. However, we need to swap adjacent bytes to achieve little endian encoding for
                # each of the blocks:
                info_channel = bytearray(info_channel.to_bytes(block_count * 2, 'big'))
                for k in range(block_count):
                    k0 = 2 * k + 0
                    k1 = 2 * k + 1
                    info_channel[k0], info_channel[k1] = info_channel[k1], info_channel[k0]
                info_channel = memoryview(info_channel)
                data_channel = memoryview(buffer.getbuffer())
                self._dst.write(info_channel[:2])
                self._dst.write(data_channel[:-1])
                self._dst.write(info_channel[2:])
                data_channel = bytes(data_channel[-1:])
                buffer.truncate(0)
                store = buffer if bitcount else self._dst
                store.write(data_channel)
            if remaining + bitcount < 0x10:
                buffer = buffer.getbuffer()
                if rest or buffer:
                    bitstore <<= 0x10 - bitcount
                    self._dst.write(bitstore.to_bytes(2, 'little'))
                    self._dst.write(buffer)
                    self._dst.write(rest)
                elif bitcount:
                    raise RuntimeError('Bitbuffer Overflow')
                break
            node = tree.root
            length = 0
            offset = 0
            sector = None
            while node.children and length < len(rest):
                for child in node.children.values():
                    if tree.data[child.start] == rest[length]:
                        node = child
                        break
                if node.start >= cursor:
                    break
                offset = node.start - length
                length = node.end + 1 - offset
            length = min(remaining, length)
            if length >= 4:
                sector, offset = divmod(cursor - offset - 1, 0x100)
            bitcount += 1
            bitstore <<= 1
            if sector is None:
                buffer.write(rest[:1])
                remaining -= 1
                continue
            bitstore |= 1
            buffer.write(bytes((offset,)))
            writeint(length - 2)
            writeint(sector + 2)
            remaining -= length

        self._dst.seek(24)
        dst = self._dst.peek()
        self._dst.seek(0)
        self._dst.write(struct.pack('>6L', 0x626C7A1A, 1, len(dst), zlib.crc32(dst), len(src), zlib.crc32(src)))
        return self._dst.getbuffer()

    def process(self, data):
        self._begin(data)
        partial = None
        try:
            return self._decompress()
        except ValueError as error:
            if isinstance(error, RefineryPartialResult):
                partial = error
            self.log_warn(F'Reverting to modified BriefLZ after decompression error: {error!s}')
            self._reset()

        try:
            return self._decompress_modded()
        except RefineryPartialResult:
            raise
        except Exception as error:
            if not partial:
                raise
            raise partial from error

    def reverse(self, data):
        return self._begin(data)._compress()
