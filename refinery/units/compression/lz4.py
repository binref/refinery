from __future__ import annotations

import io

from refinery.lib.structures import StreamDetour, StructReaderBits
from refinery.units import RefineryPartialResult, Unit
from refinery.units.crypto.hash.xxhash import xxhash


class LZ4Reader(StructReaderBits):
    def read_size(self, size):
        if size < 0xF:
            return size
        nb = 0xFF
        while nb == 0xFF:
            nb, = self.read_exactly(1)
            size += nb
        return size


class lz4(Unit):
    """
    LZ4 block decompression. See also:
    https://github.com/lz4/lz4/blob/master/doc/lz4_Block_format.md#compressed-block-format
    """
    def _read_block(self, reader: LZ4Reader, output: io.BytesIO, ubound=None):
        entry = reader.tell()
        lastend = 0

        def ubound_check():
            if ubound is None:
                return False
            consumed = reader.tell() - entry
            if consumed > ubound:
                raise ValueError(F'upper bound {ubound} exceeded by {consumed - ubound} in LZ4 block')
            return consumed == ubound

        while not reader.eof:
            reflen = reader.read_nibble()
            litlen = reader.read_nibble()
            litlen = reader.read_size(litlen)
            literal = reader.read(litlen)
            output.write(literal)
            if ubound_check():
                break
            try:
                refpos = reader.u16()
            except EOFError:
                break
            if refpos - 1 not in range(output.tell()):
                with StreamDetour(output, lastend):
                    if output.read(len(literal)) == literal:
                        # This literal could have been encoded in the last match, but it wasn't.
                        # Therefore, it is very likely that we have reached the end of the stream.
                        break
                position = reader.tell()
                remaining = len(literal) - position
                raise RefineryPartialResult(
                    F'encountered invalid match offset value {refpos} at position {position} with {remaining} bytes remaining',
                    partial=output.getvalue())
            reflen = reader.read_size(reflen)
            if ubound_check():
                raise ValueError('last sequence in block contained a match')
            reflen += 4
            available_bytes = min(refpos, reflen)
            q, r = divmod(reflen, available_bytes)
            with StreamDetour(output, -refpos, io.SEEK_CUR):
                match = output.read(available_bytes)
                match = q * match + match[:r]
                assert len(match) == reflen
                lastend = output.tell() - available_bytes + r
            output.write(match)

    def process(self, data):
        output = io.BytesIO()
        reader = LZ4Reader(memoryview(data))
        try:
            magic = reader.u32() == 0x184D2204
        except EOFError:
            magic = False
        if not magic:
            reader.seek(0)
            self._read_block(reader, output)
            return output.getvalue()

        (v1, v2, blocks_independent, blocks_checksummed,
            content_size, content_checksummed, rsrv1, dict_id) = reader.read_bits(8)
        rsrv2 = reader.read_nibble()
        try:
            block_maximum = {
                7: 0x400000,
                6: 0x100000,
                5: 0x040000,
                4: 0x010000,
            }[reader.read_integer(3)]
        except KeyError:
            raise ValueError('unknown maximum block size value in LZ4 frame header')
        rsrv3 = reader.read_bit()
        if any((rsrv1, rsrv2, rsrv3)):
            self.log_warn('nonzero reserved value in LZ4 frame header')
        if (v1, v2) != (0, 1):
            self.log_warn(F'invalid version ({v1},{v2}) in LZ4 frame header')
        content_size = content_size and reader.u64() or None
        dict_id = dict_id and reader.u32() or None
        # Header Checksum
        xxh = xxhash(data[4:reader.tell()]).intdigest() >> 8 & 0xFF
        chk = reader.read_byte()
        if chk != xxh:
            self.log_warn(F'header checksum {chk:02X} does not match computed value {xxh:02X}')

        self.log_debug(lambda: F'dictionary id: {dict_id}')
        self.log_debug(lambda: F'block max: 0x{block_maximum:X}')
        if content_size is not None:
            self.log_debug(lambda: F'chunk max: 0x{content_size:X}')
        self.log_debug(lambda: F'blocks independent: {bool(blocks_independent)}')
        self.log_debug(lambda: F'blocks checksummed: {bool(blocks_checksummed)}')

        blockindex = 0

        while True:
            blockindex += 1
            size = reader.read_integer(31)
            uncompressed = reader.read_bit()
            if not size:
                assert not uncompressed
                break
            self.log_info(F'reading block of size 0x{size:06X}')
            assert reader.bits_in_buffer == 0
            assert size <= block_maximum, 'block size exceeds maximum size'
            if uncompressed:
                output.write(reader.read_exactly(size))
            else:
                self._read_block(reader, output, size)
            if blocks_checksummed:
                with StreamDetour(reader, -size, io.SEEK_CUR):
                    xxh = xxhash(reader.read_exactly(size)).intdigest()
                chk = reader.u32()
                if chk != xxh:
                    self.log_warn(F'block {blockindex} had checksum {chk:08X} which did not match computed value {xxh:08X}')
        value = output.getvalue()
        if content_checksummed:
            self.log_info('computing checksum')
            xxh = xxhash(value).intdigest()
            chk = reader.u32()
            if chk != xxh:
                self.log_warn(F'the given checksum {chk:08X} did not match the computed checksum {xxh:08X}')
        if not reader.eof:
            pos = reader.tell()
            self.log_warn(F'found {len(data) - pos} additional bytes starting at position 0x{pos:X} after compressed data')
        return value
