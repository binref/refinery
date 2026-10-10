"""
Shared base class for RAR decompression engines.
"""
from __future__ import annotations

from refinery.lib.unrar.reader import BitInput

LDecode = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224]
LBits = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5]
SDDecode = [0, 4, 8, 16, 32, 64, 128, 192]
SDBits = [2, 2, 3, 4, 5, 6, 6, 6]


class RarUnpacker:
    _inp: BitInput
    _dest_size: int | None
    _win_size: int
    _win_mask: int
    _window: bytearray
    _solid: bool
    _old_dist: list[int]
    _last_length: int
    _unp_ptr: int
    _wr_ptr: int
    _written: int
    _output: bytearray

    def _insert_old_dist(self, distance: int):
        self._old_dist[3] = self._old_dist[2]
        self._old_dist[2] = self._old_dist[1]
        self._old_dist[1] = self._old_dist[0]
        self._old_dist[0] = distance

    def _raise_corrupt(self, message: str):
        """
        Flush the window into the output buffer and raise a corruption error that carries the
        output decoded so far, so the caller can recover the partial result.
        """
        from refinery.lib.unrar import RarCorruptArchive
        self._write_buf()
        raise RarCorruptArchive(message, partial=bytes(self._output))

    def _check_distance(self, distance: int):
        """
        Reject an LZ back-reference whose distance is zero, points outside the window or, for a
        non-solid stream, beyond the bytes decoded so far, matching the reference decoders
        which abort instead of reading uninitialized dictionary memory.
        """
        if distance == 0:
            self._raise_corrupt('LZ back-reference distance is zero.')
        if distance > self._win_size:
            self._raise_corrupt(F'LZ back-reference distance {distance} exceeds the window size.')
        if not self._solid:
            produced = self._written + ((self._unp_ptr - self._wr_ptr) & self._win_mask)
            if distance > produced:
                self._raise_corrupt(F'LZ back-reference distance {distance} exceeds the decoded size.')

    def _copy_string(self, length: int, distance: int):
        if not length:
            return
        self._check_distance(distance)
        mask = self._win_mask
        win = self._window
        win_size = self._win_size
        src = (self._unp_ptr - distance) & mask
        dst = self._unp_ptr
        if src + length <= win_size and dst + length <= win_size:
            if distance >= length:
                win[dst:dst + length] = win[src:src + length]
            else:
                copied = 0
                while copied < length:
                    chunk = min(distance, length - copied)
                    win[dst + copied:dst + copied + chunk] = win[src + copied:src + copied + chunk]
                    copied += chunk
            self._unp_ptr = (dst + length) & mask
            return
        src = self._unp_ptr - distance
        dst = self._unp_ptr
        while length > 0:
            win[dst & mask] = win[src & mask]
            src += 1
            dst += 1
            length -= 1
        self._unp_ptr = dst & mask

    def _write_data(self, data: memoryview | bytes | bytearray):
        """
        Append decompressed data to the output, which ends at the size of the file. Every byte
        counts as written, including those beyond that size, as in the reference decoder.
        """
        written = self._written
        self._written = written + len(data)
        if (size := self._dest_size) is not None:
            if written >= size:
                return
            if self._written > size:
                data = data[:size - written]
        self._output.extend(data)

    def _ended_short(self, pending: int) -> bool:
        """
        Whether the decompressed data falls short of the size of the file once the given number of
        bytes still pending in the window are written. A file of unknown size ends with its stream.
        """
        size = self._dest_size
        return size is not None and self._written + pending < size

    def _ended_early(self, pending: int) -> bool:
        """
        Whether a stream that ran out before its end mark ended before the file: always for a file
        of unknown size, which only the end mark ends, and otherwise when the data falls short of
        the size of the file.
        """
        return self._dest_size is None or self._ended_short(pending)

    def _known_size(self, algorithm: str) -> int:
        """
        The size of the file, for an algorithm whose stream has no end marker and therefore cannot
        decompress a file of unknown size.
        """
        if (size := self._dest_size) is None:
            from refinery.lib.unrar import RarCorruptArchive
            raise RarCorruptArchive(
                F'The {algorithm} algorithm has no end marker for a file of unknown size.'
            )
        return size

    def _overran(self) -> bool:
        """
        Whether more data was decompressed than the file holds, which ends its decompression.
        """
        size = self._dest_size
        return size is not None and self._written > size

    def _write_area(self, start: int, end: int):
        win = self._window
        if end < start:
            self._write_data(win[start:self._win_size])
            self._write_data(win[:end])
        elif end > start:
            self._write_data(win[start:end])

    def _write_buf(self):
        win = self._window
        if self._unp_ptr < self._wr_ptr:
            self._write_data(win[self._wr_ptr:self._win_size])
            self._write_data(win[:self._unp_ptr])
        elif self._unp_ptr > self._wr_ptr:
            self._write_data(win[self._wr_ptr:self._unp_ptr])
        self._wr_ptr = self._unp_ptr

    def init_solid(self, data: bytes | memoryview, dest_size: int | None):
        """
        Reinitialize for the next file in a solid archive chain.
        """
        self._inp.load(data)
        self._dest_size = dest_size
        self._output = bytearray()
        self._written = 0
        self._solid = True
