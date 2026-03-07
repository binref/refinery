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
    _dest_size: int
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

    def _copy_string(self, length: int, distance: int):
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
        remaining = self._dest_size - self._written
        if remaining <= 0:
            return
        write_size = min(len(data), remaining)
        self._output.extend(data[:write_size])
        self._written += write_size

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

    def init_solid(self, data: bytes | memoryview, dest_size: int):
        """
        Reinitialize for the next file in a solid archive chain.
        """
        self._inp = BitInput(data)
        self._dest_size = dest_size
        self._output = bytearray()
        self._written = 0
        self._solid = True
