from __future__ import annotations

import abc

from refinery.lib.decompression import BitBufferedReader
from refinery.lib.structures import MemoryFile, StructReader
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class NRVUnit(Unit, abstract=True):
    """
    Common base class for the NRV algorithms.
    """

    def __init__(self, bits: Param[int, Arg.Number(help='Specify the number of codec bits. The default is {default}.')] = 32):
        super().__init__(bits=bits)

    def process(self, data):
        def process(length_prefix: bool):
            src = StructReader(data)
            bbr = BitBufferedReader(src, self.args.bits)
            dst = MemoryFile(maxlen=src.u32()) if length_prefix else MemoryFile()
            self._decompress(src, dst, bbr)
            return dst.getvalue()
        try:
            return process(False)
        except Exception:
            return process(True)

    @abc.abstractmethod
    def _decompress(self, src: StructReader, dst: MemoryFile, bb: BitBufferedReader):
        ...


class nrv2b(NRVUnit):
    """
    Decompress data using the NRV2B algorithm.
    """
    def _decompress(self, src: StructReader, dst: MemoryFile, bb: BitBufferedReader):
        last_offset = 1
        while not src.eof:
            while next(bb):
                dst.write_byte(src.read_byte())
            offset = 2 + next(bb)
            while not next(bb):
                offset = 2 * offset + next(bb)
            if offset == 2:
                offset = last_offset
            else:
                offset = (offset - 3) * 0x100 + src.read_byte()
                if offset & 0xFFFFFFFF == 0xFFFFFFFF:
                    break
                offset += 1
                last_offset = offset
            length = next(bb)
            length = 2 * length + next(bb)
            if length == 0:
                length = 2 + next(bb)
                while not next(bb):
                    length = 2 * length + next(bb)
                length += 2
            length += int(bool(offset > 0xD00))
            dst.replay(offset, length + 1)


class nrv2d(NRVUnit):
    """
    Decompress data using the NRV2D algorithm.
    """
    def _decompress(self, src: StructReader, dst: MemoryFile, bb: BitBufferedReader):
        last_offset = 1
        while not src.eof:
            while next(bb):
                dst.write_byte(src.read_byte())
            offset = 2 + next(bb)
            while not next(bb):
                offset = 2 * (offset - 1) + next(bb) # noqa
                offset = 2 *  offset      + next(bb) # noqa
            if offset == 2:
                offset = last_offset
                length = next(bb)
            else:
                offset = (offset - 3) * 0x100 + src.read_byte()
                if offset & 0xFFFFFFFF == 0xFFFFFFFF:
                    break
                length = (offset  ^ 1) & 1 # noqa
                offset = (offset >> 1) + 1
                last_offset = offset
            length = 2 * length + next(bb)
            if length == 0:
                length = 2 + next(bb)
                while not next(bb):
                    length = 2 * length + next(bb)
                length += 2
            length += int(bool(offset > 0x500))
            dst.replay(offset, length + 1)


class nrv2e(NRVUnit):
    """
    Decompress data using the NRV2E algorithm.
    """
    def _decompress(self, src: StructReader, dst: MemoryFile, bb: BitBufferedReader):
        last_offset = 1
        while not src.eof:
            while next(bb):
                dst.write_byte(src.read_byte())
            offset = 2 + next(bb)
            while not next(bb):
                offset = 2 * (offset - 1) + next(bb) # noqa
                offset = 2 *  offset      + next(bb) # noqa
            if offset == 2:
                offset = last_offset
                length = next(bb)
            else:
                offset = (offset - 3) * 0x100 + src.read_byte()
                if offset & 0xFFFFFFFF == 0xFFFFFFFF:
                    break
                length = (offset ^  1) & 1 # noqa
                offset = (offset >> 1) + 1
                last_offset = offset
            if length:
                length = 1 + next(bb)
            elif next(bb):
                length = 3 + next(bb)
            else:
                length = 2 + next(bb)
                while not next(bb):
                    length = 2 * length + next(bb)
                length += 3
            length += int(bool(offset > 0x500))
            dst.replay(offset, length + 1)
