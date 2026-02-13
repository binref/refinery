from __future__ import annotations

import zlib

from refinery.lib.structures import StructReader
from refinery.units import Unit


class carve_png(Unit):
    """
    Extracts anything from the input data that looks like a PNG image file.
    """
    def process(self, data: bytearray):
        memory = memoryview(data)
        stream = StructReader(data, bigendian=True)
        offset = 0
        while (p := data.find(B'\x89PNG\r\n\x1A\n', offset)) > 0:
            stream.seekset(start := p)
            success = True
            stream.skip(8)
            try:
                while success:
                    size = stream.u32()
                    data = stream.read_exactly(4 + size)
                    crc32r = stream.u32()
                    crc32c = zlib.crc32(data) & 0xFFFFFFFF
                    self.log_debug(F'{p:#x}: chunk of size {size:#010x}, crc32={crc32c:08X}, check={crc32r:08X}', data[:4])
                    if crc32r != crc32c:
                        self.log_info(F'{p:#x}: rejecting, invalid checksum on chunk')
                        success = False
                    elif data[:4] == B'IEND':
                        self.log_info(F'{p:#x}: accepting, reached the end')
                        break
                    elif data[:4] not in (
                        b'IHDR',
                        B'PLTE',
                        B'IDAT',
                        B'bKGD',
                        B'cHRM',
                        B'cICP',
                        B'dSIG',
                        B'eXIf',
                        B'gAMA',
                        B'hIST',
                        B'iCCP',
                        B'iTXt',
                        B'pHYs',
                        B'sBIT',
                        B'sPLT',
                        B'sRGB',
                        B'sTER',
                        B'tEXt',
                        B'tIME',
                        B'tRNS',
                        B'zTXt',
                    ):
                        self.log_info(F'{p:#x}: rejecting, invalid header type', bytes(data[:4]))
                        success = False
            except Exception as e:
                self.log_info(F'{p:#x}: rejecting, exception:', e)
                success = False
            if success:
                offset = stream.tell()
                yield self.labelled(memory[start:offset], offset=start)
            else:
                offset = p + 1
