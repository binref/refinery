from __future__ import annotations

import zlib

from refinery.lib.png import PNG_CHUNK_TYPES, PNG_SIGNATURE
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
        while (p := data.find(PNG_SIGNATURE, offset)) > 0:
            stream.seekset(start := p)
            success = True
            stream.skip(8)
            try:
                while success:
                    size = stream.u32()
                    data = stream.read_exactly(4 + size)
                    crc32r = stream.u32()
                    crc32c = zlib.crc32(data) & 0xFFFFFFFF
                    tag = bytes(data[:4])
                    self.log_debug(F'{p:#x}: chunk of size {size:#010x}, crc32={crc32c:08X}, check={crc32r:08X}', tag)
                    if crc32r != crc32c:
                        self.log_info(F'{p:#x}: rejecting, invalid checksum on chunk')
                        success = False
                    elif tag == b'IEND':
                        self.log_info(F'{p:#x}: accepting, reached the end')
                        break
                    elif tag not in PNG_CHUNK_TYPES:
                        self.log_info(F'{p:#x}: rejecting, invalid header type', tag)
                        success = False
            except Exception as e:
                self.log_info(F'{p:#x}: rejecting, exception:', e)
                success = False
            if success:
                offset = stream.tell()
                yield self.labelled(memory[start:offset], offset=start)
            else:
                offset = p + 1
