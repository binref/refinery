from __future__ import annotations

from refinery.lib.un7z import SIGNATURE, SIGNATURE_HEADER_SIZE
from refinery.lib.un7z.headers import parse_signature_header
from refinery.units import Unit


class carve_7z(Unit):
    """
    Extracts anything from the input data that looks like a 7zip archive file.
    """

    HEADER_SIGNATURE = SIGNATURE

    def process(self, data: bytearray):
        cursor = 0
        mv = memoryview(data)
        while True:
            start = data.find(self.HEADER_SIGNATURE, cursor)
            if start < cursor:
                break
            self.log_debug(F'found header at offset: 0x{start:08X}')
            try:
                sig = parse_signature_header(mv[start:])
                size = sig.archive_size
                if size <= SIGNATURE_HEADER_SIZE or start + size > len(data):
                    raise ValueError('invalid archive size')
            except ImportError:
                raise
            except Exception as error:
                self.log_debug('parsing archive header failed:', error)
                cursor = start + 6
                continue
            self.log_info(F'identified archive of size 0x{size:08X} at offset 0x{start:08X}')
            cursor = start + size
            yield self.labelled(mv[start:cursor], offset=start)
