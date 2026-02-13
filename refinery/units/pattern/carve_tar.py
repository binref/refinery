from __future__ import annotations

import tarfile

from refinery.lib.structures import MemoryFile
from refinery.units import Unit


class carve_tar(Unit):
    """
    Extracts anything from the input data that looks like a tar archive file.
    """
    def process(self, data: bytearray):
        memory = memoryview(data)
        stream = MemoryFile(data)
        offset = 0
        while (p := data.find(B'ustar', offset)) > 0:
            stream.seekset(start := p - 0x101)
            try:
                success = False
                with tarfile.open(mode='r|*', fileobj=stream) as t:
                    while t.next():
                        success = True
            except Exception:
                success = False
            if success:
                offset = stream.tell()
                yield self.labelled(memory[start:offset], offset=start)
            else:
                offset = p + 1
