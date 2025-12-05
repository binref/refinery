from __future__ import annotations

from refinery.lib.zip import Zip
from refinery.units import Unit


class carve_zip(Unit):
    """
    Extracts anything from the input data that looks like a zip archive file.
    """

    def process(self, data: bytearray):
        end = len(data)
        mem = memoryview(data)
        rev = []
        while True:
            try:
                zip = Zip(mem[:end], read_unreferenced_records=False)
            except Exception:
                break
            if boundary := zip.coverage.boundary():
                start, end = boundary
                rev.append((start, end))
                end = start
            else:
                break
        for start, end in reversed(rev):
            zip = mem[start:end]
            yield self.labelled(zip, offset=start)
