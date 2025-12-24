from __future__ import annotations

from refinery.lib.zip import Zip
from refinery.units import Unit


class carve_zip(Unit):
    """
    Extracts anything from the input data that looks like a zip archive file.
    """
    def process(self, data: bytearray):
        def _sub_archive_boundaries(zip: Zip):
            if boundary := zip.coverage.boundary():
                for sub in zip.sub_archives.values():
                    yield from _sub_archive_boundaries(sub)
                yield boundary
        end = len(data)
        mem = memoryview(data)
        try:
            zip = Zip(mem[:end], read_unreferenced_records=False, sub_archives_covered=False)
        except Exception:
            return
        for lower, upper in _sub_archive_boundaries(zip):
            yield self.labelled(mem[lower:upper], offset=lower)
