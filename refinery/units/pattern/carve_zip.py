from __future__ import annotations

from refinery.lib.intervals import IntIntervalUnion
from refinery.lib.types import Param
from refinery.lib.zip import Zip
from refinery.units import Unit
from refinery.units.formats import Arg


class carve_zip(Unit):
    """
    Extracts anything from the input data that looks like a zip archive file.
    """
    def __init__(
        self,
        recursive: Param[bool, Arg.Switch('-r', help=(
            'Extract ZIP archives that occur as data caves within the parent archive. This does not'
            ' include archives that are stored as archived files, but only archives that are nested'
            ' within unused data of the parent archive.'
        ))] = False,
    ):
        super().__init__(recursive=recursive)

    def process(self, data: bytearray):
        end = len(data)
        mem = memoryview(data)
        rev = []
        cov = IntIntervalUnion() if self.args.recursive else None
        while True:
            try:
                zip = Zip(mem[:end], read_unreferenced_records=False)
            except Exception:
                break
            if boundary := zip.coverage.boundary():
                lower, upper = boundary
                if cov is None:
                    end = lower
                else:
                    if zip.eocd.offset in cov:
                        end = zip.eocd.offset
                        continue
                    for i in zip.coverage:
                        cov.addi(*i)
                    end = zip.eocd.offset
                rev.append((lower, upper))
            else:
                break
        for lower, upper in reversed(rev):
            zip = mem[lower:upper]
            yield self.labelled(zip, offset=lower)
