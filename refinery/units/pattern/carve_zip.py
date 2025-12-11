from __future__ import annotations

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
            'Extract ZIP archives that occur as data caves within the parent archive. This does '
            'not include archives that are stored as archived files, but only archives that are '
            'nested within unused data of the parent archive.'
        ))] = False,
        trim_left: Param[bool, Arg.Switch('-t', help=(
            'By default, extracted archives span from offset 0 to where their EOCD was found. '
            'When this flag is specified, they are trimmed left to include only the data that is '
            'referenced by them.'
        ))] = False,
    ):
        super().__init__(recursive=recursive, trim_left=trim_left)

    def process(self, data: bytearray):
        end = len(data)
        mem = memoryview(data)
        extractions = []
        recursive = self.args.recursive
        while True:
            def _sub_archive_boundaries(zip: Zip):
                for sub in zip.sub_archives.values():
                    if b := sub.coverage.boundary():
                        yield from _sub_archive_boundaries(sub)
                        yield b
            try:
                zip = Zip(mem[:end], read_unreferenced_records=False)
            except Exception:
                break
            if boundary := zip.coverage.boundary():
                lower, upper = boundary
                extractions.append((lower, upper))
                end = lower
                if recursive:
                    extractions.extend(_sub_archive_boundaries(zip))
            else:
                break

        if self.args.trim_left:
            extractions.sort(key=lambda t: t[0])
            for p, n in extractions:
                yield self.labelled(mem[p:n], offset=p)
        else:
            extractions.sort(key=lambda t: t[1])
            for _, n in extractions:
                yield self.labelled(mem[0:n])
