from __future__ import annotations

from refinery.lib.intervals import IntIntervalUnion
from refinery.lib.types import Param
from refinery.units import Arg, Unit
from refinery.units.pattern.carve_7z import carve_7z
from refinery.units.pattern.carve_json import carve_json
from refinery.units.pattern.carve_lnk import carve_lnk
from refinery.units.pattern.carve_pe import carve_pe
from refinery.units.pattern.carve_png import carve_png
from refinery.units.pattern.carve_rtf import carve_rtf
from refinery.units.pattern.carve_tar import carve_tar
from refinery.units.pattern.carve_xml import carve_xml
from refinery.units.pattern.carve_zip import carve_zip


class subfiles(Unit):
    """
    Deploys carvers for various file formats against the input data and generates one output chunk
    for each successfully carved subfile. The currently supported formats are:
    ZIP, TAR, 7-Zip, PE-File, Windows Shortcuts (LNK files), PNG, JSON, and XML.
    """

    _MINLENGTH = {
        'json': 300,
        'xml' : 300,
        'rtf' : 100,
    }

    def __init__(
        self,
        memdump: Param[bool, Arg.Switch('-m',
            help='Assume that the input is a memdump for PE file carving.')] = False,
        recursive: Param[bool, Arg.Switch('-r',
            help='Extract files that are subfiles of other extracted files as separate chunks.')] = False,
    ):
        super().__init__(memdump=memdump, recursive=recursive)

    def process(self, data: bytearray):
        carvers = {
            'zip'  : carve_zip(),
            '7z'   : carve_7z(),
            'pe'   : carve_pe(memdump=self.args.memdump, fileinfo=True, recursive=True, keep_root=False),
            'tar'  : carve_tar(),
            'lnk'  : carve_lnk(),
            'json' : carve_json(),
            'xml'  : carve_xml(),
            'rtf'  : carve_rtf(),
            'png'  : carve_png(),
        }

        covered = IntIntervalUnion()

        for extension, unit in carvers.items():
            self.log_info(F'carving: {extension}')
            for chunk in data | unit:
                if len(chunk) < self._MINLENGTH.get(extension, 1):
                    continue
                start = chunk['offset']
                size = len(chunk)
                end = start + size
                if any(a + n >= end for a, n in covered.overlap(start, size)):
                    continue
                if not self.args.recursive:
                    covered.addi(start, size)
                yield chunk
