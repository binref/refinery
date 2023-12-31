#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit

from refinery.units.pattern.carve_7z import carve_7z
from refinery.units.pattern.carve_json import carve_json
from refinery.units.pattern.carve_lnk import carve_lnk
from refinery.units.pattern.carve_pe import carve_pe
from refinery.units.pattern.carve_xml import carve_xml
from refinery.units.pattern.carve_zip import carve_zip
from refinery.units.pattern.carve_rtf import carve_rtf


class subfiles(Unit):
    """
    Deploys carvers for ZIP, 7-Zip, PE-File, Windows Shortcuts (LNK files), JSON and XML documents against
    the input data and generates one output chunk for each successfully carved subfile.
    """

    _MINLENGTH = {
        'json': 300,
        'xml' : 300,
        'rtf' : 100,
    }

    def __init__(
        self,
        memdump  : Unit.Arg.Switch('-m',
            help='Assume that the input is a memdump for PE file carving.') = False,
        recursive: Unit.Arg.Switch('-r',
            help='Extract files that are subfiles of other extracted files as separate chunks.') = False,
    ):
        super().__init__(memdump=memdump, recursive=recursive)

    def process(self, data: bytearray):
        carvers = {
            'zip'  : carve_zip(),
            '7z'   : carve_7z(),
            'pe'   : carve_pe(memdump=self.args.memdump, fileinfo=True, recursive=True, keep_root=True),
            'lnk'  : carve_lnk(),
            'json' : carve_json(dictonly=True),
            'xml'  : carve_xml(),
            'rtf'  : carve_rtf(),
        }

        covered = []

        for extension, unit in carvers.items():
            self.log_info(F'carving {extension} files')
            for chunk in data | unit:
                if len(chunk) < self._MINLENGTH.get(extension, 1):
                    continue
                start = chunk['offset']
                end = start + len(chunk)
                if any(start > left and end < right for left, right in covered):
                    continue
                if not self.args.recursive:
                    covered.append((start, end))
                yield chunk
