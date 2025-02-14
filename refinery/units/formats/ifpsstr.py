#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.inno.ifps import IFPSFile
from refinery.units.formats.ifps import IFPSBase


class ifpsstr(IFPSBase):
    """
    Extracts strings from compiled Pascal script files that start with the magic sequence "IFPS".
    These scripts can be found, for example, when unpacking InnoSetup installers using innounp.
    """
    def process(self, data):
        ifps = IFPSFile(data, self.args.codec)
        for string in ifps.strings:
            yield string.encode(self.codec)

    @classmethod
    def handles(self, data: bytearray) -> bool:
        return data.startswith(IFPSFile.Magic)
