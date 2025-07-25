#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The code is based on the logic implemented in IFPSTools:
 https://github.com/Wack0/IFPSTools
"""
from __future__ import annotations

from refinery.units.formats import Unit
from refinery.lib.inno.ifps import IFPSFile


class IFPSBase(Unit, abstract=True):
    def __init__(
        self,
        codec: Unit.Arg.String(
            help='Optionally specify the string encoding. The default is "{default}".') = 'cp1252',
        **more
    ):
        super().__init__(codec=codec, **more)


class ifps(IFPSBase):
    """
    Disassembles compiled Pascal script files that start with the magic sequence "IFPS". These
    scripts can be found, for example, when unpacking InnoSetup installers using innounp.
    """
    def __init__(
        self,
        bytes: IFPSBase.Arg.Switch('-b', help='Print opcode bytes in the disassembly.'),
        codec='cp1252'
    ):
        super().__init__(codec=codec, bytes=bytes)

    def process(self, data):
        return IFPSFile(data, self.args.codec).disassembly(self.args.bytes).encode(self.codec)

    @classmethod
    def handles(cls, data) -> bool:
        return data[:len(IFPSFile.Magic)] == IFPSFile.Magic
