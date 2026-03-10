from __future__ import annotations

from refinery.lib.types import Param
from refinery.units import Arg, Unit


class vbapc(Unit):
    """
    Extract VBA macro p-code from Office documents. By default, the unit also uses pcode2code to
    decompile the disassembled p-code. This unit is specifically useful for macro documents that
    use VBA code stomping, i.e. the embedded macro source code is stomped and does not represent
    the p-code functionality that the document will actually execute.
    """
    @classmethod
    def handles(cls, data) -> bool:
        return data[:4] == B'\xD0\xCF\x11\xE0'

    def __init__(self, raw: Param[bool, Arg.Switch('-r', help='Return disassembled p-code, do not try to decompile.')] = False):
        super().__init__(raw=raw)

    def process(self, data):
        from refinery.lib.ole.pcode import PCodeDisassembler
        disassembler = PCodeDisassembler(bytes(data))
        code = disassembler.disassemble()
        if not self.args.raw:
            from refinery.lib.ole.decompiler import PCodeParser
            parser = PCodeParser(code)
            code = parser.parse()
        return code.encode(self.codec)
