from __future__ import annotations

from refinery.lib.types import Param
from refinery.units import Arg
from refinery.units.formats import PathExtractorUnit, UnpackResult


class vbapc(PathExtractorUnit):
    """
    Extract VBA macro p-code from Office documents. By default, the unit also decompiles it. This
    unit is specifically useful for macro documents that use VBA code stomping, i.e. the embedded
    macro source code is stomped and does not represent the p-code functionality that the document
    will actually execute.
    """
    @classmethod
    def handles(cls, data) -> bool:
        return data[:4] == B'\xD0\xCF\x11\xE0'

    def __init__(
        self,
        *paths,
        raw: Param[bool, Arg.Switch('-R', help='Return disassembled p-code, do not try to decompile.')] = False,
        **keywords,
    ):
        super().__init__(*paths, raw=raw, **keywords)

    def unpack(self, data):
        from refinery.lib.ole.pcode import PCodeDisassembler
        disassembler = PCodeDisassembler(data)
        for module_path, pcode_text in disassembler.iter_modules():
            code = pcode_text
            if not self.args.raw:
                from refinery.lib.ole.decompiler import PCodeParser
                parser = PCodeParser(code)
                code = parser.parse()
            yield UnpackResult(module_path, code.encode(self.codec))
