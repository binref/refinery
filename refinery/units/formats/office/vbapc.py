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
        from refinery.lib.ole.pcode import PCodeDisassembler, format_pcode_text
        disassembler = PCodeDisassembler(data)
        for module in disassembler.iter_modules():
            if self.args.raw:
                code = format_pcode_text(module.path, 0, module.lines)
            else:
                from refinery.lib.ole.decompiler import PCodeParser
                parser = PCodeParser()
                code = parser.decompile_module(module)
            if not code.strip():
                continue
            yield UnpackResult(module.path, code.encode(self.codec))
