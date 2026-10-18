from __future__ import annotations

from typing import TYPE_CHECKING

from refinery.lib.types import Param
from refinery.units import Arg
from refinery.units.formats.office import VBAModuleUnit

if TYPE_CHECKING:
    from refinery.lib.ole.vba import VBAModule, VBAProject


class vbapc(VBAModuleUnit):
    """
    Extract and decompile VBA macro p-code from Office documents and Microsoft Access databases
    (.mdb and .accdb).

    This unit is specifically useful for macro documents that use VBA code stomping, i.e.
    the embedded macro source code is stomped and does not represent the p-code
    functionality that the document will actually execute. Use the -R flag to get raw
    disassembled p-code instead of decompiled output.

    Every module is extracted below a folder that is named after its VBA project, for example
    `Project/ThisDocument`. When the document holds more than one project, such as an embedded
    workbook, every folder is preceded by the number of its project: `1/Project/ThisDocument` and
    `2/VBAProject/ThisWorkbook`. The meta variable `stream` holds the location of the module stream
    in the document.
    """
    def __init__(
        self,
        *paths,
        raw: Param[bool, Arg.Switch('-R', help='Return disassembled p-code, do not try to decompile.')] = False,
        **keywords,
    ):
        super().__init__(*paths, raw=raw, **keywords)

    def _module_reader(self, project: VBAProject):
        from refinery.lib.ole.decompiler import PCodeParser
        from refinery.lib.ole.pcode import PCodeDisassembler, format_pcode_text
        disassembler = PCodeDisassembler(project)
        raw = self.args.raw

        def read(module: VBAModule) -> str | None:
            pcode = disassembler.disassemble(module)
            if raw:
                code = format_pcode_text(pcode.path, 0, pcode.lines)
            else:
                code = PCodeParser().decompile_module(pcode)
            if code.strip():
                return code

        return read
