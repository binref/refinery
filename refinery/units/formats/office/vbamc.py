from __future__ import annotations

from typing import TYPE_CHECKING

from refinery.units.formats.office import VBAModuleUnit

if TYPE_CHECKING:
    from refinery.lib.ole.vba import VBAProject


class vbamc(VBAModuleUnit):
    """
    Extract VBA macro code from Office documents such as Word and Excel, as well as from Microsoft
    Access databases (.mdb and .accdb).

    Every module is extracted below a folder that is named after its VBA project, for example
    `Project/ThisDocument`. When the document holds more than one project, such as an embedded
    workbook, every folder is preceded by the number of its project: `1/Project/ThisDocument` and
    `2/VBAProject/ThisWorkbook`. The meta variable `stream` holds the location of the module stream
    in the document.
    """
    def _module_reader(self, project: VBAProject):
        from refinery.lib.ole.vba import VBAModule
        return VBAModule.source
