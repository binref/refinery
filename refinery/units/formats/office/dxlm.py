from __future__ import annotations

from refinery.lib.excel.common import rc2ref
from refinery.lib.meta import MV
from refinery.lib.scripts.xlm import XlmEngine, XlmView
from refinery.lib.scripts.xlm.trace import visible_steps
from refinery.lib.types import Param
from refinery.units.formats import Arg, Unit


class dxlm(Unit):
    """
    Deobfuscates Excel v4.0 (XLM) macros from XLS, XLSM, and XLSB documents. By default, the
    program is emulated as the workbook stores it, and every cell the run executes is listed in
    the order it ran: the unit emits one chunk per executed cell whose data is the formula of
    the cell and whose meta holds the address of the cell, the status the run left it in, and
    the indentation of its loop depth.
    """
    @classmethod
    def handles(cls, data) -> bool | None:
        from refinery.lib.id import Fmt, get_microsoft_format, get_office_xml_type
        if get_microsoft_format(data) == Fmt.XLS:
            return True
        if get_office_xml_type(data) == Fmt.XLSX:
            return True

    def __init__(
        self,
        filter: Param[int, Arg.Counts('-f', help=(
            'Filter amount of details shown. Specify once to remove jump commands and twice to '
            'restrict to the most relevant commands.'))] = 0,
        cell: Param[str, Arg.String('-c', metavar='CELL', help=(
            'Optionally start interpretation from a specific cell address.'))] = '',
        day: Param[int, Arg.Number('-d', help=(
            'The day of month the DAY command answers instead of searching the date it reads; '
            'the default {default} leaves the day to that search.'))] = -1,
        timeout: Param[int, Arg.Number('-t', help=(
            'Stop emulation after N seconds; the default {default} means no limit.'))] = 0,
    ):
        super().__init__(filter=filter, day=day, cell=cell, timeout=timeout)

    def process(self, data: bytearray):
        view = XlmView(data)
        engine = XlmEngine(view, self.args.day, self.args.timeout)
        for step in visible_steps(engine.run(self.args.cell), self.args.filter):
            meta = {
                MV.TYPE: step.status.name,
                MV.ADDR: rc2ref(step.row, step.col),
                'indent': step.indent,
            }
            yield self.labelled(step.text.encode(self.codec), **meta)
