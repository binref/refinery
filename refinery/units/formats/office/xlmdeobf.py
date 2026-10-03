from __future__ import annotations

from refinery.lib.types import Param
from refinery.units.formats import Arg, Unit


class xlmdeobf(Unit):
    """
    Deobfuscates Excel v4.0 (XLM) macros from XLS, XLSM, and XLSB documents. The macrosheets
    are cleaned of the cells no run can reach; an extraction also folds every statically
    computable formula into the value it computes, while the trace emulates the program as it
    was stored, because a trace that folded its input would hide the program it exists to show.
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
        extract_only: Param[bool, Arg.Switch(
            '-x', help='Only extract cells without any emulation.'
        )] = False,
        sort_formulas: Param[bool, Arg.Switch(
            '-s', '--sort-formulas',
            help='Sort extracted formulas based on their cell address (implies -x).',
        )] = False,
        day: Param[int, Arg.Number(
            '-d',
            '--day',
            help='Specify the day of month',
        )] = -1,
        output_formula_format: Param[str, Arg.String(
            '-O', '--output-format',
            metavar='FMT',
            help=(
                'Specify the format for output formulas '
                '(using [[CELL-ADDR]], [[INT-FORMULA]], and [[STATUS]])'
            ),
        )] = 'CELL:[[CELL-ADDR]], [[STATUS]], [[INT-FORMULA]]',
        extract_formula_format: Param[str, Arg.String(
            '-E', '--extract-format',
            metavar='FMT',
            help=(
                'Specify the format for extracted formulas '
                '(using [[CELL-ADDR]], [[CELL-FORMULA]], and [[CELL-VALUE]])'
            ),
        )] = 'CELL:[[CELL-ADDR]], [[CELL-FORMULA]], [[CELL-VALUE]]',
        no_indent: Param[bool, Arg.Switch(
            '-I', '--no-indent',
            help='Do not show indent before formulas',
        )] = False,
        start_point: Param[str, Arg.String(
            '-c', '--start-point',
            help='Start interpretation from a specific cell address',
            metavar='CELL',
        )] = '',
        output_level: Param[int, Arg.Number(
            '-o',
            '--output-level',
            help=(
                'Set the level of details to be shown '
                '(0:all commands, 1: commands no jump 2:important '
                'commands 3:strings in important commands).'
            ),
        )] = 0,
        timeout: Param[int, Arg.Number(
            '-t',
            '--timeout',
            help=(
                'Stop emulation after N seconds '
                '(0: not interruption N>0: stop emulation after N seconds)'
            ),
        )] = 0,
    ):
        extract_only = sort_formulas or extract_only
        self.superinit(super(), **vars())

    def process(self, data: bytearray):
        from refinery.lib.excel.common import column_letters
        from refinery.lib.excel.formula import synthesize_formula
        from refinery.lib.scripts.xlm import XlmEngine, XlmView, deobfuscate
        from refinery.lib.scripts.xlm.deobfuscation import sweep
        from refinery.lib.scripts.xlm.trace import visible_steps

        view = XlmView(data)
        lines: list[str] = []
        if self.args.extract_only:
            deobfuscate(view, self.args.start_point)
            for macrosheet in view.macrosheets():
                lines.append(F'SHEET: {macrosheet.name}, {macrosheet.kind.name.lower()}')
                for cell in macrosheet.listing(self.args.sort_formulas):
                    formula = (
                        F'={synthesize_formula(cell.formula)}'
                        if cell.formula is not None
                        else 'None'
                    )
                    line = self.args.extract_formula_format
                    line = line.replace('[[CELL-ADDR]]', F'{column_letters(cell.col)}{cell.row}')
                    line = line.replace('[[CELL-FORMULA]]', formula)
                    line = line.replace('[[CELL-VALUE]]', str(cell.value))
                    lines.append(line)
        else:
            sweep(view, self.args.start_point)
            engine = XlmEngine(
                view,
                output_level=self.args.output_level,
                day=self.args.day,
                timeout=self.args.timeout,
            )
            for step in visible_steps(engine.run(self.args.start_point), self.args.output_level):
                formula = step.text
                if not self.args.no_indent:
                    formula = '\t' * step.indent + formula
                address = F'{column_letters(step.col)}{step.row}'
                line = self.args.output_formula_format
                line = line.replace('[[CELL-ADDR]]', F'{address:10}')
                line = line.replace('[[STATUS]]', F'{step.status.name:20}')
                line = line.replace('[[INT-FORMULA]]', formula)
                lines.append(line)
        return '\n'.join(lines).encode(self.codec)
