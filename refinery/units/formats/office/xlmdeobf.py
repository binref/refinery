from __future__ import annotations

from refinery.lib.types import Param
from refinery.units.formats import Arg, Unit


class xlmdeobf(Unit):
    """
    Deobfuscates Excel v4.0 (XLM) macros from XLS, XLSM, and XLSB documents. Uses an inlined port
    of XLMMacroDeobfuscator to emulate XLM macro formulas.
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
            help='Specify the format for output formulas (using [[CELL-ADDR]], [[INT-FORMULA]], and [[STATUS]])',
        )] = 'CELL:[[CELL-ADDR]], [[STATUS]], [[INT-FORMULA]]',
        extract_formula_format: Param[str, Arg.String(
            '-E', '--extract-format',
            metavar='FMT',
            help='Specify the format for extracted formulas (using [[CELL-ADDR]], [[CELL-FORMULA]], and [[CELL-VALUE]])',
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
                'Set the level of details to be shown (0:all commands, 1: commands no jump 2:important '
                'commands 3:strings in important commands).'
            ),
        )] = 0,
        timeout: Param[int, Arg.Number(
            '-t',
            '--timeout',
            help='Stop emulation after N seconds (0: not interruption N>0: stop emulation after N seconds)',
        )] = 0,
    ):
        extract_only = sort_formulas or extract_only
        self.superinit(super(), **vars())

    @staticmethod
    def _show_cells(excel_doc, sorted_formulas=False):
        from refinery.lib.thirdparty.xlm.model import EvalResult
        macrosheets = excel_doc.get_macrosheets()
        for name in macrosheets:
            sheet = macrosheets[name]
            yield sheet.name, sheet.type
            if sorted_formulas:
                formulas = []
                for _, info in sheet.cells.items():
                    if info.formula is not None:
                        formulas.append((info, 'EXTRACTED', info.formula, '', info.value))
                formulas.sort(key=lambda x: (x[0].column, int(x[0].row) if EvalResult.is_int(x[0].row) else x[0].row))
                yield from formulas
            else:
                for _, info in sheet.cells.items():
                    if info.formula is not None:
                        yield info, 'EXTRACTED', info.formula, '', info.value
            for _, info in sheet.cells.items():
                if info.formula is None:
                    yield info, 'EXTRACTED', str(info.formula), '', info.value

    @staticmethod
    def _format_output(step, format_str: str, with_indent=True):
        cell_addr = step[0].get_local_address()
        status = step[1]
        formula = step[2]
        indent = '\t' * step[3]
        result = format_str
        result = result.replace('[[CELL-ADDR]]', f'{cell_addr:10}')
        result = result.replace('[[STATUS]]', f'{status.name:20}')
        if with_indent:
            formula = indent + formula
        result = result.replace('[[INT-FORMULA]]', formula)
        return result

    def process(self, data: bytearray):
        if data[:2] == B'\xD0\xCF':
            from refinery.lib.thirdparty.xlm.wrappers import XLSWrapper
            excel_doc = XLSWrapper(data)
        elif data[:2] == B'\x50\x4B':
            if b'workbook.bin' in data:
                from refinery.lib.thirdparty.xlm.wrappers import XLSBWrapper
                excel_doc = XLSBWrapper(data)
            else:
                from refinery.lib.thirdparty.xlm.wrappers import XLSMWrapper
                excel_doc = XLSMWrapper(data)
        else:
            raise ValueError('Input file type is not supported (expected XLS, XLSM, or XLSB).')

        if self.args.extract_only:
            lines: list[str] = []
            fmt: str = self.args.extract_formula_format
            for item in self._show_cells(excel_doc, self.args.sort_formulas):
                if len(item) == 2:
                    lines.append(f'SHEET: {item[0]}, {item[1]}')
                elif len(item) == 5:
                    line = fmt
                    line = line.replace('[[CELL-ADDR]]', item[0].get_local_address())
                    line = line.replace('[[CELL-FORMULA]]', item[2])
                    line = line.replace('[[CELL-VALUE]]', str(item[4]))
                    lines.append(line)
        else:
            from refinery.lib.thirdparty.xlm.interpreter import XLMInterpreter
            interpreter = XLMInterpreter(excel_doc, output_level=self.args.output_level)
            if self.args.day > 0:
                interpreter.day_of_month = self.args.day

            fmt = self.args.output_formula_format
            with_indent = not self.args.no_indent
            lines = []
            for step in interpreter.deobfuscate_macro(
                interactive=False,
                start_point=self.args.start_point,
                timeout=self.args.timeout,
                silent_mode=True,
            ):
                lines.append(self._format_output(step, fmt, with_indent))

        return '\n'.join(lines).encode(self.codec)
