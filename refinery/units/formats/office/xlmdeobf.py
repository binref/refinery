from __future__ import annotations

from refinery.lib.tools import NoLogging
from refinery.lib.types import Param
from refinery.lib.vfs import VirtualFileSystem
from refinery.units.formats import Arg, Unit


class xlmdeobf(Unit):
    """
    Wrapper around XLMMacroDeobfuscator to decode obfuscated Excel v4.0 (XLM) macros.
    """

    def __init__(
        self,
        extract_only: Param[bool, Arg.Switch(
            '-x', help='Only extract cells without any emulation.'
        )] = False,
        sort_formulas: Param[bool, Arg.Switch(
            '-s', '--sort-formulas',
            help='Sort extracted formulas based on their cell address (implies -x).',
        )] = False,
        with_ms_excel: Param[bool, Arg.Switch(
            '-X', '--with-ms-excel', help='Use MS Excel to process XLS files.'
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
        password: Param[str, Arg.String(
            '-p',
            '--password',
            help='Password to decrypt the protected document',
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

    @Unit.Requires('XLMMacroDeobfuscator', ['formats', 'office'])
    def _process_file():
        with NoLogging(NoLogging.Mode.ALL):
            from XLMMacroDeobfuscator.configs import settings
            settings.SILENT = True
            from XLMMacroDeobfuscator.deobfuscator import process_file
            return process_file

    def process(self, data: bytearray):
        with VirtualFileSystem() as vfs, NoLogging(NoLogging.Mode.ALL):
            result = self._process_file(
                file=vfs.new(data),
                noninteractive=True,
                return_deobfuscated=True,
                extract_only=self.args.extract_only,
                silent=True,
                sort_formulas=self.args.sort_formulas,
                defined_names=False,
                with_ms_excel=self.args.with_ms_excel,
                start_with_shell=False,
                day=self.args.day,
                output_formula_format=self.args.output_formula_format,
                extract_formula_format=self.args.extract_formula_format,
                no_indent=self.args.no_indent,
                start_point=self.args.start_point,
                password=self.args.password,
                output_level=self.args.output_level,
                timeout=self.args.timeout,
            )
        return '\n'.join(result).encode(self.codec)
