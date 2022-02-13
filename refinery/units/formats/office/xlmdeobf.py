#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from refinery.units.formats import Unit
from refinery.lib.vfs import VirtualFileSystem, VirtualFile


class xlmdeobf(Unit):
    """
    Wrapper around XLMMacroDeobfuscator to decode obfuscated XLM macros
    """

    def __init__(
        self,
        extract_only: Unit.Arg.switch(
            "-x", help="only extract cells without any emulation"
        ) = False,
        sort_formulas: Unit.Arg.switch(
            "--sort-formulas",
            help="sort extracted formulas based on their cell address (requires -x)",
        ) = False,
        defined_names: Unit.Arg.switch(
            "--defined-names", help="extract all defined names"
        ) = False,
        with_ms_excel: Unit.Arg.switch(
            "--with-ms-excel", help="use MS Excel to process XLS files"
        ) = False,
        start_with_shell: Unit.Arg.switch(
            "-s", help="open an XLM shell before interpreting the macros in the input"
        ) = False,
        day: Unit.Arg(
            "-d",
            "--day",
            type=int,
            default=-1,
            action="store",
            help="Specify the day of month",
        ) = -1,
        output_formula_format: Unit.Arg(
            "--output-formula-format",
            type=str,
            default="CELL:[[CELL-ADDR]], [[STATUS]], [[INT-FORMULA]]",
            action="store",
            help="Specify the format for output formulas ([[CELL-ADDR]], [[INT-FORMULA]], and [[STATUS]]",
        ) = "CELL:[[CELL-ADDR]], [[STATUS]], [[INT-FORMULA]]",
        extract_formula_format: Unit.Arg(
            "--extract-formula-format",
            type=str,
            default="CELL:[[CELL-ADDR]], [[CELL-FORMULA]], [[CELL-VALUE]]",
            action="store",
            help="Specify the format for extracted formulas ([[CELL-ADDR]], [[CELL-FORMULA]], and [[CELL-VALUE]]",
        ) = "CELL:[[CELL-ADDR]], [[CELL-FORMULA]], [[CELL-VALUE]]",
        no_indent: Unit.Arg.switch(
            "--no-indent",
            help="Do not show indent before formulas",
        ) = False,
        start_point: Unit.Arg(
            "--start-point",
            type=str,
            default="",
            action="store",
            help="Start interpretation from a specific cell address",
            metavar=("CELL_ADDR"),
        ) = "",
        password: Unit.Arg(
            "-p",
            "--password",
            type=str,
            action="store",
            default="",
            help="Password to decrypt the protected document",
        ) = "",
        output_level: Unit.Arg(
            "-o",
            "--output-level",
            type=int,
            action="store",
            default=0,
            help=(
                "Set the level of details to be shown (0:all commands, 1: commands no jump 2:important "
                "commands 3:strings in important commands)."
            ),
        ) = 0,
        timeout: Unit.Arg(
            "--timeout",
            type=int,
            action="store",
            default=0,
            metavar=("N"),
            help="stop emulation after N seconds (0: not interruption N>0: stop emulation after N seconds)",
        ) = 0,
    ):
        pass

    @Unit.Requires("XLMMacroDeobfuscator", optional=False)
    def _process_file():
        from XLMMacroDeobfuscator.deobfuscator import process_file

        return process_file

    def process(self, data: bytearray):
        with VirtualFileSystem() as vfs:
            result = self._process_file(
                file=VirtualFile(vfs, data),
                noninteractive=True,
                return_deobfuscated=True,
                silent=True,
                sort_formulas=self.args.sort_formulas,
                defined_names=self.args.defined_names,
                with_ms_excel=self.args.with_ms_excel,
                start_with_shell=self.args.start_with_shell,
                day=self.args.day,
                output_formula_format=self.args.output_formula_format,
                extract_formula_format=self.args.extract_formula_format,
                no_indent=self.args.no_indent,
                start_point=self.args.start_point,
                password=self.args.password,
                output_level=self.args.output_level,
                timeout=self.args.timeout,
            )
        return "\n".join(result).encode(self.codec)
