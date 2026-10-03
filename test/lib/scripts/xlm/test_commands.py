from __future__ import annotations

from refinery.lib.excel import open_workbook
from refinery.lib.excel.formula.model import XlFunctionCall
from refinery.lib.scripts.xlm import XLM_COMMANDS, XlmSeverity, build_xlm_model, severity
from test import TestBase
from test.lib.excel.samples import (
    XLM_MACRO_ASSIGN_BIFF8,
    XLM_MACRO_FORMULA_XLSM,
    XLM_MACRO_NAMES_BIFF8,
    XLM_MACRO_RPN_BIFF8,
    XLM_MACRO_TEXT_XLSM,
)

#: The classification of every macro command of the old port, transcribed from the rule its
#: runtime applied: GOTO and RUN at the jump level, its important-functions set at the triage
#: level, every handler it had left — and the severity names without a handler — ordinary.
_EXPECTED_SEVERITIES = {
    'ABS': XlmSeverity.NORMAL,
    'ABSREF': XlmSeverity.NORMAL,
    'ACTIVE.CELL': XlmSeverity.NORMAL,
    'ADDRESS': XlmSeverity.NORMAL,
    'AND': XlmSeverity.NORMAL,
    'APP.MAXIMIZE': XlmSeverity.NORMAL,
    'CALL': XlmSeverity.IMPORTANT,
    'CHAR': XlmSeverity.NORMAL,
    'CLOSE': XlmSeverity.IMPORTANT,
    'CODE': XlmSeverity.NORMAL,
    'CONCATENATE': XlmSeverity.NORMAL,
    'COUNT': XlmSeverity.NORMAL,
    'COUNTA': XlmSeverity.NORMAL,
    'DAY': XlmSeverity.NORMAL,
    'DEFINE.NAME': XlmSeverity.NORMAL,
    'DIRECTORY': XlmSeverity.NORMAL,
    'END.IF': XlmSeverity.NORMAL,
    'ERROR': XlmSeverity.NORMAL,
    'FILES': XlmSeverity.NORMAL,
    'FILE.DELETE': XlmSeverity.NORMAL,
    'FOR.CELL': XlmSeverity.NORMAL,
    'FORMULA': XlmSeverity.NORMAL,
    'FORMULA.ARRAY': XlmSeverity.NORMAL,
    'FORMULA.FILL': XlmSeverity.NORMAL,
    'FOPEN': XlmSeverity.IMPORTANT,
    'FREAD': XlmSeverity.IMPORTANT,
    'FSIZE': XlmSeverity.NORMAL,
    'FWRITE': XlmSeverity.IMPORTANT,
    'FWRITELN': XlmSeverity.NORMAL,
    'GET.CELL': XlmSeverity.NORMAL,
    'GET.DOCUMENT': XlmSeverity.NORMAL,
    'GET.WINDOW': XlmSeverity.NORMAL,
    'GET.WORKSPACE': XlmSeverity.NORMAL,
    'GOTO': XlmSeverity.JUMP,
    'HALT': XlmSeverity.IMPORTANT,
    'HLOOKUP': XlmSeverity.NORMAL,
    'IF': XlmSeverity.IMPORTANT,
    'INDEX': XlmSeverity.NORMAL,
    'INDIRECT': XlmSeverity.NORMAL,
    'INT': XlmSeverity.NORMAL,
    'ISERROR': XlmSeverity.NORMAL,
    'ISNUMBER': XlmSeverity.NORMAL,
    'Kernel32.RtlCopyMemory': XlmSeverity.NORMAL,
    'Kernel32.VirtualAlloc': XlmSeverity.NORMAL,
    'Kernel32.WriteProcessMemory': XlmSeverity.NORMAL,
    'LEN': XlmSeverity.NORMAL,
    'MAX': XlmSeverity.NORMAL,
    'MID': XlmSeverity.NORMAL,
    'MIN': XlmSeverity.NORMAL,
    'MOD': XlmSeverity.NORMAL,
    'NEXT': XlmSeverity.IMPORTANT,
    'NOT': XlmSeverity.NORMAL,
    'NOW': XlmSeverity.NORMAL,
    'OFFSET': XlmSeverity.NORMAL,
    'ON.TIME': XlmSeverity.NORMAL,
    'OR': XlmSeverity.NORMAL,
    'PRODUCT': XlmSeverity.NORMAL,
    'QUOTIENT': XlmSeverity.NORMAL,
    'RANDBETWEEN': XlmSeverity.NORMAL,
    'REGISTER': XlmSeverity.IMPORTANT,
    'REGISTER.ID': XlmSeverity.NORMAL,
    'RETURN': XlmSeverity.NORMAL,
    'ROUND': XlmSeverity.NORMAL,
    'ROUNDUP': XlmSeverity.NORMAL,
    'ROWS': XlmSeverity.NORMAL,
    'RUN': XlmSeverity.JUMP,
    'SEARCH': XlmSeverity.NORMAL,
    'SELECT': XlmSeverity.NORMAL,
    'SET.NAME': XlmSeverity.NORMAL,
    'SET.VALUE': XlmSeverity.NORMAL,
    'SQRT': XlmSeverity.NORMAL,
    'SUM': XlmSeverity.NORMAL,
    'T': XlmSeverity.NORMAL,
    'TEXT': XlmSeverity.NORMAL,
    'TRUNC': XlmSeverity.NORMAL,
    'VALUE': XlmSeverity.NORMAL,
    'WHILE': XlmSeverity.IMPORTANT,
    'WORKBOOK.HIDE': XlmSeverity.NORMAL,
    '_xlfn.ARABIC': XlmSeverity.NORMAL,
}


def _top_level_commands(data: bytes) -> list[str]:
    macrosheets = build_xlm_model(open_workbook(data))
    return sorted({
        cell.formula.callee
        for sheet in macrosheets
        for cell in sheet.listing()
        if isinstance(cell.formula, XlFunctionCall) and isinstance(cell.formula.callee, str)
    })


class TestXlmCommandRegistry(TestBase):

    def test_the_registry_classifies_every_command_as_the_old_runtime_did(self):
        self.assertEqual(XLM_COMMANDS, _EXPECTED_SEVERITIES)

    def test_the_names_of_the_severity_set_the_old_runtime_never_read_are_ordinary(self):
        self.assertEqual(severity('SET.VALUE'), XlmSeverity.NORMAL)
        self.assertEqual(severity('FILE.DELETE'), XlmSeverity.NORMAL)
        self.assertEqual(severity('WORKBOOK.HIDE'), XlmSeverity.NORMAL)

    def test_fread_is_important_although_the_old_runtime_had_no_handler_for_it(self):
        self.assertEqual(severity('FREAD'), XlmSeverity.IMPORTANT)

    def test_commands_outside_the_registry_are_ordinary(self):
        for name in ('EXEC', 'WORKBOOK.UNHIDE', 'ALERT', 'SUMPRODUCT'):
            with self.subTest(command=name):
                self.assertEqual(severity(name), XlmSeverity.NORMAL)


class TestXlmCommandClassificationOfSamples(TestBase):

    def test_top_level_commands_of_the_samples_and_their_severity(self):
        for sample, data, commands, severities in [
            (
                'rpn_biff8',
                XLM_MACRO_RPN_BIFF8,
                ['CHAR', 'FORMULA', 'GOTO', 'WORKBOOK.HIDE'],
                {
                    'CHAR': XlmSeverity.NORMAL,
                    'FORMULA': XlmSeverity.NORMAL,
                    'GOTO': XlmSeverity.JUMP,
                    'WORKBOOK.HIDE': XlmSeverity.NORMAL,
                },
            ),
            (
                'names_biff8',
                XLM_MACRO_NAMES_BIFF8,
                ['EXEC', 'HALT', 'RETURN', 'SET.NAME'],
                {
                    'EXEC': XlmSeverity.NORMAL,
                    'HALT': XlmSeverity.IMPORTANT,
                    'RETURN': XlmSeverity.NORMAL,
                    'SET.NAME': XlmSeverity.NORMAL,
                },
            ),
            (
                'assign_biff8',
                XLM_MACRO_ASSIGN_BIFF8,
                [
                    'END.IF',
                    'HALT',
                    'IF',
                    'REGISTER',
                    'RETURN',
                    'SET.NAME',
                    'WORKBOOK.HIDE',
                    'WORKBOOK.UNHIDE',
                ],
                {
                    'END.IF': XlmSeverity.NORMAL,
                    'HALT': XlmSeverity.IMPORTANT,
                    'IF': XlmSeverity.IMPORTANT,
                    'REGISTER': XlmSeverity.IMPORTANT,
                    'RETURN': XlmSeverity.NORMAL,
                    'SET.NAME': XlmSeverity.NORMAL,
                    'WORKBOOK.HIDE': XlmSeverity.NORMAL,
                    'WORKBOOK.UNHIDE': XlmSeverity.NORMAL,
                },
            ),
            (
                'text_xlsm',
                XLM_MACRO_TEXT_XLSM,
                ['CALL', 'HALT', 'SET.VALUE'],
                {
                    'CALL': XlmSeverity.IMPORTANT,
                    'HALT': XlmSeverity.IMPORTANT,
                    'SET.VALUE': XlmSeverity.NORMAL,
                },
            ),
            ('formula_xlsm', XLM_MACRO_FORMULA_XLSM, [], {}),
        ]:
            with self.subTest(sample=sample):
                found = _top_level_commands(data)
                self.assertEqual(found, commands)
                self.assertEqual(
                    {name: severity(name) for name in found},
                    severities,
                )
