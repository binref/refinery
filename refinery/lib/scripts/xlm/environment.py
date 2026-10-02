"""
The environment of answers the macro commands of an XLM workbook read: the workspace and
window tables of the retiring interpreter, transcribed verbatim, and the document answers its
GET.DOCUMENT handler computed from the names of the workbook and the current sheet. The tables
hardcode the username `user` and the account name `Windows User`; routing them through
`refinery.lib.scripts.win32const.make_win32_environment` would change those answers, so the
tables stand as they were and the divergence from the other script emulators is deliberate.
"""
from __future__ import annotations

_WORKSPACE = {
    1: 'Windows (64-bit) NT :.00',
    2: '16',
    3: '0',
    4: 'FALSE',
    5: 'TRUE',
    6: 'TRUE',
    7: 'TRUE',
    8: 'TRUE',
    9: '/',
    10: '0',
    11: '-5',
    12: '-6',
    13: '1016.25',
    14: '480',
    15: '3',
    18: 'TRUE',
    19: 'TRUE',
    21: 'TRUE',
    22: '0',
    23: R'C:\Users\user\AppData\Roaming\Microsoft\Excel\XLSTART',
    25: 'FALSE',
    26: 'Windows User',
    28: '1',
    29: 'FALSE',
    31: 'FALSE',
    32: R'C:\Program Files\Microsoft Office\Office16',
    33: 'Worksheet',
    35: 'FALSE',
    36: 'TRUE',
    37: '1',
    38: '1',
    40: 'TRUE',
    42: 'TRUE',
    43: 'TRUE',
    45: 'FALSE',
    46: 'TRUE',
    48: R'C:\Program Files\Microsoft Office\Office16\LIBRARY',
    50: 'FALSE',
    51: 'FALSE',
    52: 'FALSE',
    54: 'TRUE',
    55: 'TRUE',
    56: 'Calibri',
    57: '11',
    58: 'TRUE',
    59: 'FALSE',
    60: 'FALSE',
    61: '4',
    63: '1',
    64: 'TRUE',
    65: 'TRUE',
    66: '1',
    67: R'C:\Users\user\Documents',
    68: 'TRUE',
    69: 'TRUE',
    70: 'FALSE',
    71: 'FALSE',
    72: 'TRUE',
}

_WINDOW = {
    1: '[Book1]Sheet1',
    2: 1,
    3: 0,
    4: 0,
    5: 800,
    6: 600,
    7: 'FALSE',
    8: 'TRUE',
    9: 'TRUE',
    10: 'TRUE',
    11: 'TRUE',
    12: 0,
    13: 1,
    14: 'FALSE',
    15: 'FALSE',
    16: 'FALSE',
    17: 1,
    18: 'FALSE',
    19: 'FALSE',
    20: 'TRUE',
    21: 'FALSE',
    22: 'FALSE',
    23: 3,
    24: 'FALSE',
    25: 100,
    26: 'TRUE',
    27: 'TRUE',
    28: 0,
    29: 'TRUE',
    30: '[Book1]Sheet1',
    31: 'window.xls',
}


class XlmEnvironment:
    """
    The answers the environment-reading macro commands get from an emulated Excel
    installation: the workspace and window tables and the two document answers, the way the
    retiring interpreter answered them.
    """

    def workspace(self, number: int) -> str | None:
        """
        The workspace-table answer of the old interpreter, or `None` for a number it did not
        answer; the old interpreter reported such a call as fully evaluated to no value.
        """
        return _WORKSPACE.get(number)

    def window(self, number: int) -> str | int | None:
        """
        The window-table answer, which is also the text a GET.WINDOW trace line shows: for
        numbers 1 and 30 the table holds the placeholder `[Book1]Sheet1` even though the value
        the command returns names the workbook and the sheet it was called from.
        """
        return _WINDOW.get(number)

    def window_value(self, number: int, workbook_name: str, sheet_name: str) -> str | int | None:
        """
        The value the GET.WINDOW command returns: the window-table answer, except that numbers
        1 and 30 name the given workbook and sheet.
        """
        if number in (1, 30):
            return F'[{workbook_name}]{sheet_name}'
        return _WINDOW.get(number)

    def document(self, number: int, workbook_name: str, sheet_name: str) -> str | None:
        """
        The answer of the GET.DOCUMENT handler of the old interpreter, which computed only two:
        number 76 names the workbook and the given sheet, number 88 names the workbook, and
        every other number yields a partial evaluation, which `None` stands for here.
        """
        if number == 76:
            return F'[{workbook_name}]{sheet_name}'
        if number == 88:
            return workbook_name
        return None

    def cell_info(self, sheet_name: str, row: int, col: int, number: int) -> str | None:
        """
        Not implemented: the style surface a real answer reads — row heights, font sizes and
        colors, alignment — does not exist yet, so every GET.CELL call yields nothing, exactly
        as it did through the XLSB wrapper of the old port.
        """
        return None
