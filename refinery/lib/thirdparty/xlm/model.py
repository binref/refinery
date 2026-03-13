from __future__ import annotations

import datetime
import re

from enum import Enum
from typing import Any, Dict, Optional, Tuple


class EvalStatus(Enum):
    FullEvaluation = 1
    PartialEvaluation = 2
    Error = 3
    NotImplemented = 4
    End = 5
    Branching = 6
    FullBranching = 7
    IGNORED = 8


class EvalResult:
    def __init__(
        self,
        next_cell: Cell | None,
        status: EvalStatus,
        value: Any,
        text: str | None,
    ):
        self.next_cell = next_cell
        self.status = status
        self.value = value
        self.text: str | None = None
        self.output_level: int = 0
        self.set_text(text)

    @staticmethod
    def is_int(text: Any) -> bool:
        try:
            int(text)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_float(text: Any) -> bool:
        try:
            float(text)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_datetime(text: Any) -> bool:
        try:
            datetime.datetime.strptime(text, '%Y-%m-%d %H:%M:%S.%f')
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_time(text: Any) -> bool:
        try:
            datetime.datetime.strptime(text, '%H:%M:%S')
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def unwrap_str_literal(string: Any) -> str:
        result = str(string)
        if len(result) > 1 and result.startswith('"') and result.endswith('"'):
            result = result[1:-1].replace('""', '"')
        return result

    @staticmethod
    def wrap_str_literal(data: Any, must_wrap: bool = False) -> str:
        if EvalResult.is_float(data) or (
            len(data) > 1
            and data.startswith('"')
            and data.endswith('"')
            and must_wrap is False
        ):
            return str(data)
        elif type(data) is float:
            if data.is_integer():
                data = int(data)
            return str(data)
        elif type(data) is int or type(data) is bool:
            return str(data)
        else:
            return f'"{data.replace(chr(34), chr(34) + chr(34))}"'

    def get_text(self, unwrap: bool = False) -> str:
        if self.text is not None:
            if self.is_float(self.text):
                value = float(self.text)
                if value.is_integer():
                    self.text = str(int(value))
                else:
                    self.text = str(value)
            if unwrap:
                return self.unwrap_str_literal(self.text)
            else:
                return str(self.text)
        return ''

    def set_text(self, data: Any, wrap: bool = False) -> None:
        if data is not None:
            if wrap:
                self.text = self.wrap_str_literal(data)
            else:
                self.text = str(data)


class Cell:
    _a1_re = re.compile(
        r"((?P<sheetname>[^\s]+?|'.+?')!)?\$?(?P<column>[a-zA-Z]+)\$?(?P<row>\d+)"
    )
    _r1c1_abs_re = re.compile(
        r"((?P<sheetname>[^\s]+?|'.+?')!)?R(?P<row>\d+)C(?P<column>\d+)"
    )
    _r1c1_re = re.compile(
        r"((?P<sheetname>[^\s]+?|'.+?')!)?R(\[?(?P<row>-?\d+)\]?)?C(\[?(?P<column>-?\d+)\]?)?"
    )
    _range_re = re.compile(
        r"((?P<sheetname>[^\s]+?|'.+?')[!|$])?"
        r"\$?(?P<column1>[a-zA-Z]+)\$?(?P<row1>\d+)"
        r"\:?\$?(?P<column2>[a-zA-Z]+)\$?(?P<row2>\d+)"
    )

    def __init__(self):
        self.sheet: Boundsheet | None = None
        self.column: str = ''
        self.row: int = 0
        self.formula: str | None = None
        self.value: Any = None
        self.attributes: Dict[str, Any] = {}
        self.is_set: bool = False

    def __deepcopy__(self, _memodict: dict | None = None) -> Cell:
        copy = Cell()
        copy.sheet = self.sheet
        copy.column = self.column
        copy.row = self.row
        copy.formula = self.formula
        copy.value = self.value
        copy.attributes = self.attributes
        return copy

    def get_local_address(self) -> str:
        return f'{self.column}{self.row}'

    def __str__(self) -> str:
        name = self.sheet.name if self.sheet else ''
        return f"'{name}'!{self.get_local_address()}"

    @staticmethod
    def convert_to_column_index(s: str) -> int:
        number = 0
        power = 1
        for character in reversed(s):
            digit = (ord(character.upper()) - ord('A') + 1) * power
            number += digit
            power *= 26
        return number

    @staticmethod
    def convert_to_column_name(n: int) -> str:
        string = ''
        while n > 0:
            n, remainder = divmod(n - 1, 26)
            string = chr(ord('A') + remainder) + string
        return string

    @staticmethod
    def parse_cell_addr(
        cell_addr_str: str,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        cell_addr_str = cell_addr_str.strip('"')
        m = Cell._r1c1_abs_re.match(cell_addr_str)
        if m is not None:
            sheet_name = m.group('sheetname')
            if sheet_name is not None:
                sheet_name = sheet_name.strip("'")
            column = Cell.convert_to_column_name(int(m.group('column')))
            row = m.group('row')
            return sheet_name, column, row
        m = Cell._a1_re.match(cell_addr_str)
        if m is not None:
            sheet_name = m.group('sheetname')
            if sheet_name is not None:
                sheet_name = sheet_name.strip("'")
            return sheet_name, m.group('column'), m.group('row')
        return None, None, None

    @staticmethod
    def parse_range_addr(
        range_addr_str: str,
    ) -> Tuple[Optional[str], ...]:
        m = Cell._range_re.match(range_addr_str)
        if m is not None:
            sheet_name = m.group('sheetname')
            if sheet_name is not None:
                sheet_name = sheet_name.strip("'")
            return (
                sheet_name,
                m.group('column1'),
                m.group('row1'),
                m.group('column2'),
                m.group('row2'),
            )
        return None, None, None

    @staticmethod
    def convert_twip_to_point(twips: int | str) -> float:
        return int(twips) * 0.05

    @staticmethod
    def get_abs_addr(base_addr: str, offset_addr: str) -> str:
        _, _base_col, _base_row = Cell.parse_cell_addr(base_addr)
        if _base_col is None or _base_row is None:
            return base_addr
        base_col: str = _base_col
        base_row: str = _base_row
        m = Cell._r1c1_re.match(offset_addr)
        column_offset = 0
        row_offset = 0
        if m is not None:
            col_str = m.group('column')
            row_str = m.group('row')
            if col_str is not None:
                column_offset = int(col_str)
            if row_str is not None:
                row_offset = int(row_str)
        res_col_index = Cell.convert_to_column_index(base_col) + column_offset
        res_row_index = int(base_row) + row_offset
        return f'{Cell.convert_to_column_name(res_col_index)}{res_row_index}'


class Boundsheet:
    def __init__(self, name: str, type: str):
        self.name = name
        self.type = type
        self.cells: Dict[str, Cell] = {}
        self.row_attributes: Dict[int, Dict[str, Any]] = {}
        self.col_attributes: Dict[str, Dict[str, Any]] = {}
        self.default_height: float | None = None

    def add_cell(self, cell: Cell) -> None:
        cell.sheet = self
        self.cells[cell.get_local_address()] = cell

    def get_cell(self, local_address: str) -> Cell | None:
        return self.cells.get(local_address)


class XlApplicationInternational(Enum):
    xlLeftBracket = 10
    xlListSeparator = 5
    xlRightBracket = 11


class RowAttribute(Enum):
    Height = 0
    Spans = 1
