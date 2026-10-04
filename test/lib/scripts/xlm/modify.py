"""
Modifications of the stored bytes of the XLSM sample that tests use to cover behavior the corpus
carries no vector for. Every modification fails when the part it modifies holds nothing to
replace, so that no test runs on a sample it did not change.
"""
from __future__ import annotations

import io
import re
import zipfile

_MACROSHEET_PART = 'xl/macrosheets/intlsheet1.xml'
_WORKBOOK_PART = 'xl/workbook.xml'


def _with_part(data: bytes, part: str, replace) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(data))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as target:
        for info in source.infolist():
            content = source.read(info)
            if info.filename == part:
                content = replace(content)
            target.writestr(info, content)
    return buffer.getvalue()


def _replace_once(data: bytes, part: str, pattern: bytes, replacement, missing: str) -> bytes:
    expression = re.compile(pattern, re.DOTALL)

    def replace(content: bytes) -> bytes:
        content, count = expression.subn(replacement, content, count=1)
        if count != 1:
            raise LookupError(missing)
        return content

    return _with_part(data, part, replace)


def replace_cell_formula(data: bytes, cell: str, formula: str) -> bytes:
    """
    The workbook with the stored formula of one formula cell of the macrosheet replaced.
    """
    return _replace_once(
        data,
        _MACROSHEET_PART,
        F'(<c r="{cell}"[^>]*>)<f>.*?</f>'.encode(),
        lambda match: match.group(1) + F'<f>{formula}</f>'.encode(),
        F'the macrosheet holds no formula cell {cell}',
    )


def replace_cell_element(data: bytes, cell: str, element: str) -> bytes:
    """
    The workbook with the whole cell element of one cell of the macrosheet replaced, the element
    of an empty cell included.
    """
    return _replace_once(
        data,
        _MACROSHEET_PART,
        F'<c r="{cell}"[^>]*?(?:/>|>.*?</c>)'.encode(),
        lambda _: element.encode(),
        F'the macrosheet holds no cell {cell}',
    )


def date_cell(data: bytes, cell: str, iso: str) -> bytes:
    """
    The workbook with one cell of the macrosheet turned into a date cell that stores the given
    moment as its cached value.
    """
    return replace_cell_element(data, cell, F'<c r="{cell}" t="d"><v>{iso}</v></c>')


def drop_defined_names(data: bytes) -> bytes:
    """
    The workbook with every defined name removed, so a run can start only at a start point a
    caller names.
    """
    return _replace_once(
        data,
        _WORKBOOK_PART,
        rb'<definedNames>.*?</definedNames>',
        b'',
        'the workbook defines no names',
    )


def add_defined_name(data: bytes, name: str, formula: str, sheet: int | None = None) -> bytes:
    """
    The workbook with one more defined name: for the whole workbook, or for the sheet at the
    given position of the sheet list of the workbook.
    """
    scope = '' if sheet is None else F' localSheetId="{sheet}"'
    element = F'<definedName name="{name}"{scope}>{formula}</definedName>'.encode()
    return _replace_once(
        data,
        _WORKBOOK_PART,
        rb'</definedNames>',
        lambda _: element + b'</definedNames>',
        'the workbook defines no names',
    )
