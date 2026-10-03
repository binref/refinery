"""
Modifications of the stored bytes of the XLSM sample that tests use to cover behavior the corpus
carries no vector for.
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


def replace_cell_formula(data: bytes, cell: str, formula: str) -> bytes:
    """
    The workbook with the stored formula of one cell of the macrosheet replaced.
    """
    pattern = re.compile(F'(<c r="{cell}"[^>]*>)<f>.*?</f>'.encode(), re.DOTALL)

    def replace(content: bytes) -> bytes:
        return pattern.sub(
            lambda match: match.group(1) + F'<f>{formula}</f>'.encode(),
            content,
            count=1,
        )

    return _with_part(data, _MACROSHEET_PART, replace)


def replace_cell_element(data: bytes, cell: str, element: str) -> bytes:
    """
    The workbook with the whole cell element of one cell of the macrosheet replaced.
    """
    pattern = re.compile(F'<c r="{cell}"[^>]*>.*?</c>'.encode(), re.DOTALL)

    def replace(content: bytes) -> bytes:
        return pattern.sub(element.encode(), content, count=1)

    return _with_part(data, _MACROSHEET_PART, replace)


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
    return _with_part(
        data,
        _WORKBOOK_PART,
        lambda content: re.sub(rb'<definedNames>.*?</definedNames>', b'', content, flags=re.DOTALL),
    )
