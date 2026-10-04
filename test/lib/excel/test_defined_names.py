from __future__ import annotations

import io
import struct
import zipfile

from refinery.lib.excel import open_workbook
from refinery.lib.excel.formula import synthesize_formula
from refinery.lib.ole.file import OleFile

from ... import TestBase
from .samples import (
    FORMULA_TEST_NAMES,
    ISSUE20,
    REVENG1,
    XLM_MACRO_FORMULA_XLSM,
    XLM_MACRO_RPN_BIFF8,
    XLM_MACRO_TEXT_XLSM,
)


def _names(data: bytes) -> list[tuple[str, int | None, str]]:
    """
    The defined names of a workbook with their scope and their synthesized formula text.
    """
    workbook = open_workbook(data)
    return [
        (record.name, record.sheet, synthesize_formula(workbook.formula(record.formula)))
        for record in workbook.defined_names()
    ]


def _blanked_name_formula(data: bytes) -> bytes:
    """
    Remove the formula text of the `NEVR1` defined name, leaving an element that names a
    reference no formula spells.
    """
    source = zipfile.ZipFile(io.BytesIO(data))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as target:
        for info in source.infolist():
            content = source.read(info)
            if info.filename == 'xl/workbook.xml':
                content = content.replace(
                    b'<definedName name="NEVR1">PCWV!$G$13</definedName>',
                    b'<definedName name="NEVR1"/>',
                )
            target.writestr(info, content)
    return buffer.getvalue()


def _suffixed_builtin_name(data: bytes, suffix: bytes) -> bytes:
    """
    The workbook stream of a BIFF8 workbook whose one-character builtin name carries a suffix
    after its code, with the stream positions of the sheets behind the name moved along.
    """
    stream = bytes(OleFile(data).openstream('Workbook'))
    records = []
    offset = 0
    growth = 0
    grown_at = len(stream)
    while offset + 4 <= len(stream):
        opcode, length = struct.unpack_from('<HH', stream, offset)
        body = bytearray(stream[offset + 4:offset + 4 + length])
        if opcode == 0x18 and body[0] & 0x20 and body[3] == 1:
            body[3] += len(suffix)
            body[16:16] = suffix
            growth = len(suffix)
            grown_at = offset
        records.append((opcode, body))
        offset += 4 + length
    output = bytearray()
    for opcode, body in records:
        if opcode == 0x85:
            position, = struct.unpack_from('<I', body)
            if position > grown_at:
                struct.pack_into('<I', body, 0, position + growth)
        output += struct.pack('<HH', opcode, len(body)) + body
    return bytes(output)


class TestBiffDefinedNames(TestBase):

    def test_global_names_and_their_formulas(self):
        self.assertEqual(_names(FORMULA_TEST_NAMES), [
            ('binopbool', None, '3<5'),
            ('singlesum', None, 'SUM(4)'),
            ('testchoose', None, 'CHOOSE(3,"A","B","C")'),
            ('testif', None, 'IF(0,"a","b")'),
            ('tfunc', None, 'ABS(2*-3)'),
            ('tfuncvar', None, 'SUM(1,2)'),
            ('unaryminus', None, '-7'),
        ])

    def test_sheet_scoped_builtin_names(self):
        self.assertEqual(_names(ISSUE20), [
            ('print_area', 0, '#REF!'),
            ('sheet_title', 0, '"Sheet1"'),
            ('print_area', 1, '#REF!'),
            ('sheet_title', 1, '"Sheet2"'),
            ('print_area', 2, '#REF!'),
            ('sheet_title', 2, '"Sheet3"'),
        ])

    def test_a_builtin_name_keeps_the_suffix_after_its_code(self):
        self.assertEqual(_names(XLM_MACRO_RPN_BIFF8)[1], ('auto_open', None, 'mP9mScF1m5!$S$41'))
        self.assertEqual(
            _names(_suffixed_builtin_name(XLM_MACRO_RPN_BIFF8, b'Rz'))[1],
            ('auto_openRz', None, 'mP9mScF1m5!$S$41'),
        )


class TestOoxmlDefinedNames(TestBase):

    def test_builtin_names_strip_the_prefix_and_keep_their_scope(self):
        self.assertEqual(_names(REVENG1), [
            ('print_area', 1, 'AAA2ndsheet!$1:$1048576'),
            ('print_area', 2, 'ControlChars!$1:$1048576'),
            ('print_area', 0, 'ZZZfirstsheet!$1:$1048576'),
            ('sheet_title', 1, '"AAA2ndsheet"'),
            ('sheet_title', 2, '"ControlChars"'),
            ('sheet_title', 0, '"ZZZfirstsheet"'),
        ])

    def test_the_auto_open_name_of_a_macro_workbook(self):
        self.assertEqual(_names(XLM_MACRO_TEXT_XLSM), [
            ('auto_open', None, 'Doc1!$AZ$102'),
        ])

    def test_user_names_and_the_auto_open_name(self):
        self.assertEqual(_names(XLM_MACRO_FORMULA_XLSM), [
            ('NEVR1', None, 'PCWV!$G$13'),
            ('NEVR2', None, 'PCWV!$G$15'),
            ('NEVR3', None, 'PCWV!$G$17'),
            ('NEVR4', None, 'PCWV!$G$19'),
            ('NEVR5', None, 'PCWV!$G$21'),
            ('NEVR6', None, 'PCWV!$G$23'),
            ('NEVR7', None, 'PCWV!$G$25'),
            ('auto_open', None, 'PCWV!$G$1'),
        ])

    def test_a_name_without_formula_text_synthesizes_nothing(self):
        # the BIFF and XLSB readers carry an empty formula for such a name, which decodes to
        # the empty carrier rather than to no formula at all
        names = _names(_blanked_name_formula(XLM_MACRO_FORMULA_XLSM))
        self.assertEqual(names[0], ('NEVR1', None, ''))
