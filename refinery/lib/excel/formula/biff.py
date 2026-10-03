"""
The BIFF operand layouts for the shared RPN stack machine: one reader per token whose byte
layout the BIFF record format defines. Everything that only depends on the BIFF version is
decided here — the string encoding, the reference widths, the 3-D sheet resolution — while the
token semantics stay in the shared machine. The layouts follow the OpenOffice documentation of
the BIFF format.
"""
from __future__ import annotations

from typing import Protocol

from refinery.lib.excel.common import BiffVersion
from refinery.lib.excel.formula.model import (
    Expression,
    XlA1Reference,
    XlBinaryExpression,
    XlBinaryOperator,
    XlR1C1Reference,
    XlString,
)
from refinery.lib.excel.formula.ptg import Ptg, RpnContext, RpnDecoder, RpnError


class BiffRpnContext(RpnContext, Protocol):
    """
    What the BIFF decoder additionally asks of its workbook: the sheet span of a BIFF5 3-D
    reference, which that version stores directly instead of through the extern-sheet table.
    """

    def sheet_span(self, first: int, last: int) -> tuple[str, ...]:
        """
        The sheet names a BIFF5 3-D reference spans, given the first and last index into the
        workbook's sheet table.
        """
        ...


class BiffRpnDecoder(RpnDecoder):
    """
    The stack machine over the formula stream of a BIFF cell or NAME record. The version and
    the codepage of the workbook select the layouts; the context resolves defined names and
    3-D sheet spans.
    """

    _context: BiffRpnContext | None

    def __init__(
        self,
        view: memoryview,
        version: BiffVersion,
        context: BiffRpnContext | None,
        codepage: str,
    ):
        super().__init__(view, context)
        self._version = version
        self._codepage = codepage

    def _read_string(self) -> XlString:
        """
        The `ptgStr` token: a one-byte character count followed by the characters. Only BIFF8
        writes the option byte that selects the two-byte encoding; the earlier versions write
        plain codepage characters.
        """
        count = self._read_u8()
        if self._version >= BiffVersion.BIFF8:
            flags = self._read_u8()
            if flags & 0x01:
                return XlString(value=self._read_text(2 * count, 'utf_16_le'))
            return XlString(value=self._read_text(count, 'latin_1'))
        return XlString(value=self._read_text(count, self._codepage))

    def _read_function_id(self) -> int:
        """
        The identifier of a `ptgFunc` token, which grew from one byte to two with BIFF4.
        """
        if self._version < BiffVersion.BIFF4:
            return self._read_u8()
        return self._read_u16()

    def _read_function_variable(self) -> tuple[int, int, bool]:
        """
        The payload of a `ptgFuncVar` token: an argument count whose top bit only marks a
        pending prompt, then the identifier. An identifier of 255 — with or without the macro
        bit, which selects the macro-command half of the id space — names a user-defined call
        whose name operand sits below the arguments on the stack.
        """
        argc = self._read_u8() & 0x7F
        if self._version < BiffVersion.BIFF4:
            index = self._read_u8()
        else:
            index = self._read_u16()
        return index, argc, (index & 0x7FFF) == 0xFF

    def _read_defined_name(self) -> Expression:
        """
        The `ptgName` token: a one-based index into the name table, widened to four bytes in
        BIFF8 after earlier versions padded the two-byte index with unused bytes.
        """
        if self._version >= BiffVersion.BIFF8:
            index = self._read_u32()
        else:
            index = self._read_u16()
            if self._version < BiffVersion.BIFF3:
                self._read_bytes(5)
            elif self._version < BiffVersion.BIFF5:
                self._read_bytes(8)
            else:
                self._read_bytes(12)
        if self._context is None:
            raise RpnError('a name token has no workbook to resolve it')
        return self._context.defined_name(index)

    def _read_reference(self, relative: bool) -> Expression:
        """
        The `ptgRef` and `ptgRefN` tokens. A `ptgRef` carries absolute positions whose
        relative flags say which axes a copy of the formula adjusts; a `ptgRefN` carries an
        offset on every axis flagged relative, which only the containing cell resolves.
        """
        if self._version >= BiffVersion.BIFF8:
            row_word = self._read_u16()
            col_word = self._read_u16()
            return self._compose_reference(row_word, col_word & 0x3FFF, col_word, relative)
        row_word = self._read_u16()
        col = self._read_u8()
        return self._compose_reference(row_word, col, row_word, relative)

    def _read_area(self, relative: bool) -> Expression:
        """
        The `ptgArea` and `ptgAreaN` tokens: two corners of a rectangle, each carrying the
        reference layout of its version.
        """
        if self._version >= BiffVersion.BIFF8:
            first_row = self._read_u16()
            second_row = self._read_u16()
            first_col_word = self._read_u16()
            second_col_word = self._read_u16()
            first = self._compose_reference(
                first_row,
                first_col_word & 0x3FFF,
                first_col_word,
                relative,
            )
            second = self._compose_reference(
                second_row,
                second_col_word & 0x3FFF,
                second_col_word,
                relative,
            )
        else:
            first_row = self._read_u16()
            second_row = self._read_u16()
            first_col = self._read_u8()
            second_col = self._read_u8()
            first = self._compose_reference(first_row, first_col, first_row, relative)
            second = self._compose_reference(second_row, second_col, second_row, relative)
        return XlBinaryExpression(
            left=first,
            operator=XlBinaryOperator.RANGE,
            right=second,
        )

    def _read_3d_reference(self) -> Expression:
        """
        The `ptgRef3d` token: a sheet span followed by a reference of the version's layout.
        BIFF8 resolves the span through the extern-sheet table; BIFF5 stores the first and
        last sheet of the span directly.
        """
        sheets = self._read_3d_sheets()
        return self._qualify(self._read_reference(False), sheets)

    def _read_3d_area(self) -> Expression:
        """
        The `ptgArea3d` token: a sheet span followed by an area of the version's layout.
        """
        sheets = self._read_3d_sheets()
        return self._qualify(self._read_area(False), sheets)

    def _read_3d_sheets(self) -> tuple[str, ...]:
        if self._context is None:
            raise RpnError('a 3-D reference has no workbook to resolve its sheets')
        if self._version >= BiffVersion.BIFF8:
            return self._context.extern_sheets(self._read_u16())
        externsheet = int.from_bytes(self._read_bytes(2), 'little', signed=True)
        self._read_bytes(8)
        first, last = (
            int.from_bytes(self._read_bytes(2), 'little'),
            int.from_bytes(self._read_bytes(2), 'little'),
        )
        if externsheet >= 0:
            raise RpnError('a 3-D reference names a sheet of another document')
        if first == last == 0xFFFF or first == last == 0xFFFE:
            raise RpnError('a 3-D reference names a deleted or unspecified sheet')
        return self._context.sheet_span(first, last)

    def _compose_reference(
        self,
        row_word: int,
        col: int,
        flags_word: int,
        relative: bool,
    ) -> Expression:
        """
        Compose one cell reference from its raw words. BIFF8 keeps the relative flags in the
        column word and fourteen column bits; the earlier versions keep the flags in the row
        word, fourteen row bits, and eight column bits.
        """
        if self._version >= BiffVersion.BIFF8:
            row = row_word
            row_relative = bool(flags_word & 0x8000)
            col_relative = bool(flags_word & 0x4000)
        else:
            row = row_word & 0x3FFF
            row_relative = bool(flags_word & 0x8000)
            col_relative = bool(flags_word & 0x4000)
        if not relative:
            return XlA1Reference(
                row=row + 1,
                col=col + 1,
                relative_row=row_relative,
                relative_col=col_relative,
            )
        if self._version >= BiffVersion.BIFF8:
            row_bits, col_bits = 0x8000, 0x80
        else:
            row_bits, col_bits = 0x2000, 0x80
        if row_relative and row >= row_bits:
            row -= 2 * row_bits
        if col_relative and col >= col_bits:
            col -= 2 * col_bits
        return XlR1C1Reference(
            row=row if row_relative else row + 1,
            col=col if col_relative else col + 1,
            relative_row=row_relative,
            relative_col=col_relative,
        )

    def _read_attr_data(self) -> int:
        """
        The data word of a `ptgAttr` token, which is one byte wide in BIFF2 and two bytes wide
        in every later version, for both the choose counts and their jump distances.
        """
        if self._version < BiffVersion.BIFF3:
            return self._read_u8()
        return self._read_u16()

    def _skip_mem_token(self, token: Ptg):
        """
        The memory tokens of the reference subexpressions: their payload is a size the caller
        never consumes, because the subexpression itself follows in the stream.
        """
        if token == Ptg.MEMAREA:
            if self._version < BiffVersion.BIFF3:
                self._read_bytes(3)
                self._read_u8()
            else:
                self._read_bytes(4)
                self._read_u16()
        elif token == Ptg.MEMERR or token == Ptg.MEMNOMEM:
            self._read_bytes(4 if self._version < BiffVersion.BIFF3 else 6)
        else:
            if self._version < BiffVersion.BIFF3:
                self._read_u8()
            else:
                self._read_u16()

    def _skip_mem_func(self):
        if self._version < BiffVersion.BIFF3:
            self._read_u8()
        else:
            self._read_u16()

    def _skip_reference_error(self, token: Ptg):
        """
        The broken-reference tokens: their payload mirrors the reference token of the same
        version without any cell coordinates to decode.
        """
        biff8 = self._version >= BiffVersion.BIFF8
        if token == Ptg.REFERR:
            self._read_bytes(4 if biff8 else 3)
        elif token == Ptg.AREAERR:
            self._read_bytes(8 if biff8 else 6)
        elif token == Ptg.REFERR3D:
            self._read_bytes(6 if biff8 else 17)
        else:
            self._read_bytes(10 if biff8 else 20)
