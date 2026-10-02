"""
The MS-XLSB operand layouts for the shared RPN stack machine: one reader per token whose byte
layout the XLSB formula grammar defines. The token identifiers are the same classless
spellings the BIFF decoder masks its token bytes down to, but the operand widths differ: the
XLSB grammar counts string characters with two bytes, grows the row of a reference to four
bytes, resolves 3-D references through the externals section of the workbook part, and places
array constants inside the token stream instead of the trailing pool BIFF keeps them in.
"""
from __future__ import annotations

from refinery.lib.excel.formula.model import (
    Expression,
    XlA1Reference,
    XlArrayConstant,
    XlBinaryExpression,
    XlBinaryOperator,
    XlNumber,
    XlString,
)
from refinery.lib.excel.formula.ptg import Ptg, RpnContext, RpnDecoder, RpnError


class XlsbRpnDecoder(RpnDecoder):
    """
    The stack machine over the formula stream of an MS-XLSB cell or name record. A reference
    token stores absolute coordinates whatever its relative flags say, because the flags only
    tell which axes Excel copies the reference along; the context resolves defined names and
    the extern-sheet indexes of 3-D references.
    """

    _context: RpnContext | None

    def _read_string(self) -> XlString:
        """
        The `ptgStr` token: a two-byte character count followed by UTF-16 characters.
        """
        count = self._read_u16()
        return XlString(value=self._read_bytes(2 * count).decode('utf_16_le'))

    def _read_function_id(self) -> int:
        return self._read_u16()

    def _read_function_variable(self) -> tuple[int, int, bool]:
        """
        The payload of a `ptgFuncVar` token: an argument count whose top bit only marks a
        pending prompt, then a two-byte identifier. An identifier of 255 — with or without the
        macro bit, which selects the macro-command half of the id space — names a user-defined
        call whose name operand sits below the arguments on the stack.
        """
        argc = self._read_u8() & 0x7F
        index = self._read_u16()
        return index, argc, (index & 0x7FFF) == 0xFF

    def _read_defined_name(self) -> Expression:
        """
        The `ptgName` token: a one-based index into the name table, padded with two unused
        bytes.
        """
        index = self._read_u16()
        self._read_bytes(2)
        if self._context is None:
            raise RpnError('a name token has no workbook to resolve it')
        return self._context.defined_name(index)

    def _read_reference(self, relative: bool) -> Expression:
        """
        The `ptgRef` and `ptgRefN` tokens: a four-byte row and a two-byte column whose top
        bits carry the relative flags. The grammar stores the absolute position in both
        spellings; the containing cell of a copied formula is what the flags select for.
        """
        return self._compose(self._read_u32(), self._read_u16())

    def _read_area(self, relative: bool) -> Expression:
        """
        The `ptgArea` and `ptgAreaN` tokens: two corners of a rectangle, each carrying the
        reference layout of the grammar.
        """
        first_row = self._read_u32()
        second_row = self._read_u32()
        first_col_word = self._read_u16()
        second_col_word = self._read_u16()
        return XlBinaryExpression(
            left=self._compose(first_row, first_col_word),
            operator=XlBinaryOperator.RANGE,
            right=self._compose(second_row, second_col_word),
        )

    def _read_3d_reference(self) -> Expression:
        """
        The `ptgRef3d` token: an extern-sheet index followed by a reference.
        """
        sheets = self._read_3d_sheets()
        return self._qualify(self._read_reference(False), sheets)

    def _read_3d_area(self) -> Expression:
        """
        The `ptgArea3d` token: an extern-sheet index followed by an area.
        """
        sheets = self._read_3d_sheets()
        return self._qualify(self._read_area(False), sheets)

    def _read_3d_sheets(self) -> tuple[str, ...]:
        if self._context is None:
            raise RpnError('a 3-D reference has no workbook to resolve its sheets')
        return self._context.extern_sheets(self._read_u16())

    @staticmethod
    def _compose(row: int, col_word: int) -> XlA1Reference:
        return XlA1Reference(
            row=row + 1,
            col=(col_word & 0x3FFF) + 1,
            relative_row=bool(col_word & 0x8000),
            relative_col=bool(col_word & 0x4000),
        )

    def _read_array(self) -> Expression:
        """
        The `ptgArray` token: a column count in which zero spells two hundred fifty-six, a row
        count, and then the constants in row-major order, each announced by a type byte.
        """
        cols = self._read_u8()
        if cols == 0:
            cols = 256
        rows = self._read_u16()
        constants = []
        for _ in range(cols * rows):
            kind = self._read_u8()
            if kind == 0x01:
                number = self._read_double()
                # a double that holds an integer is an integer literal: the synthesizer prints
                # it without the decimal point, as Excel writes it
                if number.is_integer():
                    number = int(number)
                constants.append(XlNumber(value=number))
            elif kind == 0x02:
                count = self._read_u16()
                constants.append(XlString(value=self._read_bytes(2 * count).decode('utf_16_le')))
            else:
                raise RpnError(F'an array constant of type {kind:#x} holds no literal')
        return XlArrayConstant(
            rows=[tuple(constants[index:index + cols]) for index in range(0, len(constants), cols)]
        )

    def _skip_mem_token(self, token: Ptg) -> None:
        """
        The memory tokens of the reference subexpressions: a length word every one of them
        carries, with the memory-area tokens additionally announcing the rectangles of the
        subexpression that follows, which this reader only has to step over.
        """
        if token == Ptg.MEMAREA:
            self._read_bytes(4)
            size = self._read_u16()
            if size:
                count = self._read_u16()
                self._read_bytes(12 * count)
        elif token == Ptg.MEMERR or token == Ptg.MEMNOMEM:
            self._read_bytes(4)
            self._read_bytes(self._read_u16())
        else:
            self._read_bytes(self._read_u16())

    def _skip_mem_func(self) -> None:
        self._read_bytes(self._read_u16())

    def _skip_reference_error(self, token: Ptg) -> None:
        """
        The broken-reference tokens: reserved words as wide as the reference token of the same
        kind, which is one reference layout wider than the BIFF8 pair.
        """
        if token == Ptg.REFERR:
            self._read_bytes(6)
        elif token == Ptg.AREAERR:
            self._read_bytes(12)
        elif token == Ptg.REFERR3D:
            self._read_bytes(8)
        else:
            self._read_bytes(14)
