"""
The AST model for Excel formulas: a family of `refinery.lib.scripts` expression nodes that
every formula source — the text an OOXML part stores, the RPN token stream a BIFF or XLSB cell
stores — decodes into, and that the synthesizer prints back as formula text.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass, field

from refinery.lib.scripts import Expression


class XlBinaryOperator(enum.Enum):
    """
    An operator written between two operands. The three reference operators are members of the
    same family: a range spans, an intersection narrows to shared cells, and a union gathers.
    """

    ADD = '+'
    SUB = '-'
    MUL = '*'
    DIV = '/'
    POW = '^'
    CONCAT = '&'
    RANGE = ':'
    ISECT = ' '
    UNION = ','
    EQ = '='
    NE = '<>'
    LT = '<'
    LE = '<='
    GT = '>'
    GE = '>='


class XlUnaryOperator(enum.Enum):
    """
    An operator written before or after one operand.
    """

    NEG = '-'
    POS = '+'
    PERCENT = '%'


@dataclass(repr=False, eq=False)
class XlNumber(Expression, spelling='raw'):
    value: int | float = 0
    raw: str = ''


@dataclass(repr=False, eq=False)
class XlString(Expression):
    value: str = ''


@dataclass(repr=False, eq=False)
class XlBoolean(Expression):
    value: bool = False


@dataclass(repr=False, eq=False)
class XlError(Expression):
    """
    An error literal such as `#N/A`; the text domain is the one `ERROR_TEXT` decodes cell
    errors into.
    """

    value: str = '#VALUE!'


XlLiteral = XlNumber | XlString | XlBoolean | XlError


@dataclass(repr=False, eq=False)
class XlBinaryExpression(Expression):
    left: Expression | None = None
    operator: XlBinaryOperator = XlBinaryOperator.ADD
    right: Expression | None = None


@dataclass(repr=False, eq=False)
class XlUnaryExpression(Expression):
    operator: XlUnaryOperator = XlUnaryOperator.NEG
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class XlParenExpression(Expression):
    """
    A parenthesis the source wrote around an operand. It spells nothing of its own, so comparing
    programs identifies it with what it holds.
    """

    operand: Expression | None = None

    def canonical_form(self) -> Expression | None:
        return self.operand


@dataclass(repr=False, eq=False)
class XlA1Reference(Expression):
    """
    A cell reference in A1 notation. The row and column are one-based absolute numbers, and the
    relative flags say which axes Excel copies the reference along; `sheets` holds one name for
    a qualified reference, two for the 3-D span that `Sheet1:Sheet2!A1` spells, and nothing for
    a reference local to the sheet the formula sits on.
    """

    sheets: tuple[str, ...] | None = None
    row: int = 1
    col: int = 1
    relative_row: bool = True
    relative_col: bool = True


@dataclass(repr=False, eq=False)
class XlR1C1Reference(Expression):
    """
    A cell reference in R1C1 notation. When a relative flag is set, the number on that axis is
    an offset from the cell that contains the formula rather than an absolute position, so only
    the macrosheet layer that knows the containing cell can resolve it. The `sheets` field
    carries the same qualification a `XlA1Reference` does.
    """

    sheets: tuple[str, ...] | None = None
    row: int = 1
    col: int = 1
    relative_row: bool = True
    relative_col: bool = True


@dataclass(repr=False, eq=False)
class XlDefinedName(Expression):
    """
    A reference to a defined name, qualified by the sheet that scoped it when it is not global.
    The `_xlfn.` and `_xlnm.` prefixes Excel writes for future and built-in names are part of
    the name and preserved verbatim.
    """

    name: str = ''
    sheet: str | None = None


@dataclass(repr=False, eq=False)
class XlFunctionCall(Expression):
    """
    A call to a function or macro. The callee is normally the function name; a defined name or
    a reference can also be called, because a macro is a cell and `R1C1()` is the call to the
    macro in the cell that reference points at.
    """

    callee: str | XlDefinedName | XlA1Reference | XlR1C1Reference = ''
    arguments: list[Expression] = field(default_factory=list)

    def canonical_form(self) -> Expression | None:
        # a defined name in the callee position spells no differently than a function name, so
        # text cannot tell the two apart and comparing programs must not either
        if isinstance(self.callee, XlDefinedName):
            return XlFunctionCall(callee=self.callee.name, arguments=self.arguments)
        return None


@dataclass(repr=False, eq=False)
class XlMissingArgument(Expression):
    """
    An argument a call omits: `IF(a,,b)` passes nothing in the middle. It prints no text.
    """


@dataclass(repr=False, eq=False)
class XlArrayConstant(Expression):
    """
    A constant array literal such as `{1,2;3,4}`. Each row is a tuple of literals; the list
    separator divides columns and the semicolon divides rows. The rows are tuples rather than
    lists so that the node framework recognizes the nesting as children.
    """

    rows: list[tuple[XlLiteral, ...]] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class XlUnparsedFormula(Expression, unparsed=True):
    """
    The carrier for a formula source the decoders or the parser could not read: hostile or
    truncated text, a token stream that does not decode. It prints the text it was handed.
    """

    text: str = ''
