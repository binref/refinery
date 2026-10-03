"""
The shared substrate for the RPN formula streams that BIFF and XLSB cells store: the `Ptg`
token table with the value-class bits masked away, the built-in function-id table that the call
tokens index, and one stack machine that folds a token stream into the AST model. The machine
owns every policy that does not depend on byte layout — operator folding, call assembly, the
`ptgAttr` rules — while each container family supplies its own operand readers through a
subclass.
"""
from __future__ import annotations

import enum
import struct

from typing import Protocol

from refinery.lib.excel.common import ERROR_TEXT
from refinery.lib.excel.formula.model import (
    Expression,
    XlA1Reference,
    XlBinaryExpression,
    XlBinaryOperator,
    XlBoolean,
    XlDefinedName,
    XlError,
    XlFunctionCall,
    XlMissingArgument,
    XlNumber,
    XlParenExpression,
    XlR1C1Reference,
    XlString,
    XlUnaryExpression,
    XlUnaryOperator,
)


class Ptg(enum.IntEnum):
    """
    The base ptg values after the value-class bits are masked off. The raw token byte of an
    operand ptg carries two class bits above the base: adding `0x40` selects the value class
    and adding `0x60` the array class, which never changes what the token means for the model.
    The names follow the Microsoft documentation, so the union operator is `UNION` even though
    its ptg is historically spelled `tList`.
    """

    EXP = 0x01
    TBL = 0x02
    ADD = 0x03
    SUB = 0x04
    MUL = 0x05
    DIV = 0x06
    POW = 0x07
    CONCAT = 0x08
    LT = 0x09
    LE = 0x0A
    EQ = 0x0B
    GE = 0x0C
    GT = 0x0D
    NE = 0x0E
    ISECT = 0x0F
    UNION = 0x10
    RANGE = 0x11
    UPLUS = 0x12
    UMINUS = 0x13
    PERCENT = 0x14
    PAREN = 0x15
    MISSARG = 0x16
    STR = 0x17
    EXTENDED = 0x18
    ATTR = 0x19
    SHEET = 0x1A
    ENDSHEET = 0x1B
    ERR = 0x1C
    BOOL = 0x1D
    INT = 0x1E
    NUM = 0x1F
    ARRAY = 0x20
    FUNC = 0x21
    FUNCVAR = 0x22
    NAME = 0x23
    REF = 0x24
    AREA = 0x25
    MEMAREA = 0x26
    MEMERR = 0x27
    MEMNOMEM = 0x28
    MEMFUNC = 0x29
    REFERR = 0x2A
    AREAERR = 0x2B
    REFN = 0x2C
    AREAN = 0x2D
    MEMAREAN = 0x2E
    MEMNOMEMN = 0x2F
    FUNCCE = 0x38
    NAMEX = 0x39
    REF3D = 0x3A
    AREA3D = 0x3B
    REFERR3D = 0x3C
    AREAERR3D = 0x3D


def base_ptg(token: int) -> Ptg:
    """
    Strip the value-class bits off a raw token byte. Control ptgs live below `0x20` and carry
    no class bits; an operand ptg keeps its reference-class spelling, `0x40` adds the value
    class and `0x60` the array class. A byte that names no ptg raises `RpnError`.
    """
    try:
        if token < 0x20:
            return Ptg(token)
        return Ptg((token | 0x20) & 0x3F)
    except ValueError:
        raise RpnError(F'the byte {token:#x} names no token') from None


BUILTIN_FUNCTIONS: dict[int, tuple[str, int, int]] = {
    # id: (name, minimum arguments, maximum arguments); -1 marks an unknown arity
    0x000: ('COUNT', 0, 30),
    0x001: ('IF', 1, 3),
    0x002: ('ISNA', 1, 1),
    0x003: ('ISERROR', 1, 1),
    0x004: ('SUM', 0, 30),
    0x005: ('AVERAGE', 1, 30),
    0x006: ('MIN', 1, 30),
    0x007: ('MAX', 1, 30),
    0x008: ('ROW', 0, 1),
    0x009: ('COLUMN', 0, 1),
    0x00A: ('NA', 0, 0),
    0x00B: ('NPV', 2, 30),
    0x00C: ('STDEV', 1, 30),
    0x00D: ('DOLLAR', 1, 2),
    0x00E: ('FIXED', 2, 3),
    0x00F: ('SIN', 1, 1),
    0x010: ('COS', 1, 1),
    0x011: ('TAN', 1, 1),
    0x012: ('ATAN', 1, 1),
    0x013: ('PI', 0, 0),
    0x014: ('SQRT', 1, 1),
    0x015: ('EXP', 1, 1),
    0x016: ('LN', 1, 1),
    0x017: ('LOG10', 1, 1),
    0x018: ('ABS', 1, 1),
    0x019: ('INT', 1, 1),
    0x01A: ('SIGN', 1, 1),
    0x01B: ('ROUND', 2, 2),
    0x01C: ('LOOKUP', 2, 3),
    0x01D: ('INDEX', 2, 4),
    0x01E: ('REPT', 2, 2),
    0x01F: ('MID', 3, 3),
    0x020: ('LEN', 1, 1),
    0x021: ('VALUE', 1, 1),
    0x022: ('TRUE', 0, 0),
    0x023: ('FALSE', 0, 0),
    0x024: ('AND', 1, 30),
    0x025: ('OR', 1, 30),
    0x026: ('NOT', 1, 1),
    0x027: ('MOD', 2, 2),
    0x028: ('DCOUNT', 3, 3),
    0x029: ('DSUM', 3, 3),
    0x02A: ('DAVERAGE', 3, 3),
    0x02B: ('DMIN', 3, 3),
    0x02C: ('DMAX', 3, 3),
    0x02D: ('DSTDEV', 3, 3),
    0x02E: ('VAR', 1, 30),
    0x02F: ('DVAR', 3, 3),
    0x030: ('TEXT', 2, 2),
    0x031: ('LINEST', 1, 4),
    0x032: ('TREND', 1, 4),
    0x033: ('LOGEST', 1, 4),
    0x034: ('GROWTH', 1, 4),
    0x035: ('GOTO', 1, 1),
    0x036: ('HALT', 0, 1),
    0x037: ('RETURN', 0, 1),
    0x038: ('PV', 3, 5),
    0x039: ('FV', 3, 5),
    0x03A: ('NPER', 3, 5),
    0x03B: ('PMT', 3, 5),
    0x03C: ('RATE', 3, 6),
    0x03D: ('MIRR', 3, 3),
    0x03E: ('IRR', 1, 2),
    0x03F: ('RAND', 0, 0),
    0x040: ('MATCH', 2, 3),
    0x041: ('DATE', 3, 3),
    0x042: ('TIME', 3, 3),
    0x043: ('DAY', 1, 1),
    0x044: ('MONTH', 1, 1),
    0x045: ('YEAR', 1, 1),
    0x046: ('WEEKDAY', 1, 2),
    0x047: ('HOUR', 1, 1),
    0x048: ('MINUTE', 1, 1),
    0x049: ('SECOND', 1, 1),
    0x04A: ('NOW', 0, 0),
    0x04B: ('AREAS', 1, 1),
    0x04C: ('ROWS', 1, 1),
    0x04D: ('COLUMNS', 1, 1),
    0x04E: ('OFFSET', 3, 5),
    0x04F: ('ABSREF', 2, 2),
    0x050: ('RELREF', 2, 2),
    0x051: ('ARGUMENT', 0, 3),
    0x052: ('SEARCH', 2, 3),
    0x053: ('TRANSPOSE', 1, 1),
    0x054: ('ERROR', 0, 2),
    0x055: ('STEP', 0, 0),
    0x056: ('TYPE', 1, 1),
    0x057: ('ECHO', -1, -1),
    0x058: ('SET.NAME', 1, 2),
    0x059: ('CALLER', 0, 0),
    0x05A: ('DEREF', 1, 1),
    0x05B: ('WINDOWS', 0, 2),
    0x05C: ('SERIESSUM', 4, 4),
    0x05D: ('DOCUMENTS', 0, 2),
    0x05E: ('ACTIVE.CELL', 0, 0),
    0x05F: ('SELECTION', 0, 0),
    0x060: ('RESULT', 0, 1),
    0x061: ('ATAN2', 2, 2),
    0x062: ('ASIN', 1, 1),
    0x063: ('ACOS', 1, 1),
    0x064: ('CHOOSE', 2, 30),
    0x065: ('HLOOKUP', 3, 4),
    0x066: ('VLOOKUP', 3, 4),
    0x067: ('LINKS', 0, 2),
    0x068: ('INPUT', 1, 7),
    0x069: ('ISREF', 1, 1),
    0x06A: ('GET.FORMULA', 1, 1),
    0x06B: ('GET.NAME', 1, 2),
    0x06C: ('SET.VALUE', 2, 2),
    0x06D: ('LOG', 1, 2),
    0x06E: ('EXEC', 1, 4),
    0x06F: ('CHAR', 1, 1),
    0x070: ('LOWER', 1, 1),
    0x071: ('UPPER', 1, 1),
    0x072: ('PROPER', 1, 1),
    0x073: ('LEFT', 1, 2),
    0x074: ('RIGHT', 1, 2),
    0x075: ('EXACT', 2, 2),
    0x076: ('TRIM', 1, 1),
    0x077: ('REPLACE', 4, 4),
    0x078: ('SUBSTITUTE', 3, 4),
    0x079: ('CODE', 1, 1),
    0x07A: ('NAMES', -1, -1),
    0x07B: ('DIRECTORY', 0, 1),
    0x07C: ('FIND', 2, 3),
    0x07D: ('CELL', 1, 2),
    0x07E: ('ISERR', 1, 1),
    0x07F: ('ISTEXT', 1, 1),
    0x080: ('ISNUMBER', 1, 1),
    0x081: ('ISBLANK', 1, 1),
    0x082: ('T', 1, 1),
    0x083: ('N', 1, 1),
    0x084: ('FOPEN', 1, 2),
    0x085: ('FCLOSE', 1, 1),
    0x086: ('FSIZE', 1, 1),
    0x087: ('FREADLN', 1, 1),
    0x088: ('FREAD', 1, 1),
    0x089: ('FWRITELN', 2, 2),
    0x08A: ('FWRITE', 2, 2),
    0x08B: ('FPOS', 1, 2),
    0x08C: ('DATEVALUE', 1, 1),
    0x08D: ('TIMEVALUE', 1, 1),
    0x08E: ('SLN', 3, 3),
    0x08F: ('SYD', 4, 4),
    0x090: ('DDB', 4, 5),
    0x091: ('GET.DEF', 1, 3),
    0x092: ('REFTEXT', 1, 2),
    0x093: ('TEXTREF', 1, 2),
    0x094: ('INDIRECT', 1, 2),
    0x095: ('REGISTER', 0, 29),
    0x096: ('CALL', 1, 30),
    0x097: ('ADD.BAR', 1, 30),
    0x098: ('ADD.MENU', 1, 4),
    0x099: ('ADD.COMMAND', 3, 5),
    0x09A: ('ENABLE.COMMAND', 4, 5),
    0x09B: ('CHECK.COMMAND', 4, 5),
    0x09C: ('RENAME.COMMAND', 4, 5),
    0x09D: ('SHOW.BAR', 1, 1),
    0x09E: ('DELETE.MENU', 2, 3),
    0x09F: ('DELETE.COMMAND', 3, 4),
    0x0A0: ('GET.CHART.ITEM', 1, 3),
    0x0A1: ('DIALOG.BOX', 1, 1),
    0x0A2: ('CLEAN', 1, 1),
    0x0A3: ('MDETERM', 1, 1),
    0x0A4: ('MINVERSE', 1, 1),
    0x0A5: ('MMULT', 2, 2),
    0x0A6: ('FILES', 0, 2),
    0x0A7: ('IPMT', 4, 6),
    0x0A8: ('PPMT', 4, 6),
    0x0A9: ('COUNTA', 0, 30),
    0x0AA: ('CANCEL.KEY', 0, 2),
    0x0AB: ('FOR', 3, 4),
    0x0AC: ('WHILE', 1, 1),
    0x0AD: ('BREAK', 0, 0),
    0x0AE: ('NEXT', 0, 0),
    0x0AF: ('INITIATE', 2, 2),
    0x0B0: ('REQUEST', 2, 2),
    0x0B1: ('POKE', 3, 3),
    0x0B2: ('EXECUTE', 2, 2),
    0x0B3: ('TERMINATE', 1, 1),
    0x0B4: ('RESTART', 1, 1),
    0x0B5: ('HELP', 1, 1),
    0x0B6: ('GET.BAR', 0, 4),
    0x0B7: ('PRODUCT', 0, 30),
    0x0B8: ('FACT', 1, 1),
    0x0B9: ('GET.CELL', 1, 2),
    0x0BA: ('GET.WORKSPACE', 1, 1),
    0x0BB: ('GET.WINDOW', 1, 2),
    0x0BC: ('GET.DOCUMENT', 1, 2),
    0x0BD: ('DPRODUCT', 3, 3),
    0x0BE: ('ISNONTEXT', 1, 1),
    0x0BF: ('GET.NOTE', 0, 3),
    0x0C0: ('NOTE', 0, 4),
    0x0C1: ('STDEVP', 1, 30),
    0x0C2: ('VARP', 1, 30),
    0x0C3: ('DSTDEVP', 3, 3),
    0x0C4: ('DVARP', 3, 3),
    0x0C5: ('TRUNC', 1, 2),
    0x0C6: ('ISLOGICAL', 1, 1),
    0x0C7: ('DCOUNTA', 3, 3),
    0x0C8: ('DELETE.BAR', 1, 1),
    0x0C9: ('UNREGISTER', 1, 1),
    0x0CC: ('USDOLLAR', 1, 2),
    0x0CD: ('FINDB', 2, 3),
    0x0CE: ('SEARCHB', 2, 3),
    0x0CF: ('REPLACEB', 4, 4),
    0x0D0: ('LEFTB', 1, 2),
    0x0D1: ('RIGHTB', 1, 2),
    0x0D2: ('MIDB', 3, 3),
    0x0D3: ('LENB', 1, 1),
    0x0D4: ('ROUNDUP', 2, 2),
    0x0D5: ('ROUNDDOWN', 2, 2),
    0x0D6: ('ASC', 1, 1),
    0x0D7: ('DBCS', 1, 1),
    0x0D8: ('RANK', 2, 3),
    0x0DB: ('ADDRESS', 2, 5),
    0x0DC: ('DAYS360', 2, 3),
    0x0DD: ('TODAY', 0, 0),
    0x0DE: ('VDB', 5, 7),
    0x0DF: ('ELSE', 0, 0),
    0x0E0: ('ELSE.IF', 1, 1),
    0x0E1: ('END.IF', 0, 0),
    0x0E2: ('FOR.CELL', 1, 3),
    0x0E3: ('MEDIAN', 1, 30),
    0x0E4: ('SUMPRODUCT', 1, 30),
    0x0E5: ('SINH', 1, 1),
    0x0E6: ('COSH', 1, 1),
    0x0E7: ('TANH', 1, 1),
    0x0E8: ('ASINH', 1, 1),
    0x0E9: ('ACOSH', 1, 1),
    0x0EA: ('ATANH', 1, 1),
    0x0EB: ('DGET', 3, 3),
    0x0EC: ('CREATE.OBJECT', 2, 11),
    0x0ED: ('VOLATILE', 1, 1),
    0x0EE: ('LAST.ERROR', 0, 0),
    0x0EF: ('CUSTOM.UNDO', 0, 2),
    0x0F0: ('CUSTOM.REPEAT', 0, 3),
    0x0F1: ('FORMULA.CONVERT', 2, 5),
    0x0F2: ('GET.LINK.INFO', 2, 4),
    0x0F3: ('TEXT.BOX', 1, 4),
    0x0F4: ('INFO', 1, 1),
    0x0F5: ('GROUP', 0, 0),
    0x0F6: ('GET.OBJECT', 1, 5),
    0x0F7: ('DB', 4, 5),
    0x0F8: ('PAUSE', 0, 1),
    0x0FB: ('RESUME', 1, 1),
    0x0FC: ('FREQUENCY', 2, 2),
    0x0FD: ('ADD.TOOLBAR', 0, 2),
    0x0FE: ('DELETE.TOOLBAR', 1, 1),
    0x0FF: ('UserDefinedFunction', 1, 30),
    0x100: ('RESET.TOOLBAR', 1, 1),
    0x101: ('EVALUATE', 1, 1),
    0x102: ('GET.TOOLBAR', 2, 2),
    0x103: ('GET.TOOL', 1, 3),
    0x104: ('SPELLING.CHECK', 1, 3),
    0x105: ('ERROR.TYPE', 1, 1),
    0x106: ('APP.TITLE', 1, 1),
    0x107: ('WINDOW.TITLE', 1, 1),
    0x108: ('SAVE.TOOLBAR', 0, 2),
    0x109: ('ENABLE.TOOL', 3, 3),
    0x10A: ('PRESS.TOOL', 3, 3),
    0x10B: ('REGISTER.ID', 3, 3),
    0x10C: ('GET.WORKBOOK', 1, 2),
    0x10D: ('AVEDEV', 1, 30),
    0x10E: ('BETADIST', 3, 5),
    0x10F: ('GAMMALN', 1, 1),
    0x110: ('BETAINV', 3, 5),
    0x111: ('BINOMDIST', 4, 4),
    0x112: ('CHIDIST', 2, 2),
    0x113: ('CHIINV', 2, 2),
    0x114: ('COMBIN', 2, 2),
    0x115: ('CONFIDENCE', 3, 3),
    0x116: ('CRITBINOM', 3, 3),
    0x117: ('EVEN', 1, 1),
    0x118: ('EXPONDIST', 3, 3),
    0x119: ('FDIST', 3, 3),
    0x11A: ('FINV', 3, 3),
    0x11B: ('FISHER', 1, 1),
    0x11C: ('FISHERINV', 1, 1),
    0x11D: ('FLOOR', 2, 2),
    0x11E: ('GAMMADIST', 4, 4),
    0x11F: ('GAMMAINV', 3, 3),
    0x120: ('CEILING', 2, 2),
    0x121: ('HYPGEOMDIST', 4, 4),
    0x122: ('LOGNORMDIST', 3, 3),
    0x123: ('LOGINV', 3, 3),
    0x124: ('NEGBINOMDIST', 3, 3),
    0x125: ('NORMDIST', 4, 4),
    0x126: ('NORMSDIST', 1, 1),
    0x127: ('NORMINV', 3, 3),
    0x128: ('NORMSINV', 1, 1),
    0x129: ('STANDARDIZE', 3, 3),
    0x12A: ('ODD', 1, 1),
    0x12B: ('PERMUT', 2, 2),
    0x12C: ('POISSON', 3, 3),
    0x12D: ('TDIST', 3, 3),
    0x12E: ('WEIBULL', 4, 4),
    0x12F: ('SUMXMY2', 2, 2),
    0x130: ('SUMX2MY2', 2, 2),
    0x131: ('SUMX2PY2', 2, 2),
    0x132: ('CHITEST', 2, 2),
    0x133: ('CORREL', 2, 2),
    0x134: ('COVAR', 2, 2),
    0x135: ('FORECAST', 3, 3),
    0x136: ('FTEST', 2, 2),
    0x137: ('INTERCEPT', 2, 2),
    0x138: ('PEARSON', 2, 2),
    0x139: ('RSQ', 2, 2),
    0x13A: ('STEYX', 2, 2),
    0x13B: ('SLOPE', 2, 2),
    0x13C: ('TTEST', 4, 4),
    0x13D: ('PROB', 3, 4),
    0x13E: ('DEVSQ', 1, 30),
    0x13F: ('GEOMEAN', 1, 30),
    0x140: ('HARMEAN', 1, 30),
    0x141: ('SUMSQ', 0, 30),
    0x142: ('KURT', 1, 30),
    0x143: ('SKEW', 1, 30),
    0x144: ('ZTEST', 2, 3),
    0x145: ('LARGE', 2, 2),
    0x146: ('SMALL', 2, 2),
    0x147: ('QUARTILE', 2, 2),
    0x148: ('PERCENTILE', 2, 2),
    0x149: ('PERCENTRANK', 2, 3),
    0x14A: ('MODE', 1, 30),
    0x14B: ('TRIMMEAN', 2, 2),
    0x14C: ('TINV', 2, 2),
    0x14E: ('MOVIE.COMMAND', -1, -1),
    0x14F: ('GET.MOVIE', -1, -1),
    0x150: ('CONCATENATE', 0, 30),
    0x151: ('POWER', 2, 2),
    0x152: ('PIVOT.ADD.DATA', -1, -1),
    0x153: ('GET.PIVOT.TABLE', -1, -1),
    0x154: ('GET.PIVOT.FIELD', -1, -1),
    0x155: ('GET.PIVOT.ITEM', -1, -1),
    0x156: ('RADIANS', 1, 1),
    0x157: ('DEGREES', 1, 1),
    0x158: ('SUBTOTAL', 2, 30),
    0x159: ('SUMIF', 2, 3),
    0x15A: ('COUNTIF', 2, 2),
    0x15B: ('COUNTBLANK', 1, 1),
    0x15C: ('SCENARIO.GET', -1, -1),
    0x15D: ('OPTIONS.LISTS.GET', 1, 1),
    0x15E: ('ISPMT', 4, 4),
    0x15F: ('DATEDIF', 3, 3),
    0x160: ('DATESTRING', 1, 1),
    0x161: ('NUMBERSTRING', 2, 2),
    0x162: ('ROMAN', 1, 2),
    0x163: ('OPEN.DIALOG', -1, -1),
    0x164: ('SAVE.DIALOG', -1, -1),
    0x165: ('VIEW.GET', -1, -1),
    0x166: ('GETPIVOTDATA', 2, 2),
    0x167: ('HYPERLINK', 1, 2),
    0x168: ('PHONETIC', 1, 1),
    0x169: ('AVERAGEA', 1, 30),
    0x16A: ('MAXA', 1, 30),
    0x16B: ('MINA', 1, 30),
    0x16C: ('STDEVPA', 1, 30),
    0x16D: ('VARPA', 1, 30),
    0x16E: ('STDEVA', 1, 30),
    0x16F: ('VARA', 1, 30),
    0x170: ('BAHTTEXT', 1, 1),
    0x171: ('THAIDAYOFWEEK', 1, 1),
    0x172: ('THAIDIGIT', 1, 1),
    0x173: ('THAIMONTHOFYEAR', 1, 1),
    0x174: ('THAINUMSOUND', 1, 1),
    0x175: ('THAINUMSTRING', 1, 1),
    0x176: ('THAISTRINGLENGTH', 1, 1),
    0x177: ('ISTHAIDIGIT', 1, 1),
    0x178: ('ROUNDBAHTDOWN', 1, 1),
    0x179: ('ROUNDBAHTUP', 1, 1),
    0x17A: ('THAIYEAR', 1, 1),
    0x17B: ('RTD', 2, 5),
    0x17C: ('CUBEVALUE', -1, -1),
    0x17D: ('CUBEMEMBER', -1, -1),
    0x17E: ('CUBEMEMBERPROPERTY', 3, 3),
    0x17F: ('CUBERANKEDMEMBER', -1, -1),
    0x180: ('HEX2BIN', -1, -1),
    0x181: ('HEX2DEC', 1, 1),
    0x182: ('HEX2OCT', -1, -1),
    0x183: ('DEC2BIN', -1, -1),
    0x184: ('DEC2HEX', -1, -1),
    0x185: ('DEC2OCT', -1, -1),
    0x186: ('OCT2BIN', -1, -1),
    0x187: ('OCT2HEX', -1, -1),
    0x188: ('OCT2DEC', 1, 1),
    0x189: ('BIN2DEC', 1, 1),
    0x18A: ('BIN2OCT', -1, -1),
    0x18B: ('BIN2HEX', -1, -1),
    0x18C: ('IMSUB', 2, 2),
    0x18D: ('IMDIV', 2, 2),
    0x18E: ('IMPOWER', 2, 2),
    0x18F: ('IMABS', 1, 1),
    0x190: ('IMSQRT', 1, 1),
    0x191: ('IMLN', 1, 1),
    0x192: ('IMLOG2', 1, 1),
    0x193: ('IMLOG10', 1, 1),
    0x194: ('IMSIN', 1, 1),
    0x195: ('IMCOS', 1, 1),
    0x196: ('IMEXP', 1, 1),
    0x197: ('IMARGUMENT', 1, 1),
    0x198: ('IMCONJUGATE', 1, 1),
    0x199: ('IMAGINARY', 1, 1),
    0x19A: ('IMREAL', 1, 1),
    0x19B: ('COMPLEX', -1, -1),
    0x19C: ('IMSUM', -1, -1),
    0x19D: ('IMPRODUCT', -1, -1),
    0x19E: ('SERIESSUM', 4, 4),
    0x19F: ('FACTDOUBLE', 1, 1),
    0x1A0: ('SQRTPI', 1, 1),
    0x1A1: ('QUOTIENT', 2, 2),
    0x1A2: ('DELTA', -1, -1),
    0x1A3: ('GESTEP', -1, -1),
    0x1A4: ('ISEVEN', 1, 1),
    0x1A5: ('ISODD', 1, 1),
    0x1A6: ('MROUND', 2, 2),
    0x1A7: ('ERF', -1, -1),
    0x1A8: ('ERFC', 1, 1),
    0x1A9: ('BESSELJ', 2, 2),
    0x1AA: ('BESSELK', 2, 2),
    0x1AB: ('BESSELY', 2, 2),
    0x1AC: ('BESSELI', 2, 2),
    0x1AD: ('XIRR', -1, -1),
    0x1AE: ('XNPV', 3, 3),
    0x1AF: ('PRICEMAT', -1, -1),
    0x1B0: ('YIELDMAT', -1, -1),
    0x1B1: ('INTRATE', -1, -1),
    0x1B2: ('RECEIVED', -1, -1),
    0x1B3: ('DISC', -1, -1),
    0x1B4: ('PRICEDISC', -1, -1),
    0x1B5: ('YIELDDISC', -1, -1),
    0x1B6: ('TBILLEQ', 3, 3),
    0x1B7: ('TBILLPRICE', 3, 3),
    0x1B8: ('TBILLYIELD', 3, 3),
    0x1B9: ('PRICE', -1, -1),
    0x1BA: ('YIELD', -1, -1),
    0x1BB: ('DOLLARDE', 2, 2),
    0x1BC: ('DOLLARFR', 2, 2),
    0x1BD: ('NOMINAL', 2, 2),
    0x1BE: ('EFFECT', 2, 2),
    0x1BF: ('CUMPRINC', 6, 6),
    0x1C0: ('CUMIPMT', 6, 6),
    0x1C1: ('EDATE', 2, 2),
    0x1C2: ('EOMONTH', 2, 2),
    0x1C3: ('YEARFRAC', -1, -1),
    0x1C4: ('COUPDAYBS', -1, -1),
    0x1C5: ('COUPDAYS', -1, -1),
    0x1C6: ('COUPDAYSNC', -1, -1),
    0x1C7: ('COUPNCD', -1, -1),
    0x1C8: ('COUPNUM', -1, -1),
    0x1C9: ('COUPPCD', -1, -1),
    0x1CA: ('DURATION', -1, -1),
    0x1CB: ('MDURATION', -1, -1),
    0x1CC: ('ODDLPRICE', -1, -1),
    0x1CD: ('ODDLYIELD', -1, -1),
    0x1CE: ('ODDFPRICE', -1, -1),
    0x1CF: ('ODDFYIELD', -1, -1),
    0x1D0: ('RANDBETWEEN', 2, 2),
    0x1D1: ('WEEKNUM', -1, -1),
    0x1D2: ('AMORDEGRC', -1, -1),
    0x1D3: ('AMORLINC', -1, -1),
    0x1D5: ('ACCRINT', -1, -1),
    0x1D6: ('ACCRINTM', -1, -1),
    0x1D7: ('WORKDAY', -1, -1),
    0x1D8: ('NETWORKDAYS', -1, -1),
    0x1D9: ('GCD', -1, -1),
    0x1DA: ('MULTINOMIAL', -1, -1),
    0x1DB: ('LCM', -1, -1),
    0x1DC: ('FVSCHEDULE', 2, 2),
    0x1DD: ('CUBEKPIMEMBER', -1, -1),
    0x1DE: ('CUBESET', -1, -1),
    0x1DF: ('CUBESETCOUNT', 1, 1),
    0x1E0: ('IFERROR', 2, 2),
    0x1E1: ('COUNTIFS', -1, -1),
    0x1E2: ('SUMIFS', -1, -1),
    0x1E3: ('AVERAGEIF', -1, -1),
    0x8000: ('BEEP', 0, 1),
    0x8001: ('OPEN', 0, 17),
    0x8002: ('OPEN.LINKS', 0, 15),
    0x8003: ('CLOSE.ALL', 0, 0),
    0x8004: ('SAVE', 0, 0),
    0x8005: ('SAVE.AS', 0, 7),
    0x8006: ('FILE.DELETE', 0, 1),
    0x8007: ('PAGE.SETUP', 0, 30),
    0x8008: ('PRINT', 0, 17),
    0x8009: ('PRINTER.SETUP', 0, 1),
    0x800A: ('QUIT', 0, 0),
    0x800B: ('NEW.WINDOW', 0, 0),
    0x800C: ('ARRANGE.ALL', 0, 4),
    0x800D: ('WINDOW.SIZE', 0, 3),
    0x800E: ('WINDOW.MOVE', 0, 3),
    0x800F: ('FULL', 0, 1),
    0x8010: ('CLOSE', 0, 2),
    0x8011: ('RUN', 0, 2),
    0x8016: ('SET.PRINT.AREA', 0, 1),
    0x8017: ('SET.PRINT.TITLES', 0, 2),
    0x8018: ('SET.PAGE.BREAK', 0, 0),
    0x8019: ('REMOVE.PAGE.BREAK', 0, 2),
    0x801A: ('FONT', 0, 2),
    0x801B: ('DISPLAY', 0, 9),
    0x801C: ('PROTECT.DOCUMENT', 0, 7),
    0x801D: ('PRECISION', 0, 1),
    0x801E: ('A1.R1C1', 0, 1),
    0x801F: ('CALCULATE.NOW', 0, 0),
    0x8020: ('CALCULATION', 0, 11),
    0x8022: ('DATA.FIND', 0, 1),
    0x8023: ('EXTRACT', 0, 1),
    0x8024: ('DATA.DELETE', 0, 0),
    0x8025: ('SET.DATABASE', 0, 0),
    0x8026: ('SET.CRITERIA', 0, 0),
    0x8027: ('SORT', 0, 17),
    0x8028: ('DATA.SERIES', 0, 6),
    0x8029: ('TABLE', 0, 2),
    0x802A: ('FORMAT.NUMBER', 0, 1),
    0x802B: ('ALIGNMENT', 0, 10),
    0x802C: ('STYLE', 0, 2),
    0x802D: ('BORDER', 0, 27),
    0x802E: ('CELL.PROTECTION', 0, 2),
    0x802F: ('COLUMN.WIDTH', 0, 5),
    0x8030: ('UNDO', 0, 0),
    0x8031: ('CUT', 0, 2),
    0x8032: ('COPY', 0, 2),
    0x8033: ('PASTE', 0, 1),
    0x8034: ('CLEAR', 0, 1),
    0x8035: ('PASTE.SPECIAL', 0, 7),
    0x8036: ('EDIT.DELETE', 0, 1),
    0x8037: ('INSERT', 0, 2),
    0x8038: ('FILL.RIGHT', 0, 0),
    0x8039: ('FILL.DOWN', 0, 0),
    0x803D: ('DEFINE.NAME', 0, 7),
    0x803E: ('CREATE.NAMES', 0, 4),
    0x803F: ('FORMULA.GOTO', 0, 2),
    0x8040: ('FORMULA.FIND', 0, 12),
    0x8041: ('SELECT.LAST.CELL', 0, 0),
    0x8042: ('SHOW.ACTIVE.CELL', 0, 0),
    0x8043: ('GALLERY.AREA', 0, 2),
    0x8044: ('GALLERY.BAR', 0, 2),
    0x8045: ('GALLERY.COLUMN', 0, 2),
    0x8046: ('GALLERY.LINE', 0, 2),
    0x8047: ('GALLERY.PIE', 0, 2),
    0x8048: ('GALLERY.SCATTER', 0, 2),
    0x8049: ('COMBINATION', 0, 1),
    0x804A: ('PREFERRED', 0, 0),
    0x804B: ('ADD.OVERLAY', 0, 0),
    0x804C: ('GRIDLINES', 0, 7),
    0x804D: ('SET.PREFERRED', 0, 1),
    0x804E: ('AXES', 0, 6),
    0x804F: ('LEGEND', 0, 1),
    0x8050: ('ATTACH.TEXT', 0, 3),
    0x8051: ('ADD.ARROW', 0, 0),
    0x8052: ('SELECT.CHART', 0, 0),
    0x8053: ('SELECT.PLOT.AREA', 0, 0),
    0x8054: ('PATTERNS', 0, 13),
    0x8055: ('MAIN.CHART', 0, 10),
    0x8056: ('OVERLAY', 0, 12),
    0x8057: ('SCALE', 0, 10),
    0x8058: ('FORMAT.LEGEND', 0, 1),
    0x8059: ('FORMAT.TEXT', 0, 11),
    0x805A: ('EDIT.REPEAT', 0, 0),
    0x805B: ('PARSE', 0, 2),
    0x805C: ('JUSTIFY', 0, 0),
    0x805D: ('HIDE', 0, 0),
    0x805E: ('UNHIDE', 0, 1),
    0x805F: ('WORKSPACE', 0, 16),
    0x8060: ('FORMULA', 0, 2),
    0x8061: ('FORMULA.FILL', 0, 2),
    0x8062: ('FORMULA.ARRAY', 0, 2),
    0x8063: ('DATA.FIND.NEXT', 0, 0),
    0x8064: ('DATA.FIND.PREV', 0, 0),
    0x8065: ('FORMULA.FIND.NEXT', 0, 0),
    0x8066: ('FORMULA.FIND.PREV', 0, 0),
    0x8067: ('ACTIVATE', 0, 2),
    0x8068: ('ACTIVATE.NEXT', 0, 1),
    0x8069: ('ACTIVATE.PREV', 0, 1),
    0x806A: ('UNLOCKED.NEXT', 0, 0),
    0x806B: ('UNLOCKED.PREV', 0, 0),
    0x806C: ('COPY.PICTURE', 0, 3),
    0x806D: ('SELECT', 0, 2),
    0x806E: ('DELETE.NAME', 0, 1),
    0x806F: ('DELETE.FORMAT', 0, 1),
    0x8070: ('VLINE', 0, 1),
    0x8071: ('HLINE', 0, 1),
    0x8072: ('VPAGE', 0, 1),
    0x8073: ('HPAGE', 0, 1),
    0x8074: ('VSCROLL', 0, 2),
    0x8075: ('HSCROLL', 0, 2),
    0x8076: ('ALERT', 0, 3),
    0x8077: ('NEW', 0, 3),
    0x8078: ('CANCEL.COPY', 0, 1),
    0x8079: ('SHOW.CLIPBOARD', 0, 0),
    0x807A: ('MESSAGE', 0, 2),
    0x807C: ('PASTE.LINK', 0, 0),
    0x807D: ('APP.ACTIVATE', 0, 2),
    0x807E: ('DELETE.ARROW', 0, 0),
    0x807F: ('ROW.HEIGHT', 0, 4),
    0x8080: ('FORMAT.MOVE', 0, 3),
    0x8081: ('FORMAT.SIZE', 0, 3),
    0x8082: ('FORMULA.REPLACE', 0, 11),
    0x8083: ('SEND.KEYS', 0, 2),
    0x8084: ('SELECT.SPECIAL', 0, 3),
    0x8085: ('APPLY.NAMES', 0, 7),
    0x8086: ('REPLACE.FONT', 0, 10),
    0x8087: ('FREEZE.PANES', 0, 3),
    0x8088: ('SHOW.INFO', 0, 1),
    0x8089: ('SPLIT', 0, 2),
    0x808A: ('ON.WINDOW', 0, 2),
    0x808B: ('ON.DATA', 0, 2),
    0x808C: ('DISABLE.INPUT', 0, 1),
    0x808E: ('OUTLINE', 0, 4),
    0x808F: ('LIST.NAMES', 0, 0),
    0x8090: ('FILE.CLOSE', 0, 2),
    0x8091: ('SAVE.WORKBOOK', 0, 6),
    0x8092: ('DATA.FORM', 0, 0),
    0x8093: ('COPY.CHART', 0, 1),
    0x8094: ('ON.TIME', 0, 4),
    0x8095: ('WAIT', 0, 1),
    0x8096: ('FORMAT.FONT', 0, 15),
    0x8097: ('FILL.UP', 0, 0),
    0x8098: ('FILL.LEFT', 0, 0),
    0x8099: ('DELETE.OVERLAY', 0, 0),
    0x809B: ('SHORT.MENUS', 0, 1),
    0x809F: ('SET.UPDATE.STATUS', 0, 3),
    0x80A1: ('COLOR.PALETTE', 0, 1),
    0x80A2: ('DELETE.STYLE', 0, 1),
    0x80A3: ('WINDOW.RESTORE', 0, 1),
    0x80A4: ('WINDOW.MAXIMIZE', 0, 1),
    0x80A6: ('CHANGE.LINK', 0, 3),
    0x80A7: ('CALCULATE.DOCUMENT', 0, 0),
    0x80A8: ('ON.KEY', 0, 2),
    0x80A9: ('APP.RESTORE', 0, 0),
    0x80AA: ('APP.MOVE', 0, 2),
    0x80AB: ('APP.SIZE', 0, 2),
    0x80AC: ('APP.MINIMIZE', 0, 0),
    0x80AD: ('APP.MAXIMIZE', 0, 0),
    0x80AE: ('BRING.TO.FRONT', 0, 0),
    0x80AF: ('SEND.TO.BACK', 0, 0),
    0x80B9: ('MAIN.CHART.TYPE', 0, 1),
    0x80BA: ('OVERLAY.CHART.TYPE', 0, 1),
    0x80BB: ('SELECT.END', 0, 1),
    0x80BC: ('OPEN.MAIL', 0, 2),
    0x80BD: ('SEND.MAIL', 0, 3),
    0x80BE: ('STANDARD.FONT', 0, 9),
    0x80BF: ('CONSOLIDATE', 0, 5),
    0x80C0: ('SORT.SPECIAL', 0, 14),
    0x80C1: ('GALLERY.3D.AREA', 0, 1),
    0x80C2: ('GALLERY.3D.COLUMN', 0, 1),
    0x80C3: ('GALLERY.3D.LINE', 0, 1),
    0x80C4: ('GALLERY.3D.PIE', 0, 1),
    0x80C5: ('VIEW.3D', 0, 6),
    0x80C6: ('GOAL.SEEK', 0, 3),
    0x80C7: ('WORKGROUP', 0, 1),
    0x80C8: ('FILL.GROUP', 0, 1),
    0x80C9: ('UPDATE.LINK', 0, 2),
    0x80CA: ('PROMOTE', 0, 1),
    0x80CB: ('DEMOTE', 0, 1),
    0x80CC: ('SHOW.DETAIL', 0, 4),
    0x80CE: ('UNGROUP', 0, 0),
    0x80CF: ('OBJECT.PROPERTIES', 0, 2),
    0x80D0: ('SAVE.NEW.OBJECT', 0, 1),
    0x80D1: ('SHARE', 0, 0),
    0x80D2: ('SHARE.NAME', 0, 1),
    0x80D3: ('DUPLICATE', 0, 0),
    0x80D4: ('APPLY.STYLE', 0, 1),
    0x80D5: ('ASSIGN.TO.OBJECT', 0, 1),
    0x80D6: ('OBJECT.PROTECTION', 0, 2),
    0x80D7: ('HIDE.OBJECT', 0, 2),
    0x80D8: ('SET.EXTRACT', 0, 0),
    0x80D9: ('CREATE.PUBLISHER', 0, 4),
    0x80DA: ('SUBSCRIBE.TO', 0, 2),
    0x80DB: ('ATTRIBUTES', 0, 2),
    0x80DC: ('SHOW.TOOLBAR', 0, 10),
    0x80DE: ('PRINT.PREVIEW', 0, 1),
    0x80DF: ('EDIT.COLOR', 0, 4),
    0x80E0: ('SHOW.LEVELS', 0, 2),
    0x80E1: ('FORMAT.MAIN', 0, 14),
    0x80E2: ('FORMAT.OVERLAY', 0, 14),
    0x80E3: ('ON.RECALC', 0, 2),
    0x80E4: ('EDIT.SERIES', 0, 7),
    0x80E5: ('DEFINE.STYLE', 0, 14),
    0x80F0: ('LINE.PRINT', 0, 11),
    0x80F3: ('ENTER.DATA', 0, 1),
    0x80F9: ('GALLERY.RADAR', 0, 2),
    0x80FA: ('MERGE.STYLES', 0, 1),
    0x80FB: ('EDITION.OPTIONS', 0, 7),
    0x80FC: ('PASTE.PICTURE', 0, 0),
    0x80FD: ('PASTE.PICTURE.LINK', 0, 0),
    0x80FE: ('SPELLING', 0, 6),
    0x8100: ('ZOOM', 0, 1),
    0x8103: ('INSERT.OBJECT', 0, 13),
    0x8104: ('WINDOW.MINIMIZE', 0, 1),
    0x8109: ('SOUND.NOTE', 0, 3),
    0x810A: ('SOUND.PLAY', 0, 3),
    0x810B: ('FORMAT.SHAPE', 0, 5),
    0x810C: ('EXTEND.POLYGON', 0, 1),
    0x810D: ('FORMAT.AUTO', 0, 7),
    0x8110: ('GALLERY.3D.BAR', 0, 1),
    0x8111: ('GALLERY.3D.SURFACE', 0, 1),
    0x8112: ('FILL.AUTO', 0, 2),
    0x8114: ('CUSTOMIZE.TOOLBAR', 0, 1),
    0x8115: ('ADD.TOOL', 0, 3),
    0x8116: ('EDIT.OBJECT', 0, 1),
    0x8117: ('ON.DOUBLECLICK', 0, 2),
    0x8118: ('ON.ENTRY', 0, 2),
    0x8119: ('WORKBOOK.ADD', 0, 3),
    0x811A: ('WORKBOOK.MOVE', 0, 3),
    0x811B: ('WORKBOOK.COPY', 0, 3),
    0x811C: ('WORKBOOK.OPTIONS', 0, 3),
    0x811D: ('SAVE.WORKSPACE', 0, 1),
    0x8120: ('CHART.WIZARD', 0, 14),
    0x8121: ('DELETE.TOOL', 0, 2),
    0x8122: ('MOVE.TOOL', 0, 6),
    0x8123: ('WORKBOOK.SELECT', 0, 3),
    0x8124: ('WORKBOOK.ACTIVATE', 0, 2),
    0x8125: ('ASSIGN.TO.TOOL', 0, 3),
    0x8127: ('COPY.TOOL', 0, 2),
    0x8128: ('RESET.TOOL', 0, 2),
    0x8129: ('CONSTRAIN.NUMERIC', 0, 1),
    0x812A: ('PASTE.TOOL', 0, 2),
    0x812E: ('WORKBOOK.NEW', 0, 3),
    0x8131: ('SCENARIO.CELLS', 0, 1),
    0x8132: ('SCENARIO.DELETE', 0, 1),
    0x8133: ('SCENARIO.ADD', 0, 6),
    0x8134: ('SCENARIO.EDIT', 0, 7),
    0x8135: ('SCENARIO.SHOW', 0, 1),
    0x8136: ('SCENARIO.SHOW.NEXT', 0, 0),
    0x8137: ('SCENARIO.SUMMARY', 0, 2),
    0x8138: ('PIVOT.TABLE.WIZARD', 0, 16),
    0x8139: ('PIVOT.FIELD.PROPERTIES', 0, 7),
    0x813A: ('PIVOT.FIELD', 0, 4),
    0x813B: ('PIVOT.ITEM', 0, 4),
    0x813C: ('PIVOT.ADD.FIELDS', 0, 5),
    0x813E: ('OPTIONS.CALCULATION', 0, 10),
    0x813F: ('OPTIONS.EDIT', 0, 11),
    0x8140: ('OPTIONS.VIEW', 0, 18),
    0x8141: ('ADDIN.MANAGER', 0, 3),
    0x8142: ('MENU.EDITOR', 0, 0),
    0x8143: ('ATTACH.TOOLBARS', 0, 0),
    0x8144: ('VBAActivate', 0, 2),
    0x8145: ('OPTIONS.CHART', 0, 3),
    0x8148: ('VBA.INSERT.FILE', 0, 1),
    0x814A: ('VBA.PROCEDURE.DEFINITION', 0, 0),
    0x8150: ('ROUTING.SLIP', 0, 6),
    0x8152: ('ROUTE.DOCUMENT', 0, 0),
    0x8153: ('MAIL.LOGON', 0, 3),
    0x8156: ('INSERT.PICTURE', 0, 2),
    0x8157: ('EDIT.TOOL', 0, 2),
    0x8158: ('GALLERY.DOUGHNUT', 0, 2),
    0x815E: ('CHART.TREND', 0, 8),
    0x8160: ('PIVOT.ITEM.PROPERTIES', 0, 7),
    0x8162: ('WORKBOOK.INSERT', 0, 1),
    0x8163: ('OPTIONS.TRANSITION', 0, 5),
    0x8164: ('OPTIONS.GENERAL', 0, 14),
    0x8172: ('FILTER.ADVANCED', 0, 5),
    0x8175: ('MAIL.ADD.MAILER', 0, 0),
    0x8176: ('MAIL.DELETE.MAILER', 0, 0),
    0x8177: ('MAIL.REPLY', 0, 0),
    0x8178: ('MAIL.REPLY.ALL', 0, 0),
    0x8179: ('MAIL.FORWARD', 0, 0),
    0x817A: ('MAIL.NEXT.LETTER', 0, 0),
    0x817B: ('DATA.LABEL', 0, 10),
    0x817C: ('INSERT.TITLE', 0, 5),
    0x817D: ('FONT.PROPERTIES', 0, 14),
    0x817E: ('MACRO.OPTIONS', 0, 10),
    0x817F: ('WORKBOOK.HIDE', 0, 2),
    0x8180: ('WORKBOOK.UNHIDE', 0, 1),
    0x8181: ('WORKBOOK.DELETE', 0, 1),
    0x8182: ('WORKBOOK.NAME', 0, 2),
    0x8184: ('GALLERY.CUSTOM', 0, 1),
    0x8186: ('ADD.CHART.AUTOFORMAT', 0, 2),
    0x8187: ('DELETE.CHART.AUTOFORMAT', 0, 1),
    0x8188: ('CHART.ADD.DATA', 0, 6),
    0x8189: ('AUTO.OUTLINE', 0, 0),
    0x818A: ('TAB.ORDER', 0, 0),
    0x818B: ('SHOW.DIALOG', 0, 1),
    0x818C: ('SELECT.ALL', 0, 0),
    0x818D: ('UNGROUP.SHEETS', 0, 0),
    0x818E: ('SUBTOTAL.CREATE', 0, 6),
    0x818F: ('SUBTOTAL.REMOVE', 0, 0),
    0x8190: ('RENAME.OBJECT', 0, 1),
    0x819C: ('WORKBOOK.SCROLL', 0, 2),
    0x819D: ('WORKBOOK.NEXT', 0, 0),
    0x819E: ('WORKBOOK.PREV', 0, 0),
    0x819F: ('WORKBOOK.TAB.SPLIT', 0, 1),
    0x81A0: ('FULL.SCREEN', 0, 1),
    0x81A1: ('WORKBOOK.PROTECT', 0, 3),
    0x81A4: ('SCROLLBAR.PROPERTIES', 0, 7),
    0x81A5: ('PIVOT.SHOW.PAGES', 0, 2),
    0x81A6: ('TEXT.TO.COLUMNS', 0, 14),
    0x81A7: ('FORMAT.CHARTTYPE', 0, 4),
    0x81A8: ('LINK.FORMAT', 0, 0),
    0x81A9: ('TRACER.DISPLAY', 0, 2),
    0x81AE: ('TRACER.NAVIGATE', 0, 3),
    0x81AF: ('TRACER.CLEAR', 0, 0),
    0x81B0: ('TRACER.ERROR', 0, 0),
    0x81B1: ('PIVOT.FIELD.GROUP', 0, 4),
    0x81B2: ('PIVOT.FIELD.UNGROUP', 0, 0),
    0x81B3: ('CHECKBOX.PROPERTIES', 0, 5),
    0x81B4: ('LABEL.PROPERTIES', 0, 3),
    0x81B5: ('LISTBOX.PROPERTIES', 0, 5),
    0x81B6: ('EDITBOX.PROPERTIES', 0, 4),
    0x81B7: ('PIVOT.REFRESH', 0, 1),
    0x81B8: ('LINK.COMBO', 0, 1),
    0x81B9: ('OPEN.TEXT', 0, 17),
    0x81BA: ('HIDE.DIALOG', 0, 1),
    0x81BB: ('SET.DIALOG.FOCUS', 0, 1),
    0x81BC: ('ENABLE.OBJECT', 0, 2),
    0x81BD: ('PUSHBUTTON.PROPERTIES', 0, 6),
    0x81BE: ('SET.DIALOG.DEFAULT', 0, 1),
    0x81BF: ('FILTER', 0, 6),
    0x81C0: ('FILTER.SHOW.ALL', 0, 0),
    0x81C1: ('CLEAR.OUTLINE', 0, 0),
    0x81C2: ('FUNCTION.WIZARD', 0, 1),
    0x81C3: ('ADD.LIST.ITEM', 0, 2),
    0x81C4: ('SET.LIST.ITEM', 0, 2),
    0x81C5: ('REMOVE.LIST.ITEM', 0, 2),
    0x81C6: ('SELECT.LIST.ITEM', 0, 2),
    0x81C7: ('SET.CONTROL.VALUE', 0, 1),
    0x81C8: ('SAVE.COPY.AS', 0, 1),
    0x81CA: ('OPTIONS.LISTS.ADD', 0, 2),
    0x81CB: ('OPTIONS.LISTS.DELETE', 0, 1),
    0x81CC: ('SERIES.AXES', 0, 1),
    0x81CD: ('SERIES.X', 0, 1),
    0x81CE: ('SERIES.Y', 0, 2),
    0x81CF: ('ERRORBAR.X', 0, 4),
    0x81D0: ('ERRORBAR.Y', 0, 4),
    0x81D1: ('FORMAT.CHART', 0, 18),
    0x81D2: ('SERIES.ORDER', 0, 3),
    0x81D3: ('MAIL.LOGOFF', 0, 0),
    0x81D4: ('CLEAR.ROUTING.SLIP', 0, 1),
    0x81D5: ('APP.ACTIVATE.MICROSOFT', 0, 1),
    0x81D6: ('MAIL.EDIT.MAILER', 0, 6),
    0x81D7: ('ON.SHEET', 0, 3),
    0x81D8: ('STANDARD.WIDTH', 0, 1),
    0x81D9: ('SCENARIO.MERGE', 0, 1),
    0x81DA: ('SUMMARY.INFO', 0, 5),
    0x81DB: ('FIND.FILE', 0, 0),
    0x81DC: ('ACTIVE.CELL.FONT', 0, 14),
    0x81DD: ('ENABLE.TIPWIZARD', 0, 1),
    0x81DE: ('VBA.MAKE.ADDIN', 0, 1),
    0x81E0: ('INSERTDATATABLE', 0, 1),
    0x81E1: ('WORKGROUP.OPTIONS', 0, 0),
    0x81E2: ('MAIL.SEND.MAILER', 0, 2),
    0x81E5: ('AUTOCORRECT', 0, 2),
    0x81E9: ('POST.DOCUMENT', 0, 1),
    0x81EB: ('PICKLIST', 0, 0),
    0x81ED: ('VIEW.SHOW', 0, 1),
    0x81EE: ('VIEW.DEFINE', 0, 3),
    0x81EF: ('VIEW.DELETE', 0, 1),
    0x81FD: ('SHEET.BACKGROUND', 0, 2),
    0x81FE: ('INSERT.MAP.OBJECT', 0, 0),
    0x81FF: ('OPTIONS.MENONO', 0, 5),
    0x8205: ('MSOCHECKS', 0, 0),
    0x8206: ('NORMAL', 0, 0),
    0x8207: ('LAYOUT', 0, 0),
    0x8208: ('RM.PRINT.AREA', 0, 1),
    0x8209: ('CLEAR.PRINT.AREA', 0, 0),
    0x820A: ('ADD.PRINT.AREA', 0, 0),
    0x820B: ('MOVE.BRK', 0, 4),
    0x8221: ('HIDECURR.NOTE', 0, 2),
    0x8222: ('HIDEALL.NOTES', 0, 1),
    0x8223: ('DELETE.NOTE', 0, 1),
    0x8224: ('TRAVERSE.NOTES', 0, 2),
    0x8225: ('ACTIVATE.NOTES', 0, 2),
    0x826C: ('PROTECT.REVISIONS', 0, 0),
    0x826D: ('UNPROTECT.REVISIONS', 0, 0),
    0x8287: ('OPTIONS.ME', 0, 9),
    0x828D: ('WEB.PUBLISH', 0, 9),
    0x829B: ('NEWWEBQUERY', 0, 1),
    0x82A1: ('PIVOT.TABLE.CHART', 0, 16),
    0x82F1: ('OPTIONS.SAVE', 0, 4),
    0x82F3: ('OPTIONS.SPELL', 0, 12),
    0x8328: ('HIDEALL.INKANNOTS', 0, 1),
}

# the ptgAttr grbit bits, from the Microsoft documentation.
ATTR_VOLATILE = 0x01
ATTR_IF = 0x02
ATTR_CHOOSE = 0x04
ATTR_SKIP = 0x08
ATTR_SUM = 0x10
ATTR_ASSIGN = 0x20
ATTR_SPACE = 0x40

_BINARY_OPERATORS = {
    Ptg.ADD: XlBinaryOperator.ADD,
    Ptg.SUB: XlBinaryOperator.SUB,
    Ptg.MUL: XlBinaryOperator.MUL,
    Ptg.DIV: XlBinaryOperator.DIV,
    Ptg.POW: XlBinaryOperator.POW,
    Ptg.CONCAT: XlBinaryOperator.CONCAT,
    Ptg.LT: XlBinaryOperator.LT,
    Ptg.LE: XlBinaryOperator.LE,
    Ptg.EQ: XlBinaryOperator.EQ,
    Ptg.GE: XlBinaryOperator.GE,
    Ptg.GT: XlBinaryOperator.GT,
    Ptg.NE: XlBinaryOperator.NE,
    Ptg.ISECT: XlBinaryOperator.ISECT,
    Ptg.UNION: XlBinaryOperator.UNION,
    Ptg.RANGE: XlBinaryOperator.RANGE,
}

_UNARY_OPERATORS = {
    Ptg.UPLUS: XlUnaryOperator.POS,
    Ptg.UMINUS: XlUnaryOperator.NEG,
    Ptg.PERCENT: XlUnaryOperator.PERCENT,
}

_MEMORY_TOKENS = frozenset((
    Ptg.MEMAREA,
    Ptg.MEMERR,
    Ptg.MEMNOMEM,
    Ptg.MEMAREAN,
    Ptg.MEMNOMEMN,
))


class RpnError(Exception):
    """
    Raised when a formula token stream cannot be decoded in full. The workbook layer catches
    it and hands the caller the unparsed carrier instead, so a hostile stream never breaks a
    caller.
    """


class RpnContext(Protocol):
    """
    What the stack machine needs to know about the workbook a formula stream belongs to: the
    names its `ptgName` tokens index and the sheets its 3-D tokens resolve through.
    """

    def defined_name(self, index: int) -> XlDefinedName:
        """
        The defined name the given name index refers to.
        """
        ...

    def extern_sheets(self, ixti: int) -> tuple[str, ...]:
        """
        The sheet names the given extern-sheet index spans, from one entry for a plain
        qualification to two for a 3-D span.
        """
        ...


class RpnDecoder:
    """
    The stack machine a BIFF or XLSB subclass drives over its formula bytes. Every token is
    folded into the model as it is read; a stream is only valid if it consumes exactly and
    leaves exactly one expression on the stack.
    """

    def __init__(self, view: memoryview, context: RpnContext | None = None):
        self._view = view
        self._pos = 0
        self._context = context
        self._stack: list[Expression] = []

    def decode(self) -> Expression:
        while self._pos < len(self._view):
            self._step()
        if len(self._stack) != 1:
            raise RpnError(F'the token stream left {len(self._stack)} operands on the stack')
        return self._stack[0]

    def _take(self, count: int) -> list[Expression]:
        if len(self._stack) < count:
            raise RpnError(F'a token asked for {count} operands but {len(self._stack)} remain')
        if not count:
            return []
        operands = self._stack[-count:]
        del self._stack[-count:]
        return operands

    def _step(self):
        token = base_ptg(self._read_u8())
        if token in _BINARY_OPERATORS:
            left, right = self._take(2)
            self._stack.append(XlBinaryExpression(
                left=left,
                operator=_BINARY_OPERATORS[token],
                right=right,
            ))
            return
        if token in _UNARY_OPERATORS:
            operand, = self._take(1)
            self._stack.append(XlUnaryExpression(
                operator=_UNARY_OPERATORS[token],
                operand=operand,
            ))
            return
        if token == Ptg.PAREN:
            operand, = self._take(1)
            self._stack.append(XlParenExpression(operand=operand))
            return
        if token == Ptg.MISSARG:
            self._stack.append(XlMissingArgument())
            return
        if token == Ptg.ATTR:
            self._attr()
            return
        if token == Ptg.ERR:
            code = self._read_u8()
            text = ERROR_TEXT.get(code)
            if text is None:
                raise RpnError(F'unknown error code {code:#x}')
            self._stack.append(XlError(value=text))
            return
        if token == Ptg.BOOL:
            self._stack.append(XlBoolean(value=self._read_u8() != 0))
            return
        if token == Ptg.INT:
            self._stack.append(XlNumber(value=self._read_u16()))
            return
        if token == Ptg.NUM:
            number = self._read_double()
            # a double that holds an integer is an integer literal: the synthesizer prints it
            # without the decimal point, as Excel writes it
            if number.is_integer():
                number = int(number)
            self._stack.append(XlNumber(value=number))
            return
        if token == Ptg.STR:
            self._stack.append(self._read_string())
            return
        if token == Ptg.FUNC:
            index = self._read_function_id()
            self._stack.append(self._call_fixed_arity(index))
            return
        if token == Ptg.FUNCVAR:
            index, argc, user_defined = self._read_function_variable()
            self._stack.append(self._call_variable_arity(index, argc, user_defined))
            return
        if token == Ptg.NAME:
            self._stack.append(self._read_defined_name())
            return
        if token == Ptg.REF:
            self._stack.append(self._read_reference(relative=False))
            return
        if token == Ptg.AREA:
            self._stack.append(self._read_area(relative=False))
            return
        if token == Ptg.REFN:
            self._stack.append(self._read_reference(relative=True))
            return
        if token == Ptg.AREAN:
            self._stack.append(self._read_area(relative=True))
            return
        if (
            token == Ptg.REFERR
            or token == Ptg.REFERR3D
        ):
            self._skip_reference_error(token)
            self._stack.append(XlError(value='#REF!'))
            return
        if (
            token == Ptg.AREAERR
            or token == Ptg.AREAERR3D
        ):
            self._skip_reference_error(token)
            self._stack.append(XlError(value='#REF!'))
            return
        if token == Ptg.REF3D:
            self._stack.append(self._read_3d_reference())
            return
        if token == Ptg.AREA3D:
            self._stack.append(self._read_3d_area())
            return
        if token == Ptg.ARRAY:
            self._stack.append(self._read_array())
            return
        if token in _MEMORY_TOKENS:
            self._skip_mem_token(token)
            return
        if token == Ptg.MEMFUNC:
            self._skip_mem_func()
            return
        raise RpnError(F'the token {token:#x} has no decoder')

    def _attr(self):
        """
        The `ptgAttr` rules: whitespace and assignment bookkeeping is dropped, the control-flow
        subtypes are consumed with their jump tables, and the sum subtype is the `SUM` call,
        because `=SUM(1)` is stored as `tInt(1), tAttrSum` with no call token anywhere.
        """
        grbit = self._read_u8()
        count = self._read_attr_data()
        if grbit & ATTR_CHOOSE:
            for _ in range(count + 1):
                self._read_attr_data()
        if grbit & ATTR_SUM:
            operand, = self._take(1)
            self._stack.append(XlFunctionCall(callee='SUM', arguments=[operand]))

    def _call_fixed_arity(self, index: int) -> XlFunctionCall:
        entry = BUILTIN_FUNCTIONS.get(index)
        if entry is None:
            raise RpnError(F'unknown fixed-arity function id {index:#x}')
        name, lo, _hi = entry
        if lo < 0:
            raise RpnError(F'function id {index:#x} has no recorded arity')
        return XlFunctionCall(callee=name, arguments=self._take(lo))

    def _call_variable_arity(
        self,
        index: int,
        argc: int,
        user_defined: bool,
    ) -> XlFunctionCall:
        if user_defined:
            operands = self._take(argc)
            if not operands:
                raise RpnError('a user-defined call carries no name operand')
            callee, *arguments = operands
            if isinstance(callee, XlString):
                return XlFunctionCall(callee=callee.value, arguments=arguments)
            if not isinstance(callee, (XlA1Reference, XlR1C1Reference, XlDefinedName)):
                raise RpnError('a user-defined call has an unspellable name operand')
            return XlFunctionCall(callee=callee, arguments=arguments)
        entry = BUILTIN_FUNCTIONS.get(index)
        if entry is None:
            raise RpnError(F'unknown function id {index:#x}')
        name, lo, hi = entry
        if lo >= 0 and not lo <= argc <= hi:
            raise RpnError(F'function {name} was called with {argc} of {lo}..{hi} arguments')
        return XlFunctionCall(callee=name, arguments=self._take(argc))

    def _read_u8(self) -> int:
        if self._pos >= len(self._view):
            raise RpnError('the token stream ends inside a token')
        value = self._view[self._pos]
        self._pos += 1
        return value

    def _read_u16(self) -> int:
        if self._pos + 2 > len(self._view):
            raise RpnError('the token stream ends inside a token')
        value = struct.unpack_from('<H', self._view, self._pos)[0]
        self._pos += 2
        return value

    def _read_u32(self) -> int:
        if self._pos + 4 > len(self._view):
            raise RpnError('the token stream ends inside a token')
        value = struct.unpack_from('<I', self._view, self._pos)[0]
        self._pos += 4
        return value

    def _read_double(self) -> float:
        if self._pos + 8 > len(self._view):
            raise RpnError('the token stream ends inside a token')
        value = struct.unpack_from('<d', self._view, self._pos)[0]
        self._pos += 8
        return value

    def _read_bytes(self, count: int) -> bytes:
        if self._pos + count > len(self._view):
            raise RpnError('the token stream ends inside a token')
        raw = bytes(self._view[self._pos:self._pos + count])
        self._pos += count
        return raw

    def _read_text(self, count: int, encoding: str) -> str:
        """
        Read `count` bytes as text in the given encoding; bytes that do not decode in it are a
        defect of the stream like any other.
        """
        try:
            return self._read_bytes(count).decode(encoding)
        except UnicodeDecodeError as error:
            raise RpnError(F'a string token does not decode as {encoding}') from error

    # the operand readers a container family supplies; every default raises so that a subclass
    # cannot silently skip a token it does not implement.

    def _read_string(self) -> XlString:
        raise RpnError('this decoder does not read string tokens')

    def _read_function_id(self) -> int:
        raise RpnError('this decoder does not read fixed-arity call tokens')

    def _read_function_variable(self) -> tuple[int, int, bool]:
        raise RpnError('this decoder does not read variable-arity call tokens')

    def _read_defined_name(self) -> Expression:
        raise RpnError('this decoder does not read name tokens')

    def _read_reference(self, relative: bool) -> Expression:
        raise RpnError('this decoder does not read reference tokens')

    def _read_area(self, relative: bool) -> Expression:
        raise RpnError('this decoder does not read area tokens')

    def _read_3d_reference(self) -> Expression:
        raise RpnError('this decoder does not read 3-D reference tokens')

    def _read_3d_area(self) -> Expression:
        raise RpnError('this decoder does not read 3-D area tokens')

    def _read_array(self) -> Expression:
        raise RpnError('this decoder does not read array tokens')

    def _read_attr_data(self) -> int:
        return self._read_u16()

    def _qualify(self, expression: Expression, sheets: tuple[str, ...]) -> Expression:
        """
        Attach the sheet span of a 3-D token to every reference it contains.
        """
        if isinstance(expression, XlBinaryExpression):
            if expression.left is not None:
                self._qualify(expression.left, sheets)
            if expression.right is not None:
                self._qualify(expression.right, sheets)
        elif isinstance(expression, (XlA1Reference, XlR1C1Reference)):
            expression.sheets = sheets
        return expression

    def _skip_mem_token(self, token: Ptg) -> None:
        raise RpnError('this decoder does not read memory tokens')

    def _skip_mem_func(self) -> None:
        raise RpnError('this decoder does not read memory tokens')

    def _skip_reference_error(self, token: Ptg) -> None:
        raise RpnError('this decoder does not read broken reference tokens')
