from __future__ import annotations

import enum
import zipfile
import zlib

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import IO, Iterator
from xml.etree.ElementTree import ParseError

from defusedxml.ElementTree import fromstring

from refinery.lib.excel.common import (
    Cell,
    DefinedName,
    ExcelFormatError,
    FormulaSource,
    SheetKind,
    local_name,
)
from refinery.lib.excel.formula.model import Expression
from refinery.lib.id import Fmt, get_microsoft_format
from refinery.lib.structures import MemoryFile


class ExcelFormat(enum.Enum):
    """
    The container family of an Excel workbook.
    """
    OOXML = enum.auto()
    XLSB = enum.auto()
    BIFF = enum.auto()


class ExcelSheet(ABC):
    """
    A single sheet of an `ExcelWorkbook`.
    """
    name: str
    kind: SheetKind

    @abstractmethod
    def cells(self) -> Iterator[Cell]:
        """
        Iterate over every cell of the sheet, in document order.
        """


class ExcelWorkbook(ABC):
    """
    A workbook of arbitrary Excel format, exposing its sheets without interpreting or
    rendering any of the values they contain.
    """

    format: ExcelFormat

    @abstractmethod
    def sheets(self) -> Sequence[ExcelSheet]:
        """
        All sheets of the workbook in document order.
        """

    def formula(self, source: FormulaSource) -> Expression | None:
        """
        Decode the formula source of a cell or a defined name of this workbook into the
        formula model. A source the format cannot decode yields the unparsed carrier rather
        than an error, and `None` — a cell that is not a formula — yields `None`.
        """
        raise NotImplementedError

    def defined_names(self) -> Sequence[DefinedName]:
        """
        All defined names of the workbook, in the order their records appear; the position
        of a name in this list is the index its format's name token carries.
        """
        raise NotImplementedError


_RAW_BIFF_VERSIONS = b'\x00\x02\x04\x08'
_RAW_BIFF_LENGTHS = frozenset((0x0004, 0x0006, 0x0008, 0x0010))

_PACKAGE_DEFECTS = (zipfile.BadZipFile, zlib.error, EOFError, RuntimeError)


class _PartStream:
    """
    A package part as a read-only binary stream. Reading a defective entry of the archive
    raises `ExcelFormatError` instead of the exception class of the `zipfile` module.
    """

    def __init__(self, stream: IO[bytes]):
        self._stream = stream

    def read(self, size: int = -1) -> bytes:
        try:
            return self._stream.read(size)
        except _PACKAGE_DEFECTS as error:
            raise ExcelFormatError('the package contains a defective part') from error


class _Package:
    """
    The zip container of an OOXML or XLSB workbook. Parts are looked up case-insensitively
    and with normalized slashes because workbooks written by non-Microsoft software
    frequently deviate from the conventional part names. A part that is stored under the
    same name more than once resolves to its last entry, as it does for `zipfile`.
    """

    def __init__(self, data: bytes | bytearray | memoryview):
        self._zip = zipfile.ZipFile(MemoryFile(data, bytes))
        self._entries: dict[str, zipfile.ZipInfo] = {}
        for info in self._zip.infolist():
            if not info.is_dir():
                self._entries[self._key(info.filename)] = info

    @staticmethod
    def _key(name: str) -> str:
        return name.replace('\\', '/').lower()

    def __contains__(self, part: str) -> bool:
        return self._key(part) in self._entries

    def open(self, part: str) -> _PartStream | None:
        info = self._entries.get(self._key(part))
        if info is None:
            return None
        try:
            return _PartStream(self._zip.open(info))
        except _PACKAGE_DEFECTS as error:
            raise ExcelFormatError('the package contains a defective part') from error


def detect_format(data: bytes | bytearray | memoryview) -> ExcelFormat | None:
    """
    Determine the Excel container family of the input: a zip archive containing an OOXML
    workbook part, a zip archive containing an XLSB workbook part, an OLE compound file with
    a workbook stream, or a raw BIFF record stream that is not wrapped in any container.
    The zip detection accepts a part at its conventional location or one that the content
    types of the package declare as the main document part, which is exactly what the readers
    resolve; any other zip is not a workbook.
    """
    view = memoryview(data)
    if view[:2] == b'PK':
        try:
            package = _Package(view)
        except zipfile.BadZipFile:
            return None
        if 'xl/workbook.xml' in package:
            return ExcelFormat.OOXML
        if 'xl/workbook.bin' in package:
            return ExcelFormat.XLSB
        try:
            content_types = package.open('[Content_Types].xml')
        except ExcelFormatError:
            return None
        if content_types is not None:
            try:
                root = fromstring(content_types.read())
            except (ParseError, ExcelFormatError):
                return None
            for element in root.iter():
                if (
                    local_name(element.tag) == 'Override'
                    and 'sheet.main+xml' in (element.get('ContentType') or '')
                ):
                    return ExcelFormat.OOXML
        return None
    if get_microsoft_format(view) == Fmt.XLS:
        return ExcelFormat.BIFF
    if (
        view[:1] == b'\x09'
        and view[1:2] in _RAW_BIFF_VERSIONS
        and int.from_bytes(view[2:4], 'little') in _RAW_BIFF_LENGTHS
    ):
        return ExcelFormat.BIFF
    return None


def open_workbook(data: bytes | bytearray | memoryview) -> ExcelWorkbook:
    """
    Read a workbook of any supported Excel format. Raises `ExcelFormatError` when the input
    is not a workbook at all; sheets that are defective are reported while iterating their
    cells rather than when opening the workbook.
    """
    detected = detect_format(data)
    if detected is ExcelFormat.OOXML:
        from refinery.lib.excel.ooxml import OoxmlWorkbook
        return OoxmlWorkbook(data)
    if detected is ExcelFormat.BIFF:
        from refinery.lib.excel.biff import BiffWorkbook
        return BiffWorkbook(data)
    if detected is ExcelFormat.XLSB:
        from refinery.lib.excel.xlsb import XlsbWorkbook
        return XlsbWorkbook(data)
    if detected is None:
        raise ExcelFormatError('Input not recognized as Excel workbook.')
    raise ExcelFormatError(F'The {detected.name} format is not implemented yet.')
