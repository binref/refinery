from __future__ import annotations

import datetime
import posixpath

from collections.abc import Iterator, Sequence
from xml.etree.ElementTree import Element, ParseError

from defusedxml.ElementTree import fromstring, iterparse

from refinery.lib.excel.common import (
    Cell,
    CellKind,
    DefinedName,
    ExcelFormatError,
    FormulaSource,
    SheetKind,
    date_cell,
    decode_xstring,
    is_builtin_date_format,
    is_date_format_string,
    local_name,
    rc2ref,
    ref2rc,
)
from refinery.lib.excel.formula.model import Expression, XlUnparsedFormula
from refinery.lib.excel.formula.parse import parse_formula
from refinery.lib.excel.workbook import ExcelFormat, ExcelSheet, ExcelWorkbook, _Package

_REL_WORKSHEET = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet'
_REL_CHARTSHEET = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/chartsheet'
_REL_MACROSHEET = 'http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet'
_REL_INTL_MACROSHEET = 'http://schemas.microsoft.com/office/2006/relationships/xlIntlMacrosheet'
_REL_SHARED_STRINGS = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings'
_REL_STYLES = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles'
_RELATIONSHIP_NS = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'

_SHEET_KINDS = {
    _REL_WORKSHEET: SheetKind.WORKSHEET,
    _REL_CHARTSHEET: SheetKind.CHART,
    _REL_MACROSHEET: SheetKind.MACROSHEET,
    _REL_INTL_MACROSHEET: SheetKind.MACROSHEET,
}


def _resolve_part(base: str, target: str) -> str:
    target = target.replace('\\', '/')
    if target.startswith('/'):
        return target.lstrip('/')
    return posixpath.normpath(posixpath.join(base, target))


def _collect_text(element: Element) -> str:
    parts: list[str] = []
    for child in element:
        local = local_name(child.tag)
        if local == 't':
            parts.append(child.text or '')
        elif local == 'r':
            for run in child:
                if local_name(run.tag) == 't':
                    parts.append(run.text or '')
    return ''.join(parts)


def _cast_number(text: str) -> int | float:
    if '.' in text or 'e' in text or 'E' in text:
        number = float(text)
    else:
        number = int(text)
    if isinstance(number, float) and number.is_integer():
        return int(number)
    return number


class OoxmlSheet(ExcelSheet):
    """
    A worksheet, macrosheet, or chart sheet of an `OoxmlWorkbook`. Calling `cells` streams the
    cell elements of the sheet part; when the part is missing or malformed, the cells read up
    to the defect are yielded first and an `ExcelFormatError` is raised afterwards.
    """

    def __init__(self, name: str, kind: SheetKind, part: str | None, workbook: OoxmlWorkbook):
        self.name = name
        self.kind = kind
        self._part = part
        self._workbook = workbook

    def cells(self) -> Iterator[Cell]:
        """
        Iterate over every cell of the sheet, in document order.
        """
        if self._part is None:
            raise ExcelFormatError(F'sheet {self.name!r} is not attached to a cell part')
        stream = self._workbook._package.open(self._part)
        if stream is None:
            raise ExcelFormatError(F'part {self._part!r} of sheet {self.name!r} is missing')
        context = iterparse(stream, events=('start', 'end'))
        root = None
        row_number = 0
        try:
            first = next(context, None)
            if first is None or first[0] != 'start':
                raise ExcelFormatError(F'part {self._part!r} of sheet {self.name!r} is empty')
            root = first[1]
            for event, element in context:
                if event != 'end' or local_name(element.tag) != 'row':
                    continue
                reference = element.get('r')
                if reference is not None and reference.isascii() and reference.isdigit():
                    row_number = int(reference)
                else:
                    row_number += 1
                next_col = 1
                for cell_element in element:
                    if local_name(cell_element.tag) != 'c':
                        continue
                    row = row_number
                    col = next_col
                    cell_reference = cell_element.get('r')
                    if cell_reference is not None:
                        try:
                            row, col = ref2rc(cell_reference)
                        except ValueError:
                            pass
                    next_col = col + 1
                    yield self._build_cell(cell_element, row, col)
                element.clear()
                root.clear()
        except ParseError as error:
            raise ExcelFormatError(F'sheet {self.name!r} is malformed') from error

    def _build_cell(self, element: Element, row: int, col: int) -> Cell:
        formula: str | None = None
        assignment = False
        value_text: str | None = None
        inline: str | None = None
        for child in element:
            local = local_name(child.tag)
            if local == 'f':
                formula = child.text or None
                assignment = (child.get('bx') or '').lower() in ('1', 'true')
            elif local == 'v':
                value_text = child.text
            elif local == 'is':
                inline = decode_xstring(_collect_text(child))
        workbook = self._workbook
        kind_hint = element.get('t')
        if kind_hint == 's':
            if value_text is None:
                return Cell(row, col, CellKind.BLANK, None, formula)
            try:
                index = int(value_text)
            except ValueError:
                index = -1
            strings = workbook._ensure_shared_strings()
            if not 0 <= index < len(strings):
                raise ExcelFormatError(
                    F'cell {rc2ref(row, col)} of sheet {self.name!r} references shared string'
                    F' {value_text} outside the table of {len(strings)} entries')
            return Cell(row, col, CellKind.TEXT, strings[index], formula, assignment)
        if kind_hint == 'inlineStr' and inline is not None:
            return Cell(row, col, CellKind.TEXT, inline, formula, assignment)
        if value_text is None:
            if formula is not None:
                return Cell(row, col, CellKind.FORMULA, None, formula, assignment)
            return Cell(row, col, CellKind.BLANK, None, None)
        if kind_hint == 'str':
            return Cell(
                row,
                col,
                CellKind.TEXT,
                decode_xstring(value_text),
                formula,
                assignment,
            )
        if kind_hint == 'b':
            return Cell(
                row,
                col,
                CellKind.BOOLEAN,
                value_text.strip().lower() in ('1', 'true'),
                formula,
                assignment,
            )
        if kind_hint == 'e':
            return Cell(row, col, CellKind.ERROR, value_text, formula, assignment)
        if kind_hint == 'd':
            try:
                return Cell(
                    row,
                    col,
                    CellKind.DATE,
                    datetime.datetime.fromisoformat(value_text),
                    formula,
                    assignment,
                )
            except ValueError as error:
                raise ExcelFormatError(
                    F'cell {rc2ref(row, col)} of sheet {self.name!r} has the malformed value'
                    F' {value_text!r}') from error
        try:
            number = _cast_number(value_text)
        except ValueError as error:
            raise ExcelFormatError(
                F'cell {rc2ref(row, col)} of sheet {self.name!r} has the malformed value'
                F' {value_text!r}') from error
        if workbook._style_is_date(element.get('s')):
            return date_cell(row, col, number, workbook._date_mode_1904, formula, assignment)
        return Cell(row, col, CellKind.NUMBER, number, formula, assignment)


class OoxmlWorkbook(ExcelWorkbook):
    """
    A reader for workbooks in the Office Open XML format, which covers the XLSX and XLSM file
    extensions. The parts of the container are located through the relationships of the
    workbook part so that relocated or oddly cased part names do not break extraction.
    """

    format = ExcelFormat.OOXML

    def __init__(self, data: bytes | bytearray | memoryview):
        self._package = _Package(data)
        workbook_part = self._workbook_part()
        self._base = posixpath.dirname(workbook_part)
        self._rels = self._read_rels(workbook_part)
        self._date_mode_1904 = False
        self._sheets: list[OoxmlSheet] = []
        self._names: list[DefinedName] = []
        self._shared_strings: list[str] = []
        self._shared_strings_loaded = False
        self._formats: dict[int, str] = {}
        self._style_formats: list[int] | None = None
        root = self._parse_part(workbook_part, 'workbook part')
        for element in root.iter():
            local = local_name(element.tag)
            if local == 'workbookPr':
                mode = element.get('date1904') or ''
                self._date_mode_1904 = mode.lower() in ('true', '1')
            elif local == 'sheet':
                name = element.get('name') or ''
                rid = element.get(F'{{{_RELATIONSHIP_NS}}}id')
                target, rel_type = self._rels.get(rid or '', (None, None))
                part = None if target is None else _resolve_part(self._base, target)
                kind = _SHEET_KINDS.get(rel_type or '', SheetKind.OTHER)
                self._sheets.append(OoxmlSheet(name, kind, part, self))
            elif local == 'definedName':
                self._names.append(self._defined_name(element))

    def sheets(self) -> list[OoxmlSheet]:
        """
        All sheets of the workbook in document order.
        """
        return self._sheets

    def defined_names(self) -> Sequence[DefinedName]:
        """
        All defined names of the workbook, in the order their `definedName` elements appear.
        """
        return self._names

    def formula(self, source: FormulaSource) -> Expression | None:
        """
        Decode the formula text of a cell or a defined name of this workbook through the text
        parser. Text the parser cannot read in full yields the carrier that prints it verbatim,
        and `None` yields `None`; a byte string is not an OOXML source.
        """
        if source is None:
            return None
        if isinstance(source, str):
            return parse_formula(source)
        return XlUnparsedFormula(text=bytes(source).hex())

    @staticmethod
    def _defined_name(element: Element) -> DefinedName:
        """
        Parse one `definedName` element. A built-in name carries the `_xlnm.` prefix, which the
        BIFF readers spell away as the lower-case name its single-byte code selects, so the
        prefix is stripped and the name lower-cased to match. An element without text names a
        broken reference; the empty formula it yields decodes to the empty carrier, as the empty
        token stream of the other readers does.
        """
        name = element.get('name') or ''
        if name.startswith('_xlnm.'):
            name = name[len('_xlnm.'):].lower()
        sheet = element.get('localSheetId')
        try:
            scope = None if sheet is None else int(sheet)
        except ValueError:
            scope = None
        return DefinedName(
            name=name,
            formula=element.text or '',
            sheet=scope,
        )

    def _workbook_part(self) -> str:
        part = 'xl/workbook.xml'
        stream = self._package.open('[Content_Types].xml')
        if stream is not None:
            try:
                root = fromstring(stream.read())
            except ParseError:
                return part
            for element in root.iter():
                if local_name(element.tag) != 'Override':
                    continue
                if 'sheet.main+xml' not in (element.get('ContentType') or ''):
                    continue
                override = element.get('PartName')
                if override:
                    part = override.replace('\\', '/').lstrip('/')
                    break
        return part

    def _read_rels(self, workbook_part: str) -> dict[str, tuple[str, str]]:
        base = posixpath.dirname(workbook_part)
        name = posixpath.basename(workbook_part)
        rels = posixpath.join(base, '_rels', F'{name}.rels')
        stream = self._package.open(rels)
        if stream is None:
            return {}
        try:
            root = fromstring(stream.read())
        except ParseError:
            return {}
        result: dict[str, tuple[str, str]] = {}
        for element in root.iter():
            if local_name(element.tag) != 'Relationship':
                continue
            rid = element.get('Id')
            if rid:
                result[rid] = (element.get('Target') or '', element.get('Type') or '')
        return result

    def _parse_part(self, part: str, what: str) -> Element:
        stream = self._package.open(part)
        if stream is None:
            raise ExcelFormatError(F'{what} {part!r} is missing from the archive')
        try:
            return fromstring(stream.read())
        except ParseError as error:
            raise ExcelFormatError(F'{what} {part!r} is malformed') from error

    def _part_for(self, rel_type: str) -> str | None:
        for target, rtype in self._rels.values():
            if rtype == rel_type:
                return _resolve_part(self._base, target)
        return None

    def _ensure_shared_strings(self) -> list[str]:
        if not self._shared_strings_loaded:
            self._load_shared_strings()
            self._shared_strings_loaded = True
        return self._shared_strings

    def _load_shared_strings(self) -> None:
        part = self._part_for(_REL_SHARED_STRINGS)
        if part is None:
            return
        stream = self._package.open(part)
        if stream is None:
            raise ExcelFormatError(F'shared string part {part!r} is missing from the archive')
        context = iterparse(stream, events=('start', 'end'))
        root = None
        strings: list[str] = []
        try:
            first = next(context, None)
            if first is None or first[0] != 'start':
                raise ExcelFormatError(F'shared string part {part!r} is empty')
            root = first[1]
            for event, element in context:
                if event != 'end' or local_name(element.tag) != 'si':
                    continue
                strings.append(decode_xstring(_collect_text(element)))
                element.clear()
                root.clear()
        except ParseError as error:
            raise ExcelFormatError(F'shared string part {part!r} is malformed') from error
        self._shared_strings = strings

    def _load_styles(self) -> None:
        part = self._part_for(_REL_STYLES)
        self._style_formats = []
        if part is None:
            return
        stream = self._package.open(part)
        if stream is None:
            return
        try:
            root = fromstring(stream.read())
        except ParseError:
            return
        for element in root.iter():
            local = local_name(element.tag)
            if local == 'numFmt':
                try:
                    self._formats[int(element.get('numFmtId') or 0)] = element.get('formatCode') or ''
                except ValueError:
                    pass
            elif local == 'cellXfs':
                for xf in element:
                    try:
                        self._style_formats.append(int(xf.get('numFmtId') or 0))
                    except ValueError:
                        self._style_formats.append(0)

    def _style_is_date(self, style: str | None) -> bool:
        if self._style_formats is None:
            self._load_styles()
        assert self._style_formats is not None
        if style is None:
            return False
        try:
            index = int(style)
        except ValueError:
            return False
        if not 0 <= index < len(self._style_formats):
            return False
        fmt_id = self._style_formats[index]
        code = self._formats.get(fmt_id)
        if code is None:
            return is_builtin_date_format(fmt_id)
        return is_date_format_string(code)
