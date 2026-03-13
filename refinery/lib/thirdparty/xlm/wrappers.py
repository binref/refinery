from __future__ import annotations

import re

from fnmatch import fnmatch
from io import BytesIO
from typing import Any, Dict, List, Tuple
from zipfile import ZipFile

from refinery.lib.thirdparty.xlm.model import (
    Boundsheet,
    Cell,
    RowAttribute,
    XlApplicationInternational,
)

_XL_INTERNATIONAL_DEFAULTS = {
    XlApplicationInternational.xlLeftBracket : '[',
    XlApplicationInternational.xlListSeparator: ',',
    XlApplicationInternational.xlRightBracket : ']',
}

_XLSM_COLOR_TABLE: List[Tuple[int, int, int, int]] = [
    (  0,   0,   0,  1), (255, 255, 255,  2), (255,   0,   0,  3), (  0, 255,   0,  4),
    (  0,   0, 255,  5), (255, 255,   0,  6), (255,   0, 255,  7), (  0, 255, 255,  8),
    (128,   0,   0,  9), (  0, 128,   0, 10), (  0,   0, 128, 11), (128, 128,   0, 12),
    (128,   0, 128, 13), (  0, 128, 128, 14), (192, 192, 192, 15), (128, 128, 128, 16),
    (153, 153, 255, 17), (153,  51, 102, 18), (255, 255, 204, 19), (204, 255, 255, 20),
    (102,   0, 102, 21), (255, 128, 128, 22), (  0, 102, 204, 23), (204, 204, 255, 24),
    (  0,   0, 128, 25), (255,   0, 255, 26), (255, 255,   0, 27), (  0, 255, 255, 28),
    (128,   0, 128, 29), (128,   0,   0, 30), (  0, 128, 128, 31), (  0,   0, 255, 32),
    (  0, 204, 255, 33), (204, 255, 255, 34), (204, 255, 204, 35), (255, 255, 153, 36),
    (153, 204, 255, 37), (255, 153, 204, 38), (204, 153, 255, 39), (255, 204, 153, 40),
    ( 51, 102, 255, 41), ( 51, 204, 204, 42), (153, 204,   0, 43), (255, 204,   0, 44),
    (255, 153,   0, 45), (255, 102,   0, 46), (102, 102, 153, 47), (150, 150, 150, 48),
    (  0,  51, 102, 49), ( 51, 153, 102, 50), (  0,  51,   0, 51), ( 51,  51,   0, 52),
    (153,  51,   0, 53), (153,  51, 102, 54), ( 51,  51, 153, 55), ( 51,  51,  51, 56),
]

CellInfoResult = Tuple[Any, bool, bool]


class XLSWrapper:
    def __init__(self, data: bytes | bytearray):
        import xlrd2
        self._xlrd2 = xlrd2
        self.xls_workbook = xlrd2.open_workbook(file_contents=bytes(data), formatting_info=True)
        self._workbook_name = 'workbook.xls'
        self._macrosheets: Dict[str, Boundsheet] | None = None
        self._worksheets: Dict[str, Boundsheet] | None = None
        self._defined_names: Dict[str, Any] | None = None
        control_chars = ''.join(map(chr, range(0, 32)))
        control_chars += ''.join(map(chr, range(127, 160)))
        control_chars += '\ufefe\uffff\ufeff\ufffe\uffef\ufff0\ufff1\ufff6\ufefd\udddd\ufffd'
        self._control_char_re = re.compile(f'[{re.escape(control_chars)}]')

    oNUM = 2
    oSTRG = 1
    oREF = -1
    oARR = 6

    def get_xl_international_char(self, flag_name: XlApplicationInternational) -> str | None:
        return _XL_INTERNATIONAL_DEFAULTS.get(flag_name)

    def get_workbook_name(self) -> str:
        return self._workbook_name

    def get_defined_names(self) -> Dict[str, Any]:
        if self._defined_names is None:
            self._defined_names = {}
            for name_obj, cells in self.xls_workbook.name_map.items():
                name = name_obj.lower()
                index = 1 if len(cells) > 1 else 0
                filtered_name = name.lower()
                if name != filtered_name:
                    if filtered_name in self._defined_names:
                        filtered_name = filtered_name + str(index)
                    if cells[0].result is not None:
                        self._defined_names[filtered_name] = cells[0].result.text

                if name in self._defined_names:
                    name = name + str(index)
                if cells[0].result is not None:
                    cell_location = cells[0].result.text
                    if cells[0].result.kind == self.oNUM:
                        self._defined_names[name] = cells[0].result.value
                    elif cells[0].result.kind == self.oSTRG:
                        self._defined_names[name] = cells[0].result.text
                    elif cells[0].result.kind == self.oARR:
                        self._defined_names[name] = cells[0].result.value
                    elif cells[0].result.kind == self.oREF:
                        if '$' in cell_location:
                            self._defined_names[name] = cells[0].result.text
                        else:
                            curr_cell = cells[0].result
                            if 'auto_open' in name:
                                coords = curr_cell.value[0].coords
                                r = int(coords[3])
                                c = int(coords[5])
                                sheet_name = curr_cell.text.split('!')[0].replace("'", '')
                                cell_ref = f'${Cell.convert_to_column_name(c)}${r}'
                                self._defined_names[name] = f'{sheet_name}!{cell_ref}'
        return self._defined_names

    def get_defined_name(self, name: str, full_match: bool = True) -> Any:
        result: Any = []
        name = name.lower().replace('[', '')
        if full_match:
            if name in self.get_defined_names():
                result = self._defined_names[name]  # type: ignore
        else:
            for defined_name, cell_address in self.get_defined_names().items():
                if defined_name.startswith(name):
                    result.append((defined_name, cell_address))
            if isinstance(result, list) and len(result) == 0:
                for defined_name, cell_address in self.get_defined_names().items():
                    lastidx = 0
                    match = True
                    for c in name:
                        idx = defined_name.find(c, lastidx)
                        if idx == -1:
                            match = False
                            break
                        lastidx = idx
                    if match:
                        result.append((defined_name, cell_address))
        return result

    def _load_cells(self, boundsheet: Boundsheet, xls_sheet: Any) -> None:
        try:
            for xls_cell in xls_sheet.get_used_cells():
                cell = Cell()
                cell.sheet = boundsheet
                if xls_cell.formula is not None and len(xls_cell.formula) > 0:
                    cell.formula = f'={xls_cell.formula}'
                cell.value = xls_cell.value
                cell.row = xls_cell.row + 1
                cell.column = Cell.convert_to_column_name(xls_cell.column + 1)
                if cell.value is not None or cell.formula is not None:
                    boundsheet.add_cell(cell)
        except Exception:
            pass

    def get_macrosheets(self) -> Dict[str, Boundsheet]:
        if self._macrosheets is None:
            import xlrd2
            self._macrosheets = {}
            for sheet in self.xls_workbook.sheets():
                if sheet.boundsheet_type == xlrd2.biffh.XL_MACROSHEET:
                    macrosheet = Boundsheet(sheet.name, 'Macrosheet')
                    self._load_cells(macrosheet, sheet)
                    self._macrosheets[sheet.name] = macrosheet
        return self._macrosheets

    def get_worksheets(self) -> Dict[str, Boundsheet]:
        if self._worksheets is None:
            import xlrd2
            self._worksheets = {}
            for sheet in self.xls_workbook.sheets():
                if sheet.boundsheet_type == xlrd2.biffh.XL_WORKSHEET:
                    worksheet = Boundsheet(sheet.name, 'Worksheet')
                    self._load_cells(worksheet, sheet)
                    self._worksheets[sheet.name] = worksheet
        return self._worksheets

    def get_cell_info(
        self, sheet_name: str, col: str, row: str, info_type_id: str,
    ) -> CellInfoResult:
        sheet = self.xls_workbook.sheet_by_name(sheet_name)
        irow = int(row) - 1
        column = Cell.convert_to_column_index(col) - 1
        tid = int(float(info_type_id))
        data: Any = None
        not_exist = False
        not_implemented = False

        if tid == 5:
            data = sheet.cell(irow, column).value
        elif tid == 17:
            if irow in sheet.rowinfo_map:
                data = sheet.rowinfo_map[irow].height
            else:
                data = sheet.default_row_height
            data = round(Cell.convert_twip_to_point(data) * 4) / 4
        else:
            if (irow, column) in sheet.used_cells:
                cell = sheet.cell(irow, column)
                if cell.xf_index is not None and cell.xf_index < len(self.xls_workbook.xf_list):
                    fmt = self.xls_workbook.xf_list[cell.xf_index]
                    font = self.xls_workbook.font_list[fmt.font_index]
                else:
                    normal_style = self.xls_workbook.style_name_map['Normal'][1]
                    fmt = self.xls_workbook.xf_list[normal_style]
                    font = self.xls_workbook.font_list[fmt.font_index]
            else:
                normal_style = self.xls_workbook.style_name_map['Normal'][1]
                fmt = self.xls_workbook.xf_list[normal_style]
                font = self.xls_workbook.font_list[fmt.font_index]

            if tid == 8:
                data = fmt.alignment.hor_align + 1
            elif tid == 19:
                data = Cell.convert_twip_to_point(font.height)
            elif tid == 24:
                data = font.colour_index - 7 if font.colour_index > 7 else font.colour_index
            elif tid == 38:
                data = fmt.background.pattern_colour_index - 7 if font.colour_index > 7 else font.colour_index
            elif tid == 50:
                data = fmt.alignment.vert_align + 1
            else:
                not_implemented = True

        return data, not_exist, not_implemented


class XLSBWrapper:
    def __init__(self, data: bytes | bytearray):
        from pyxlsb2 import open_workbook
        self._xlsb_workbook = open_workbook(BytesIO(data))
        self._workbook_name = 'workbook.xlsb'
        self._macrosheets: Dict[str, Boundsheet] | None = None
        self._worksheets: Dict[str, Boundsheet] | None = None
        self._defined_names: Dict[str, Any] | None = None

    def get_xl_international_char(self, flag_name: XlApplicationInternational) -> str | None:
        return _XL_INTERNATIONAL_DEFAULTS.get(flag_name)

    def get_workbook_name(self) -> str:
        return self._workbook_name

    def get_defined_names(self) -> Dict[str, Any]:
        if self._defined_names is None:
            names: Dict[str, Any] = {}
            for key, val in self._xlsb_workbook.defined_names.items():
                names[key.lower()] = key.lower(), val.formula
            self._defined_names = names
        return self._defined_names

    def get_defined_name(self, name: str, full_match: bool = True) -> Any:
        result: list[Any] = []
        if full_match:
            if name.lower() in self.get_defined_names():
                result.append(self.get_defined_names()[name.lower()])
        else:
            for defined_name, cell_address in self.get_defined_names().items():
                if defined_name.startswith(name.lower()):
                    result.append(cell_address)
        return result

    def _load_cells(self, boundsheet: Boundsheet) -> None:
        from pyxlsb2.formula import Formula
        row_cnt = 0
        with self._xlsb_workbook.get_sheet_by_name(boundsheet.name) as sheet:
            for row in sheet:
                if row_cnt > 1048576:
                    break
                row_cnt += 1
                column_cnt = 0
                for cell in row:
                    if column_cnt > 16384:
                        break
                    tmp_cell = Cell()
                    tmp_cell.row = cell.row_num + 1
                    tmp_cell.column = Cell.convert_to_column_name(cell.col + 1)
                    tmp_cell.value = cell.value
                    tmp_cell.sheet = boundsheet
                    formula_str = Formula.parse(cell.formula)
                    if formula_str._tokens:
                        try:
                            tmp_cell.formula = f'={formula_str.stringify(self._xlsb_workbook)}'
                        except NotImplementedError:
                            pass
                        except Exception:
                            pass
                    if tmp_cell.value is not None or tmp_cell.formula is not None:
                        boundsheet.cells[tmp_cell.get_local_address()] = tmp_cell
                    column_cnt += 1

    def get_macrosheets(self) -> Dict[str, Boundsheet]:
        if self._macrosheets is None:
            self._macrosheets = {}
            for xlsb_sheet in self._xlsb_workbook.sheets:
                if xlsb_sheet.type == 'macrosheet':
                    macrosheet = Boundsheet(xlsb_sheet.name, 'macrosheet')
                    self._load_cells(macrosheet)
                    self._macrosheets[macrosheet.name] = macrosheet
        return self._macrosheets

    def get_worksheets(self) -> Dict[str, Boundsheet]:
        if self._worksheets is None:
            self._worksheets = {}
            for xlsb_sheet in self._xlsb_workbook.sheets:
                if xlsb_sheet.type == 'worksheet':
                    worksheet = Boundsheet(xlsb_sheet.name, 'worksheet')
                    self._load_cells(worksheet)
                    self._worksheets[worksheet.name] = worksheet
        return self._worksheets

    def get_cell_info(
        self, sheet_name: str, col: str, row: str, info_type_id: str,
    ) -> CellInfoResult:
        return None, False, True


_OOXML_NS = {
    's' : 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
    'r' : 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
    'xm': 'http://schemas.microsoft.com/office/excel/2006/main',
    'mc': 'http://schemas.openxmlformats.org/markup-compatibility/2006',
    'ct': 'http://schemas.openxmlformats.org/package/2006/content-types',
    'pr': 'http://schemas.openxmlformats.org/package/2006/relationships',
}

_MACRO_REL_TYPES = {
    'http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet',
    'http://schemas.microsoft.com/office/2006/relationships/xlIntlMacrosheet',
}
_WORKSHEET_REL_TYPE = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet'


def _etfind(root: Any, path: str, ns: dict[str, str] = _OOXML_NS) -> Any:
    return root.find(path, ns)


def _etfindall(root: Any, path: str, ns: dict[str, str] = _OOXML_NS) -> list[Any]:
    return root.findall(path, ns)


class XLSMWrapper:
    def __init__(self, data: bytes | bytearray):
        self._data = BytesIO(data)
        self._workbook_name = 'workbook.xlsm'
        self._content_types: Any = None
        self._workbook_xml: Any = None
        self._workbook_rels: Dict[str, Tuple[str, str]] | None = None
        self._defined_names: Dict[str, str] | None = None
        self._macrosheets: Dict[str, Boundsheet] | None = None
        self._worksheets: Dict[str, Boundsheet] | None = None
        self._shared_strings: List[str] | None = None
        self._style_xml: Any = None
        self._color_map: Dict[Tuple[int, int, int], int] | None = None

    def get_xl_international_char(self, flag_name: XlApplicationInternational) -> str | None:
        return _XL_INTERNATIONAL_DEFAULTS.get(flag_name)

    def get_workbook_name(self) -> str:
        return self._workbook_name

    def _get_zip_files(self, patterns: List[str] | None = None) -> Dict[str, bytes]:
        result: Dict[str, bytes] = {}
        if not patterns:
            patterns = ['*']
        with ZipFile(self._data) as zf:
            for name in zf.namelist():
                for pat in patterns:
                    if name == pat or fnmatch(name, pat):
                        result[name] = zf.read(name)
            if not result:
                for name in zf.namelist():
                    for pat in patterns:
                        alt_pat = pat.replace('/', '\\')
                        if name == alt_pat or fnmatch(name, alt_pat):
                            result[name.replace('\\', '/')] = zf.read(name)
        return result

    def _parse_xml(self, path: str, ignore_pattern: str | None = None) -> Any:
        try:
            from defusedxml.ElementTree import fromstring
        except ImportError:
            from xml.etree.ElementTree import fromstring
        if path.startswith('/'):
            path = path[1:]
        files = self._get_zip_files([path])
        if len(files) != 1:
            return None
        content = next(iter(files.values())).decode('utf-8')
        if ignore_pattern:
            content = re.sub(ignore_pattern, '', content)
        return fromstring(content)

    def _get_workbook_path(self) -> Tuple[str, str, str]:
        wb_path = 'xl/workbook.xml'
        ct = self._get_content_types()
        if ct is not None:
            for override in _etfindall(ct, './/ct:Override', _OOXML_NS) + _etfindall(ct, './/{%s}Override' % _OOXML_NS['ct']):
                ctype = override.get('ContentType', '')
                if 'sheet.main+xml' in ctype:
                    wb_path = override.get('PartName', wb_path).lstrip('/')
                    break
        wb_path = wb_path.lstrip('/')
        if '/' in wb_path:
            base_dir = wb_path[:wb_path.index('/')]
            name = wb_path[wb_path.index('/') + 1:]
        else:
            base_dir = ''
            name = wb_path
        return wb_path, base_dir, name

    def _get_content_types(self) -> Any:
        if self._content_types is None:
            self._content_types = self._parse_xml('[Content_Types].xml')
        return self._content_types

    def _get_workbook(self) -> Any:
        if self._workbook_xml is None:
            wb_path, _, _ = self._get_workbook_path()
            self._workbook_xml = self._parse_xml(wb_path)
        return self._workbook_xml

    def _get_rels(self) -> Dict[str, Tuple[str, str]]:
        if self._workbook_rels is None:
            self._workbook_rels = {}
            _, base_dir, name = self._get_workbook_path()
            rels_path = f'{base_dir}/_rels/{name}.rels'
            rels_xml = self._parse_xml(rels_path)
            if rels_xml is not None:
                ns = _OOXML_NS['pr']
                for rel in list(rels_xml):
                    tag = rel.tag
                    if tag == f'{{{ns}}}Relationship' or tag == 'Relationship':
                        rid = rel.get('Id', '')
                        target = rel.get('Target', '')
                        rtype = rel.get('Type', '')
                        self._workbook_rels[rid] = (target, rtype)
        return self._workbook_rels

    def _get_sheet_info(self, rid: str) -> Tuple[str | None, str | None]:
        rels = self._get_rels()
        if rid not in rels:
            return None, None
        target, rtype = rels[rid]
        if rtype in _MACRO_REL_TYPES:
            return 'Macrosheet', target
        elif rtype == _WORKSHEET_REL_TYPE:
            return 'Worksheet', target
        return 'Unknown', target

    def get_defined_names(self) -> Dict[str, str]:
        if self._defined_names is None:
            self._defined_names = {}
            wb = self._get_workbook()
            if wb is None:
                return self._defined_names
            sn = _OOXML_NS['s']
            dn_container = _etfind(wb, f'{{{sn}}}definedNames')
            if dn_container is None:
                return self._defined_names
            for dn in list(dn_container):
                name_attr = dn.get('name', '')
                name_key = name_attr.replace('_xlnm.', '').lower()
                cdata = dn.text or ''
                self._defined_names[name_key] = cdata
        return self._defined_names

    def get_defined_name(self, name: str, full_match: bool = True) -> Any:
        result: list[Any] = []
        name = name.lower()
        if full_match:
            if name in self.get_defined_names():
                result = self._defined_names[name]  # type: ignore
        else:
            for defined_name, cell_address in self.get_defined_names().items():
                if defined_name.startswith(name):
                    result.append((defined_name, cell_address))
        return result

    def _get_shared_strings(self) -> List[str] | None:
        if self._shared_strings is None:
            _, base_dir, _ = self._get_workbook_path()
            ss_xml = self._parse_xml(f'{base_dir}/sharedStrings.xml')
            if ss_xml is not None:
                sn = _OOXML_NS['s']
                self._shared_strings = []
                for si in _etfindall(ss_xml, f'{{{sn}}}si'):
                    t_elem = si.find(f'{{{sn}}}t')
                    if t_elem is not None and t_elem.text is not None:
                        self._shared_strings.append(t_elem.text)
                    else:
                        r_elems = si.findall(f'{{{sn}}}r')
                        if r_elems:
                            t_in_r = r_elems[0].find(f'{{{sn}}}t')
                            if t_in_r is not None and t_in_r.text is not None:
                                self._shared_strings.append(t_in_r.text)
                            else:
                                self._shared_strings.append('')
                        else:
                            self._shared_strings.append('')
        return self._shared_strings

    def _get_sheet_infos(self, types: List[str]) -> List[Dict[str, Any]]:
        result: list[Dict[str, Any]] = []
        wb = self._get_workbook()
        if wb is None:
            return result
        sn = _OOXML_NS['s']
        sheets_el = _etfind(wb, f'{{{sn}}}sheets')
        if sheets_el is None:
            return result
        _, base_dir, _ = self._get_workbook_path()
        seen: set[str] = set()
        for sheet_el in list(sheets_el):
            rid = sheet_el.get(f'{{{_OOXML_NS["r"]}}}id', '')
            name = sheet_el.get('name', '')
            sheet_type, rel_path = self._get_sheet_info(rid)
            if rel_path is not None and sheet_type in types and name not in seen:
                path = f'{base_dir}/{rel_path}'
                sheet = Boundsheet(name, sheet_type)
                sheet_xml = self._parse_xml(path, ignore_pattern=r'<c[^>]+/>')
                result.append({'sheet': sheet, 'sheet_path': path, 'sheet_xml': sheet_xml})
                seen.add(name)
        return result

    def _load_macro_cells(
        self, sheet: Boundsheet, sheet_xml: Any, macrosheet_names: List[str],
    ) -> None:
        strings = self._get_shared_strings()
        sn = _OOXML_NS['s']
        xm_ns = _OOXML_NS['xm']
        root = sheet_xml
        sheet_data = (
            _etfind(root, f'{{{xm_ns}}}sheetData')
            or _etfind(root, f'{{{sn}}}sheetData')
        )
        if sheet_data is None:
            return
        for row_el in list(sheet_data):
            row_r = row_el.get('r', '')
            row_attribs: Dict[RowAttribute, str] = {}
            ht = row_el.get('ht')
            if ht is not None:
                row_attribs[RowAttribute.Height] = ht
            spans = row_el.get('spans')
            if spans is not None:
                row_attribs[RowAttribute.Spans] = spans
            if row_attribs:
                sheet.row_attributes[row_r] = row_attribs  # type: ignore
            for cell_el in list(row_el):
                tag = cell_el.tag
                if not (tag.endswith('}c') or tag == 'c'):
                    continue
                formula_text: str | None = None
                f_el = cell_el.find(f'{{{sn}}}f') or cell_el.find(f'{{{xm_ns}}}f')
                if f_el is not None:
                    if f_el.get('bx') == '1':
                        text = f_el.text or ''
                        if text:
                            eq_pos = text.find('=')
                            if eq_pos > 0:
                                formula_text = f'=SET.NAME("{text[:eq_pos]}",{text[eq_pos + 1:]})'
                    else:
                        if f_el.text:
                            formula_text = f'={f_el.text}'
                if formula_text:
                    for ms_name in macrosheet_names:
                        if f'{ms_name.lower()}!' in formula_text.lower():
                            formula_text = re.sub(
                                f'{re.escape(ms_name)}!',
                                f"'{ms_name}'!",
                                formula_text,
                                flags=re.IGNORECASE,
                            )
                value_text: str | None = None
                is_string = cell_el.get('t') == 's'
                cached_str = cell_el.get('t') == 'str'
                v_el = cell_el.find(f'{{{sn}}}v') or cell_el.find(f'{{{xm_ns}}}v')
                if v_el is not None and v_el.text is not None:
                    value_text = v_el.text
                    if is_string and strings is not None:
                        try:
                            value_text = strings[int(value_text)]
                        except (ValueError, IndexError):
                            pass
                location = cell_el.get('r', '')
                if formula_text or value_text:
                    cell = Cell()
                    _, cell.column, row_str = Cell.parse_cell_addr(location)
                    if row_str is not None:
                        cell.row = int(row_str)
                    cell.sheet = sheet
                    if not cached_str:
                        cell.formula = formula_text
                    cell.value = value_text
                    sheet.cells[location] = cell
                    for attr_name in cell_el.attrib:
                        if attr_name != 'r':
                            cell.attributes[attr_name] = cell_el.get(attr_name)

    def _load_worksheet_cells(self, sheet: Boundsheet, sheet_xml: Any) -> None:
        strings = self._get_shared_strings()
        sn = _OOXML_NS['s']
        root = sheet_xml
        sheet_data = _etfind(root, f'{{{sn}}}sheetData')
        if sheet_data is None:
            return
        for row_el in list(sheet_data):
            row_r = row_el.get('r', '')
            row_attribs: Dict[RowAttribute, str] = {}
            ht = row_el.get('ht')
            if ht is not None:
                row_attribs[RowAttribute.Height] = ht
            spans = row_el.get('spans')
            if spans is not None:
                row_attribs[RowAttribute.Spans] = spans
            if row_attribs:
                sheet.row_attributes[row_r] = row_attribs  # type: ignore
            for cell_el in list(row_el):
                tag = cell_el.tag
                if not (tag.endswith('}c') or tag == 'c'):
                    continue
                formula_text: str | None = None
                f_el = cell_el.find(f'{{{sn}}}f')
                if f_el is not None and f_el.text:
                    formula_text = f'={f_el.text}'
                value_text: str | None = None
                is_string = cell_el.get('t') == 's'
                v_el = cell_el.find(f'{{{sn}}}v')
                if v_el is not None and v_el.text is not None:
                    value_text = v_el.text
                    if is_string and strings is not None:
                        try:
                            value_text = strings[int(value_text)]
                        except (ValueError, IndexError):
                            pass
                location = cell_el.get('r', '')
                cell = Cell()
                _, cell.column, row_str = Cell.parse_cell_addr(location)
                if row_str is not None:
                    cell.row = int(row_str)
                cell.sheet = sheet
                cell.formula = formula_text
                cell.value = value_text
                sheet.cells[location] = cell
                for attr_name in cell_el.attrib:
                    if attr_name != 'r':
                        cell.attributes[attr_name] = cell_el.get(attr_name)

    def get_macrosheets(self) -> Dict[str, Boundsheet]:
        if self._macrosheets is None:
            self._macrosheets = {}
            infos = self._get_sheet_infos(['Macrosheet'])
            macrosheet_names = [info['sheet'].name for info in infos]
            sn = _OOXML_NS['s']
            xm_ns = _OOXML_NS['xm']
            for info in infos:
                if info['sheet_xml'] is not None:
                    self._load_macro_cells(info['sheet'], info['sheet_xml'], macrosheet_names)
                    root = info['sheet_xml']
                    fmt_pr = (
                        _etfind(root, f'{{{xm_ns}}}sheetFormatPr')
                        or _etfind(root, f'{{{sn}}}sheetFormatPr')
                    )
                    if fmt_pr is not None:
                        info['sheet'].default_height = fmt_pr.get('defaultRowHeight')
                self._macrosheets[info['sheet'].name] = info['sheet']
        return self._macrosheets

    def get_worksheets(self) -> Dict[str, Boundsheet]:
        if self._worksheets is None:
            self._worksheets = {}
            infos = self._get_sheet_infos(['Worksheet'])
            sn = _OOXML_NS['s']
            for info in infos:
                if info['sheet_xml'] is not None:
                    self._load_worksheet_cells(info['sheet'], info['sheet_xml'])
                    root = info['sheet_xml']
                    fmt_pr = _etfind(root, f'{{{sn}}}sheetFormatPr')
                    if fmt_pr is not None:
                        info['sheet'].default_height = fmt_pr.get('defaultRowHeight')
                self._worksheets[info['sheet'].name] = info['sheet']
        return self._worksheets

    def _get_style(self) -> Any:
        if self._style_xml is None:
            _, base_dir, _ = self._get_workbook_path()
            rels = self._get_rels()
            style_target = None
            for _, (target, rtype) in rels.items():
                if 'styles' in rtype:
                    style_target = target
                    break
            if style_target:
                self._style_xml = self._parse_xml(f'{base_dir}/{style_target}')
        return self._style_xml

    def _get_color_index(self, rgba_str: str) -> int | None:
        r = int(rgba_str[2:4], 16)
        g = int(rgba_str[4:6], 16)
        b = int(rgba_str[6:8], 16)
        if self._color_map is None:
            self._color_map = {}
            for cr, cg, cb, idx in _XLSM_COLOR_TABLE:
                if (cr, cg, cb) not in self._color_map:
                    self._color_map[(cr, cg, cb)] = idx
        return self._color_map.get((r, g, b))

    def get_cell_info(
        self, sheet_name: str, col: str, row: str, info_type_id: str,
    ) -> CellInfoResult:
        data: Any = None
        not_exist = True
        not_implemented = False

        ms = self.get_macrosheets()
        if sheet_name not in ms:
            return data, not_exist, not_implemented
        sheet = ms[sheet_name]
        cell_addr = f'{col}{row}'
        tid = int(float(info_type_id))
        sn = _OOXML_NS['s']

        if tid == 17:
            style_xml = self._get_style()
            if row in sheet.row_attributes and RowAttribute.Height in sheet.row_attributes.get(row, {}):
                not_exist = False
                data = sheet.row_attributes[row][RowAttribute.Height]
            elif sheet.default_height is not None:
                data = sheet.default_height
            if data is not None:
                data = round(float(data) * 4) / 4
        else:
            style_xml = self._get_style()
            if style_xml is None:
                return data, not_exist, True
            not_exist = False
            cell_format = None
            font = None
            xfs = _etfind(style_xml, f'{{{sn}}}cellXfs')
            fonts_el = _etfind(style_xml, f'{{{sn}}}fonts')
            styles_el = _etfind(style_xml, f'{{{sn}}}cellStyles')
            style_xfs = _etfind(style_xml, f'{{{sn}}}cellStyleXfs')

            if cell_addr in sheet.cells:
                cell = sheet.cells[cell_addr]
                if 's' in cell.attributes and xfs is not None:
                    index = int(cell.attributes['s'])
                    xf_list = _etfindall(xfs, f'{{{sn}}}xf')
                    if index < len(xf_list):
                        cell_format = xf_list[index]
                        font_id_str = cell_format.get('fontId')
                        if font_id_str is not None and fonts_el is not None:
                            font_index = int(font_id_str)
                            font_list = _etfindall(fonts_el, f'{{{sn}}}font')
                            if font_index < len(font_list):
                                font = font_list[font_index]

            if cell_format is None and styles_el is not None and style_xfs is not None:
                for cs in _etfindall(styles_el, f'{{{sn}}}cellStyle'):
                    if cs.get('name') == 'Normal':
                        xf_id = int(cs.get('xfId', '0'))
                        xf_list = _etfindall(style_xfs, f'{{{sn}}}xf')
                        if xf_id < len(xf_list):
                            cell_format = xf_list[xf_id]
                            font_id_str = cell_format.get('fontId')
                            if font_id_str is not None and fonts_el is not None:
                                font_index = int(font_id_str)
                                font_list = _etfindall(fonts_el, f'{{{sn}}}font')
                                if font_index < len(font_list):
                                    font = font_list[font_index]
                        break

            if tid == 8:
                if cell_format is not None:
                    align = _etfind(cell_format, f'{{{sn}}}alignment')
                    if align is not None:
                        h_map = {
                            'general': 1, 'left': 2, 'center': 3, 'right': 4,
                            'fill': 5, 'justify': 6, 'centercontinuous': 7, 'distributed': 8,
                        }
                        data = h_map.get(align.get('horizontal', 'general').lower(), 1)
                    else:
                        data = 1
            elif tid == 19:
                if font is not None:
                    sz = _etfind(font, f'{{{sn}}}sz')
                    if sz is not None:
                        data = float(sz.get('val', '11'))
            elif tid == 24:
                if font is not None:
                    color_el = _etfind(font, f'{{{sn}}}color')
                    if color_el is not None:
                        rgb = color_el.get('rgb')
                        if rgb:
                            data = self._get_color_index(rgb)
                        else:
                            data = 1
                    else:
                        data = 1
            elif tid == 38:
                if cell_format is not None:
                    fill_id_str = cell_format.get('fillId')
                    if fill_id_str is not None:
                        fills_el = _etfind(style_xml, f'{{{sn}}}fills')
                        if fills_el is not None:
                            fill_list = _etfindall(fills_el, f'{{{sn}}}fill')
                            fill_id = int(fill_id_str)
                            if fill_id < len(fill_list):
                                pf = _etfind(fill_list[fill_id], f'{{{sn}}}patternFill')
                                if pf is not None:
                                    fg = _etfind(pf, f'{{{sn}}}fgColor')
                                    if fg is not None:
                                        rgb = fg.get('rgb')
                                        if rgb:
                                            data = self._get_color_index(rgb)
                                        else:
                                            data = 0
                                    else:
                                        data = 0
            elif tid == 50:
                v_map = {'top': 1, 'center': 2, 'bottom': 3, 'justify': 4, 'distributed': 5}
                if cell_format is not None:
                    align = _etfind(cell_format, f'{{{sn}}}alignment')
                    if align is not None:
                        data = v_map.get(align.get('vertical', 'bottom').lower(), 3)
                    else:
                        data = 3
                else:
                    data = 3
            else:
                not_implemented = True

        return data, not_exist, not_implemented
