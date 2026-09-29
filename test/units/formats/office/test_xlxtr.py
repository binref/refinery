import io
import zipfile

from ....lib.excel.samples import (
    APACHE_POI_52348,
    BINARY_REFINERY,
    DATES_XLSB,
    LOWER_CASE_CELLNAMES,
    REVENG1,
    SELF_EVALUATION_REPORT,
    SHARED_STRINGS_ALT_LOCATION,
    TEST_XLSB,
)
from ... import TestUnitBase


def _replace_part(data: bytes, part: str, replacements: list[tuple[bytes, bytes]]) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(data))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as target:
        for info in source.infolist():
            content = source.read(info)
            if info.filename == part:
                for old, new in replacements:
                    content = content.replace(old, new)
            target.writestr(info, content)
    return buffer.getvalue()


class TestExcelExtractor(TestUnitBase):

    def test_id(self):
        from refinery.lib.id import Fmt, get_office_xml_type
        self.assertEqual(get_office_xml_type(BINARY_REFINERY), Fmt.XLSX)

    def test_regular_xlsx(self):
        data = BINARY_REFINERY
        unit = self.load()
        self.assertEqual(unit(data), B'Binary\nRefinery.\nBinary Refinery.')
        xl1 = self.load('A1', 'R33', squeeze=True)(data)
        xl2 = self.load('2!E10')(data)
        xl3 = self.load('Refinery!E10')(data)
        self.assertEqual(xl2, xl3)
        self.assertEqual(xl1, b'BinaryRefinery.')
        self.assertEqual(xl2, b'Binary Refinery.')

    def test_extract_all_sheets(self):
        self.assertEqual(self.load()(LOWER_CASE_CELLNAMES), b'1\n2\n3\n4')
        self.assertEqual(self.load()(SELF_EVALUATION_REPORT), b'one\ntwo\nthree\nfour')
        self.assertEqual(
            self.load()(SHARED_STRINGS_ALT_LOCATION),
            b'Test\nValues\n1\na\n2\nb\n3\nc\n4\nd\n5\ne',
        )

    def test_inline_string_cells(self):
        self.assertEqual(
            self.load('balance!A10:L10')(APACHE_POI_52348),
            b'Totals\n-\n-\n-\n600.25',
        )

    def test_formula_cells_emit_cached_results(self):
        data = REVENG1
        self.assertEqual(
            self.load('ZZZfirstsheet!A28:C28')(data),
            b'Short Date\n1999-12-31 00:00:00\n2000-01-01 00:00:00',
        )
        self.assertEqual(self.load('ZZZfirstsheet!C3', squeeze=True)(data), 127 * b'x')
        # An empty cached string is distinct from a cell without a value.
        self.assertEqual(self.load('ZZZfirstsheet!B2')(data), b'')

    def test_error_values(self):
        self.assertEqual(
            self.load('ZZZfirstsheet!A17:C17')(REVENG1),
            b'#div/0!\n#DIV/0!\n#DIV/0!',
        )

    def test_time_values(self):
        self.assertEqual(
            self.load('ZZZfirstsheet!A45:C45')(REVENG1),
            b'time\n02:10:54\n02:10:54',
        )

    def test_unrepresentable_date_renders_the_excel_error(self):
        # Excel renders a date whose serial number no datetime can represent as `#VALUE!`;
        # the serial 2958466 is one day past December 31, 9999.
        data = _replace_part(REVENG1, 'xl/worksheets/sheet1.xml', [(b'>36525<', b'>2958466<')])
        self.assertEqual(self.load('ZZZfirstsheet!B28')(data), b'#VALUE!')

    def test_control_characters(self):
        self.assertEqual(
            self.load('ControlChars!A1:C1')(REVENG1),
            b'1\n\x01\n\x01',
        )

    def test_escaped_underscores(self):
        # The literal text `_x000F__x000f_` survives the ST_Xstring decoding of shared strings
        # and of formula results alike.
        self.assertEqual(
            self.load('ZZZfirstsheet!A46:C46')(REVENG1),
            b'more underscores\n_x000F__x000f_\n_x000F__x000f_',
        )

    def test_xlsb_dates_and_references(self):
        self.assertEqual(
            self.load('Test!A5:C5')(TEST_XLSB),
            b'2017-12-27 00:00:00\n18:06:00\n2017-12-27 18:08:00',
        )
        self.assertEqual(
            self.load('Sheet1!A1:A3')(DATES_XLSB),
            b'2020-03-03 00:00:00\n22:05:00\n2020-03-03 22:05:00',
        )

    def test_sheet_reference_grammar(self):
        data = REVENG1
        self.assertEqual(self.load('ZZZfirstsheet!C46')(data), b'_x000F__x000f_')
        # A quoted sheet name may contain characters that would otherwise start a reference.
        self.assertEqual(self.load('"ZZZfirstsheet"!C46')(data), b'_x000F__x000f_')
        self.assertEqual(self.load("'ZZZfirstsheet'!C46")(data), b'_x000F__x000f_')
        # Sheet indices are one-based.
        self.assertEqual(self.load('1!A1')(data), b'description')
        self.assertEqual(self.load('3!A1')(data), b'1')
        # Shell-style wildcards match sheet names.
        self.assertEqual(self.load('*Chars!A1')(data), b'1')
        # A cell is addressed by a one-based row.column pair as an alternative to a reference.
        self.assertEqual(self.load('46.3')(data), b'_x000F__x000f_')

    def test_unparsable_reference_selects_a_sheet(self):
        # A reference that parses as neither a cell nor a range is taken to be a sheet name.
        data = REVENG1
        self.assertEqual(
            self.load('ControlChars')(data),
            self.load('ControlChars!')(data),
        )
        self.assertEqual(self.load('ControlChars!A1:C1')(data), b'1\n\x01\n\x01')

    def test_mixed_case_reference_selects_a_sheet(self):
        # Only an all-uppercase token is a cell reference; a mixed-case token like the name
        # of a sheet is not, and selecting a sheet by its unquoted name extracts all of it.
        data = LOWER_CASE_CELLNAMES
        self.assertEqual(self.load('Sheet1')(data), b'1\n2\n3\n4')
        self.assertEqual(self.load('Sheet1')(data), self.load('1!')(data))

    def test_cell_ranges(self):
        data = REVENG1
        self.assertEqual(
            self.load('ZZZfirstsheet!B28:C28')(data),
            b'1999-12-31 00:00:00\n2000-01-01 00:00:00',
        )
        self.assertEqual(
            self.load('ZZZfirstsheet!1.2:2.3')(data),
            b'entered\ncalculated\n',
        )
        self.assertEqual(
            self.load('AAA2ndsheet!A3:E5')(data),
            b'nm\nmerged cells can be quite a barrel of fun\nnm\nnm\nnm\nnm\nnm\nnm\nnm\nnm',
        )
