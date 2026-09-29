from __future__ import annotations

import datetime

from refinery.lib.excel.common import (
    ERROR_TEXT,
    Cell,
    CellKind,
    date_cell,
    decode_rk,
    decode_xstring,
    is_builtin_date_format,
    is_date_format_string,
    rc2ref,
    ref2rc,
    serial_to_datetime,
)

from ... import TestBase


class TestCellReferences(TestBase):

    def test_reference_to_row_and_column(self):
        for ref, expected in [
            ('A1', (1, 1)),
            ('c4', (4, 3)),
            ('Z9', (9, 26)),
            ('AA1', (1, 27)),
            ('AZ1', (1, 52)),
            ('BA1', (1, 53)),
            ('ZZ1', (1, 702)),
            ('AAA1', (1, 703)),
            ('XFD1048576', (1048576, 16384)),
        ]:
            with self.subTest(ref=ref):
                self.assertEqual(ref2rc(ref), expected)

    def test_row_and_column_to_reference(self):
        for rc, expected in [
            ((1, 1), 'A1'),
            ((9, 26), 'Z9'),
            ((1, 27), 'AA1'),
            ((1, 52), 'AZ1'),
            ((1, 53), 'BA1'),
            ((1, 702), 'ZZ1'),
            ((1, 703), 'AAA1'),
            ((1048576, 16384), 'XFD1048576'),
        ]:
            with self.subTest(rc=rc):
                self.assertEqual(rc2ref(*rc), expected)

    def test_malformed_reference(self):
        for ref in ('1A', 'A', '12', '', 'A1B', ' A1', 'A 1', '$A$1', 'A0'):
            with self.subTest(ref=ref):
                self.assertRaises(ValueError, ref2rc, ref)

    def test_zero_row_or_column(self):
        self.assertRaises(ValueError, rc2ref, 0, 1)
        self.assertRaises(ValueError, rc2ref, 1, 0)

    def test_round_trip(self):
        for row in range(1, 40):
            for col in range(1, 40):
                with self.subTest(row=row, col=col):
                    self.assertEqual(ref2rc(rc2ref(row, col)), (row, col))


class TestSerialDates(TestBase):

    def test_days_after_the_1900_epoch(self):
        for serial, expected in [
            (1, datetime.datetime(1900, 1, 1)),
            (61, datetime.datetime(1900, 3, 1)),
            (36526, datetime.datetime(2000, 1, 1)),
            (40000, datetime.datetime(2009, 7, 6)),
            (1.5, datetime.datetime(1900, 1, 1, 12, 0, 0)),
            (40000.5, datetime.datetime(2009, 7, 6, 12, 0, 0)),
        ]:
            with self.subTest(serial=serial):
                self.assertEqual(serial_to_datetime(serial, False), expected)

    def test_spurious_leap_day(self):
        # Excel inherits a non-existent February 29, 1900 from Lotus 1-2-3, so serials 59 and
        # 60 both resolve to February 28 and March 1 follows at serial 61.
        february = datetime.datetime(1900, 2, 28)
        march = datetime.datetime(1900, 3, 1)
        self.assertEqual(serial_to_datetime(59, False), february)
        self.assertEqual(serial_to_datetime(60, False), february)
        self.assertEqual(serial_to_datetime(61, False), march)

    def test_days_after_the_1904_epoch(self):
        for serial, expected in [
            (1, datetime.datetime(1904, 1, 2)),
            (60, datetime.datetime(1904, 3, 1)),
            (36526, datetime.datetime(2004, 1, 2)),
        ]:
            with self.subTest(serial=serial):
                self.assertEqual(serial_to_datetime(serial, True), expected)

    def test_fraction_only_serial_is_a_time(self):
        for serial, expected in [
            (0.5, datetime.time(12, 0)),
            (0.25, datetime.time(6, 0)),
            (0.75, datetime.time(18, 0)),
            (1 / 3, datetime.time(8, 0)),
        ]:
            with self.subTest(serial=serial):
                self.assertEqual(serial_to_datetime(serial, False), expected)


class TestDateCells(TestBase):

    def test_serial_composes_a_date_cell(self):
        self.assertEqual(
            date_cell(2, 3, 36526, False, 'B2+1'),
            Cell(2, 3, CellKind.DATE, datetime.datetime(2000, 1, 1), 'B2+1'),
        )
        self.assertEqual(
            date_cell(2, 3, 0.75, False),
            Cell(2, 3, CellKind.DATE, datetime.time(18, 0), None),
        )

    def test_unrepresentable_serial_degrades_to_the_excel_error(self):
        # Excel renders a date whose serial number no datetime can represent as `#VALUE!`,
        # the largest serial being 2958465 for December 31, 9999.
        self.assertEqual(
            date_cell(1, 1, 2958466, False, 'A1+1'),
            Cell(1, 1, CellKind.ERROR, '#VALUE!', 'A1+1'),
        )


class TestRkNumbers(TestBase):
    """
    The RK encoding stores a number in four bytes, either as a signed 30-bit integer or as the
    upper half of an IEEE 754 double, with the low two bits of the first byte holding a flag that
    selects between them and a second flag that divides the result by one hundred. Each vector
    below exercises one combination of the flags.
    """

    def test_signed_integer_form(self):
        self.assertEqual(decode_rk(bytes.fromhex('92 01 00 00')), 100.0)
        self.assertEqual(decode_rk(bytes.fromhex('f6 ff ff ff')), -3.0)

    def test_hundredth_form(self):
        self.assertEqual(decode_rk(bytes.fromhex('e7 c0 00 00')), 123.45)

    def test_double_form(self):
        self.assertEqual(decode_rk(bytes.fromhex('00 00 f8 3f')), 1.5)
        self.assertEqual(decode_rk(bytes.fromhex('00 00 d0 3f')), 0.25)


class TestErrorValues(TestBase):

    def test_biff_error_codes(self):
        self.assertEqual(ERROR_TEXT, {
            0x00: '#NULL!',
            0x07: '#DIV/0!',
            0x0F: '#VALUE!',
            0x17: '#REF!',
            0x1D: '#NAME?',
            0x24: '#NUM!',
            0x2A: '#N/A',
            0x2B: '#GETTING_DATA',
        })


class TestXstringEscapes(TestBase):

    def test_escaped_control_characters(self):
        self.assertEqual(decode_xstring('_x0009_'), '\t')
        self.assertEqual(decode_xstring('_x0041_'), 'A')

    def test_plain_text(self):
        self.assertEqual(decode_xstring('Binary Refinery.'), 'Binary Refinery.')
        self.assertEqual(decode_xstring('x0041_'), 'x0041_')

    def test_escaped_underscore(self):
        self.assertEqual(decode_xstring('_x005F_'), '_')
        self.assertEqual(decode_xstring('_x005F_x0041_'), '_x0041_')

    def test_authentic_stored_text(self):
        # The reveng1 workbook stores the literal text `_x000F__x000f_` as this sequence.
        self.assertEqual(decode_xstring('_x005F_x000F__x005F_x000f_'), '_x000F__x000f_')


class TestDateFormatDetection(TestBase):

    def test_number_formats(self):
        for fmt in [
            'General', 'general', '@', '0', '0.00', '#,##0', '0%', '0.0000',
            '0.00E+00', '##0.0E+0', '$#,##0.00', '0.00 "kg"', '0"kg"',
            '#,##0 ;(#,##0)', R'\y\y', '0.00_ ;[Red](-0.00)', '[Blue]+0;-0', '0;d',
        ]:
            with self.subTest(fmt=fmt):
                self.assertFalse(is_date_format_string(fmt))

    def test_date_formats(self):
        for fmt in [
            'dd/mm/yy', 'd-mmm-yy', 'yyyy-mm-dd', 'm/d/yy', 'mm-dd-yy', 'h:mm AM/PM',
            'h:mm:ss', 'mm:ss', 'mmmm d, yyyy', 'hh:mm:ss.000', '[h]:mm:ss', 'd', 'm',
            's', 'yy', '[$-409]d/m/yy h:mm', '"Delivery at" hh:mm',
        ]:
            with self.subTest(fmt=fmt):
                self.assertTrue(is_date_format_string(fmt))

    def test_uppercase_date_formats(self):
        for fmt in ['DDDD', 'HH', 'SS', 'HH:MM', 'DD/MM/YYYY']:
            with self.subTest(fmt=fmt):
                self.assertTrue(is_date_format_string(fmt))

    def test_builtin_format_identifiers(self):
        for fmt_id, expected in [
            (0, False),
            (13, False),
            (14, True),
            (22, True),
            (23, False),
            (26, False),
            (27, True),
            (36, True),
            (45, True),
            (47, True),
            (49, False),
            (50, True),
            (58, True),
            (71, True),
            (81, True),
            (82, False),
        ]:
            with self.subTest(fmt_id=fmt_id):
                self.assertEqual(is_builtin_date_format(fmt_id), expected)
