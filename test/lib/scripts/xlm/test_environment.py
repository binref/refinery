from __future__ import annotations

from refinery.lib.scripts.xlm import XlmEnvironment
from test import TestBase


class TestXlmWorkspace(TestBase):

    def setUp(self):
        self.environment = XlmEnvironment()

    def test_pinned_workspace_answers(self):
        for number, expected in [
            (1, 'Windows (64-bit) NT :.00'),
            (2, '16'),
            (9, '/'),
            (13, '1016.25'),
            (23, R'C:\Users\user\AppData\Roaming\Microsoft\Excel\XLSTART'),
            (26, 'Windows User'),
            (32, R'C:\Program Files\Microsoft Office\Office16'),
            (33, 'Worksheet'),
            (48, R'C:\Program Files\Microsoft Office\Office16\LIBRARY'),
            (56, 'Calibri'),
            (57, '11'),
            (67, R'C:\Users\user\Documents'),
            (72, 'TRUE'),
        ]:
            with self.subTest(number=number):
                self.assertEqual(self.environment.workspace(number), expected)

    def test_numbers_the_table_does_not_answer_yield_nothing(self):
        for number in (0, 16, 24, 27, 73):
            with self.subTest(number=number):
                self.assertEqual(self.environment.workspace(number), None)


class TestXlmWindow(TestBase):

    def setUp(self):
        self.environment = XlmEnvironment()

    def test_pinned_window_table_answers(self):
        for number, expected in [
            (1, '[Book1]Sheet1'),
            (2, 1),
            (5, 800),
            (6, 600),
            (12, 0),
            (17, 1),
            (25, 100),
            (30, '[Book1]Sheet1'),
            (31, 'window.xls'),
        ]:
            with self.subTest(number=number):
                self.assertEqual(self.environment.window(number), expected)

    def test_numbers_the_table_does_not_answer_yield_nothing(self):
        for number in (0, 32, 100):
            with self.subTest(number=number):
                self.assertEqual(self.environment.window(number), None)

    def test_the_value_of_numbers_one_and_thirty_names_the_workbook_and_sheet(self):
        self.assertEqual(
            self.environment.window_value(1, 'workbook.xlsm', 'Doc1'),
            '[workbook.xlsm]Doc1',
        )
        self.assertEqual(
            self.environment.window_value(30, 'workbook.xlsb', 'Tiposa'),
            '[workbook.xlsb]Tiposa',
        )

    def test_the_value_of_every_other_number_is_the_table_answer(self):
        self.assertEqual(self.environment.window_value(5, 'workbook.xlsm', 'Doc1'), 800)
        self.assertEqual(self.environment.window_value(2, 'workbook.xlsm', 'Doc1'), 1)
        self.assertEqual(self.environment.window_value(31, 'workbook.xlsm', 'Doc1'), 'window.xls')


class TestXlmDocument(TestBase):

    def setUp(self):
        self.environment = XlmEnvironment()

    def test_number_seventy_six_names_the_workbook_and_sheet(self):
        self.assertEqual(
            self.environment.document(76, 'workbook.xlsm', 'Doc1'),
            '[workbook.xlsm]Doc1',
        )

    def test_number_eighty_eight_names_the_workbook(self):
        self.assertEqual(
            self.environment.document(88, 'workbook.xlsb', 'Tiposa'),
            'workbook.xlsb',
        )

    def test_every_other_number_yields_nothing(self):
        for number in (0, 12, 75, 77, 87, 89, 100):
            with self.subTest(number=number):
                self.assertEqual(
                    self.environment.document(number, 'workbook.xlsm', 'Doc1'),
                    None,
                )


class TestXlmCellInfo(TestBase):

    def test_cell_info_is_not_implemented(self):
        environment = XlmEnvironment()
        for number in (1, 5, 13, 16, 18, 66):
            with self.subTest(number=number):
                self.assertEqual(
                    environment.cell_info('Doc1', 97, 59, number),
                    None,
                )
