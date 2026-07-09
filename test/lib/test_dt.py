from datetime import datetime, timedelta, timezone

from .. import TestBase

from refinery.lib.dt import pdfdate


class TestPdfDate(TestBase):

    def test_full_with_timezone(self):
        self.assertEqual(
            pdfdate("D:20190909050347+02'00'"),
            datetime(2019, 9, 9, 5, 3, 47, tzinfo=timezone(timedelta(hours=2))),
        )

    def test_negative_timezone(self):
        self.assertEqual(
            pdfdate("D:20190909050347-05'30'"),
            datetime(2019, 9, 9, 5, 3, 47, tzinfo=timezone(-timedelta(hours=5, minutes=30))),
        )

    def test_full_with_z_offset(self):
        self.assertEqual(
            pdfdate('D:20171022055144Z'),
            datetime(2017, 10, 22, 5, 51, 44, tzinfo=timezone.utc),
        )

    def test_without_prefix(self):
        self.assertEqual(pdfdate('20111020193727'), datetime(2011, 10, 20, 19, 37, 27))

    def test_date_only(self):
        self.assertEqual(pdfdate('D:20230228'), datetime(2023, 2, 28, 0, 0, 0))

    def test_year_and_month_only(self):
        self.assertEqual(pdfdate('D:201503'), datetime(2015, 3, 1, 0, 0, 0))

    def test_naive_when_no_offset(self):
        self.assertIsNone(pdfdate('20111020193727').tzinfo)

    def test_rejects_non_date(self):
        self.assertIsNone(pdfdate('not a date'))

    def test_rejects_invalid_month(self):
        self.assertIsNone(pdfdate('D:20191320050347'))
