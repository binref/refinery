#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestDateFix(TestUnitBase):

    def test_dates(self):
        unit = self.load()
        self.assertEqual(b'2016-03-15 04:35:35', unit(b'0x56e79117'))
        self.assertEqual(b'2016-03-15 04:35:35', unit(b'1458016535'))
        self.assertEqual(b'2016-03-15 04:35:35', unit(b'1458016535000'))
        self.assertEqual(b'2010-03-15 06:27:50', unit(b'2010-03-15T06:27:50'))
        self.assertEqual(b'2017-09-11 21:47:22', unit(b'2017:09:11 23:47:22+02:00'))
        self.assertEqual(b'2017-10-22 05:51:44', unit(b'20171022055144Z'))
        self.assertEqual(b'2011-10-20 19:37:27', unit(b'20111020193727'))
        self.assertEqual(b'2010-03-15 06:27:50', unit(b'2010-03-15T06:27:50.000000'))
        self.assertEqual(b'2010-03-15 06:27:50', unit(b'2010-03-15 06:27:50'))
        self.assertEqual(b'2014-04-24 19:32:21', unit(b'Thu Apr 24 2014 12:32:21 GMT-0700 (PDT)'))
        self.assertEqual(b'2023-02-28 00:00:00', unit(b'02/28/2023'))
        self.assertEqual(b'2023-02-28 12:12:12', unit(b'02/28/2023 12:12:12'))

    def test_dates_dos(self):
        unit = self.load(dos=True)
        self.assertEqual(b'2019-04-02 10:58:44', unit(b'1317164886'))
        self.assertEqual(b'2019-04-02 10:58:44', unit(b'1317164886000'))
