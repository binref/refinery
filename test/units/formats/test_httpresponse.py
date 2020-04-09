#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestHTTPParser(TestUnitBase):

    def test_basice(self):
        unit = self.load()
        data = B'\r\n'.join([
            B'HTTP/1.1 200 OK',
            B'Date: Thu, 09 Apr 2020 21:20:32 GMT',
            B'Content-Type: text/plain',
            B'Transfer-Encoding: chunked',
            B'Connection: keep-alive',
            B'Last-Modified: Mon, 01 Apr 2053 12:55:23 GMT',
            B'Vary: Accept-Encoding',
            B'CF-Cache-Status: REVALIDATED',
            B'Server: pipel1nez4lyfe',
            B'',
            B'0010',
            B'BINARY REFINERY!',
            B'0010',
            B'BINARY REFINERY!',
            B'0',
        ])
        self.assertEqual(unit(data), B'BINARY REFINERY!BINARY REFINERY!')
