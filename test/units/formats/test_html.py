#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect

from .. import TestUnitBase


class TestHTMLExtractor(TestUnitBase):

    _TEST_DOCUMENT = inspect.cleandoc(
        """
        <html>
            <head>
                <title>Test &nbsp;</title>
                <script>alert(9)</script>
                <woober oink=9 />
            </head>
            <body>
                <p>Paragraph 1 &#62; &#x3E;</p>
                <p>Paragraph 2</p>
                <p>Paragraph 3</p>
                <div><div>Half-Open
            </body>
            </div>
        </html>
        """
    ).encode('utf8')

    def test_listing(self):
        listing = str(self._TEST_DOCUMENT | self.load('-l', '??*'))
        self.assertEqual(
            listing,
            '\n'.join((
                'html',
                'html/0.head',
                'html/0.head/0.title',
                'html/0.head/1.script',
                'html/0.head/2.woober',
                'html/1.body',
                'html/1.body/0.p',
                'html/1.body/1.p',
                'html/1.body/2.p',
                'html/1.body/3.div',
                'html/1.body/3.div/0.div',
            ))
        )

    def test_extraction(self):
        self.assertEqual(
            str(self._TEST_DOCUMENT | self.load('0.p')),
            'Paragraph 1 &#62; &#x3E;'
        )

    def test_extraction_outer(self):
        result = str(self._TEST_DOCUMENT | self.load('*.head', outer=True))
        self.assertEqual(
            result,
            '\n'.join((
                '    <head>',
                '        <title>Test &nbsp;</title>',
                '        <script>alert(9)</script>',
                '        <woober oink=9 />',
                '    </head>',
            ))
        )
