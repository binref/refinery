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
                'html/head',
                'html/head/title',
                'html/head/script',
                'html/head/woober',
                'html/body',
                'html/body/p/1',
                'html/body/p/2',
                'html/body/p/3',
                'html/body/div',
                'html/body/div/div',
            ))
        )

    def test_extraction(self):
        self.assertEqual(
            str(self._TEST_DOCUMENT | self.load('p/1')),
            'Paragraph 1 &#62; &#x3E;'
        )

    def test_extraction_outer(self):
        result = str(self._TEST_DOCUMENT | self.load('head', outer=True))
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

    def test_javascript_regression(self):
        data = self.download_sample('5775dd79d6529e77182ceccb5f0a1d9d22d4884017df41dade409caf6471e48f')
        pipe = self.load_pipeline('loop 8 xthtml[script]:csd[string]:url | deob-ps1 | csd string | b64 | xtp url')
        self.assertEqual(
            data | pipe | str,
            'http'':/''/198.46.178''.''151/65/seethebesthtingswithmewhichgivegreatoutputofmegood.tIF'
        )
