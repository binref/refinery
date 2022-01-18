#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect

from .. import TestUnitBase


class TestHTMLExtractor(TestUnitBase):

    def test_simple_01(self):

        @inspect.getdoc
        class data:
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

        data = data.encode('utf8')

        self.assertEqual(
            str(data | self.load('-l', '*.inner')),
            '\n'.join((
                'html.inner',
                'html/head.inner',
                'html/head/title.inner',
                'html/head/script.inner',
                'html/head/woober.inner',
                'html/body.inner',
                'html/body/p(1).inner',
                'html/body/p(2).inner',
                'html/body/p(3).inner',
                'html/body/div.inner',
                'html/body/div/div.inner',
            ))
        )
        self.assertEqual(
            str(data | self.load('p(1).inner')),
            'Paragraph 1 &#62; &#x3E;'
        )
        self.assertEqual(
            str(data | self.load('head.outer')),
            '\n'.join((
                '    <head>',
                '        <title>Test &nbsp;</title>',
                '        <script>alert(9)</script>',
                '        <woober oink=9 />',
                '    </head>',
            ))
        )
