#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestXML(TestUnitBase):

    def test_simple(self):
        for k in range(5):
            unit = self.load(indent=k)
            self.assertTrue(
                unit(b'<foo><bar>baz</bar><bar>bat</bar></foo>').endswith(
                    B'<foo>\n%s<bar>baz</bar>\n%s<bar>bat</bar>\n</foo>' % (2 * (k * B' ',))
                )
            )

    def test_xml_header(self):
        unit = self.load(indent=1)
        self.assertEqual(
            B'<?xml version="1.0" ?>\n<foo>\n <bar>baz</bar>\n <bar>bamf</bar>\n</foo>',
            unit(B'<?xml version="1.0" encoding="UTF-8"?><foo><bar>baz</bar><bar>bamf</bar></foo>')
        )
