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
