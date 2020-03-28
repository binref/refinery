#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestPS1String(TestUnitBase):

    def test_unicode(self):
        unit = self.load()
        data = u'refinery:\n all about the パイプライン.'.encode('UTF8')
        self.assertEqual(
            B"'%s'" % data.replace(B'\n', B'`n'),
            unit.reverse(data)
        )
