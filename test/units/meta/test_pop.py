#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestPop(TestUnitBase):

    def test_error_when_variables_cannot_be_assigned(self):
        pl = self.ldu('push') [ self.ldu('rex', 'XX(.)', '{1}') | self.load('oops') ] # noqa
        with self.assertRaises(Exception):
            b'TEST' | pl | None
