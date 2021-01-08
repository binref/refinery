#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
from refinery.lib.patterns import indicators

from .. import TestBase


class TestIndicators(TestBase):

    def test_ipv4_too_large_ocets(self):
        self.assertFalse(re.fullmatch(indicators.ipv4.pattern, '127.0.0.288'))
