#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import get_all_entry_points

from .. import TestBase


class TestLoader(TestBase):

    def test_load_stuff(self):
        ep = {u.name for u in get_all_entry_points()}
        self.assertIn('md5', ep)
