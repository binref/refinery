#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestBase58(TestUnitBase):

    def test_bitcoin_address(self):
        unit = self.load(reverse=True)
        data = bytes.fromhex('00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8')
        self.assertEqual(data | unit | bytes, B'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')
