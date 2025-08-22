#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestCabExtractor(TestUnitBase):

    def test_x86_filter_regression(self):
        data = self.download_sample('55e0e9167fa3612135815ed01119a91281373c08c257efc8f7cc36bcc08734d2')
        test = data | self.load() [ self.ldu('sha256', text=True) ]| {str}
        self.assertSetEqual(test, {
            '4ed76fa68ef9e1a7705a849d47b3d9dcdf969e332bd5bcb68138579c288a16d3',
            'fd65d192f2425916585450e46c9cc1db7747d00d1614a8ef835940f06795e2b4',
            '29835e2b02d6cb017fe9fdb957c79b120be6c91b6b908eefc29cae7efe3ffbf9',
        })

    def test_cab_works_in_xt(self):
        data = self.download_sample('55e0e9167fa3612135815ed01119a91281373c08c257efc8f7cc36bcc08734d2')
        test = data | self.ldu('xt', 'kZuIfcn') | self.ldu('snip', ':8') | bytes
        self.assertEqual(test, bytes.fromhex('77 A2 09 53 D7 1B EA C6'))
