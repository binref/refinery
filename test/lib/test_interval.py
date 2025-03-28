#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.intervals import IntIntervalUnion, MemoryIntervalUnion

from .. import TestBase


class TestIntervalUnion(TestBase):

    def test_merging_int(self):
        # [00][01][02][03][04][05][06][07][08][09][10][11][12]
        #         [--I3--][----I1----][----I2----]
        #     [------I4------]                [--I5--]
        #         [------------------I6------------------]

        iu = IntIntervalUnion()
        iu.addi(20, 5) # I0
        iu.addi(4, 3) # I1
        self.assertEqual(len(iu), 2)
        self.assertEqual(list(iu), [(4, 3), (20, 5)])
        iu.addi(7, 3) # I2
        self.assertEqual(len(iu), 2)
        self.assertEqual(list(iu), [(4, 6), (20, 5)])
        iu.addi(2, 2) # I3
        self.assertEqual(len(iu), 2)
        self.assertEqual(list(iu), [(2, 8), (20, 5)])
        iu.addi(1, 4) # I4
        self.assertEqual(len(iu), 2)
        self.assertEqual(list(iu), [(1, 9), (20, 5)])
        iu.addi(9, 2) # I5
        self.assertEqual(len(iu), 2)
        self.assertEqual(list(iu), [(1, 10), (20, 5)])
        iu.addi(2, 10) # I6
        self.assertEqual(len(iu), 2)
        self.assertEqual(list(iu), [(1, 11), (20, 5)])

    def test_merging_bytes(self):
        # [00][01][02][03][04][05][06][07][08][09][10][11][12]
        #         [CCCCCC][AAAAAAAAAA][BBBBBBBBBB]
        #     [DDDDDDDDDDDDDD]                [EEEEEE]
        #         [FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF]

        iu = MemoryIntervalUnion()
        iu.addi(4, 3 * B'A')
        self.assertEqual(list(iu), [(4, B'AAA')])
        iu.addi(7, 3 * B'B') 
        self.assertEqual(list(iu), [(4, B'AAABBB')])
        iu.addi(2, 2 * B'C')
        self.assertEqual(list(iu), [(2, B'CCAAABBB')])
        iu.addi(1, B'DDDD')
        self.assertEqual(list(iu), [(1, B'DDDDAABBB')])
        iu.addi(9, B'EE')
        self.assertEqual(list(iu), [(1, B'DDDDAABBEE')])
        iu.addi(2, B'FFFFFFFFFF')
        self.assertEqual(list(iu), [(1, B'DFFFFFFFFFF')])
