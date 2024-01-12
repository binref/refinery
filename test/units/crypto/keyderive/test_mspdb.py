#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestPasswordDeriveBytes(TestUnitBase):

    def test_real_world_01(self):
        data = B'amp4Z0wpKzJ5Cg0GDT5sJD0sMw0IDAsaGQ1Afik6NwXr6rrSEQE='
        unit = self.load(32, B'aGQ1Afik6NampDT5sJEQE4Z0wpsMw0IDAD06rrSswXrKzJ5Cg0G=', iter=2)
        wish = bytes.fromhex(
            '34 88 6D 5B 09 7A 94 19 78 D0 E3 8B 1B 5C A3 29'
            '60 74 6A 5E 5D 64 87 11 B1 2C 67 AA 5B 3A 8E BF'
        )
        self.assertEqual(unit(data), wish)
