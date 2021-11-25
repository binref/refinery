#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_commandline as L
from .. import TestUnitBase


class TestSnip(TestUnitBase):

    def test_snip_multiple_pieces(self):
        fuse = self.ldu('sep', B'')
        unit = self.load('3:5', '13:19', '21:')[fuse]
        self.assertEqual(unit(B'UJKHEOFKSJEUCLLOWORDDLD'), B'HELLOWORLD')

    def test_snip_negative_slice(self):
        unit = self.load('--', '-4:')
        data = B'FOO BAR BARF'
        self.assertEqual(unit(data), B'BARF')

    def test_snip_remove(self):
        unit = self.load('2::3', remove=True)
        data = B'He!ll!o !Wo!rl!d'
        self.assertEqual(unit(data), B'Hello World')

    def test_snip_remove_many(self):
        unit = self.load('::3', '1::3', remove=True)
        data = B'012012012012012013012'
        self.assertEqual(
            [bytes(t) for t in unit.process(data)],
            [B'12121212121312', B'02020202020302']
        )

    def test_snip_can_use_variables(self):
        pipeline = L(R'rex "#(?P<k>\d+)" ABCDEFGHIJKLMNOPQRSTUVWXYZ')[
            L('put k eval:var:k') | L('snip k:k+1')
        ]
        self.assertEqual(pipeline(B'#17#4#5_#8-#13#4#17.#24!'), B'REFINERY')
