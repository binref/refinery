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

    def test_length_argument(self):
        data = b"FOOBARFOOBAZBAZ"
        unit = self.load('3:3', '9:', length=True, squeeze=True)
        self.assertEqual(data | unit | bytes, B'BARBAZBAZ')

    def test_stream_normal(self):
        data = (
            B'0'   # skipped
            B'12'  # selected
            B'3'   # selected
            B'45'  # skipped
            B'567' # selected
        )
        unit = self.load('1:3', ':1', '2:5', stream=True, squeeze=True)
        self.assertEqual(data | unit | bytes, B'123567')

        unit = self.load('1:2', ':1', '2:3', stream=True, squeeze=True, length=True)
        self.assertEqual(data | unit | bytes, B'123567')

    def test_stream_removal(self):
        data = B'0123456789'
        unit = self.load('1:2', '1:2',
            stream=True, length=True, remove=True)
        self.assertListEqual(data | unit | [bytes], [
            B'03456789',
            B'01236789',
        ])

    def test_stream_partitioning(self):
        a = self.generate_random_buffer(280)
        b = self.generate_random_buffer(900)
        c = self.generate_random_buffer(128)
        data = a + b + c
        unit = self.load(':280', ':900', ':', stream=True)
        test = data | unit | [bytes]
        self.assertListEqual(test, [a, b, c])

    def test_snip_regression_01(self):
        self.assertEqual(
            bytes.fromhex('00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF') | self.load('--', '-5::-1') | bytes,
            bytes.fromhex('BB AA 99 88 77 66 55 44 33 22 11 00'))

    def test_snip_regression_02(self):
        self.assertEqual(
            bytes.fromhex('00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF') | self.load('5::-1') | bytes,
            bytes.fromhex('55  44  33 22 11 00'))

    def test_snip_regression_03(self):
        self.assertEqual(
            bytes.fromhex('00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF') | self.load(':-5:-1') | bytes,
            bytes.fromhex('FF EE DD CC'))

    def test_snip_regression_04(self):
        self.assertEqual(
            bytes.fromhex('00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF') | self.load(':5:-1') | bytes,
            bytes.fromhex('FF EE DD CC BB AA 99 88 77 66'))

    def test_remove_negative(self):
        data = B'REFINERY'
        self.assertEqual(data | self.load('--', '-2:-2:-1', length=True) | bytes, B'RE')
        self.assertEqual(data | self.load('--', '-2:-4:-1', remove=True) | bytes, B'REFINY')
