#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestChop(TestUnitBase):

    def test_check_invalid_args(self):
        with self.assertRaises(Exception):
            self.load(-1)()
        with self.assertRaises(Exception):
            self.load(B'FOOBAR')()
        with self.assertRaises(Exception):
            self.load(0)()

    def test_simple_chunk_with_custom_separator(self):
        for n in range(1, 20):
            unit = self.load(n)
            for m in range(1, 20):
                self.assertEqual(
                    unit(B'A' * n * m),
                    B'\n'.join([B'A' * n for _ in range(m)])
                )

    def test_uneven_chop(self):
        unit = self.load(3)
        self.assertEqual(unit(B'ABCDEFGH'), B'ABC\nDEF\nGH')

    def test_chopped_chunks_fuse_again(self):
        pl = self.load_pipeline('emit FOOBARBAZ [| chop 3 [| chop 1 [| nop ]]| sep , ]')
        self.assertEqual(pl(), B'FOOBARBAZ')

    def test_chop_into(self):
        unit = self.load('--into', 10)
        for size in (11, 15, 20, 34, 200, 2011):
            buffer = self.generate_random_buffer(size)
            chunks = list(unit.process(buffer))
            self.assertEqual(len(chunks), 10)
            self.assertEqual(B''.join(chunks), buffer)
