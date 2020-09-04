#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct

from .. import TestUnitBase


class TestLengthPrefix(TestUnitBase):

    def test_different_headers(self):
        for prefix in ('<xxLx', '<L', '<H', '>xH', '>xxxL', '<20xQxx'):
            chunks = [self.generate_random_buffer(t) for t in (35, 712, 11, 9, 934)]
            data = B''.join(struct.pack(prefix, len(chunk)) + chunk for chunk in chunks)
            unit = self.load(prefix)
            self.assertEqual(list(unit.process(data)), chunks)
            junk = struct.calcsize(prefix) * B'\xFF' + self.generate_random_buffer(45)
            data += junk
            chunks.append(junk)
            self.assertEqual(list(unit.process(data)), chunks)
            unit = self.load(prefix, strict=True)
            self.assertEqual(list(unit.process(data)), chunks[:-1])

    def test_modified_value(self):
        body = self.generate_random_buffer(3133)
        head = struct.pack('=HbbLbH', 12, 6, 6, 3133, 0, 0xBEEF)
        pack = head + body
        unit = self.load('=4xL3x', header=2)
        self.assertEqual(unit(pack), pack)
        unit = self.load('=4xL3x')
        self.assertEqual(unit(pack), body)
        unit = self.load('=4xL3x', header=1, derive='N+11')
        self.assertEqual(unit(pack), pack)

