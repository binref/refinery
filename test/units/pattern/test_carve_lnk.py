#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestCarveLNK(TestUnitBase):

    def test_artifical_01(self):
        samples = [
            self.download_sample('03160be7cb698e1684f47071cb441ff181ff299cb38429636d11542ba8d306ae'),
            self.download_sample('c8fe70f61d05b50dd5f9000979f517e2e9a89b6f9d3e8d896af82064de187cb7'),
        ]
        for sample in samples:
            for a, b in [
                (1, 1),
                (0, 0),
                (0, 9),
                (9, 0),
                (122, 20034),
                (20032, 100),
            ]:
                prefix = self.generate_random_buffer(a)
                suffix = self.generate_random_buffer(b)
                test = prefix + sample + suffix
                result = test | self.load() | bytes
                self.assertEqual(result, sample)

    def test_double_buffer(self):
        a = self.download_sample('03160be7cb698e1684f47071cb441ff181ff299cb38429636d11542ba8d306ae')
        b = self.download_sample('c8fe70f61d05b50dd5f9000979f517e2e9a89b6f9d3e8d896af82064de187cb7')
        for sequence in [[a, a], [b, b], [a, b], [b, a], [b, a, b]]:
            concatenation = B''.join(sequence)
            test = self.generate_random_buffer(42) + concatenation + self.generate_random_buffer(12)
            test = test | self.load() | []
            self.assertListEqual(test, sequence)
