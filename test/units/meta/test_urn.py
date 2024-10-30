#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import TestUnitBase


class TestUrn(TestUnitBase):

    def test_the_urn(self):
        import itertools
        test_values = [B'A', B'B', B'FOO', B'BAR']
        F = False
        T = True
        for sort, keep, method in [
            (F, F, lambda i, r: itertools.product(i, repeat=r)),
            (F, T, itertools.combinations),
            (T, F, itertools.combinations_with_replacement),
            (T, T, itertools.permutations),
        ]:
            for length in range(1, 4):
                unit = self.load(length, keep=keep, sort=sort)
                emit = self.ldu('emit', *test_values)
                _nop = self.ldu('nop')
                _sep = self.ldu('sep', B'-')
                goal = {B'-'.join(s) for s in method(test_values, length)}
                test = emit[unit[_sep] | _nop]
                test = test | {bytes}
                self.assertSetEqual(goal, test)

    def test_variables_are_preserved(self):
        test = self.load_pipeline('emit FOO BAR BAZ [| pop a | urn -ks []| ccp var:a ]')
        test = test | {str}
        self.assertSetEqual(test, {
            'FOOBARBAZ',
            'FOOBAZBAR',
        })

    def test_default_behavior_nonempty(self):
        test = self.load_pipeline('emit A B C [| urn -ks []]') | bytes
        self.assertEqual(len(test), 18)
