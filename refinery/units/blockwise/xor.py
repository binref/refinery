#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import BinaryOperation, NoNumpy


class xor(BinaryOperation):
    """
    Form the exclusive or of the input data with the given argument.
    """
    def process_ecb_fast(self, data):
        try:
            return super().process_ecb_fast(data)
        except NoNumpy as E:
            try:
                from Crypto.Util.strxor import strxor
            except ModuleNotFoundError:
                raise E
            else:
                from itertools import islice, cycle
                take = len(data) // self.args.blocksize + 1
                argb = self.unchunk(islice(cycle(x & self.fmask for x in self.args.argument[0]), take))
                return strxor(data, argb[:len(data)])

    @staticmethod
    def operate(a, b): return a ^ b
    @staticmethod
    def inplace(a, b): a ^= b
