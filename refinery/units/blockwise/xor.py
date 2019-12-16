#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import ArithmeticUnit


class xor(ArithmeticUnit):
    """
    Form the exclusive or of the input data with the given argument.
    """
    def process_ecb_fast(self, data):
        try:
            from Crypto.Util.strxor import strxor
        except ModuleNotFoundError:
            self.log_warn('the pycryptodome package does not seem to be installed, falling back to numpy.')
            return super().process_ecb_fast(data)
        from itertools import islice, cycle
        take = len(data) // self.args.blocksize + 1
        argb = self.unchunk(islice(cycle(x & self.fmask for x in self.args.arg[0]), take))
        return strxor(data, argb[:len(data)])

    @staticmethod
    def operate(a, b): return a ^ b
    @staticmethod
    def inplace(a, b): a ^= b
