#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.blockwise import BinaryOperationWithAutoBlockAdjustment, FastBlockError


class xor(BinaryOperationWithAutoBlockAdjustment):
    """
    Form the exclusive or of the input data with the given argument.
    """
    @staticmethod
    def operate(a, b): return a ^ b
    @staticmethod
    def inplace(a, b): a ^= b

    def _fastblock(self, data):
        try:
            return super()._fastblock(data)
        except FastBlockError as E:
            try:
                from Cryptodome.Util.strxor import strxor
            except ModuleNotFoundError:
                raise E
            else:
                from itertools import islice
                size = len(data)
                arg0 = self._normalize_argument(*self._argument_parse_hook(self.args.argument[0]))
                take = len(data) // self.blocksize + 1
                argb = self.unchunk(islice(arg0, take))
                del argb[size:]
                return strxor(data, argb)
