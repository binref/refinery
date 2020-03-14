#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import BinaryOperation


class rotl(BinaryOperation):
    """
    Rotate the bits of each block left.
    """
    def operate(self, value, shift):
        shift %= self.fbits
        return (value << shift) | (value >> (self.fbits - shift))

    def inplace(self, value, shift):
        shift %= self.fbits
        lower = value >> (self.fbits - shift)
        value <<= shift
        value |= lower
