#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import BinaryOperation


class rotr(BinaryOperation):
    """
    Rotate the bits of each block right.
    """
    def operate(self, value, shift):
        shift %= self.fbits
        return (value >> shift) | (value << (self.fbits - shift))

    def inplace(self, value, shift):
        shift %= self.fbits
        lower = value >> shift
        value <<= self.fbits - shift
        value |= lower
