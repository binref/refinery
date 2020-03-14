#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import UnaryOperation


class neg(UnaryOperation):
    """
    Each block of the input data is negated bitwise. This is sometimes
    also called the bitwise complement or inverse.
    """
    def operate(self, a): return ~a
    def inplace(self, a): a ^= self.fmask
