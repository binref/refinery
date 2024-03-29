#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.blockwise import BinaryOperationWithAutoBlockAdjustment


class add(BinaryOperationWithAutoBlockAdjustment):
    """
    Add the given argument to each block.
    """
    @staticmethod
    def operate(a, b): return a + b
    @staticmethod
    def inplace(a, b): a += b
