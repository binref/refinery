#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import BinaryOperation


class sub(BinaryOperation):
    """
    Subtract the given argument from each block.
    """
    @staticmethod
    def operate(a, b): return a - b
    @staticmethod
    def inplace(a, b): a -= b
