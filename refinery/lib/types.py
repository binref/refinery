#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exports two singletons `refinery.lib.types.INF` and `refinery.lib.types.AST`.
Used by `refinery.units.pattern.PatternExtractorBase` as the default values
for certain command line arguments.
"""
__all__ = ['INF', 'AST']


class INF:
    def __lt__(self, other): return False
    def __le__(self, other): return False
    def __gt__(self, other): return True
    def __ge__(self, other): return True
    def __eq__(self, other): return other is INF
    def __rmul__(self, other): return self
    def __radd__(self, other): return self
    def __mul__(self, other): return self
    def __add__(self, other): return self
    def __sub__(self, other): return self
    def __div__(self, other): return self
    def __mod__(self, other): return self
    def __pow__(self, other): return self
    def __abs__(self): return None
    def __repr__(self): return '∞'
    def __truediv__(self, other): return self
    def __floordiv__(self, other): return self


class AST:
    def __eq__(self, other): return True
    def __ne__(self, other): return False
    def __or__(self, other): return other
    def __repr__(self): return '*'


INF = INF()
"""
A crude object representing infinity, which is greater than anything it
is compared to, and only equal to itself.
"""

AST = AST()
"""
A wildcard object which is equal to everything.
"""
