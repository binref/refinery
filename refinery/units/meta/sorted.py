#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit


class sorted(Unit):
    """
    Sorts all elements of the input `refinery.lib.frame` lexicographically.
    This unit is a `refinery.nop` on single inputs.
    """

    def filter(self, chunks):
        gobble = list(chunks)
        gobble.sort()
        yield from gobble
