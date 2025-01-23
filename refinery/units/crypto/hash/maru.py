#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.maru import maru32digest
from refinery.units.crypto.hash import HashUnit, Arg


class MaruHash(HashUnit, abstract=True):
    def __init__(self, seed: Arg.Number(help='optional seed value') = 0, text=False):
        super().__init__(seed=seed, text=text)


class maru(MaruHash):
    """
    Returns the 64bit maru hash of the input data.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return maru32digest(data, self.args.seed)
