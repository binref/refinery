#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.crypto.hash import HashUnit
from refinery.lib.thirdparty.xxhash import xxhash


class xxh(HashUnit):
    """
    Implements the xxHash hashing algorithm.
    """
    def __init__(
        self,
        seed: HashUnit.Arg.Number(metavar='seed', help='specify the seed value; the default is {default}') = 0,
        text=False
    ):
        super().__init__(text, seed=seed)

    def _algorithm(self, data):
        return xxhash(data, self.args.seed)
