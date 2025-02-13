#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.murmur import (
    v3_mmh128digest32,
    v3_mmh128digest64,
    v3_mmh32digest,
    v2_mmh32digest,
    v2_mmh32digestA,
    v2_mmh64digestA,
    v2_mmh64digestB,
)
from refinery.units.crypto.hash import HashUnit, Arg


class MurMurHash(HashUnit, abstract=True):
    def __init__(
        self,
        seed: Arg.Number(help='Optional seed value, defaults to {default}.') = 0,
        reps=1,
        text=False,
    ):
        super().__init__(seed=seed, text=text, reps=reps)


class m2h(MurMurHash):
    """
    Returns the 32bit Murmur Hash, Version 2.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return v2_mmh32digest(data, self.args.seed)


class m2ha(MurMurHash):
    """
    Returns the 32bit Murmur Hash, Version 2, Variant A.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return v2_mmh32digestA(data, self.args.seed)


class m2h64a(MurMurHash):
    """
    Returns the 64bit Murmur Hash, Version 2, Variant A.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return v2_mmh64digestA(data, self.args.seed)


class m2h64b(MurMurHash):
    """
    Returns the 64bit Murmur Hash, Version 2, Variant B.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return v2_mmh64digestB(data, self.args.seed)


class m3h(MurMurHash):
    """
    Returns the 32bit Murmur Hash, Version 3.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return v3_mmh32digest(data, self.args.seed)


class m3h64(MurMurHash):
    """
    Returns the 128bit Murmur Hash, Version 3, 64bit digest size.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return v3_mmh128digest64(data, self.args.seed)


class m3h32(MurMurHash):
    """
    Returns the 128bit Murmur Hash, Version 3, 32bit digest size.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return v3_mmh128digest32(data, self.args.seed)
