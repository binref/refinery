#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements various hashing algorithms.
"""
from refinery.units import Arg, Unit, abc


class HashUnit(Unit, abstract=True):

    @abc.abstractmethod
    def _algorithm(self, data: bytes) -> bytes:
        raise NotImplementedError

    def __init__(
        self,
        reps: Arg.Number('-r', help='Optionally specify a number of times to apply the hash to its own output.') = 1,
        text: Arg.Switch('-t', help='Output a hexadecimal representation of the hash.') = False,
        **kwargs
    ):
        super().__init__(text=text, reps=reps, **kwargs)

    def process(self, data: bytes) -> bytes:
        reps = self.args.reps
        digest = data
        for _ in range(reps):
            digest = self._algorithm(digest)
        if self.args.text:
            digest = digest.hex().encode(self.codec)
        return digest
