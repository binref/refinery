"""
Implements various hashing algorithms.
"""
from __future__ import annotations

from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit, abc


class HashUnit(Unit, abstract=True):

    @abc.abstractmethod
    def _algorithm(self, data: buf) -> bytes:
        raise NotImplementedError

    def __init__(
        self,
        reps: Param[int, Arg.Number('-r', help='Optionally specify a number of times to apply the hash to its own output.')] = 1,
        text: Param[bool, Arg.Switch('-t', help='Output a hexadecimal representation of the hash.')] = False,
        **kwargs
    ):
        super().__init__(text=text, reps=reps, **kwargs)

    def process(self, data: bytearray) -> bytes:
        reps = self.args.reps
        digest = data
        for _ in range(reps):
            digest = self._algorithm(digest)
        if self.args.text:
            digest = digest.hex().encode(self.codec)
        return digest
