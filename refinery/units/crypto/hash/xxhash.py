from __future__ import annotations

from refinery.lib.thirdparty.xxhash import xxhash
from refinery.lib.types import Param
from refinery.units.crypto.hash import Arg, HashUnit


class xxh(HashUnit):
    """
    Implements the xxHash hashing algorithm.
    """
    def __init__(
        self,
        seed: Param[int, Arg.Number(metavar='seed', help='specify the seed value; the default is {default}')] = 0,
        text=False
    ):
        super().__init__(text, seed=seed)

    def _algorithm(self, data):
        return xxhash(data, self.args.seed).digest()
