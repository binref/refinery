from __future__ import annotations

from refinery.lib.maru import maru32digest
from refinery.units.crypto.hash import HashUnit, Arg


class maru(HashUnit):
    """
    Returns the 64bit maru hash of the input data.
    """
    def __init__(
        self,
        seed: Arg.Number(help='optional seed value') = 0,
        reps=1,
        text=False,
    ):
        super().__init__(seed=seed, text=text, reps=reps)

    def _algorithm(self, data) -> bytes:
        return maru32digest(data, self.args.seed)
