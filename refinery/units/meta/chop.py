from __future__ import annotations

from refinery.lib.tools import splitchunks
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class chop(Unit):
    """
    Reinterprets the input as a sequence of equally sized chunks and outputs this sequence.
    """

    def __init__(
        self,
        size: Param[int, Arg.Number('size', help='Chop data into chunks of this size')],
        step: Param[int, Arg.Number('step', help=(
            'Optionally specify a step size (which is equal to the size by default) which indicates the number of bytes by '
            'which the cursor will be increased after extracting a chunk.'))] = None,
        truncate: Param[bool, Arg.Switch('-t', help=(
            'Truncate possible excess bytes at the end of the input, by default they are appended as a single chunk.'))] = False,
    ):
        return super().__init__(size=size, step=step, truncate=truncate)

    def process(self, data):
        view = memoryview(data)
        size = self.args.size
        step = self.args.step
        if size < 1:
            raise ValueError('The chunk size has to be a positive integer value.')
        yield from splitchunks(view, size, step, self.args.truncate)
