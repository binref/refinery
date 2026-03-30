from __future__ import annotations

import abc

from zlib import crc32

from refinery.lib.decorators import unicoded
from refinery.lib.types import Param, buf
from refinery.units import Arg, Chunk, RefineryPartialResult, Unit


class AutoDeobfuscationTimeout(RefineryPartialResult):
    def __init__(self, partial):
        super().__init__(
            'The deobfuscation timeout was reached before the data stabilized.',
            partial=partial,
        )


class Deobfuscator(Unit, abstract=True):

    def __init__(self):
        super().__init__()

    @unicoded
    def process(self, data: str) -> str:
        return self.deobfuscate(data)

    @abc.abstractmethod
    def deobfuscate(self, data: str) -> str:
        return data


class IterativeDeobfuscator(Deobfuscator, abstract=True):

    def __init__(
        self,
        timeout: Param[int, Arg(
            '-t', help='Maximum number of iterations; the default is 100.')] = 100,
    ):
        if timeout < 1:
            raise ValueError('The timeout must be at least 1.')
        super().__init__()
        self.args.timeout = timeout

    def process(self, data: Chunk) -> buf:
        previous = crc32(data)
        for _ in range(self.args.timeout):
            try:
                data[:] = super().process(data)
            except KeyboardInterrupt:
                raise RefineryPartialResult(
                    'Returning partially deobfuscated data', partial=data)
            checksum = crc32(data)
            if checksum == previous:
                break
            previous = checksum
        else:
            raise AutoDeobfuscationTimeout(data)
        return data
