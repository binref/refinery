from __future__ import annotations

import abc
import codecs
import sys

from refinery.lib.scripts import Node
from refinery.lib.types import Param, buf
from refinery.units import Arg, Chunk, RefineryPartialResult, Unit


class AutoDeobfuscationTimeout(RefineryPartialResult):
    def __init__(self, partial):
        super().__init__(
            'The deobfuscation timeout was reached before the data stabilized.',
            partial=partial,
        )


class IterativeDeobfuscator(Unit, abstract=True):

    def __init__(
        self,
        timeout: Param[int, Arg.Number(
            '-t', help='Maximum number of iterations; the default is {default}.')] = 500,
    ):
        super().__init__(timeout=timeout)

    @abc.abstractmethod
    def parse(self, data: str) -> Node:
        ...

    @abc.abstractmethod
    def transform(self, ast: Node) -> int:
        ...

    @abc.abstractmethod
    def synthesize(self, ast: Node) -> str:
        ...

    def process(self, data: Chunk) -> buf:
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(max(old_limit, 10000))
        try:
            return self._process(data)
        finally:
            sys.setrecursionlimit(old_limit)

    def _process(self, data: Chunk) -> buf:
        def _result():
            return codecs.encode(
                self.synthesize(ast), self.codec, errors='surrogateescape')

        self.log_info('parsing input data')
        txt = codecs.decode(data, self.codec, errors='surrogateescape')
        ast = self.parse(txt)

        for k in range(self.args.timeout):
            self.log_info(F'starting round {k}')
            if self.transform(ast):
                continue
            return _result()
        else:
            raise AutoDeobfuscationTimeout(_result())
