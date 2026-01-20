from __future__ import annotations

from itertools import cycle

from refinery.lib.argformats import PythonExpression
from refinery.lib.types import Param
from refinery.units.crypto.cipher import Arg, StreamCipherUnit


class rc4mod(StreamCipherUnit):
    """
    Implements a modified version of the RC4 stream cipher where the size of the RC4 SBox can be altered.
    """

    def __init__(
        self, key, stateful=False, discard=0, *,
        size: Param[int, Arg.Number('-t', bound=(1, None), help='Table size, {default} by default.')] = 0x100,
        body: Param[str, Arg.String('-K', help=(
            'Optional expression involving the table T and the two indices A and B. This expression is used '
            'to compute the actual key stream byte during each RC4 round. The default is {default}.'
        ))] = 'T[T[A]+T[B]]'
    ):
        super().__init__(key=key, stateful=stateful, discard=discard, body=body, size=size)

    def keystream(self):
        size = self.args.size
        body = PythonExpression(self.args.body, *'TAB', modulus=size)
        tablerange = range(max(size, 0x100))
        b, table = 0, bytearray(k & 0xFF for k in tablerange)
        for a, keybyte in zip(tablerange, cycle(self.args.key)):
            t = table[a]
            b = (b + keybyte + t) % size
            table[a] = table[b]
            table[b] = t
        self.log_debug(lambda: F'SBOX = {table.hex(" ").upper()}', clip=True)
        b, a = 0, 0
        while True:
            a = (a + 1) % size
            t = table[a]
            b = (b + t) % size
            table[a] = table[b]
            table[b] = t
            yield body(T=table, A=a, B=b)
