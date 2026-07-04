from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from refinery.lib.argformats import DelayedNumSeqArgument
from refinery.lib.types import NIL, Param
from refinery.units import Arg, Chunk, Unit


@dataclass
class ScanRegister:
    """
    A register used by the `scan` unit.
    """
    name: str
    expression: str
    value: Any = None

    @classmethod
    def FromString(cls, spec: str):
        name, eq, rest = spec.partition('=')
        if eq != '=':
            raise ValueError
        return cls(name, rest)


class scan(Unit):
    """
    Scan the frame, threading an accumulator through the chunks. This is the counterpart to the
    `refinery.reduce` unit: rather than folding the frame down to a single chunk, it keeps every
    chunk and stores the running accumulator as a meta variable on each of them.

    The arguments to <this> are expressions of the form `x=update` where `x` is a variable name
    and `update` is a multibin expression.

    For each chunk after the first, the variable `x` is overwritten with its previous value. The
    update expression is then evaluated on the current chunk to compute the next value. If `x`
    does not exist on the chunk, a best effort is made to choose a neutral value of the correct
    type. Use the `put` unit first to explicitly choose an initial value.

    For example, imagine a frame where each chunk contains a variable `n`:

        ... [| <this> m=m+n | snip -l m:n | ... ]

    The above call to <this> will populate a new variable `m` which holds the running sum of all
    values of `n` up to and including each chunk.
    """

    def __init__(
        self,
        *registers: Param[str, Arg.String(metavar='x=update', help='accumulator expressions')],
    ):
        if not registers:
            raise ValueError('At least one register must be specified.')
        super().__init__(registers=registers)

    def filter(self, chunks: Iterable[Chunk]):
        registers = [ScanRegister.FromString(a) for a in self.args.registers]
        for chunk in chunks:
            if not chunk.visible:
                yield chunk
                continue
            empty_names = set()
            meta = chunk.meta
            for register in registers:
                name = register.name
                if register.value is not None:
                    meta[name] = register.value
                elif name not in meta:
                    meta[name] = NIL()
                    empty_names.add(name)
            self.log_debug(list(meta))
            for register in registers:
                name = register.name
                rv = DelayedNumSeqArgument(register.expression, reverse=True)(chunk)
                if NIL.Concretize(rv) is None:
                    continue
                meta[name] = register.value = rv
                empty_names.discard(name)
            for name in empty_names:
                meta.discard(name)
            yield chunk
