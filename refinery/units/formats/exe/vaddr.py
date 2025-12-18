from __future__ import annotations

from refinery.lib.argformats import metavars
from refinery.lib.executable import LT, Executable
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class vaddr(Unit):
    """
    Converts a metadata variable holding a file offset to a virtual address. This unit only works when the
    chunk body contains a PE, ELF, or MachO executable. The variable will be substituted in place. If you
    would like to retain the original value, it is recommended to use the `refinery.put` unit first to create
    a copy of an already existing variable, and then convert the copy.
    """

    def __init__(
        self, *name: Param[str, Arg.String(help='The name of a metadata variable holding an integer.')],
        base: Param[int | None, Arg.Number('-b', metavar='ADDR', help='Optionally specify a custom base address B.')] = None
    ):
        return super().__init__(names=name, base=base)

    def _convert(self, data, t: LT):
        try:
            exe = Executable.Load(data, self.args.base)
        except Exception:
            self.log_warn('unable to parse input as executable; no variable conversion was performed')
            return data
        meta = metavars(data)
        w = 2 + exe.pointer_size_in_bytes * 2
        for name in self.args.names:
            value = meta[name]
            if not isinstance(value, int):
                raise ValueError(F'The variable {name} is not an integer.')
            pos = exe.lookup_location(value, t)
            self.log_debug('determined location:', pos)
            val = pos.virtual.position if t == LT.PHYSICAL else pos.physical.position
            self.log_info(F'{value:#0{w}x} to {val:#0{w}x}')
            meta[name] = val
        return data

    def process(self, data):
        return self._convert(data, LT.PHYSICAL)

    def reverse(self, data):
        return self._convert(data, LT.VIRTUAL)
