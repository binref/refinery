from __future__ import annotations

from refinery.lib.executable import Executable
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class EndOfStringNotFound(ValueError):
    def __init__(self):
        super().__init__('end of string could not be determined')


class MemoryArea:
    def __init__(self, slice: slice, bounded: bool):
        if slice.start is None:
            self.start = slice.stop
            self.count = None
            self.align = 1
        else:
            self.start = slice.start
            self.count = slice.stop
            self.align = slice.step or 1
            if bounded:
                if (count := self.count - self.start) < 0:
                    raise ValueError(F'Invalid bounds: {self.start:#x}-{self.count:#x}')
                self.count = count


class vsnip(Unit):
    """
    Extract one or more data chunks from PE, ELF, and MachO executables based on their respective
    virtual address.
    """
    @classmethod
    def handles(cls, data) -> bool | None:
        from refinery.lib.id import get_executable_type
        if get_executable_type(data) is not None:
            return True

    def __init__(
        self, *addresses: Param[slice, Arg.Bounds(metavar='start:count:align', help=(
            'Use Python slice syntax to describe an area of virtual memory to read. If a chunksize is '
            'specified, then the unit will always read a multiple of that number of bytes'))],
        bounded: Param[bool, Arg.Switch('-d', group='END', help=(
            'When this flag is specified, addresses are understood as start:end:align, i.e. the second '
            'part of the slice marks the end of the buffer to be extracted.'))] = False,
        ascii: Param[bool, Arg.Switch('-a', group='END',
            help='Read ASCII strings; equivalent to -th:00')] = False,
        utf16: Param[bool, Arg.Switch('-u', group='END',
            help='Read UTF16 strings; equivalent to -th:0000 (also sets chunksize to 2)')] = False,
        until: Param[buf, Arg.Binary('-t', group='END',
            help='Read until sequence {varname} is read.')] = B'',
        base: Param[int | None, Arg.Number('-b', metavar='ADDR',
            help='Optionally specify a custom base address B.')] = None,
    ):
        if sum(1 for t in (until, utf16, ascii) if t) > 1:
            raise ValueError('Only one of utf16, ascii, and until can be specified.')
        return super().__init__(addresses=addresses, bounded=bounded, utf16=utf16, ascii=ascii, until=until, base=base)

    def process(self, data: bytearray):
        bounded = self.args.bounded
        until = self.args.until
        addrs = self.args.addresses
        if self.args.ascii:
            until = B'\0'
        if self.args.utf16:
            until = B'\0\0'
            addrs = (slice(a.start, a.stop, 2) for a in addrs)

        exe = Executable.Load(data, self.args.base)

        for addr in addrs:
            area = MemoryArea(addr, bounded)
            location = exe.location_from_address(area.start)
            offset = location.physical.position
            max_offset = location.physical.box.upper
            if not until:
                end = max_offset
            else:
                end = offset - 1
                align = area.align
                while True:
                    end = data.find(until, end + 1)
                    if end not in range(offset, max_offset):
                        raise EndOfStringNotFound
                    if (end - offset) % align == 0:
                        break

            if area.count:
                end = min(end, offset + area.count)

            yield self.labelled(data[offset:end], offset=offset)
