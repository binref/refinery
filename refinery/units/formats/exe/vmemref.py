from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Container

from refinery.lib.executable import CompartmentNotFound, Executable, Range
from refinery.lib.shared import smda
from refinery.lib.tools import NoLogging
from refinery.lib.types import Param
from refinery.units import Arg, Unit

if TYPE_CHECKING:
    from smda.common.SmdaFunction import SmdaFunction


class vmemref(Unit):
    """
    The unit expects an executable as input (PE/ELF/MachO) and scans a function at a given virtual
    address for memory references. For each memory reference, the unit looks up the corresponding
    section and file offset for the reference. It then returns all data from that section starting
    at the given offset.
    """
    def _memory_references(
        self,
        exe: Executable,
        function: SmdaFunction,
        codes: Container[Range],
        max_dereference_depth: int,
        max_dereference_count: int,
        references: dict,
    ):
        def is_valid_data_address(address):
            if not isinstance(address, int):
                return False
            if address not in exe:
                return False
            if address in instructions:
                return False
            for code in codes:
                if address in code:
                    return False
            return True

        def dereference(address):
            return int.from_bytes(exe[address:address + pointer_size], exe.byte_order().value)

        pointer_size = exe.pointer_size // 8

        with NoLogging():
            instructions = {op.offset: op for op in function.getInstructions()}

        for op in instructions.values():
            try:
                with NoLogging():
                    refs = list(op.getDataRefs())
            except Exception:
                continue
            for address in refs:
                try:
                    address = int(address)
                except Exception:
                    continue
                addresses = deque([address])
                while addresses:
                    address = addresses.pop()
                    if not is_valid_data_address(address):
                        continue
                    if (count := references.get(address, 0)) > max_dereference_depth:
                        continue
                    elif not count:
                        yield address
                    references[address] = count + 1
                    for _ in range(max_dereference_count):
                        try:
                            point = dereference(address)
                        except Exception:
                            pass
                        else:
                            addresses.appendleft(point)
                        finally:
                            address += pointer_size

    def __init__(
        self,
        *address: Param[int, Arg.Number(metavar='ADDR', help=(
            'Specify the address of a function to scan. If no argument is given, the unit will scan'
            ' all functions for memory references.'))],
        take: Param[int, Arg.Number('-t', metavar='SIZE', help=(
            'Optionally specify the number of bytes to read from each reference; by default, all '
            'data until the end of the section is returned.'))] = None,
        base: Param[int, Arg.Number('-b', metavar='ADDR',
            help='Optionally specify a custom base address B.')] = None,
        deref_count: Param[int, Arg.Number('-c', help=(
            'Optionally specify the number of items to inspect at a discovered memory address as '
            'as a potential pointer. The default is {default}.'))] = 1,
        deref_depth: Param[int, Arg.Number('-d', help=(
            'Optionally specify the maximum number of times that referenced data is dereferenced '
            'as a pointer, potentially leading to another referenced memory location. The default '
            'is {default}.'))] = 2,
    ):
        super().__init__(
            address=address,
            take=take,
            base=base,
            deref_count=deref_count,
            deref_depth=deref_depth,
        )

    def process(self, data):
        take = self.args.take
        exe = Executable.Load(data, self.args.base)
        fmt = exe.pointer_size // 4
        addresses = self.args.address

        self.log_info('disassembling and exploring call graph using smda')
        with NoLogging():
            cfg = smda.Disassembler.SmdaConfig()
            cfg.CALCULATE_SCC = False
            cfg.CALCULATE_NESTING = False
            cfg.TIMEOUT = 600
            dsm = smda.Disassembler.Disassembler(cfg)
            _input = data
            if not isinstance(_input, bytes):
                _input = bytes(data)
            graph = dsm.disassembleUnmappedBuffer(_input)

        self.log_info('collecting code addresses for memory reference exclusion list')
        visits = {}
        avoid = set()

        for symbol in exe.symbols():
            if not symbol.function:
                continue
            if not symbol.exported:
                continue
            avoid.add(exe.location_from_address(symbol.address).virtual.box)

        if addresses:
            reset = visits.clear
        else:
            def reset():
                pass
            self.log_info('scanning executable for functions')
            with NoLogging():
                addresses = [pfn.offset for pfn in graph.getFunctions()]
                addresses.sort()

        for a in addresses:
            reset()
            address, function = min(
                graph.xcfg.items(), key=lambda t: (abs(t[0] - a), t[0] >= a))
            self.log_debug(F'scanning function: 0x{address:0{fmt}X}')
            refs = list(self._memory_references(
                exe,
                function,
                avoid,
                self.args.deref_depth,
                self.args.deref_count,
                visits,
            ))
            refs.sort(reverse=True)
            last_start = None
            for ref in refs:
                try:
                    box = exe.location_from_address(ref)
                    end = box.physical.box.upper
                    if take is not None:
                        end = min(box.physical.position + take, end)
                    if last_start is not None:
                        end = min(last_start, end)
                    last_start = box.physical.position
                except CompartmentNotFound:
                    self.log_info(F'memory reference could not be resolved: 0x{ref:0{fmt}X}')
                else:
                    yield exe.data[last_start:end]
