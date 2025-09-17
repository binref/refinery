from __future__ import annotations

from refinery.lib.dotnet.disassembler import Disassembler
from refinery.lib.dotnet.disassembler.factory import OutputFactory
from refinery.lib.types import Param
from refinery.units.sinks import Arg, Unit


class DotnetDisassemblerUnit(Unit, abstract=True):
    """
    Abstract unit to share arguments between `dnopc` and `dnasm`.
    """

    def __init__(
        self,
        *,
        count: Param[int, Arg.Number(
            '-c',
            help='Maximum number of bytes to disassemble, infinite by default.',
        )] = None,
        until: Param[str, Arg.String(
            '-u',
            help='Disassemble until the given string appears among the disassembly.',
        )] = None,
        **more
    ):
        super().__init__(count=count, until=until, **more)


class dnopc(DotnetDisassemblerUnit):
    """
    Disassembles the input data as MSIL (.NET/C# bytecode) and generates opcodes with metadata as output. This
    is useful for programmatic disassembly, while the `refinery.dnasm` unit outputs a human-readable
    representation.
    """

    def __init__(
        self,
        *,
        count=None,
        until=None,
        nvar: Param[str, Arg.String(
            '-n',
            help='Variable to receive the disassembled mnemonic. Default is "{default}".',
        )] = 'name',
        avar: Param[str, Arg.String(
            '-a',
            help='Variable to receive the address of the instruction. Default is "{default}".',
        )] = 'addr',
        ovar: Param[str, Arg.String(
            '-o',
            help=('Variable prefix for instruction operands. Default is "{default}". The complete operand '
                  'string will be in {default}s, the first argument in {default}1, the second in {default}2, '
                  'and so on.'),
        )] = 'arg',
        **more
    ):
        super().__init__(
            count=count,
            until=until,
            nvar=nvar,
            avar=avar,
            ovar=ovar,
            **more
        )

    def process(self, data):
        until = str(self.args.until or '').lower()
        factory = OutputFactory()
        for ins in Disassembler().disasm(data, self.args.count):
            kwargs = {
                self.args.avar: ins.offset,
                self.args.nvar: ins.op.mnemonic,
            }
            for k, arg in enumerate(ins.arguments, 1):
                kwargs[F'{self.args.ovar}{k}'] = arg.value
            yield self.labelled(ins.data, **kwargs)

            if until and until in factory.instruction(ins).lower():
                break
