from __future__ import annotations

import re

from refinery.lib.dotnet.disassembler import Disassembler
from refinery.lib.dotnet.disassembler.factory import OutputFactory
from refinery.lib.meta import metavars
from refinery.lib.types import Param
from refinery.units.formats.pe.dotnet.dnopc import DotnetDisassemblerUnit
from refinery.units.sinks import Arg


class dnasm(DotnetDisassemblerUnit):
    """
    Disassembles the input data as MSIL (.NET/C# bytecode) and produces a human-readable disassembly listing. If you are
    looking for a more programmatic disassembly, take a look at `refinery.dnopc`.
    """

    def __init__(
        self, *,
        count=None, until=None,
        no_il_refs: Param[bool, Arg.Switch('-I', help='Disable reference resolution to IL_*.')] = False,
        no_address: Param[bool, Arg.Switch('-A', help='Disable address display.')] = False,
        no_hexdump: Param[bool, Arg.Switch('-H', help='Disable opcodes hexdump.')] = False,
        no_args: Param[bool, Arg.Switch('-O', help='Disable output of instruction arguments.')] = False,
        description: Param[bool, Arg.Switch('-d', help='Enable opcodes descriptions in output.')] = False,
    ):
        self._output_factory = OutputFactory(
            il_refs=not no_il_refs,
            address=not no_address,
            hexdump=not no_hexdump,
            arguments=not no_args,
        )
        self._disassembler = Disassembler()
        super().__init__(
            count=count,
            until=until,
            description=description,
        )

    def process(self, data):
        meta = metavars(data)
        r = re.compile(r't[0-9a-f]+', re.IGNORECASE)
        self._output_factory.extend_token_labels({int(k[1:], 16): v for k, v in meta.items() if r.match(k)})
        until = str(self.args.until or '').lower()

        max_line_length = 0
        if self.args.description:
            disasm = []
            for ins in self._disassembler.disasm(data, self.args.count):
                disasm.append(ins)
                line = self._output_factory.instruction(ins)
                max_line_length = max(max_line_length, len(line))
        else:
            disasm = self._disassembler.disasm(data, self.args.count)

        for ins in disasm:
            line = self._output_factory.instruction(ins)
            if self.args.description:
                line += ' ' * (max_line_length - len(line) + 2)
                line += f'-- {ins.op.description}'
            yield line.encode("utf-8")

            if until and until in line.lower():
                break
