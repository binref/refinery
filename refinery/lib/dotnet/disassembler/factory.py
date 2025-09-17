from __future__ import annotations

from refinery.lib.dotnet.disassembler.model import (
    Argument,
    DisassemblerException,
    Instruction,
    Method,
    Op,
    String,
)


class InstructionFactory:
    @staticmethod
    def create(data: bytes, i: int, op: Op) -> Instruction:
        argument_data = (
            data[len(op.code): len(op)] if op.fixed_length else data[len(op.code):]
        )
        if len(op) - len(op.code) != len(argument_data):
            raise DisassemblerException(
                'Mismatching argument length for "%s" %i - %i != %i: %s'
                % (
                    op.mnemonic,
                    len(op),
                    len(op.code),
                    len(argument_data),
                    argument_data.hex(),
                )
            )

        arguments = []
        k = 0
        for cil_arg in op.arguments:
            arguments.append(Argument(argument_data[k: k + len(cil_arg)], cil_arg))
            k += len(cil_arg)
        return Instruction(data, i, op, arguments)

    @staticmethod
    def switch(data: bytes, i: int, op: Op) -> Instruction:
        assert data[0] == 69
        case_count_arg = op.arguments[0]
        case_data = data[1:5]
        cases = case_count_arg.unpack(case_data)
        end_offset = (cases + 1) * 4
        if len(data) < end_offset:
            raise DisassemblerException(F'Check failed during switch disassembly: {len(data)} < ({cases} + 1) * 4')
        if op.arguments[2] is not ...:
            raise DisassemblerException('Last argument for switch op must be ellipsis.')

        args = [Argument(case_data, case_count_arg)]
        case_arg = op.arguments[1]
        for k in range(4, end_offset, 4):
            raw_data = data[1 + k:1 + k + 4]
            args.append(Argument(raw_data, case_arg))
        return Instruction(data[:1 + end_offset], i, op, args)


class OutputFactory:
    def __init__(
        self,
        il_refs: bool = False,
        address: bool = True,
        hexdump: bool = True,
        arguments: bool = True,
        token_labels: dict[int, str] | None = None,
    ):
        self._il_refs = il_refs
        self._address = address
        self._hexdump = hexdump
        self._arguments = arguments
        self._token_labels = {} if token_labels is None else token_labels

    def extend_token_labels(self, token_labels: dict[int, str]):
        self._token_labels.update(token_labels)

    def instruction(self, instruction: Instruction) -> str:
        if not self._arguments or len(instruction.op.arguments) == 0:
            args = ''
        elif instruction.op.is_switch:
            args = F" -> {', '.join(self._il(instruction, arg.value) for arg in instruction.arguments[1:])}"
        else:
            ins_argument = instruction.arguments[0]
            op_argument = instruction.op.arguments[0]
            args = f"(0x{ins_argument.value:X}"
            if self._il_refs and op_argument.has_target:
                args += f" -> {self._il(instruction, ins_argument.value)}"
            elif isinstance(op_argument, Method) and ins_argument.value in self._token_labels.keys():
                args += f" -> {self._token_labels[ins_argument.value]}"
            elif isinstance(op_argument, String) and ins_argument.value in self._token_labels.keys():
                args += f' -> "{self._token_labels[ins_argument.value]}"'
            args += ')'

        prefix_parts = []
        if self._hexdump:
            prefix_parts.append(f"/* {instruction.data.hex():<12} */")
        if self._address:
            prefix_parts.append(f"IL_{instruction.offset:04X}")
        line = ' '.join(prefix_parts) + ': ' if prefix_parts else ''
        line += F"{instruction.op.mnemonic}{args}"

        return line

    @staticmethod
    def _il(instruction: Instruction, offset: int) -> str:
        return F"IL_{instruction.offset + offset + len(instruction):04X}"
