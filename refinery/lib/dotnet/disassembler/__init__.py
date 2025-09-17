"""
A library to disassemble .NET assembly
"""
from __future__ import annotations

from typing import Iterator

from refinery.lib.dotnet.disassembler.factory import InstructionFactory
from refinery.lib.dotnet.disassembler.model import Instruction, UnknownInstruction
from refinery.lib.dotnet.disassembler.repository import OpRepository


class Disassembler:
    def __init__(self):
        self._op_repository = OpRepository()
        self._factory = InstructionFactory()

    def disasm(self, data: bytes, max_byte_count: int | None = None) -> Iterator[Instruction]:
        i = 0
        while i < len(data):
            if max_byte_count and i >= max_byte_count:
                break
            op = self._op_repository.lookup(data[i:])
            if op is None:
                raise UnknownInstruction(f"Found at {i}: {data[i:i + 8].hex()}...")
            if op.is_switch:
                ins = self._factory.switch(data[i:], i, op)
            else:
                ins = self._factory.create(data[i: i + len(op)], i, op)
            yield ins
            if op.fixed_length:
                assert len(op) == len(ins)
            i += len(ins)
